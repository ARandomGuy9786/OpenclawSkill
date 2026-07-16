/**
 * Receiver core — Tier-2 session engine (SYNC-3 §3–§6, §9).
 *
 * The session manager the receiver-daemon design (§4) deferred until Phase 3:
 * a correlation `Map` (session_id → entry) + a per-session turn lock. It plays
 * BOTH handshake roles — responder when invited, initiator once the CLI (A3)
 * POSTs /sessions — participates in the mutual-authentication challenge-response,
 * signs/verifies every data frame with the connector's Ed25519 key (via
 * signing.js — the connector owns ALL crypto; the brain never sees keys or
 * signatures), and drives the brain across multi-turn conversations.
 *
 * Additive to Tier-1: this engine only ever sees `session.*` frames (the task
 * path in receiver.js is untouched and runs first). No back-compat shims.
 *
 * Batch A3 (built here — §4, §7, §9, §10):
 *   - File transfer (§7): outbound `FILE:` lines are path-guarded, hashed,
 *     uploaded (POST /sessions/{id}/files → signed URL → upload), then emitted
 *     as signed `session.file` frames; inbound `session.file` is downloaded,
 *     sha256-verified against the SIGNED descriptor, saved into the session
 *     workdir, and rendered to the brain (mismatch/failure → session.error).
 *   - Per-session workdir: <connectorHome()>/sessions/<id>/files/ (lazy create,
 *     best-effort recursive removal on close).
 *   - Log-index catch-up (§4): a detected `log_index` gap triggers a
 *     GET /sessions/{id}/messages?after_index=N reconciliation, replaying the
 *     partner's intervening frames through the SAME acceptance path (recursion
 *     guarded) before the frame that revealed the gap.
 *   - Initiator CLI handoff (§10): the CLI (receiver/session_cli.js) POSTs
 *     /sessions and drops a pending file; on `session.open` for an unknown
 *     session the daemon adopts that pending handoff (registerInitiatedSession).
 */

import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename } from "node:path";
import * as signingModule from "./signing.js";
import { COORDINATOR_URL, AGENT_KEY, connectorHome } from "./config.js";
import {
  ensureSessionWorkdir,
  listSendableFiles,
  mimeForName,
  pendingFilePath,
  readOutboundFile,
  removeSessionWorkdir,
  resolveInWorkdir,
  sha256HexBytes,
  uniquePath,
} from "./files.js";
import {
  parseConsent,
  parseSessionReply,
  renderInvite,
  renderSessionTurn,
} from "./contract.js";

export class SessionEngine {
  /**
   * @param {object} deps
   * @param {{ send: Function }} deps.transport  frame-capturing transport (receiver.js's Transport)
   * @param {object} deps.adapter                the brain adapter (run/resume/closeSession/supportsResume)
   * @param {object} deps.config                 { agentId, keyPath, agentKey?, coordinatorUrl?, home? }
   * @param {object} [deps.signing]              signing.js (injectable for tests)
   * @param {Function} [deps.fetch]              fetch impl (injectable for tests)
   * @param {Function} [deps.log]
   */
  constructor({ transport, adapter, config, signing, fetch, log } = {}) {
    this.transport = transport;
    this.adapter = adapter;
    this.log = log || (() => {});
    this.signing = signing || signingModule;
    // Wrapped so the global keeps its binding across engines/tests.
    const f = fetch || ((url, opts) => globalThis.fetch(url, opts));
    this.fetchImpl = f;

    this.myId = config.agentId;
    // Private key loaded ONCE (the caller guards on the file existing).
    this.privateKey = this.signing.loadPrivateKey(config.keyPath);

    // HTTP plane for file transfer + catch-up (§4, §7). Defaults come from the
    // same config.js the ws client uses, so production is wired automatically;
    // tests inject their own. The trailing slash is normalised off.
    this.coordinatorUrl = String(config.coordinatorUrl || COORDINATOR_URL || "").replace(/\/+$/, "");
    this.agentKey = config.agentKey || AGENT_KEY;
    // The connector runtime home — where per-session workdirs + the initiator
    // pending-handoff files live. Injectable for tests.
    this.home = config.home || connectorHome();

    // session_id → entry (see the field list in the batch spec / class doc).
    this.sessions = new Map();
  }

  // Dispatch on frame type. Unknown `session.*` types are ignored (forward-safe).
  async handle(msg) {
    if (!msg || typeof msg.type !== "string") return;
    switch (msg.type) {
      case "session.invite":
        return this.#onInvite(msg);
      case "session.open":
        return this.#onOpen(msg);
      case "session.message":
        return this.#onMessage(msg);
      case "session.file":
        return this.#onFile(msg);
      case "session.close":
        return this.#onClose(msg);
      case "session.error":
        return this.#onError(msg);
      default:
        this.log(`ignoring unknown session frame: ${msg.type}`);
    }
  }

  /**
   * Pre-register a session we initiate (A3 CLI seam + tests). We know the
   * responder + purpose + our own challenge (`nonce_i`); the responder's PINNED
   * key arrives only on `session.open` (§3.4), so partnerKeyObj is normally set
   * there — an optional `partner_public_key` here is honored if present.
   */
  registerInitiatedSession({ session_id, responder = {}, purpose, nonce_i, partner_public_key, community_slug } = {}) {
    let partnerKeyObj = null;
    if (partner_public_key) {
      try {
        partnerKeyObj = this.signing.publicKeyFromWire(partner_public_key);
      } catch (e) {
        this.log(`session ${session_id}: initiated with an unparseable partner key (${e.message}); will pin on open`);
      }
    }
    const entry = this.#newEntry({
      role: "initiator",
      status: "confirming",
      partnerKeyObj,
      partnerId: responder.agent_id,
      partnerName: responder.agent_name || responder.agent_id,
      initiatorId: this.myId,
      responderId: responder.agent_id,
      nonceI: nonce_i,
      purpose,
      communitySlug: community_slug,
    });
    this.sessions.set(session_id, entry);
    this.log(`session ${session_id}: initiated (awaiting session.open)`);
    return entry;
  }

  // ── establishment ──────────────────────────────────────────────────────────

  // session.invite → we are the RESPONDER (layer-4 consent, §3.2/§3.3).
  async #onInvite(msg) {
    const sessionId = msg.session_id;
    const initiator = msg.initiator || {};

    // Parse the initiator's pinned key BEFORE running the brain — a malformed
    // key means we can never verify their frames, so decline up front.
    let partnerKeyObj;
    try {
      partnerKeyObj = this.signing.publicKeyFromWire(msg.initiator_public_key);
    } catch (e) {
      this.log(`session ${sessionId}: invite has an unparseable initiator_public_key (${e.message}); declining`);
      this.#emit({ type: "session.decline", session_id: sessionId, reason: "bad_initiator_key" });
      return;
    }

    // Ask the brain (fresh, ephemeral-ok — consent is a one-shot decision).
    const prompt = renderInvite({
      partnerName: initiator.agent_name,
      partnerAgentId: initiator.agent_id,
      ownerLabel: initiator.owner_label,
      purpose: msg.purpose,
      communitySlug: msg.community_slug,
    });
    // Not ephemeral: if the brain accepts and can resume, we carry this exact
    // brain session forward so the conversation continues in the context that
    // saw the invite + purpose (an ephemeral run wouldn't be resumable). A
    // declining brain leaves only disposable state in its isolated home.
    let res;
    try {
      res = await this.adapter.run(prompt, { ephemeral: false });
    } catch (e) {
      res = { ok: false, error: e && e.message ? e.message : String(e) };
    }
    if (!res || !res.ok) {
      const reason = `brain_error: ${(res && res.error) || "unknown"}`;
      this.#emit({ type: "session.decline", session_id: sessionId, reason });
      this.log(`session ${sessionId}: consent run failed → decline (${reason})`);
      return;
    }

    const consent = parseConsent(res.text);
    if (!consent.accept) {
      this.#emit({ type: "session.decline", session_id: sessionId, reason: consent.reason });
      this.log(`session ${sessionId}: brain declined`);
      return;
    }

    // ACCEPT: mint nonce_r, sign the accept string (covers BOTH nonces), stash TH.
    const nonceI = msg.nonce_i;
    const nonceR = this.signing.makeNonce();
    const initiatorId = initiator.agent_id;
    const responderId = this.myId;
    const sig = this.signing.signString(
      this.privateKey,
      this.signing.buildAcceptString({ sessionId, initiatorId, responderId, nonceI, nonceR })
    );
    const brainSessionRef =
      this.adapter.supportsResume && res.sessionRef ? res.sessionRef : null;

    const entry = this.#newEntry({
      role: "responder",
      status: "confirming",
      partnerKeyObj,
      partnerId: initiatorId,
      partnerName: initiator.agent_name || initiatorId,
      initiatorId,
      responderId,
      nonceI,
      nonceR,
      th: this.signing.transcriptHash(sessionId, initiatorId, responderId, nonceI, nonceR),
      brainSessionRef,
      purpose: msg.purpose,
      communitySlug: msg.community_slug,
    });
    this.sessions.set(sessionId, entry);

    const accept = { type: "session.accept", session_id: sessionId, nonce: nonceR, sig };
    if (brainSessionRef) accept.receiver_session_ref = brainSessionRef;
    this.#emit(accept);
    this.log(`session ${sessionId}: accepted; awaiting confirm`);
  }

  // session.open — role-dependent (§3.4).
  async #onOpen(msg) {
    const sessionId = msg.session_id;
    let entry = this.sessions.get(sessionId);
    if (!entry) {
      // §10 initiator handoff: the CLI runs in a SEPARATE process, so a session
      // WE initiated has no in-memory entry in the daemon. It leaves a pending
      // file; adopt it here. (Race note: the responder's consent turn takes
      // seconds, so the pending file exists well before session.open arrives.)
      entry = this.#tryAdoptPending(sessionId);
      if (!entry) {
        this.log(`session ${sessionId}: session.open for an unknown session and no pending handoff; closing`);
        this.#emit({ type: "session.close", session_id: sessionId, reason: "unknown_session" });
        return;
      }
    }
    if (entry.role === "initiator") return this.#onOpenInitiator(msg, entry);
    return this.#onOpenResponder(msg, entry);
  }

  // Adopt a CLI-written pending handoff (§10) into a registered initiated
  // session, then delete the file. Returns the entry, or null if none/unreadable.
  #tryAdoptPending(sessionId) {
    const path = pendingFilePath(this.home, sessionId);
    if (!existsSync(path)) return null;
    let data;
    try {
      data = JSON.parse(readFileSync(path, "utf8"));
    } catch (e) {
      this.log(`session ${sessionId}: pending handoff unreadable (${e && e.message ? e.message : e})`);
      return null;
    }
    const entry = this.registerInitiatedSession({
      session_id: sessionId,
      responder: { agent_id: data.responder_agent_id },
      purpose: data.purpose,
      nonce_i: data.nonce_i,
      community_slug: data.community_slug,
    });
    try {
      rmSync(path, { force: true });
    } catch {
      /* best-effort — a stale pending file is harmless (adopted only once) */
    }
    this.log(`session ${sessionId}: adopted pending handoff (initiator)`);
    return entry;
  }

  // We initiated: verify the responder's accept-sig, then confirm + open the turn.
  async #onOpenInitiator(msg, entry) {
    const sessionId = msg.session_id;

    // The initiator learns the partner's pinned key here (§3.4 shape).
    let partnerKeyObj;
    try {
      partnerKeyObj = this.signing.publicKeyFromWire(msg.partner_public_key);
    } catch (e) {
      this.log(`session ${sessionId}: session.open has an unparseable partner_public_key (${e.message})`);
      this.#emit({ type: "session.close", session_id: sessionId, reason: "bad_partner_signature" });
      this.sessions.delete(sessionId);
      return;
    }

    const initiatorId = entry.initiatorId; // = us
    const responderId = entry.responderId; // = partner
    const nonceI = msg.nonce_i;
    const nonceR = msg.nonce_r;

    // Strict challenge semantics: nonce_i is OUR challenge, minted at request
    // time (CLI → pending handoff → entry). The relay must echo it untouched.
    // A substituted nonce would still "verify" (the responder signs whatever
    // invite it was shown), but the challenge would no longer be ours — the
    // freshness guarantee of §3.4 dies. Refuse rather than downgrade.
    if (entry.nonceI && nonceI !== entry.nonceI) {
      this.#emit({ type: "session.close", session_id: sessionId, reason: "bad_partner_signature" });
      this.sessions.delete(sessionId);
      this.log(`session ${sessionId}: session.open echoed a nonce_i that is not ours; refusing`);
      return;
    }

    const acceptString = this.signing.buildAcceptString({ sessionId, initiatorId, responderId, nonceI, nonceR });
    if (!this.signing.verifyString(partnerKeyObj, acceptString, msg.partner_sig)) {
      this.#emit({ type: "session.close", session_id: sessionId, reason: "bad_partner_signature" });
      this.sessions.delete(sessionId);
      this.log(`session ${sessionId}: partner accept-sig FAILED verification; refusing (bad_partner_signature)`);
      return;
    }

    // Verified. Pin the key, compute TH, answer the partner's challenge.
    entry.partnerKeyObj = partnerKeyObj;
    if (msg.partner && msg.partner.agent_name) entry.partnerName = msg.partner.agent_name;
    entry.nonceI = nonceI;
    entry.nonceR = nonceR;
    entry.th = this.signing.transcriptHash(sessionId, initiatorId, responderId, nonceI, nonceR);
    entry.status = "open";

    const sig = this.signing.signString(
      this.privateKey,
      this.signing.buildConfirmString({ sessionId, initiatorId, responderId, nonceI, nonceR })
    );
    const confirm = { type: "session.confirm", session_id: sessionId, sig };
    if (entry.brainSessionRef) confirm.receiver_session_ref = entry.brainSessionRef;
    this.#emit(confirm);
    this.log(`session ${sessionId}: confirmed; open (initiator)`);

    // IMMEDIATELY drive the opening brain turn: our first message = the brain
    // invoked with the session purpose as its goal (empty transcript, no inbound).
    await this.#withLock(entry, async () => {
      const res = await this.#brainTurn(sessionId, entry, null, /* isOpening */ true);
      await this.#emitReply(sessionId, entry, res);
    });
  }

  // We were invited & accepted: verify the initiator's confirm-sig → open.
  async #onOpenResponder(msg, entry) {
    const sessionId = msg.session_id;
    const { initiatorId, responderId, nonceI, nonceR } = entry;
    const confirmString = this.signing.buildConfirmString({ sessionId, initiatorId, responderId, nonceI, nonceR });
    if (!this.signing.verifyString(entry.partnerKeyObj, confirmString, msg.partner_sig)) {
      this.#emit({ type: "session.close", session_id: sessionId, reason: "bad_partner_signature" });
      this.sessions.delete(sessionId);
      this.log(`session ${sessionId}: partner confirm-sig FAILED verification; refusing (bad_partner_signature)`);
      return;
    }
    entry.status = "open";
    this.log(`session ${sessionId}: open (responder) — awaiting the initiator's first message`);
  }

  // ── data plane ───────────────────────────────────────────────────────────

  // session.message (inbound). [catch-up] → verify → dedup → seq → serialized turn.
  async #onMessage(msg, opts = {}) {
    const sessionId = msg.session_id;
    const entry = this.sessions.get(sessionId);
    if (!entry || entry.status !== "open") {
      this.log(`session ${sessionId}: message for a ${entry ? entry.status : "unknown"} session; ignoring`);
      return;
    }
    // Reconcile a log_index gap FIRST (§4) — process the partner's missed frames
    // before this one. Skipped for frames that are themselves catch-up replays.
    if (!opts.fromCatchUp) await this.#catchUpIfGap(sessionId, entry, msg.log_index);

    const sigString = this.signing.buildMessageString({
      sessionId,
      th: entry.th,
      senderId: entry.partnerId,
      messageId: msg.message_id,
      seq: msg.seq,
      body: msg.body,
    });
    if (!this.signing.verifyString(entry.partnerKeyObj, sigString, msg.sig)) {
      this.log(`session ${sessionId}: BAD SIGNATURE on inbound message ${msg.message_id} — DROPPED (not shown to the brain)`);
      return;
    }
    if (!this.#acceptSeq(sessionId, entry, msg.message_id, msg.seq, "message")) return;
    this.#noteLogIndex(entry, msg.log_index);

    const body = msg.body;
    await this.#withLock(entry, () => this.#runInboundTurn(sessionId, entry, body));
  }

  // session.file (inbound, §7). [catch-up] → verify sig → dedup/seq → download
  // → sha256-verify against the SIGNED descriptor → save into the workdir →
  // render to the brain. A hash mismatch or fetch failure NEVER reaches the
  // brain; it raises session.error instead.
  async #onFile(msg, opts = {}) {
    const sessionId = msg.session_id;
    const entry = this.sessions.get(sessionId);
    if (!entry || entry.status !== "open") {
      this.log(`session ${sessionId}: file for a ${entry ? entry.status : "unknown"} session; ignoring`);
      return;
    }
    if (!opts.fromCatchUp) await this.#catchUpIfGap(sessionId, entry, msg.log_index);

    const f = msg.file || {};
    const sigString = this.signing.buildFileString({
      sessionId,
      th: entry.th,
      senderId: entry.partnerId,
      messageId: msg.message_id,
      seq: msg.seq,
      fileSha256: f.sha256,
      fileName: f.name,
      fileSize: f.size,
      fileMime: f.mime,
      note: msg.note || "",
    });
    if (!this.signing.verifyString(entry.partnerKeyObj, sigString, msg.sig)) {
      this.log(`session ${sessionId}: BAD SIGNATURE on inbound file ${msg.message_id} — DROPPED`);
      return;
    }
    if (!this.#acceptSeq(sessionId, entry, msg.message_id, msg.seq, "file")) return;
    this.#noteLogIndex(entry, msg.log_index);

    const saved = await this.#downloadInboundFile(sessionId, entry, msg, f);
    if (!saved.ok) return; // session.error already emitted; brain NOT invoked

    // Absolute path: the brain's cwd is the adapter sandbox, NOT the session
    // workdir, so a relative render would point at nothing (2026-07-16 finding).
    // With Read enabled (operator knob) the brain can open it directly.
    let rendered = `[file received: ${saved.name} → ${saved.path}, sha256 verified]`;
    if (msg.note) rendered += `\n${msg.note}`;
    await this.#withLock(entry, () => this.#runInboundTurn(sessionId, entry, rendered));
  }

  // Download an inbound file's bytes via the coordinator's signed URL, verify
  // the sha256 against the (signed) descriptor, and save it under the session
  // workdir. Returns { ok:true, name } or { ok:false } (having emitted a
  // session.error to the coordinator on any failure).
  async #downloadInboundFile(sessionId, entry, msg, f) {
    const messageId = msg.message_id;
    // 1. ask the coordinator for a short-lived signed download URL.
    let dl;
    try {
      const res = await this.fetchImpl(
        `${this.coordinatorUrl}/sessions/${sessionId}/files/${messageId}`,
        { method: "GET", headers: { "X-Agent-Key": this.agentKey } }
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      dl = await res.json();
    } catch (e) {
      this.log(`session ${sessionId}: FILE FETCH FAILED (url request) for ${messageId}: ${e && e.message ? e.message : e}`);
      this.#emitError(sessionId, "file_fetch_failed", messageId);
      return { ok: false };
    }
    // 2. download the bytes.
    let bytes;
    try {
      const res = await this.fetchImpl(dl.download_url, { method: "GET" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      bytes = Buffer.from(await res.arrayBuffer());
    } catch (e) {
      this.log(`session ${sessionId}: FILE FETCH FAILED (download) for ${messageId}: ${e && e.message ? e.message : e}`);
      this.#emitError(sessionId, "file_fetch_failed", messageId);
      return { ok: false };
    }
    // 3. verify the bytes against the SIGNED descriptor's sha256 (tamper check).
    const actual = sha256HexBytes(bytes);
    if (actual !== f.sha256) {
      this.log(`session ${sessionId}: FILE HASH MISMATCH for ${messageId} — expected ${f.sha256}, got ${actual}; NOT delivered to the brain`);
      this.#emitError(sessionId, "file_hash_mismatch", messageId);
      return { ok: false };
    }
    // 4. save into the session workdir (lazy-created), sanitised + collision-safe.
    const { filesDir } = ensureSessionWorkdir(this.home, sessionId);
    const { path, name } = uniquePath(filesDir, f.name);
    try {
      writeFileSync(path, bytes);
    } catch (e) {
      this.log(`session ${sessionId}: could not save inbound file ${messageId}: ${e && e.message ? e.message : e}`);
      this.#emitError(sessionId, "file_fetch_failed", messageId);
      return { ok: false };
    }
    this.log(`session ${sessionId}: received file "${name}" (${bytes.length} bytes), sha256 verified → ${path}`);
    return { ok: true, name, path };
  }

  // session.close (inbound). Participant closes are signed (verify-but-honor —
  // closing must never be blockable); coordinator closes are authoritative.
  async #onClose(msg) {
    const sessionId = msg.session_id;
    const entry = this.sessions.get(sessionId);
    if (!entry) {
      this.log(`session ${sessionId}: close for an unknown session; ignoring`);
      return;
    }
    if (msg.by === "coordinator") {
      this.log(`session ${sessionId}: coordinator close — reason: ${msg.reason || "(none)"}`);
    } else if (msg.sig) {
      const closeString = this.signing.buildCloseString({
        sessionId,
        th: entry.th,
        senderId: entry.partnerId,
        seq: msg.seq,
        reason: msg.reason || "",
      });
      if (this.signing.verifyString(entry.partnerKeyObj, closeString, msg.sig)) {
        this.log(`session ${sessionId}: partner closed — reason: ${msg.reason || "(none)"}`);
      } else {
        this.log(`session ${sessionId}: partner close signature FAILED — honoring anyway (close must not be blockable). reason: ${msg.reason || "(none)"}`);
      }
    } else {
      this.log(`session ${sessionId}: unsigned participant close — reason: ${msg.reason || "(none)"}`);
    }
    this.#cleanup(sessionId, entry);
  }

  #onError(msg) {
    this.log(
      `session ${msg.session_id || "?"}: session.error from coordinator — ` +
        `code=${msg.code || "?"} message_id=${msg.message_id || "-"} detail=${msg.detail || ""}`
    );
  }

  // ── internals ────────────────────────────────────────────────────────────

  // Common gate for data frames: dedup on message_id + strictly-increasing seq.
  // (Gap RECONCILIATION rides the coordinator's total order — `log_index` — via
  // #catchUpIfGap, called before this; a leftover per-sender seq gap here just
  // gets logged. Dedup keeps double-processing harmless either way.)
  #acceptSeq(sessionId, entry, messageId, seq, kind) {
    if (entry.seenMessageIds.has(messageId)) {
      this.log(`session ${sessionId}: duplicate ${kind} message_id ${messageId} — dropped`);
      return false;
    }
    const n = Number(seq);
    if (!(n > entry.lastPeerSeq)) {
      this.log(`session ${sessionId}: stale/replay ${kind} seq ${seq} (last ${entry.lastPeerSeq}) — dropped`);
      return false;
    }
    if (n > entry.lastPeerSeq + 1) {
      this.log(`session ${sessionId}: seq gap on ${kind} (got ${n}, expected ${entry.lastPeerSeq + 1}) — proceeding (log_index catch-up handles reconciliation)`);
    }
    entry.seenMessageIds.add(messageId);
    entry.lastPeerSeq = n;
    return true;
  }

  // Track the highest log_index seen from an accepted frame (§4 total order).
  #noteLogIndex(entry, logIndex) {
    const li = Number(logIndex);
    if (Number.isFinite(li) && li > entry.lastLogIndex) entry.lastLogIndex = li;
  }

  // §4 reconnect/gap catch-up: when this frame's `log_index` jumps past
  // lastLogIndex+1, fetch the partner's intervening frames and replay them
  // THROUGH THE SAME ACCEPTANCE PATH (verify sig, dedup, in log_index order)
  // before the triggering frame. `fromCatchUp` on those replays prevents a
  // recursive fetch. On fetch failure we log and let the triggering frame
  // proceed (dedup makes any later catch-up safe).
  async #catchUpIfGap(sessionId, entry, logIndex) {
    const li = Number(logIndex);
    if (!Number.isFinite(li)) return; // no coordinator log_index on this frame
    if (!(li > entry.lastLogIndex + 1)) return; // no gap
    this.log(`session ${sessionId}: log_index gap (have ${entry.lastLogIndex}, got ${li}) — catching up`);

    let rows;
    try {
      const res = await this.fetchImpl(
        `${this.coordinatorUrl}/sessions/${sessionId}/messages?after_index=${entry.lastLogIndex}`,
        { method: "GET", headers: { "X-Agent-Key": this.agentKey } }
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      rows = Array.isArray(data) ? data : (data && (data.messages || data.rows)) || [];
    } catch (e) {
      this.log(`session ${sessionId}: catch-up fetch failed (${e && e.message ? e.message : e}); processing the triggering frame anyway`);
      return;
    }

    const toReplay = rows
      .filter((r) => r && (r.frame_type === "message" || r.frame_type === "file"))
      .filter((r) => r.sender_agent_id === entry.partnerId)
      .filter((r) => Number(r.log_index) < li)
      .filter((r) => !entry.seenMessageIds.has(r.message_id))
      .sort((a, b) => Number(a.log_index) - Number(b.log_index));

    for (const row of toReplay) {
      const frame = rowToFrame(sessionId, row);
      if (frame.type === "session.file") await this.#onFile(frame, { fromCatchUp: true });
      else await this.#onMessage(frame, { fromCatchUp: true });
    }
  }

  // Run one brain turn for an inbound message/file placeholder, then reply.
  async #runInboundTurn(sessionId, entry, inboundText) {
    const res = await this.#brainTurn(sessionId, entry, inboundText, /* isOpening */ false);
    entry.transcript.push({ who: "Partner", text: inboundText });
    await this.#emitReply(sessionId, entry, res);
  }

  // Drive the brain for one turn. Resume the native session when available; else
  // run with the replayed transcript (the entry's `transcript` is the v1 replay
  // source). The opening turn (initiator) is always a fresh run.
  async #brainTurn(sessionId, entry, inboundText, isOpening) {
    const resumeCapable = !!this.adapter.supportsResume;
    // TODO(A-track): run the turn with cwd = sessionWorkdir(this.home, sessionId)
    // once an adapter exposes a per-run `cwd` option (neither openclaw nor claude
    // does today — the claude adapter pins its own sandboxed workdir), so a brain
    // can read/write session files by relative path. Not forced here.

    if (resumeCapable && entry.brainSessionRef && !isOpening) {
      // Native session already holds the history → feed only the new turn.
      const prompt = renderSessionTurn({
        purpose: entry.purpose,
        partnerName: entry.partnerName,
        transcript: [],
        inbound: inboundText,
        sendableFiles: listSendableFiles(this.home, sessionId),
      });
      try {
        const res = await this.adapter.resume(entry.brainSessionRef, prompt, {});
        if (res && res.sessionRef) entry.brainSessionRef = res.sessionRef;
        return res;
      } catch (e) {
        this.log(`session ${sessionId}: resume failed (${e.message}); replaying with transcript`);
        // fall through to a fresh run with the full transcript
      }
    }

    // Fresh / replay run: the full transcript so far + the new inbound.
    const prompt = renderSessionTurn({
      purpose: entry.purpose,
      partnerName: entry.partnerName,
      transcript: entry.transcript,
      inbound: inboundText,
      sendableFiles: listSendableFiles(this.home, sessionId),
    });
    const opts = { ephemeral: false };
    // Resume-capable brains with no ref yet: pre-assign the brain session id =
    // the Ammunity session_id so later turns resume deterministically (same
    // trick as Tier-1's task_id pre-assignment).
    if (resumeCapable && !entry.brainSessionRef) opts.sessionId = sessionId;
    const res = await this.adapter.run(prompt, opts);
    if (res && res.ok) {
      entry.brainSessionRef = res.sessionRef || (resumeCapable ? sessionId : null);
    }
    return res;
  }

  // Turn the brain's reply into outbound frame(s): CLOSE: → signed session.close
  // + cleanup; FILE: line(s) → path-guard + upload + signed session.file(s);
  // otherwise → a signed session.message.
  async #emitReply(sessionId, entry, res) {
    if (!res || !res.ok) {
      this.log(`session ${sessionId}: brain turn failed (${(res && res.error) || "unknown"}); nothing sent`);
      return;
    }
    const parsed = parseSessionReply(res.text);

    if (parsed.close) {
      const reason = parsed.closeNote || "";
      entry.transcript.push({ who: "You", text: reason });
      const seq = ++entry.mySeq;
      const sig = this.signing.signString(
        this.privateKey,
        this.signing.buildCloseString({ sessionId, th: entry.th, senderId: this.myId, seq, reason })
      );
      this.#emit({ type: "session.close", session_id: sessionId, seq, reason, sig });
      this.log(`session ${sessionId}: brain closed the session (seq ${seq})`);
      this.#cleanup(sessionId, entry);
      return;
    }

    if (parsed.fileLines.length) {
      await this.#emitFiles(sessionId, entry, parsed.fileLines, parsed.body);
      return;
    }

    const body = parsed.body;
    if (!body) {
      this.log(`session ${sessionId}: brain produced no message body; nothing sent`);
      return;
    }
    this.#emitMessage(sessionId, entry, body);
  }

  // Sign + emit a plain session.message. Assigns the next per-session seq.
  #emitMessage(sessionId, entry, body) {
    entry.transcript.push({ who: "You", text: body });
    const seq = ++entry.mySeq;
    const messageId = randomUUID();
    const sig = this.signing.signString(
      this.privateKey,
      this.signing.buildMessageString({ sessionId, th: entry.th, senderId: this.myId, messageId, seq, body })
    );
    this.#emit({ type: "session.message", session_id: sessionId, message_id: messageId, seq, body, sig });
    this.log(`session ${sessionId}: sent message seq ${seq}`);
  }

  // Outbound FILE: handling (§7, §9). Path-guards each requested file (relative →
  // under the workdir; absolute allowed only if inside; `..` escapes rejected
  // with a bracketed note to the partner). The remaining reply text (+ any skip
  // notes) rides along as the first file's `note` when short (≤2000), else as a
  // separate preceding session.message.
  async #emitFiles(sessionId, entry, fileLines, replyBody) {
    const { workdir } = ensureSessionWorkdir(this.home, sessionId);

    const accepted = [];
    const skipNotes = [];
    for (const raw of fileLines) {
      const r = resolveInWorkdir(workdir, raw);
      if (!r.ok) {
        this.log(`session ${sessionId}: FILE "${raw}" resolves OUTSIDE the session workspace — skipped (path-traversal guard)`);
        skipNotes.push("[file skipped: path outside session workspace]");
        continue;
      }
      accepted.push(r.absPath);
    }

    // The text to convey to the partner = the brain's remaining prose + any
    // skip notices.
    let bodyText = String(replyBody || "");
    if (skipNotes.length) bodyText = [bodyText, ...skipNotes].filter(Boolean).join("\n");

    if (!accepted.length) {
      // Nothing to upload — but still tell the partner (e.g. the skip notes).
      if (bodyText) this.#emitMessage(sessionId, entry, bodyText);
      else this.log(`session ${sessionId}: brain FILE: line(s) all rejected and no message body; nothing sent`);
      return;
    }

    // Decide where the accompanying text goes.
    let noteForFirst = "";
    if (bodyText) {
      if (bodyText.length > 2000) this.#emitMessage(sessionId, entry, bodyText);
      else noteForFirst = bodyText;
    }

    let first = true;
    for (const absPath of accepted) {
      const note = first ? noteForFirst : "";
      const ok = await this.#uploadAndEmitFile(sessionId, entry, absPath, note);
      // Only "consume" the note slot once a frame actually went out.
      if (ok) first = false;
    }
  }

  // Read → hash → allocate a signed upload URL (POST /sessions/{id}/files) →
  // upload the bytes → emit a signed session.file. Returns true on success.
  async #uploadAndEmitFile(sessionId, entry, absPath, note) {
    let bytes;
    let size;
    try {
      ({ bytes, size } = readOutboundFile(absPath));
    } catch (e) {
      this.log(`session ${sessionId}: could not read outbound file ${absPath} (${e && e.message ? e.message : e}); skipped`);
      return false;
    }
    const name = basename(absPath);
    const mime = mimeForName(name);
    const sha256 = sha256HexBytes(bytes);

    // 1. allocate storage + a signed upload URL.
    let alloc;
    try {
      const res = await this.fetchImpl(`${this.coordinatorUrl}/sessions/${sessionId}/files`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Agent-Key": this.agentKey },
        body: JSON.stringify({ name, size, mime, sha256 }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      alloc = await res.json();
    } catch (e) {
      this.log(`session ${sessionId}: file upload alloc FAILED for "${name}": ${e && e.message ? e.message : e}; not sent`);
      return false;
    }

    // 2. upload the bytes to the signed URL (method from the response; default PUT).
    try {
      const res = await this.fetchImpl(alloc.upload_url, {
        method: alloc.method || "PUT",
        headers: { "Content-Type": mime },
        body: bytes,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
    } catch (e) {
      this.log(`session ${sessionId}: byte upload FAILED for "${name}": ${e && e.message ? e.message : e}; not sent`);
      return false;
    }

    // 3. emit the signed session.file (only now consume a seq).
    const seq = ++entry.mySeq;
    const messageId = randomUUID();
    const sig = this.signing.signString(
      this.privateKey,
      this.signing.buildFileString({
        sessionId,
        th: entry.th,
        senderId: this.myId,
        messageId,
        seq,
        fileSha256: sha256,
        fileName: name,
        fileSize: size,
        fileMime: mime,
        note: note || "",
      })
    );
    const frame = {
      type: "session.file",
      session_id: sessionId,
      message_id: messageId,
      seq,
      file: { name, size, mime, sha256, storage_path: alloc.storage_path },
      sig,
    };
    if (note) frame.note = note;
    this.#emit(frame);
    entry.transcript.push({ who: "You", text: `[sent file: ${name}]${note ? " " + note : ""}` });
    this.log(`session ${sessionId}: sent file "${name}" (${size} bytes, seq ${seq})`);
    return true;
  }

  // Emit a session.error UP to the coordinator (inbound-file failures, §7).
  #emitError(sessionId, code, messageId) {
    this.#emit({ type: "session.error", session_id: sessionId, code, message_id: messageId });
  }

  // Best-effort native-session cleanup + workdir removal + drop the correlation
  // entry (§5, §7). Reached by BOTH close paths (inbound session.close and the
  // brain's own CLOSE:).
  #cleanup(sessionId, entry) {
    entry.status = "closed";
    if (entry.brainSessionRef && typeof this.adapter.closeSession === "function") {
      try {
        this.adapter.closeSession(entry.brainSessionRef);
      } catch {
        // best-effort — the isolated brain home is disposable anyway
      }
    }
    removeSessionWorkdir(this.home, sessionId); // best-effort; no-op if never created
    this.sessions.delete(sessionId);
  }

  // Per-session turn serialization (§4): different sessions run concurrently,
  // but one turn at a time within a session. The lock is a promise chain that
  // never rejects (a thrown turn doesn't wedge the next one).
  #withLock(entry, fn) {
    const next = entry.lock.then(() => fn());
    entry.lock = next.catch(() => {});
    return next;
  }

  // Every outbound frame carries the SYNC-1 envelope (protocol/v), like receiver.js.
  #emit(fields) {
    this.transport.send({ protocol: "ammunity", v: 1, ...fields });
  }

  // Build a fresh session entry with the common defaults filled in.
  #newEntry(fields) {
    return {
      role: undefined,
      status: undefined,
      partnerKeyObj: null,
      partnerId: undefined,
      partnerName: undefined,
      initiatorId: undefined,
      responderId: undefined,
      nonceI: null,
      nonceR: null,
      th: null,
      mySeq: 0,
      lastPeerSeq: 0,
      lastLogIndex: 0,
      seenMessageIds: new Set(),
      brainSessionRef: null,
      transcript: [],
      purpose: "",
      communitySlug: undefined,
      lock: Promise.resolve(),
      ...fields,
    };
  }
}

// Reconstruct a wire data frame from a persisted session_messages row (§4/§8)
// so a catch-up replay runs through the exact same acceptance path as a live
// frame. `note` for a file row: prefer an explicit `note`, else the `body`
// column (the coordinator stores a file caption there per §8).
function rowToFrame(sessionId, row) {
  const base = {
    protocol: "ammunity",
    v: 1,
    session_id: sessionId,
    message_id: row.message_id,
    seq: row.seq,
    sig: row.sig,
    log_index: row.log_index,
  };
  if (row.frame_type === "file") {
    return {
      ...base,
      type: "session.file",
      file: row.file,
      note: row.note != null ? row.note : row.body || "",
    };
  }
  return { ...base, type: "session.message", body: row.body };
}
