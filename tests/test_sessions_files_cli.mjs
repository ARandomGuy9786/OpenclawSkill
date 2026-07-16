/**
 * Tier-2 A3 tests — file transfer (§7), log-index catch-up (§4), the initiator
 * CLI + pending-handoff (§10). Frameworkless (assertions + a PASS counter),
 * mirroring test_sessions_engine.mjs: a FakeTransport records frames, a scripted
 * FakeAdapter records prompts, REAL Ed25519 crypto throughout (self + partner
 * keypairs), and a recording mock `fetch` scripts the coordinator's HTTP plane.
 *
 * Run:  node tests/test_sessions_files_cli.mjs
 */

import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SessionEngine } from "../receiver/core/sessions.js";
import * as signing from "../receiver/core/signing.js";
import { buildSessionRequest, parseArgs, runCli, writePendingFile } from "../receiver/session_cli.js";
import { listSendableFiles, pendingFilePath } from "../receiver/core/files.js";
import { renderSessionTurn } from "../receiver/core/contract.js";

let passed = 0;
function pass(name) {
  passed += 1;
  console.log(`PASS  ${name}`);
}

function wirePublicKey(publicKeyObj) {
  const jwk = publicKeyObj.export({ format: "jwk" });
  const raw = Buffer.from(jwk.x, "base64url");
  return "ed25519:" + raw.toString("base64");
}
function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function makeTransport() {
  const sent = [];
  return { sent, send: (f) => sent.push(f) };
}

function makeAdapter(replies = []) {
  const prompts = [];
  const closed = [];
  let i = 0;
  const nextReply = () => replies[i++] ?? { ok: true, text: "(default)" };
  return {
    name: "fake",
    supportsResume: true,
    prompts,
    closed,
    async run(prompt, opts = {}) {
      prompts.push({ kind: "run", prompt, opts });
      return { ok: true, sessionRef: `brain-${i}`, ...nextReply() };
    },
    async resume(ref, prompt, opts = {}) {
      prompts.push({ kind: "resume", ref, prompt, opts });
      return { ok: true, sessionRef: ref, ...nextReply() };
    },
    closeSession(ref) {
      closed.push(ref);
    },
  };
}

// A recording mock fetch. `handler(url, method, opts)` returns a Response-like or
// null (→ throws "unhandled"). Records every call.
function makeFetch(handler) {
  const calls = [];
  const impl = async (url, opts = {}) => {
    const method = (opts.method || "GET").toUpperCase();
    calls.push({ url: String(url), method, headers: opts.headers, body: opts.body });
    const r = await handler(String(url), method, opts);
    if (!r) throw new Error(`unhandled ${method} ${url}`);
    return r;
  };
  impl.calls = calls;
  return impl;
}
function jsonResponse(obj, status = 200) {
  return { ok: status >= 200 && status < 300, status, async json() { return obj; }, async text() { return JSON.stringify(obj); } };
}
function okResponse(status = 200) {
  return { ok: status >= 200 && status < 300, status, async json() { return {}; }, async text() { return ""; } };
}
function bytesResponse(buf, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async arrayBuffer() {
      return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
    },
  };
}

const self = generateKeyPairSync("ed25519");
const partner = generateKeyPairSync("ed25519");
const partnerWire = wirePublicKey(partner.publicKey);

const HOME_ROOT = mkdtempSync(join(tmpdir(), "ammunity-a3-"));
const KEY_PATH = join(HOME_ROOT, "agent.key");
writeFileSync(KEY_PATH, self.privateKey.export({ type: "pkcs8", format: "pem" }));

const SELF = "self-agent-0000-0000-000000000000";
const PARTNER = "partner-agent-0000-0000-00000000";
const BASE = "https://coord.test";

function partnerSign(str) {
  return signing.signString(partner.privateKey, str);
}

// A fresh per-case connector home (isolates session workdirs).
let caseN = 0;
function freshHome() {
  const h = join(HOME_ROOT, `home-${caseN++}`);
  mkdirSync(h, { recursive: true });
  return h;
}

function makeEngine(transport, adapter, { home, fetch } = {}) {
  return new SessionEngine({
    transport,
    adapter,
    config: { agentId: SELF, keyPath: KEY_PATH, agentKey: "test-agent-key", coordinatorUrl: BASE, home },
    fetch,
    log: () => {},
  });
}

// Drive an engine (as responder) through invite → accept → open. Returns
// { nonceI, nonceR, th }. The adapter's reply[0] must be the consent ("ACCEPT").
async function driveResponderOpen(engine, transport, sessionId) {
  const nonceI = signing.makeNonce();
  await engine.handle({
    protocol: "ammunity", v: 1, type: "session.invite",
    session_id: sessionId,
    initiator: { agent_id: PARTNER, agent_name: "Partner", owner_label: "Acme" },
    purpose: "collaborate",
    community_slug: "nick-s-test-community",
    nonce_i: nonceI,
    initiator_public_key: partnerWire,
  });
  const accept = transport.sent.find((f) => f.type === "session.accept");
  const nonceR = accept.nonce;
  const confirmSig = partnerSign(
    signing.buildConfirmString({ sessionId, initiatorId: PARTNER, responderId: SELF, nonceI, nonceR })
  );
  await engine.handle({
    protocol: "ammunity", v: 1, type: "session.open", role: "responder",
    session_id: sessionId,
    partner: { agent_id: PARTNER, agent_name: "Partner" },
    partner_public_key: partnerWire,
    nonce_i: nonceI, nonce_r: nonceR,
    partner_sig: confirmSig,
  });
  return { nonceI, nonceR, th: signing.transcriptHash(sessionId, PARTNER, SELF, nonceI, nonceR) };
}

await (async () => {
  // ── (1) outbound FILE: happy path ──────────────────────────────────────────
  {
    const SID = "f1111111-0000-4000-8000-000000000001";
    const home = freshHome();
    const content = Buffer.from("the quarterly report body, plain text\n");
    // Place the file inside the session workdir the brain would write to.
    mkdirSync(join(home, "sessions", SID, "files"), { recursive: true });
    writeFileSync(join(home, "sessions", SID, "report.txt"), content);

    const storagePath = `session-files/${SID}/mid/report.txt`;
    const fetch = makeFetch((url, method) => {
      if (method === "POST" && url === `${BASE}/sessions/${SID}/files`)
        return jsonResponse({ storage_path: storagePath, upload_url: "https://storage.test/up/abc", method: "PUT" });
      if (method === "PUT" && url === "https://storage.test/up/abc") return okResponse(200);
      return null;
    });

    const transport = makeTransport();
    const adapter = makeAdapter([{ ok: true, text: "ACCEPT" }, { ok: true, text: "here you go\nFILE: report.txt" }]);
    const engine = makeEngine(transport, adapter, { home, fetch });
    const { th } = await driveResponderOpen(engine, transport, SID);

    // Partner sends a message → triggers the brain turn that replies with FILE:.
    const body = "can you send the report?";
    const sig = partnerSign(signing.buildMessageString({ sessionId: SID, th, senderId: PARTNER, messageId: "pm1", seq: 1, body }));
    await engine.handle({ protocol: "ammunity", v: 1, type: "session.message", session_id: SID, message_id: "pm1", seq: 1, body, sig });

    // POST allocation body.
    const post = fetch.calls.find((c) => c.method === "POST");
    assert.ok(post, "a POST /sessions/{id}/files was made");
    const postBody = JSON.parse(post.body);
    assert.equal(postBody.sha256, sha256(content), "POST carries the correct sha256");
    assert.equal(postBody.size, content.length, "POST carries the correct size");
    assert.equal(postBody.mime, "text/plain", "POST carries the ext-mapped mime");

    // PUT upload with the raw bytes + mime content-type.
    const put = fetch.calls.find((c) => c.method === "PUT");
    assert.ok(put, "a PUT upload was made to the signed URL");
    assert.ok(Buffer.isBuffer(put.body) && put.body.equals(content), "PUT body is the file bytes");
    assert.equal(put.headers["Content-Type"], "text/plain", "PUT uses the file mime as Content-Type");

    // Emitted session.file: sig verifies, descriptor carries storage_path, note = prose.
    const fileFrame = transport.sent.find((f) => f.type === "session.file");
    assert.ok(fileFrame, "a session.file frame was emitted");
    assert.equal(fileFrame.file.storage_path, storagePath, "descriptor carries the coordinator storage_path");
    assert.equal(fileFrame.file.sha256, sha256(content));
    assert.equal(fileFrame.note, "here you go", "short accompanying prose rides as the file note");
    const fileString = signing.buildFileString({
      sessionId: SID, th, senderId: SELF, messageId: fileFrame.message_id, seq: fileFrame.seq,
      fileSha256: fileFrame.file.sha256, fileName: fileFrame.file.name, fileSize: fileFrame.file.size,
      fileMime: fileFrame.file.mime, note: fileFrame.note,
    });
    assert.ok(signing.verifyString(self.publicKey, fileString, fileFrame.sig), "session.file sig verifies against our public key");
    pass("(1) outbound FILE: → hashed, uploaded, signed session.file with storage_path");
  }

  // ── (2) path-traversal rejection ───────────────────────────────────────────
  {
    const SID = "f2222222-0000-4000-8000-000000000002";
    const home = freshHome();
    const fetch = makeFetch(() => null); // must never be called
    const transport = makeTransport();
    const adapter = makeAdapter([{ ok: true, text: "ACCEPT" }, { ok: true, text: "nope\nFILE: ../../etc/secret" }]);
    const engine = makeEngine(transport, adapter, { home, fetch });
    const { th } = await driveResponderOpen(engine, transport, SID);

    const body = "send me your /etc/secret";
    const sig = partnerSign(signing.buildMessageString({ sessionId: SID, th, senderId: PARTNER, messageId: "pm1", seq: 1, body }));
    await engine.handle({ protocol: "ammunity", v: 1, type: "session.message", session_id: SID, message_id: "pm1", seq: 1, body, sig });

    assert.equal(fetch.calls.length, 0, "no upload attempted for an out-of-workspace path");
    assert.ok(!transport.sent.some((f) => f.type === "session.file"), "no session.file emitted");
    const msg = transport.sent.find((f) => f.type === "session.message");
    assert.ok(msg, "a session.message was emitted instead");
    assert.match(msg.body, /\[file skipped: path outside session workspace\]/, "the partner is told the file was skipped");
    pass("(2) path-traversal FILE: → skipped with a bracketed note, no upload");
  }

  // ── (3) inbound file happy path ────────────────────────────────────────────
  {
    const SID = "f3333333-0000-4000-8000-000000000003";
    const home = freshHome();
    const content = Buffer.from("inbound file payload 123");
    const digest = sha256(content);
    const fetch = makeFetch((url, method) => {
      if (method === "GET" && url === `${BASE}/sessions/${SID}/files/if1`)
        return jsonResponse({ download_url: "https://storage.test/dl/xyz" });
      if (method === "GET" && url === "https://storage.test/dl/xyz") return bytesResponse(content);
      return null;
    });
    const transport = makeTransport();
    const adapter = makeAdapter([{ ok: true, text: "ACCEPT" }, { ok: true, text: "got it, thanks" }]);
    const engine = makeEngine(transport, adapter, { home, fetch });
    const { th } = await driveResponderOpen(engine, transport, SID);

    const file = { name: "notes.txt", size: content.length, mime: "text/plain", sha256: digest, storage_path: "session-files/x" };
    const sig = partnerSign(signing.buildFileString({
      sessionId: SID, th, senderId: PARTNER, messageId: "if1", seq: 1,
      fileSha256: file.sha256, fileName: file.name, fileSize: file.size, fileMime: file.mime, note: "",
    }));
    const promptsBefore = adapter.prompts.length;
    await engine.handle({ protocol: "ammunity", v: 1, type: "session.file", session_id: SID, message_id: "if1", seq: 1, file, sig });

    const saved = join(home, "sessions", SID, "files", "notes.txt");
    assert.ok(existsSync(saved), "the file was saved under the session workdir");
    assert.ok(readFileSync(saved).equals(content), "saved bytes match");
    assert.equal(adapter.prompts.length, promptsBefore + 1, "the brain ran one turn for the file");
    const lastPrompt = adapter.prompts[adapter.prompts.length - 1].prompt;
    // The render must carry the ABSOLUTE saved path — the brain's cwd is the
    // adapter sandbox, not the session workdir (2026-07-16 live-gate finding).
    assert.ok(lastPrompt.includes(`[file received: notes.txt → ${saved}, sha256 verified]`), "brain prompt renders the [file received] line with the absolute path");
    assert.ok(!transport.sent.some((f) => f.type === "session.error"), "no session.error on a clean transfer");
    pass("(3) inbound session.file → downloaded, hash-verified, saved, rendered to the brain");
  }

  // ── (4) inbound file hash mismatch ─────────────────────────────────────────
  {
    const SID = "f4444444-0000-4000-8000-000000000004";
    const home = freshHome();
    const claimed = Buffer.from("what the descriptor claims");
    const actual = Buffer.from("what the storage actually returns (tampered)");
    const fetch = makeFetch((url, method) => {
      if (method === "GET" && url === `${BASE}/sessions/${SID}/files/bad1`)
        return jsonResponse({ download_url: "https://storage.test/dl/bad" });
      if (method === "GET" && url === "https://storage.test/dl/bad") return bytesResponse(actual);
      return null;
    });
    const transport = makeTransport();
    const adapter = makeAdapter([{ ok: true, text: "ACCEPT" }]);
    const engine = makeEngine(transport, adapter, { home, fetch });
    const { th } = await driveResponderOpen(engine, transport, SID);

    const file = { name: "bad.txt", size: claimed.length, mime: "text/plain", sha256: sha256(claimed), storage_path: "x" };
    const sig = partnerSign(signing.buildFileString({
      sessionId: SID, th, senderId: PARTNER, messageId: "bad1", seq: 1,
      fileSha256: file.sha256, fileName: file.name, fileSize: file.size, fileMime: file.mime, note: "",
    }));
    const promptsBefore = adapter.prompts.length;
    await engine.handle({ protocol: "ammunity", v: 1, type: "session.file", session_id: SID, message_id: "bad1", seq: 1, file, sig });

    assert.ok(!existsSync(join(home, "sessions", SID, "files", "bad.txt")), "nothing saved on a hash mismatch");
    assert.equal(adapter.prompts.length, promptsBefore, "the brain was NOT invoked");
    const err = transport.sent.find((f) => f.type === "session.error");
    assert.ok(err, "a session.error was emitted");
    assert.equal(err.code, "file_hash_mismatch");
    assert.equal(err.message_id, "bad1");
    pass("(4) inbound file hash mismatch → not saved, brain skipped, session.error(file_hash_mismatch)");
  }

  // ── (5) log-index catch-up (gap 1 → 4, GET returns rows 2,3) ────────────────
  {
    const SID = "f5555555-0000-4000-8000-000000000005";
    const home = freshHome();
    let messagesFetches = 0;
    const rowFor = (li, mid, seq, body) => ({
      frame_type: "message", sender_agent_id: PARTNER, log_index: li, message_id: mid, seq, body,
      sig: null, // filled after th known
    });
    // th needs the engine's nonces; build lazily below.
    let rows = [];
    const fetch = makeFetch((url, method) => {
      if (method === "GET" && url.includes(`/sessions/${SID}/messages`)) {
        messagesFetches += 1;
        return jsonResponse(rows);
      }
      return null;
    });
    const transport = makeTransport();
    const adapter = makeAdapter([
      { ok: true, text: "ACCEPT" },
      { ok: true, text: "reply to 1" },
      { ok: true, text: "reply to 2" },
      { ok: true, text: "reply to 3" },
      { ok: true, text: "reply to 4" },
    ]);
    const engine = makeEngine(transport, adapter, { home, fetch });
    const { th } = await driveResponderOpen(engine, transport, SID);

    const signMsg = (mid, seq, body) => partnerSign(signing.buildMessageString({ sessionId: SID, th, senderId: PARTNER, messageId: mid, seq, body }));

    // The GET returns rows for log_index 2 and 3 (partner, signed).
    const r2 = rowFor(2, "m2", 2, "body two"); r2.sig = signMsg("m2", 2, "body two");
    const r3 = rowFor(3, "m3", 3, "body three"); r3.sig = signMsg("m3", 3, "body three");
    rows = [r2, r3];

    // Frame at log_index 1 → processed normally.
    await engine.handle({ protocol: "ammunity", v: 1, type: "session.message", session_id: SID, message_id: "m1", seq: 1, log_index: 1, body: "body one", sig: signMsg("m1", 1, "body one") });
    // Frame at log_index 4 → gap → catch-up fetches 2,3 → process 2,3 then 4.
    await engine.handle({ protocol: "ammunity", v: 1, type: "session.message", session_id: SID, message_id: "m4", seq: 4, log_index: 4, body: "body four", sig: signMsg("m4", 4, "body four") });

    assert.equal(messagesFetches, 1, "the catch-up endpoint was fetched exactly once (no re-fetch)");
    const inboundOrder = adapter.prompts
      .filter((p) => p.kind === "resume")
      .map((p) => p.prompt)
      .join("\n---\n");
    const i1 = inboundOrder.indexOf("body one");
    const i2 = inboundOrder.indexOf("body two");
    const i3 = inboundOrder.indexOf("body three");
    const i4 = inboundOrder.indexOf("body four");
    assert.ok(i1 >= 0 && i2 > i1 && i3 > i2 && i4 > i3, "the brain saw all four bodies in log_index order");
    assert.equal(engine.sessions.get(SID).lastLogIndex, 4, "lastLogIndex advanced to 4");
    assert.equal(transport.sent.filter((f) => f.type === "session.message").length, 4, "four replies emitted (one per inbound)");
    pass("(5) log_index gap → catch-up replays missed frames in order, then the trigger, no re-fetch");
  }

  // ── (6) CLI buildSessionRequest + writePendingFile ──────────────────────────
  {
    const fixedNonce = signing.makeNonce();
    const req = buildSessionRequest(
      { agentId: SELF, agentKey: "cli-key", coordinatorUrl: BASE + "/", privateKey: self.privateKey, nonce: fixedNonce },
      { responderId: PARTNER, purpose: "do X together", community: "nick-s-test-community" }
    );
    assert.equal(req.url, `${BASE}/sessions`, "URL is <base>/sessions (trailing slash normalised)");
    assert.equal(req.headers["X-Agent-Key"], "cli-key");
    assert.equal(req.body.responder_agent_id, PARTNER);
    assert.equal(req.body.purpose, "do X together");
    assert.equal(req.body.community_slug, "nick-s-test-community");
    assert.equal(req.body.nonce, fixedNonce);
    const reqString = signing.buildRequestString({ initiatorId: SELF, responderId: PARTNER, nonceI: fixedNonce, purpose: "do X together" });
    assert.ok(signing.verifyString(self.publicKey, reqString, req.body.sig), "the session.request sig verifies with the test key");

    const home = freshHome();
    const path = writePendingFile(home, {
      session_id: "cli-sid-0001", responder_agent_id: PARTNER, purpose: "do X together", nonce_i: fixedNonce, community_slug: "nick-s-test-community",
    });
    assert.equal(path, pendingFilePath(home, "cli-sid-0001"));
    assert.ok(existsSync(path), "the pending file exists");
    const saved = JSON.parse(readFileSync(path, "utf8"));
    assert.equal(saved.session_id, "cli-sid-0001");
    assert.equal(saved.responder_agent_id, PARTNER);
    assert.equal(saved.nonce_i, fixedNonce);
    assert.equal(saved.community_slug, "nick-s-test-community");
    assert.ok(saved.created_at, "created_at stamped");

    // Usage guard.
    assert.deepEqual(parseArgs([PARTNER, "purpose", "--community", "c"]), { responderId: PARTNER, purpose: "purpose", community: "c" });
    pass("(6) CLI buildSessionRequest signs correctly + writePendingFile writes valid JSON");
  }

  // ── (6b) runCli: 200 writes pending file; error prints detail verbatim ──────
  {
    const home = freshHome();
    const fetchOk = makeFetch((url, method) => {
      if (method === "POST" && url === `${BASE}/sessions`)
        return jsonResponse({ session_id: "run-sid-1", status: "requested" });
      return null;
    });
    const logs = [];
    const code = await runCli([PARTNER, "let's talk"], {
      fetch: fetchOk, log: (...a) => logs.push(a.join(" ")), err: () => {},
      agentId: SELF, agentKey: "k", coordinatorUrl: BASE, keyPath: KEY_PATH, home,
    });
    assert.equal(code, 0, "runCli returns 0 on success");
    assert.ok(existsSync(pendingFilePath(home, "run-sid-1")), "runCli wrote the pending file");

    const fetchErr = makeFetch((url, method) => {
      if (method === "POST" && url === `${BASE}/sessions`) return jsonResponse({ detail: "community_required" }, 409);
      return null;
    });
    const errs = [];
    const code2 = await runCli([PARTNER, "talk"], {
      fetch: fetchErr, log: () => {}, err: (...a) => errs.push(a.join(" ")),
      agentId: SELF, agentKey: "k", coordinatorUrl: BASE, keyPath: KEY_PATH, home: freshHome(),
    });
    assert.equal(code2, 1, "runCli returns 1 on a coordinator rejection");
    assert.ok(errs.join("\n").includes("community_required"), "the rejection detail is printed verbatim");
    pass("(6b) runCli: 200 → pending file written; 4xx → detail printed verbatim, exit 1");
  }

  // ── (7) daemon pending-file pickup on session.open ──────────────────────────
  {
    const SID = "f7777777-0000-4000-8000-000000000007";
    const home = freshHome();
    const nonceI = signing.makeNonce();
    writePendingFile(home, { session_id: SID, responder_agent_id: PARTNER, purpose: "discuss Z", nonce_i: nonceI });

    const fetch = makeFetch(() => null); // the initiator open path does no HTTP
    const transport = makeTransport();
    const adapter = makeAdapter([{ ok: true, text: "Hi Partner, opening on Z." }]);
    const engine = makeEngine(transport, adapter, { home, fetch });

    const nonceR = signing.makeNonce();
    const acceptSig = partnerSign(signing.buildAcceptString({ sessionId: SID, initiatorId: SELF, responderId: PARTNER, nonceI, nonceR }));
    await engine.handle({
      protocol: "ammunity", v: 1, type: "session.open", role: "initiator",
      session_id: SID,
      partner: { agent_id: PARTNER, agent_name: "Partner" },
      partner_public_key: partnerWire,
      nonce_i: nonceI, nonce_r: nonceR,
      partner_sig: acceptSig,
    });

    const entry = engine.sessions.get(SID);
    assert.ok(entry && entry.role === "initiator" && entry.status === "open", "the pending session was adopted + opened as initiator");
    assert.ok(transport.sent.some((f) => f.type === "session.confirm"), "a session.confirm was emitted");
    const opening = transport.sent.find((f) => f.type === "session.message");
    assert.ok(opening && opening.seq === 1, "the opening brain turn produced session.message seq 1");
    assert.ok(!existsSync(pendingFilePath(home, SID)), "the pending file was deleted after adoption");
    pass("(7) daemon adopts the pending handoff on session.open → confirm + opening turn, file deleted");
  }

  // ── (7b) session.open with no entry and no pending file → close unknown ─────
  {
    const SID = "f8888888-0000-4000-8000-000000000008";
    const home = freshHome();
    const transport = makeTransport();
    const engine = makeEngine(transport, makeAdapter([]), { home, fetch: makeFetch(() => null) });
    await engine.handle({ protocol: "ammunity", v: 1, type: "session.open", role: "initiator", session_id: SID, partner: {}, partner_public_key: partnerWire, nonce_i: "x", nonce_r: "y", partner_sig: "z" });
    const close = transport.sent.find((f) => f.type === "session.close");
    assert.ok(close && close.reason === "unknown_session", "unknown session.open → session.close(unknown_session)");
    pass("(7b) session.open for an unknown session with no pending handoff → close(unknown_session)");
  }

  // ── (8) sendable-file legibility (2026-07-16 live-gate fix) ─────────────────
  // listSendableFiles lists workdir-ROOT regular files only (received files live
  // under files/), and renderSessionTurn tells the brain exactly what it can
  // send — or that it has nothing, so it doesn't probe or invent.
  {
    const SID = "f9999999-0000-4000-8000-000000000009";
    const home = freshHome();
    assert.deepEqual(listSendableFiles(home, SID), [], "no workdir yet → empty list, no throw");
    mkdirSync(join(home, "sessions", SID, "files"), { recursive: true });
    writeFileSync(join(home, "sessions", SID, "report.csv"), "a,b\n1,2\n");
    writeFileSync(join(home, "sessions", SID, "brief.md"), "# brief\n");
    writeFileSync(join(home, "sessions", SID, "files", "inbound.txt"), "from partner");
    assert.deepEqual(listSendableFiles(home, SID), ["brief.md", "report.csv"], "root files listed sorted; files/ (received) excluded");

    const withFiles = renderSessionTurn({ purpose: "p", transcript: [], inbound: "hi", sendableFiles: ["report.csv"] });
    assert.ok(withFiles.includes("Files you can send right now: report.csv"), "turn prompt lists sendable files");
    const withoutFiles = renderSessionTurn({ purpose: "p", transcript: [], inbound: "hi", sendableFiles: [] });
    assert.ok(withoutFiles.includes("no sendable files right now"), "turn prompt says clearly when there is nothing to send");
    pass("(8) sendable files are legible to the brain (listed when present, denied when absent)");
  }

  rmSync(HOME_ROOT, { recursive: true, force: true });
  console.log(`\n${passed} passed`);
})();
