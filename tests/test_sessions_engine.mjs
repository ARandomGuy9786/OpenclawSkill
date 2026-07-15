/**
 * Tier-2 session engine tests (SYNC-3 §3–§6, §9) — the connector's SessionEngine.
 *
 * No test framework (mirrors test_receiver / test_signing): assertions + a PASS
 * counter. A FakeTransport records outbound frames; a scripted FakeAdapter
 * records prompts and returns a queue of brain replies. REAL crypto throughout:
 * two Ed25519 keypairs (self + partner) — the partner keypair stands in for the
 * coordinator, building/signing the frames the coordinator would relay.
 *
 * Run:  node tests/test_sessions_engine.mjs
 */

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SessionEngine } from "../receiver/core/sessions.js";
import { Receiver } from "../receiver/core/receiver.js";
import * as signing from "../receiver/core/signing.js";

let passed = 0;
function pass(name) {
  passed += 1;
  console.log(`PASS  ${name}`);
}

// Wrap a KeyObject public key on the wire exactly as the coordinator stores it.
function wirePublicKey(publicKeyObj) {
  const jwk = publicKeyObj.export({ format: "jwk" });
  const raw = Buffer.from(jwk.x, "base64url");
  return "ed25519:" + raw.toString("base64");
}

// FakeTransport: records every frame the engine emits.
function makeTransport() {
  const sent = [];
  return { sent, send: (f) => sent.push(f) };
}

// Scripted FakeAdapter: `replies` is a queue consumed one per run/resume.
// supportsResume = true; run/resume both return {ok, text, sessionRef}.
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
      const r = nextReply();
      return { ok: true, sessionRef: `brain-${i}`, ...r };
    },
    async resume(ref, prompt, opts = {}) {
      prompts.push({ kind: "resume", ref, prompt, opts });
      const r = nextReply();
      return { ok: true, sessionRef: ref, ...r };
    },
    closeSession(ref) {
      closed.push(ref);
    },
  };
}

// One self keypair for the whole suite (the connector under test); a temp PKCS#8
// PEM on disk for the engine to load. One partner keypair (the remote agent).
const self = generateKeyPairSync("ed25519");
const partner = generateKeyPairSync("ed25519");
const partnerWire = wirePublicKey(partner.publicKey);

const HOME = mkdtempSync(join(tmpdir(), "ammunity-sessions-"));
const KEY_PATH = join(HOME, "agent.key");
writeFileSync(KEY_PATH, self.privateKey.export({ type: "pkcs8", format: "pem" }));

const SELF = "self-agent-0000-0000-000000000000";
const PARTNER = "partner-agent-0000-0000-00000000";

function makeEngine(transport, adapter) {
  return new SessionEngine({
    transport,
    adapter,
    config: { agentId: SELF, keyPath: KEY_PATH },
    log: () => {},
  });
}

// Partner (acting as coordinator relay) signs a canonical string.
function partnerSign(str) {
  return signing.signString(partner.privateKey, str);
}

// Build a responder session up to `open` and return { engine, transport, adapter,
// nonceI, nonceR, sessionId }. `replies` seeds the adapter (index 0 = consent).
function establishResponderOpen(sessionId, replies) {
  const transport = makeTransport();
  const adapter = makeAdapter(replies);
  const engine = makeEngine(transport, adapter);
  const nonceI = signing.makeNonce();
  return engine
    .handle({
      protocol: "ammunity", v: 1, type: "session.invite",
      session_id: sessionId,
      initiator: { agent_id: PARTNER, agent_name: "Partner", owner_label: "Acme" },
      purpose: "collaborate on the report",
      community_slug: "nick-s-test-community",
      nonce_i: nonceI,
      initiator_public_key: partnerWire,
    })
    .then(() => {
      const accept = transport.sent.find((f) => f.type === "session.accept");
      const nonceR = accept.nonce;
      const confirmSig = partnerSign(
        signing.buildConfirmString({ sessionId, initiatorId: PARTNER, responderId: SELF, nonceI, nonceR })
      );
      return engine
        .handle({
          protocol: "ammunity", v: 1, type: "session.open", role: "responder",
          session_id: sessionId,
          partner: { agent_id: PARTNER, agent_name: "Partner" },
          partner_public_key: partnerWire,
          nonce_i: nonceI, nonce_r: nonceR,
          partner_sig: confirmSig,
        })
        .then(() => ({ engine, transport, adapter, nonceI, nonceR, sessionId }));
    });
}

// The TH a partner would compute for a responder-side session (initiator=PARTNER).
function responderTH(sessionId, nonceI, nonceR) {
  return signing.transcriptHash(sessionId, PARTNER, SELF, nonceI, nonceR);
}

await (async () => {
  // ── (a) invite → ACCEPT → session.accept with a verifiable sig + 32B nonce ──
  {
    const SID = "aaaaaaaa-0000-4000-8000-000000000001";
    const transport = makeTransport();
    const adapter = makeAdapter([{ ok: true, text: "ACCEPT" }]);
    const engine = makeEngine(transport, adapter);
    const nonceI = signing.makeNonce();
    await engine.handle({
      protocol: "ammunity", v: 1, type: "session.invite",
      session_id: SID,
      initiator: { agent_id: PARTNER, agent_name: "Partner", owner_label: "Acme" },
      purpose: "work together",
      community_slug: "nick-s-test-community",
      nonce_i: nonceI,
      initiator_public_key: partnerWire,
    });
    const accept = transport.sent.find((f) => f.type === "session.accept");
    assert.ok(accept, "a session.accept was emitted");
    assert.equal(accept.session_id, SID);
    assert.equal(Buffer.from(accept.nonce, "base64").length, 32, "nonce_r is 32 bytes");
    const acceptString = signing.buildAcceptString({
      sessionId: SID, initiatorId: PARTNER, responderId: SELF, nonceI, nonceR: accept.nonce,
    });
    assert.ok(signing.verifyString(self.publicKey, acceptString, accept.sig), "accept sig verifies against our public key");
    pass("(a) invite → ACCEPT → verifiable session.accept with a 32-byte nonce_r");
  }

  // ── (b) invite → free text → fail-closed decline with the text as the reason ─
  {
    const SID = "aaaaaaaa-0000-4000-8000-000000000002";
    const transport = makeTransport();
    const adapter = makeAdapter([{ ok: true, text: "hmm, not sure about this one" }]);
    const engine = makeEngine(transport, adapter);
    await engine.handle({
      protocol: "ammunity", v: 1, type: "session.invite",
      session_id: SID,
      initiator: { agent_id: PARTNER, agent_name: "Partner" },
      purpose: "work together",
      nonce_i: signing.makeNonce(),
      initiator_public_key: partnerWire,
    });
    const decline = transport.sent.find((f) => f.type === "session.decline");
    assert.ok(decline, "a session.decline was emitted");
    assert.equal(decline.reason, "hmm, not sure about this one", "free text becomes the decline reason (fail-closed)");
    assert.ok(!transport.sent.some((f) => f.type === "session.accept"), "no accept emitted");
    pass("(b) invite → free-text reply → fail-closed decline carrying the reply text");
  }

  // ── (c) responder handshake to open; tampered confirm-sig → bad_partner_signature ─
  {
    const SID = "aaaaaaaa-0000-4000-8000-000000000003";
    const { engine, transport } = await establishResponderOpen(SID, [{ ok: true, text: "ACCEPT" }]);
    assert.equal(engine.sessions.get(SID).status, "open", "responder session is open after a valid confirm-sig");
    assert.ok(!transport.sent.some((f) => f.type === "session.message"), "responder sends no message on open (awaits the initiator)");
    pass("(c) responder handshake: valid confirm-sig → open");

    // Now the tampered-sig branch on a FRESH session.
    const SID2 = "aaaaaaaa-0000-4000-8000-000000000013";
    const t2 = makeTransport();
    const a2 = makeAdapter([{ ok: true, text: "ACCEPT" }]);
    const e2 = makeEngine(t2, a2);
    const nonceI = signing.makeNonce();
    await e2.handle({
      protocol: "ammunity", v: 1, type: "session.invite",
      session_id: SID2,
      initiator: { agent_id: PARTNER, agent_name: "Partner" },
      purpose: "x",
      nonce_i: nonceI,
      initiator_public_key: partnerWire,
    });
    const accept = t2.sent.find((f) => f.type === "session.accept");
    const goodSig = partnerSign(
      signing.buildConfirmString({ sessionId: SID2, initiatorId: PARTNER, responderId: SELF, nonceI, nonceR: accept.nonce })
    );
    const badSig = Buffer.from(goodSig, "base64");
    badSig[0] ^= 0xff; // flip a byte
    await e2.handle({
      protocol: "ammunity", v: 1, type: "session.open", role: "responder",
      session_id: SID2,
      partner: { agent_id: PARTNER, agent_name: "Partner" },
      partner_public_key: partnerWire,
      nonce_i: nonceI, nonce_r: accept.nonce,
      partner_sig: badSig.toString("base64"),
    });
    const close = t2.sent.find((f) => f.type === "session.close");
    assert.ok(close, "a session.close was emitted on a bad confirm-sig");
    assert.equal(close.reason, "bad_partner_signature");
    assert.equal(e2.sessions.get(SID2), undefined, "the session entry was dropped");
    pass("(c) responder handshake: tampered confirm-sig → session.close bad_partner_signature + dropped");
  }

  // ── (d) initiator path: register → open (valid accept-sig) → confirm + opening msg ─
  {
    const SID = "aaaaaaaa-0000-4000-8000-000000000004";
    const transport = makeTransport();
    const adapter = makeAdapter([{ ok: true, text: "Hi Partner — let's get started on Y." }]);
    const engine = makeEngine(transport, adapter);
    const nonceI = signing.makeNonce();
    engine.registerInitiatedSession({
      session_id: SID,
      responder: { agent_id: PARTNER, agent_name: "Partner" },
      purpose: "discuss Y",
      nonce_i: nonceI,
    });
    const nonceR = signing.makeNonce();
    // As initiator: initiatorId = SELF, responderId = PARTNER; partner signs ACCEPT.
    const acceptSig = partnerSign(
      signing.buildAcceptString({ sessionId: SID, initiatorId: SELF, responderId: PARTNER, nonceI, nonceR })
    );
    await engine.handle({
      protocol: "ammunity", v: 1, type: "session.open", role: "initiator",
      session_id: SID,
      partner: { agent_id: PARTNER, agent_name: "Partner" },
      partner_public_key: partnerWire,
      nonce_i: nonceI, nonce_r: nonceR,
      partner_sig: acceptSig,
    });

    const confirm = transport.sent.find((f) => f.type === "session.confirm");
    assert.ok(confirm, "a session.confirm was emitted");
    const confirmString = signing.buildConfirmString({ sessionId: SID, initiatorId: SELF, responderId: PARTNER, nonceI, nonceR });
    assert.ok(signing.verifyString(self.publicKey, confirmString, confirm.sig), "confirm sig verifies against our public key");
    assert.equal(engine.sessions.get(SID).status, "open");

    const opening = transport.sent.find((f) => f.type === "session.message");
    assert.ok(opening, "the opening brain turn produced a session.message");
    assert.equal(opening.seq, 1, "opening message is seq 1");
    const th = signing.transcriptHash(SID, SELF, PARTNER, nonceI, nonceR);
    const msgString = signing.buildMessageString({
      sessionId: SID, th, senderId: SELF, messageId: opening.message_id, seq: 1, body: opening.body,
    });
    assert.ok(signing.verifyString(self.publicKey, msgString, opening.sig), "opening message sig verifies");
    pass("(d) initiator: valid accept-sig → verifiable confirm + a signed opening session.message");
  }

  // ── (e) inbound messages → brain runs → signed replies with seq 1 then 2 ─────
  {
    const SID = "aaaaaaaa-0000-4000-8000-000000000005";
    const { engine, transport, adapter, nonceI, nonceR } = await establishResponderOpen(SID, [
      { ok: true, text: "ACCEPT" },
      { ok: true, text: "first reply back" },
      { ok: true, text: "second reply back" },
    ]);
    const th = responderTH(SID, nonceI, nonceR);

    const sendPartnerMessage = (messageId, seq, body) => {
      const sig = partnerSign(
        signing.buildMessageString({ sessionId: SID, th, senderId: PARTNER, messageId, seq, body })
      );
      return engine.handle({
        protocol: "ammunity", v: 1, type: "session.message",
        session_id: SID, message_id: messageId, seq, body, sig,
      });
    };

    await sendPartnerMessage("msg-1", 1, "hello there");
    await sendPartnerMessage("msg-2", 2, "and a follow-up");

    const replies = transport.sent.filter((f) => f.type === "session.message");
    assert.equal(replies.length, 2, "two reply messages emitted");
    assert.equal(replies[0].seq, 1, "first reply is seq 1");
    assert.equal(replies[1].seq, 2, "second reply is seq 2");
    for (const r of replies) {
      const s = signing.buildMessageString({
        sessionId: SID, th, senderId: SELF, messageId: r.message_id, seq: r.seq, body: r.body,
      });
      assert.ok(signing.verifyString(self.publicKey, s, r.sig), `reply seq ${r.seq} sig verifies`);
    }
    // consent run + two resumed turns
    assert.equal(adapter.prompts.filter((p) => p.kind === "resume").length, 2, "each inbound message resumed the brain");
    pass("(e) inbound messages → brain runs → signed replies, seq increments 1 → 2");
  }

  // ── (f) tampered inbound message sig → dropped, brain NOT invoked ────────────
  {
    const SID = "aaaaaaaa-0000-4000-8000-000000000006";
    const { engine, transport, adapter, nonceI, nonceR } = await establishResponderOpen(SID, [{ ok: true, text: "ACCEPT" }]);
    const th = responderTH(SID, nonceI, nonceR);
    const promptsBefore = adapter.prompts.length;
    const sentBefore = transport.sent.length;
    const good = partnerSign(signing.buildMessageString({ sessionId: SID, th, senderId: PARTNER, messageId: "m", seq: 1, body: "hi" }));
    const bad = Buffer.from(good, "base64");
    bad[0] ^= 0xff;
    await engine.handle({
      protocol: "ammunity", v: 1, type: "session.message",
      session_id: SID, message_id: "m", seq: 1, body: "hi", sig: bad.toString("base64"),
    });
    assert.equal(adapter.prompts.length, promptsBefore, "brain was NOT invoked on a bad-sig message");
    assert.equal(transport.sent.length, sentBefore, "nothing was emitted");
    pass("(f) tampered inbound message sig → dropped; brain never runs");
  }

  // ── (g) message_id replay + stale seq are both dropped ──────────────────────
  {
    const SID = "aaaaaaaa-0000-4000-8000-000000000007";
    const { engine, transport, adapter, nonceI, nonceR } = await establishResponderOpen(SID, [
      { ok: true, text: "ACCEPT" },
      { ok: true, text: "reply to seq 1" },
    ]);
    const th = responderTH(SID, nonceI, nonceR);
    const signMsg = (messageId, seq, body) =>
      partnerSign(signing.buildMessageString({ sessionId: SID, th, senderId: PARTNER, messageId, seq, body }));

    // Valid seq 1 → processed.
    await engine.handle({ protocol: "ammunity", v: 1, type: "session.message", session_id: SID, message_id: "dup", seq: 1, body: "one", sig: signMsg("dup", 1, "one") });
    const afterFirst = transport.sent.filter((f) => f.type === "session.message").length;
    assert.equal(afterFirst, 1, "the first valid message produced a reply");

    // Same message_id again → dedup drop.
    await engine.handle({ protocol: "ammunity", v: 1, type: "session.message", session_id: SID, message_id: "dup", seq: 1, body: "one", sig: signMsg("dup", 1, "one") });
    // New message_id but stale seq (1, not > lastPeerSeq 1) → dropped.
    await engine.handle({ protocol: "ammunity", v: 1, type: "session.message", session_id: SID, message_id: "stale", seq: 1, body: "again", sig: signMsg("stale", 1, "again") });

    const afterReplays = transport.sent.filter((f) => f.type === "session.message").length;
    assert.equal(afterReplays, afterFirst, "replayed message_id + stale seq produced no further replies");
    assert.equal(adapter.prompts.filter((p) => p.kind === "resume").length, 1, "the brain ran exactly once");
    pass("(g) duplicate message_id and stale seq are both dropped");
  }

  // ── (h) brain replies CLOSE: thanks → signed close + closeSession + entry gone ─
  {
    const SID = "aaaaaaaa-0000-4000-8000-000000000008";
    const { engine, transport, adapter, nonceI, nonceR } = await establishResponderOpen(SID, [
      { ok: true, text: "ACCEPT" },
      { ok: true, text: "CLOSE: thanks" },
    ]);
    const th = responderTH(SID, nonceI, nonceR);
    const brainRef = engine.sessions.get(SID).brainSessionRef;
    const sig = partnerSign(signing.buildMessageString({ sessionId: SID, th, senderId: PARTNER, messageId: "m", seq: 1, body: "any last words?" }));
    await engine.handle({ protocol: "ammunity", v: 1, type: "session.message", session_id: SID, message_id: "m", seq: 1, body: "any last words?", sig });

    const close = transport.sent.find((f) => f.type === "session.close");
    assert.ok(close, "a session.close was emitted");
    assert.equal(close.reason, "thanks", "the closing note is the close reason");
    assert.equal(close.seq, 1, "close carries our seq (1)");
    const closeString = signing.buildCloseString({ sessionId: SID, th, senderId: SELF, seq: 1, reason: "thanks" });
    assert.ok(signing.verifyString(self.publicKey, closeString, close.sig), "close sig verifies");
    assert.ok(adapter.closed.includes(brainRef), "adapter.closeSession was called with the brain ref");
    assert.equal(engine.sessions.get(SID), undefined, "the session entry is gone");
    pass("(h) brain CLOSE: → signed session.close + closeSession + entry removed");
  }

  // ── (i) inbound coordinator close → cleanup, no signature demanded ──────────
  {
    const SID = "aaaaaaaa-0000-4000-8000-000000000009";
    const { engine, adapter } = await establishResponderOpen(SID, [{ ok: true, text: "ACCEPT" }]);
    const brainRef = engine.sessions.get(SID).brainSessionRef;
    await engine.handle({
      protocol: "ammunity", v: 1, type: "session.close",
      session_id: SID, by: "coordinator", reason: "idle_timeout",
    });
    assert.equal(engine.sessions.get(SID), undefined, "coordinator close removed the entry (no sig required)");
    assert.ok(adapter.closed.includes(brainRef), "brain session cleaned up on coordinator close");
    pass("(i) inbound coordinator close → unconditional cleanup");
  }

  // ── (j) Tier-1 regression: a plain task frame still flows with the engine on ─
  {
    const TASK = "11111111-1111-1111-1111-111111111111";
    const taskAdapter = {
      name: "openclaw",
      supportsResume: false,
      async run() {
        return { ok: true, text: "the answer" };
      },
      resume() {
        throw new Error("no resume");
      },
      closeSession() {},
    };
    const r = new Receiver({ url: "ws://test", agentId: SELF, agentKey: "k", adapter: taskAdapter, log: () => {}, keyPath: KEY_PATH });
    assert.ok(r.sessions instanceof SessionEngine, "the session engine is attached (agent.key present)");
    const sent = [];
    r.transport = { send: (f) => sent.push(f) };
    await r.onMessage({ type: "task", task_id: TASK, task_description: "Explain X", payload: {} });
    assert.equal(sent.length, 1, "exactly one frame sent");
    assert.equal(sent[0].type, "result");
    assert.equal(sent[0].status, "completed");
    assert.equal(sent[0].result, "the answer");
    assert.equal(sent[0].task_id, TASK, "result is tagged with the task_id (Tier-1 byte-identical)");
    pass("(j) Tier-1 regression: a task frame flows exactly as before with the engine attached");
  }

  rmSync(HOME, { recursive: true, force: true });
  console.log(`\n${passed} passed`);
})();
