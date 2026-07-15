/**
 * Tier-2 session signing tests (SYNC-3 §6) — the connector's crypto core.
 *
 * No test framework (mirrors test_receiver / test_keygen): assertions + a PASS
 * counter. Covers sign/verify round-trips, wire public-key import, PKCS#8 PEM
 * load, the `hello.features` upgrade, and the CROSS-LANGUAGE GOLDEN VECTORS that
 * pin byte-exact agreement with the coordinator's Python verifier — if a vector
 * fails, the Node implementation is wrong, not the vector.
 *
 * Run:  node tests/test_signing.mjs
 */

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildAcceptString,
  buildCloseString,
  buildConfirmString,
  buildFileString,
  buildMessageString,
  buildRequestString,
  loadPrivateKey,
  makeNonce,
  publicKeyFromWire,
  sha256Hex,
  signString,
  transcriptHash,
  verifyString,
} from "../receiver/core/signing.js";
import { Transport } from "../receiver/core/transport.js";

let passed = 0;
function pass(name) {
  passed += 1;
  console.log(`PASS  ${name}`);
}

// Export the RAW 32-byte public key (base64) of a generated key, then wrap it
// on the wire exactly as the coordinator stores it (`ed25519:<b64>`).
function wirePublicKey(publicKeyObj) {
  const jwk = publicKeyObj.export({ format: "jwk" });
  const raw = Buffer.from(jwk.x, "base64url");
  assert.equal(raw.length, 32, "raw Ed25519 public key is 32 bytes");
  return "ed25519:" + raw.toString("base64");
}

await (async () => {
  // ── sign → verify round-trip + tamper / wrong-key rejection ────────────────
  {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const body = "the quick brown fox";
    const s = buildMessageString({
      sessionId: "s", th: "t", senderId: "me", messageId: "m", seq: 1, body,
    });
    const sig = signString(privateKey, s);
    assert.ok(verifyString(publicKey, s, sig), "fresh keypair round-trip verifies");

    // One body character changes → the canonical string changes → verify fails.
    const tampered = buildMessageString({
      sessionId: "s", th: "t", senderId: "me", messageId: "m", seq: 1, body: body + "!",
    });
    assert.equal(verifyString(publicKey, tampered, sig), false, "tampered body fails verification");

    // A different key must not verify a signature it didn't make.
    const other = generateKeyPairSync("ed25519");
    assert.equal(verifyString(other.publicKey, s, sig), false, "wrong key fails verification");

    // A garbage signature returns false, never throws.
    assert.equal(verifyString(publicKey, s, "not-base64-sig"), false, "bad sig returns false, no throw");
    pass("sign/verify: round-trip verifies; tamper + wrong key + garbage sig all fail");
  }

  // ── publicKeyFromWire round-trip (import a raw wire key, verify a real sig) ─
  {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const wire = wirePublicKey(publicKey);
    const imported = publicKeyFromWire(wire);
    const s = buildAcceptString({
      sessionId: "s", initiatorId: "i", responderId: "r", nonceI: "ni", nonceR: "nr",
    });
    const sig = signString(privateKey, s);
    assert.ok(verifyString(imported, s, sig), "wire-imported public key verifies the matching private key's sig");
    // Malformed wire keys throw with a clear message.
    assert.throws(() => publicKeyFromWire("nope"), /prefix/, "missing prefix throws");
    assert.throws(() => publicKeyFromWire("ed25519:AAAA"), /32 raw bytes/, "wrong length throws");
    pass("publicKeyFromWire: raw ed25519:<b64> imports + verifies; malformed keys throw");
  }

  // ── loadPrivateKey against a temp PKCS#8 PEM file ──────────────────────────
  {
    const home = mkdtempSync(join(tmpdir(), "ammunity-signing-"));
    try {
      const { privateKey, publicKey } = generateKeyPairSync("ed25519");
      const pem = privateKey.export({ type: "pkcs8", format: "pem" });
      const path = join(home, "agent.key");
      writeFileSync(path, pem);
      const loaded = loadPrivateKey(path);
      assert.equal(loaded.asymmetricKeyType, "ed25519", "loaded a valid Ed25519 key");
      const s = "ammunity-sig-v1\nsession.close\ns\nt\nme\n1\n" + sha256Hex("");
      assert.ok(verifyString(publicKey, s, signString(loaded, s)), "loaded key signs verifiably");
      // A missing file throws an error that NAMES the path.
      const missing = join(home, "does-not-exist.key");
      assert.throws(() => loadPrivateKey(missing), (e) => e.message.includes(missing), "missing key error names the path");
      // A corrupt PEM throws an error that names the path.
      const bad = join(home, "corrupt.key");
      writeFileSync(bad, "not a pem\n");
      assert.throws(() => loadPrivateKey(bad), (e) => e.message.includes(bad), "corrupt key error names the path");
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
    pass("loadPrivateKey: reads a PKCS#8 PEM; missing/corrupt errors name the path");
  }

  // ── makeNonce: 32 random bytes, base64 ─────────────────────────────────────
  {
    const n = makeNonce();
    assert.equal(Buffer.from(n, "base64").length, 32, "nonce decodes to 32 bytes");
    assert.notEqual(makeNonce(), makeNonce(), "nonces are random");
    pass("makeNonce: 32 random base64 bytes");
  }

  // ── GOLDEN VECTORS (cross-language interop pins — do NOT adjust) ────────────
  {
    const sessionId = "11111111-1111-4111-8111-111111111111";
    const initiatorId = "22222222-2222-4222-8222-222222222222";
    const responderId = "33333333-3333-4333-8333-333333333333";
    const messageId = "44444444-4444-4444-8444-444444444444";
    const nonceI = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const nonceR = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

    const th = transcriptHash(sessionId, initiatorId, responderId, nonceI, nonceR);
    assert.equal(th, "a9a52b8ed48a0419a4fa9bccddea9c22c0426f94003e30b0e7acf755c591b126", "TH golden vector");

    assert.equal(
      sha256Hex("hello world"),
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
      "sha256Hex golden vector"
    );

    assert.equal(
      sha256Hex(buildMessageString({ sessionId, th, senderId: initiatorId, messageId, seq: 3, body: "hello world" })),
      "b2046e67fe309c43c2c420b2a6a9649a811c8932a7be226288de5d800aef3422",
      "session.message signing-string golden vector"
    );

    assert.equal(
      sha256Hex(buildAcceptString({ sessionId, initiatorId, responderId, nonceI, nonceR })),
      "069392997de5990ee1da51a8758a856d5cbffddcbfd748c3b26a1c2aab4f752c",
      "session.accept signing-string golden vector"
    );

    // The file-descriptor sub-hash (field 8) — asserted via the full string too.
    const fileStr = buildFileString({
      sessionId, th, senderId: initiatorId, messageId, seq: 4,
      fileSha256: "f".repeat(64), fileName: "report.pdf", fileSize: 182044, fileMime: "application/pdf", note: "",
    });
    const descriptorHash = sha256Hex(["f".repeat(64), "report.pdf", String(182044), "application/pdf"].join("\n"));
    assert.equal(
      descriptorHash,
      "6676a2f93800c6ee2e456d10a38d0cdb2719da6038b03e57649be4830fc85a46",
      "session.file descriptor-hash (field 8) golden vector"
    );
    // The built string carries that exact descriptor hash as its field 8.
    assert.ok(fileStr.split("\n")[7] === descriptorHash, "buildFileString embeds the descriptor hash at field 8");

    // Confirm/request/close build without error and differ from accept by label.
    const confirm = buildConfirmString({ sessionId, initiatorId, responderId, nonceI, nonceR });
    assert.equal(confirm.split("\n")[1], "session.confirm", "confirm label distinct from accept");
    assert.equal(buildRequestString({ initiatorId, responderId, nonceI, purpose: "x" }).split("\n")[1], "session.request", "request label");
    assert.equal(buildCloseString({ sessionId, th, senderId: initiatorId, seq: 9, reason: "" }).split("\n")[1], "session.close", "close label");
    pass("golden vectors: TH, sha256Hex, session.message, session.accept, session.file descriptor all match");
  }

  // ── hello frame advertises the sessions feature (real open handler) ────────
  {
    const t = new Transport({ url: "ws://localhost:0", agentId: "agent-1", agentKey: "k", log: () => {} });
    const sent = [];
    t.send = (f) => sent.push(f);
    t.startHeartbeat = () => {}; // don't start the interval in a unit test
    t.scheduleReconnect = () => {}; // the dead url will error/close — don't reconnect
    t.connect(); // registers the REAL 'open' handler on a real ws
    const openHandlers = t.ws.listeners("open");
    assert.equal(openHandlers.length, 1, "exactly one open handler registered");
    openHandlers[0](); // fire the open handler exactly as the ws lib would → sends hello
    // Tear down the never-connected socket. terminate() on a CONNECTING socket
    // emits 'error' synchronously, so swap the listeners for a no-op error sink
    // first (otherwise it's an unhandled 'error' that crashes the process).
    t.ws.removeAllListeners();
    t.ws.on("error", () => {});
    try {
      t.ws.terminate();
    } catch {
      /* ignore */
    }
    const hello = sent.find((f) => f.type === "hello");
    assert.ok(hello, "a hello frame is sent on open");
    assert.equal(hello.agent_id, "agent-1", "hello still carries agent_id");
    assert.deepEqual(hello.features, ["sessions"], "hello advertises the sessions feature");
    pass("hello: open frame advertises features:['sessions'] (additive, agent_id unchanged)");
  }

  console.log(`\n${passed} passed`);
})();
