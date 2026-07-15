/**
 * Receiver core — Tier-2 session signing / crypto (SYNC-3 §6).
 *
 * Pure crypto module: builds the canonical newline-joined signing strings, and
 * signs / verifies them with Ed25519 (the Phase-2 keys as they already exist).
 * The connector owns ALL crypto — the brain never sees keys or signatures
 * (principle 4). No I/O beyond `loadPrivateKey` reading the on-disk PKCS#8 PEM.
 *
 * The signing strings here are the CROSS-LANGUAGE CONTRACT: the Python
 * coordinator verifies byte-for-byte what this module produces, so the field
 * order, the "\n" join, the `ammunity-sig-v1` version line, and the hashed
 * sub-fields must match §6 exactly. Golden vectors pin it (tests/test_signing.mjs).
 *
 * Cross-platform: Node built-in `node:crypto` only (native Ed25519 since v12).
 * No new dependency; no hardcoded paths.
 *
 * Key formats (same as installer/keygen.js):
 *   - private key on disk: PKCS#8 PEM (`agent.key`, chmod 600)
 *   - public key on the wire: `ed25519:<base64 of the raw 32 public bytes>`
 */

import { createHash, createPrivateKey, createPublicKey, sign, verify, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";

const SIG_VERSION = "ammunity-sig-v1";
const TH_VERSION = "ammunity-th-v1";
const WIRE_PREFIX = "ed25519:";

// ── primitives ─────────────────────────────────────────────────────────────

/** Lowercase hex SHA-256 of a string's UTF-8 bytes. */
export function sha256Hex(str) {
  return createHash("sha256").update(String(str), "utf8").digest("hex");
}

/** A fresh challenge nonce: 32 random bytes, base64. */
export function makeNonce() {
  return randomBytes(32).toString("base64");
}

/**
 * Load a PKCS#8 PEM private key from disk → KeyObject. Throws a clear error
 * naming the path if the file is unreadable or not a valid Ed25519 key.
 */
export function loadPrivateKey(path) {
  let pem;
  try {
    pem = readFileSync(path, "utf8");
  } catch (err) {
    throw new Error(`could not read private key at ${path}: ${err && err.message ? err.message : err}`);
  }
  let key;
  try {
    key = createPrivateKey({ key: pem });
  } catch (err) {
    throw new Error(`invalid private key at ${path} (expected PKCS#8 PEM): ${err && err.message ? err.message : err}`);
  }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error(`private key at ${path} is not Ed25519 (got ${key.asymmetricKeyType})`);
  }
  return key;
}

/**
 * Build a KeyObject from a wire public key `ed25519:<b64 raw 32B>`.
 * Validates the prefix and that the decoded key is exactly 32 bytes, then
 * imports via JWK (OKP/Ed25519, `x` = base64url of the raw bytes). Throws on a
 * malformed key.
 */
export function publicKeyFromWire(str) {
  const s = String(str || "");
  if (!s.startsWith(WIRE_PREFIX)) {
    throw new Error(`malformed public key: expected "${WIRE_PREFIX}<base64>" prefix`);
  }
  const b64 = s.slice(WIRE_PREFIX.length);
  const raw = Buffer.from(b64, "base64");
  if (raw.length !== 32) {
    throw new Error(`malformed Ed25519 public key: expected 32 raw bytes, got ${raw.length}`);
  }
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
    format: "jwk",
  });
}

/** Ed25519 sign a canonical string's UTF-8 bytes → base64 signature. */
export function signString(privateKeyObj, canonicalString) {
  return sign(null, Buffer.from(String(canonicalString), "utf8"), privateKeyObj).toString("base64");
}

/**
 * Verify an Ed25519 signature (base64) over a canonical string. Returns a
 * boolean; never throws on a bad signature (only crypto.verify's own key
 * errors would surface — a malformed KeyObject is the caller's problem).
 */
export function verifyString(publicKeyObj, canonicalString, sigB64) {
  try {
    return verify(
      null,
      Buffer.from(String(canonicalString), "utf8"),
      publicKeyObj,
      Buffer.from(String(sigB64 || ""), "base64")
    );
  } catch {
    return false;
  }
}

// ── transcript hash (channel binding, §1) ────────────────────────────────────

/**
 * TH — binds every data frame to THIS authenticated handshake:
 *   sha256_hex("ammunity-th-v1\n" + [session_id, initiator_id, responder_id, nonce_i, nonce_r].join("\n"))
 */
export function transcriptHash(sessionId, initiatorId, responderId, nonceI, nonceR) {
  return sha256Hex(TH_VERSION + "\n" + [sessionId, initiatorId, responderId, nonceI, nonceR].join("\n"));
}

// ── canonical signing strings (§6) ───────────────────────────────────────────
// Every string: first line the version, second line the frame label, then the
// frame fields; all joined with "\n". Byte-exact — the coordinator verifies these.

function join(...fields) {
  return fields.join("\n");
}

/** session.request — `sha256_hex(purpose)` is the last field. */
export function buildRequestString({ initiatorId, responderId, nonceI, purpose }) {
  return join(SIG_VERSION, "session.request", initiatorId, responderId, nonceI, sha256Hex(purpose));
}

/** session.accept — covers both nonces. */
export function buildAcceptString({ sessionId, initiatorId, responderId, nonceI, nonceR }) {
  return join(SIG_VERSION, "session.accept", sessionId, initiatorId, responderId, nonceI, nonceR);
}

/** session.confirm — same fields as accept, distinct label (anti-mirroring). */
export function buildConfirmString({ sessionId, initiatorId, responderId, nonceI, nonceR }) {
  return join(SIG_VERSION, "session.confirm", sessionId, initiatorId, responderId, nonceI, nonceR);
}

/** session.message — TH-bound; seq stringified; body hashed. */
export function buildMessageString({ sessionId, th, senderId, messageId, seq, body }) {
  return join(SIG_VERSION, "session.message", sessionId, th, senderId, messageId, String(seq), sha256Hex(body));
}

/**
 * session.file — TH-bound. Field 8 is the file descriptor hash
 *   sha256_hex(file.sha256 \n file.name \n file.size \n file.mime)
 * and field 9 is sha256_hex(note or "").
 */
export function buildFileString({ sessionId, th, senderId, messageId, seq, fileSha256, fileName, fileSize, fileMime, note }) {
  const descriptor = sha256Hex(join(fileSha256, fileName, String(fileSize), fileMime));
  return join(SIG_VERSION, "session.file", sessionId, th, senderId, messageId, String(seq), descriptor, sha256Hex(note || ""));
}

/** session.close — TH-bound; reason hashed (empty allowed). */
export function buildCloseString({ sessionId, th, senderId, seq, reason }) {
  return join(SIG_VERSION, "session.close", sessionId, th, senderId, String(seq), sha256Hex(reason || ""));
}
