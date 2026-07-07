/**
 * Piece 2.1 of the installer: agent keypair generation + public-key upload.
 *
 * The connector owns ALL crypto. It generates an Ed25519 keypair locally at
 * install time and uploads ONLY the public key to the coordinator. The private
 * key is written to the connector's runtime home (`agent.key`, chmod 600) and
 * NEVER leaves the host — it is never logged, never put in a frame, never in
 * the `.env` dump. (Per-message signing is Phase 3; today the private key just
 * has to exist so we can derive + upload its public half, and be pinned into a
 * trust edge later — Phase 2.4.)
 *
 * Key formats (documented, so a later phase that loads the key knows what it
 * gets):
 *   - Private key on disk: PKCS#8 PEM (`agent.key`, mode 0600). Standard,
 *     text-safe, importable by `crypto.createPrivateKey` on any OS.
 *   - Public key on the wire: base64 of the RAW 32-byte Ed25519 public key
 *     (NOT the 44-byte SPKI/DER wrapper). Sent as
 *     `{ "public_key": "<base64>", "algorithm": "ed25519" }`; the coordinator
 *     stores it as `ed25519:<base64>` and a re-upload is a rotation.
 *
 * Cross-platform: Node built-in `node:crypto` only (native Ed25519 since v12),
 * global `fetch` (Node >= 18, already required by system.js). No new dep.
 */

import { generateKeyPairSync, createPrivateKey, createPublicKey } from "node:crypto";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// Where the private key lives inside the connector's runtime home. Sits next
// to the `.env` (same home, same 0600 posture).
export function keyPath(home) {
  return join(home, "agent.key");
}

/**
 * Extract the RAW 32-byte Ed25519 public key (base64) from a KeyObject.
 *
 * The gotcha: Node's `publicKey.export({ type: "spki", format: "der" })` gives
 * a 44-byte SPKI structure (a fixed 12-byte ASN.1 prefix + the 32 raw bytes),
 * NOT the raw key the coordinator's validator wants. Rather than slice the last
 * 32 bytes off the DER (which works, but hardcodes the DER layout), we export
 * the JWK form: for an OKP/Ed25519 key the `x` member is exactly the raw
 * 32-byte public key, base64url-encoded. We decode that and re-encode standard
 * base64. Verified equal to the SPKI-last-32 bytes, and asserted to be 32 bytes.
 */
export function rawPublicKeyBase64(keyObject) {
  const pub =
    keyObject.type === "public" ? keyObject : createPublicKey(keyObject);
  const jwk = pub.export({ format: "jwk" });
  if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.x) {
    throw new Error("not an Ed25519 public key (unexpected JWK shape)");
  }
  const raw = Buffer.from(jwk.x, "base64url");
  if (raw.length !== 32) {
    throw new Error(`expected a 32-byte raw Ed25519 public key, got ${raw.length}`);
  }
  return raw.toString("base64");
}

// Derive the raw public key (base64) directly from a PKCS#8 PEM private key —
// used when reusing an existing on-disk key (idempotent path).
export function publicKeyBase64FromPrivatePem(pem) {
  const priv = createPrivateKey({ key: pem });
  return rawPublicKeyBase64(createPublicKey(priv));
}

/**
 * Generate a fresh Ed25519 keypair.
 * Returns { privatePem (PKCS#8 PEM string), publicKeyBase64 (raw 32-byte b64) }.
 * Pure — no side effects, no disk I/O (easy to unit-test).
 */
export function generateKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicKeyBase64: rawPublicKeyBase64(publicKey),
  };
}

// Is `pem` a loadable Ed25519 PKCS#8 private key? (corruption check)
function isValidPrivatePem(pem) {
  try {
    const priv = createPrivateKey({ key: pem });
    return priv.asymmetricKeyType === "ed25519";
  } catch {
    return false;
  }
}

/**
 * Ensure a keypair exists in `home`, reusing the on-disk one when possible.
 *
 * Idempotent by default: an existing, valid `agent.key` is REUSED (installs
 * don't churn the identity on every re-run). Regenerates only when:
 *   - the file is missing, or
 *   - the file is corrupt/unreadable, or
 *   - `rotate` is true (explicit `--rotate-key`).
 *
 * Writes the private key at 0600 and never logs its contents. Returns
 * { publicKeyBase64, created, rotated, reused, path }.
 */
export function loadOrCreateKeypair(home, { rotate = false } = {}, log = () => {}) {
  const path = keyPath(home);
  const present = existsSync(path);

  if (present && !rotate) {
    let pem = "";
    try {
      pem = readFileSync(path, "utf8");
    } catch {
      pem = "";
    }
    if (pem && isValidPrivatePem(pem)) {
      log(`reusing existing agent keypair (${path})`);
      return {
        publicKeyBase64: publicKeyBase64FromPrivatePem(pem),
        created: false,
        rotated: false,
        reused: true,
        path,
      };
    }
    log(`⚠ existing agent key at ${path} is unreadable/corrupt — regenerating`);
  }

  const { privatePem, publicKeyBase64 } = generateKeypair();
  writeFileSync(path, privatePem, { mode: 0o600 });
  try {
    chmodSync(path, 0o600); // re-assert (umask can widen the create mode)
  } catch {
    /* best-effort on platforms without POSIX perms (Windows) */
  }
  log(
    rotate && present
      ? `rotated agent keypair → ${path} (chmod 600)`
      : `generated agent keypair → ${path} (chmod 600)`
  );
  return {
    publicKeyBase64,
    created: true,
    rotated: Boolean(rotate && present),
    reused: false,
    path,
  };
}

// The exact request body the coordinator expects (locked at SYNC-2).
export function buildPublicKeyBody(publicKeyBase64) {
  return { public_key: publicKeyBase64, algorithm: "ed25519" };
}

/**
 * Upload the PUBLIC key to POST {coordinatorUrl}/agents/{agentId}/public-key,
 * authed with the agent's own key (X-Agent-Key). Graceful: never throws — a
 * failure is logged as a warning and returned as { ok:false, ... } so the caller
 * can continue the install (a pinned key isn't enforced yet — Phase 2.4).
 *
 * `fetchImpl` is injectable for tests; defaults to the global fetch (Node >=18).
 */
export async function uploadPublicKey(
  { coordinatorUrl, agentId, agentKey, publicKeyBase64 },
  log = () => {},
  fetchImpl = globalThis.fetch
) {
  const base = String(coordinatorUrl || "").replace(/\/+$/, "");
  const url = `${base}/agents/${agentId}/public-key`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const res = await fetchImpl(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Agent-Key": agentKey,
      },
      body: JSON.stringify(buildPublicKeyBody(publicKeyBase64)),
      signal: controller.signal,
    });
    if (res.ok) {
      log(`registered public key with the coordinator (HTTP ${res.status})`);
      return { ok: true, status: res.status };
    }
    let detail = "";
    try {
      detail = (await res.text()).slice(0, 200);
    } catch {
      /* ignore body read errors */
    }
    log(
      `⚠ couldn't register the public key (HTTP ${res.status}${detail ? `: ${detail}` : ""}). ` +
        `The agent still works; re-run the installer to retry.`
    );
    return { ok: false, status: res.status, detail };
  } catch (err) {
    const msg = err && err.name === "AbortError" ? "timed out" : err && err.message ? err.message : String(err);
    log(`⚠ couldn't reach the coordinator to register the public key (${msg}). ` + `The agent still works; re-run the installer to retry.`);
    return { ok: false, error: msg };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Full flow used by the installer: ensure a keypair exists, then upload the
 * public key. Non-fatal throughout. Returns the combined result.
 */
export async function ensureAndUploadKey(
  { home, coordinatorUrl, agentId, agentKey, rotate = false },
  log = () => {}
) {
  const key = loadOrCreateKeypair(home, { rotate }, log);
  const upload = await uploadPublicKey(
    { coordinatorUrl, agentId, agentKey, publicKeyBase64: key.publicKeyBase64 },
    log
  );
  return { key, upload };
}
