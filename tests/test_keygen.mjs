/**
 * Installer piece 2.1 unit tests — Ed25519 keypair generation + upload payload.
 *
 * Covers: raw-32-byte public-key generation, PKCS#8 PEM private key on disk,
 * idempotent reuse, explicit rotation, corrupt-key recovery, and the exact
 * upload payload shape / request wiring (with an injected fetch stub — no
 * network).
 *
 * Run:  node tests/test_keygen.mjs
 */

import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildPublicKeyBody,
  ensureAndUploadKey,
  generateKeypair,
  keyPath,
  loadOrCreateKeypair,
  publicKeyBase64FromPrivatePem,
  rawPublicKeyBase64,
  uploadPublicKey,
} from "../installer/keygen.js";

let passed = 0;
function pass(name) {
  passed += 1;
  console.log(`PASS  ${name}`);
}

// A throwaway home under the OS temp dir — resolved at runtime, so no host
// path is baked into this test file (secret-scan hygiene).
function freshHome() {
  return mkdtempSync(join(tmpdir(), "ammunity-keygen-"));
}

await (async () => {
  // ── generateKeypair: raw 32-byte public key + PKCS#8 PEM private key ───────
  {
    const { privatePem, publicKeyBase64 } = generateKeypair();
    const raw = Buffer.from(publicKeyBase64, "base64");
    assert.equal(raw.length, 32, "public key decodes to exactly 32 raw bytes (not the 44-byte SPKI)");
    assert.match(privatePem, /^-----BEGIN PRIVATE KEY-----/, "private key is PKCS#8 PEM");
    const priv = createPrivateKey({ key: privatePem });
    assert.equal(priv.asymmetricKeyType, "ed25519", "private key is Ed25519");
    // Derived-from-PEM public key matches the generated one.
    assert.equal(publicKeyBase64FromPrivatePem(privatePem), publicKeyBase64, "public key derivable from the private PEM");
    pass("generate: raw 32-byte public key + Ed25519 PKCS#8 PEM private key");
  }

  // ── rawPublicKeyBase64 matches the SPKI-last-32-bytes, and round-trips ─────
  {
    const { privatePem, publicKeyBase64 } = generateKeypair();
    const pub = createPublicKey(createPrivateKey({ key: privatePem }));
    const der = pub.export({ type: "spki", format: "der" });
    const spkiLast32 = der.subarray(der.length - 32).toString("base64");
    assert.equal(rawPublicKeyBase64(pub), spkiLast32, "JWK-x extraction equals SPKI last-32 bytes");
    // A signature made with the private key verifies under a public key rebuilt
    // from ONLY the raw 32 bytes we uploaded (proves the raw key is the real one).
    const priv = createPrivateKey({ key: privatePem });
    const sig = sign(null, Buffer.from("ammunity"), priv);
    const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(publicKeyBase64, "base64")]);
    const reconstructed = createPublicKey({ key: spki, format: "der", type: "spki" });
    assert.ok(verify(null, Buffer.from("ammunity"), reconstructed, sig), "sig verifies under a public key rebuilt from the raw 32 bytes");
    pass("extract: raw key round-trips (sign with private, verify with rebuilt public)");
  }

  // ── loadOrCreateKeypair: creates on first run, chmod 600 ───────────────────
  {
    const home = freshHome();
    try {
      const r = loadOrCreateKeypair(home, {});
      assert.ok(r.created && !r.reused && !r.rotated, "first run creates a new key");
      assert.ok(existsSync(keyPath(home)), "agent.key written to the home");
      assert.equal(Buffer.from(r.publicKeyBase64, "base64").length, 32, "returned public key is 32 raw bytes");
      if (process.platform !== "win32") {
        const mode = statSync(keyPath(home)).mode & 0o777;
        assert.equal(mode, 0o600, "agent.key is chmod 600");
      }
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
    pass("store: first run creates agent.key (chmod 600) with a 32-byte public key");
  }

  // ── idempotency: a second run REUSES the same key ──────────────────────────
  {
    const home = freshHome();
    try {
      const first = loadOrCreateKeypair(home, {});
      const pemAfterFirst = readFileSync(keyPath(home), "utf8");
      const second = loadOrCreateKeypair(home, {});
      assert.ok(second.reused && !second.created, "second run reuses");
      assert.equal(second.publicKeyBase64, first.publicKeyBase64, "same public key across runs");
      assert.equal(readFileSync(keyPath(home), "utf8"), pemAfterFirst, "private key file unchanged on reuse");
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
    pass("idempotent: re-running reuses the existing keypair (no churn)");
  }

  // ── rotation: --rotate-key generates a FRESH key ───────────────────────────
  {
    const home = freshHome();
    try {
      const first = loadOrCreateKeypair(home, {});
      const rotated = loadOrCreateKeypair(home, { rotate: true });
      assert.ok(rotated.rotated && rotated.created, "rotate flag regenerates");
      assert.notEqual(rotated.publicKeyBase64, first.publicKeyBase64, "rotation yields a different key");
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
    pass("rotate: --rotate-key generates a fresh, different keypair");
  }

  // ── corruption: an unreadable agent.key is regenerated ─────────────────────
  {
    const home = freshHome();
    try {
      writeFileSync(keyPath(home), "not a real pem\n");
      const r = loadOrCreateKeypair(home, {});
      assert.ok(r.created && !r.reused, "corrupt key is regenerated, not reused");
      assert.equal(Buffer.from(r.publicKeyBase64, "base64").length, 32, "regenerated key is valid 32-byte");
      assert.ok(existsSync(keyPath(home)), "a valid key now exists");
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
    pass("recover: a corrupt agent.key is regenerated");
  }

  // ── upload payload shape (the locked SYNC-2 body) ──────────────────────────
  {
    const body = buildPublicKeyBody("QUJD");
    assert.deepEqual(body, { public_key: "QUJD", algorithm: "ed25519" }, "body is {public_key, algorithm:'ed25519'}");
    pass("payload: upload body matches the locked spec");
  }

  // ── upload wiring: method / URL / headers / body (injected fetch stub) ─────
  {
    const calls = [];
    const stub = async (url, opts) => {
      calls.push({ url, opts });
      return { ok: true, status: 200, text: async () => "" };
    };
    const res = await uploadPublicKey(
      {
        coordinatorUrl: "https://coord.example/", // trailing slash must be trimmed
        agentId: "abc-123",
        agentKey: "ammu_testkey",
        publicKeyBase64: "QUJD",
      },
      () => {},
      stub
    );
    assert.ok(res.ok && res.status === 200, "returns ok on 2xx");
    assert.equal(calls.length, 1, "one request");
    const { url, opts } = calls[0];
    assert.equal(url, "https://coord.example/agents/abc-123/public-key", "URL is trimmed + correctly composed");
    assert.equal(opts.method, "POST", "POST");
    assert.equal(opts.headers["X-Agent-Key"], "ammu_testkey", "authed with the agent key header");
    assert.equal(opts.headers["Content-Type"], "application/json", "JSON content-type");
    assert.deepEqual(JSON.parse(opts.body), { public_key: "QUJD", algorithm: "ed25519" }, "body is the locked payload");
    pass("upload: POSTs the right URL, X-Agent-Key auth, and payload");
  }

  // ── upload is graceful: non-2xx and network errors never throw ─────────────
  {
    const bad = await uploadPublicKey(
      { coordinatorUrl: "https://coord.example", agentId: "x", agentKey: "k", publicKeyBase64: "QUJD" },
      () => {},
      async () => ({ ok: false, status: 401, text: async () => "unauthorized" })
    );
    assert.ok(!bad.ok && bad.status === 401, "non-2xx returns {ok:false} without throwing");

    const errored = await uploadPublicKey(
      { coordinatorUrl: "https://coord.example", agentId: "x", agentKey: "k", publicKeyBase64: "QUJD" },
      () => {},
      async () => {
        throw new Error("ECONNREFUSED");
      }
    );
    assert.ok(!errored.ok && errored.error, "network error returns {ok:false, error} without throwing");
    pass("graceful: upload failures never throw (install continues)");
  }

  // ── ensureAndUploadKey: end-to-end orchestration (stubbed fetch via global) ─
  {
    const home = freshHome();
    const origFetch = globalThis.fetch;
    let seen = null;
    globalThis.fetch = async (url, opts) => {
      seen = { url, body: JSON.parse(opts.body) };
      return { ok: true, status: 200, text: async () => "" };
    };
    try {
      const { key, upload } = await ensureAndUploadKey({
        home,
        coordinatorUrl: "https://coord.example",
        agentId: "agent-9",
        agentKey: "ammu_k",
      });
      assert.ok(key.created, "keypair created");
      assert.ok(upload.ok, "upload succeeded");
      assert.equal(seen.url, "https://coord.example/agents/agent-9/public-key", "posted to the right endpoint");
      assert.equal(seen.body.algorithm, "ed25519", "algorithm sent");
      assert.equal(Buffer.from(seen.body.public_key, "base64").length, 32, "uploaded public key is 32 raw bytes");
    } finally {
      globalThis.fetch = origFetch;
      rmSync(home, { recursive: true, force: true });
    }
    pass("ensureAndUploadKey: generates then uploads the public key end-to-end");
  }

  console.log(`\n${passed} passed`);
})();
