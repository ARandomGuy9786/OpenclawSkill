/**
 * Ammunity connector — Tier-2 initiator trigger (SYNC-3 §3.1, §10).
 *
 * Usage:  node receiver/session_cli.js <responder_agent_id> "<purpose>" [--community <slug>]
 *
 * How a session starts (§10, A-track freedom): this CLI is the human/operator
 * trigger — "go open a session with agent Y about X". It runs as a SEPARATE
 * process from the running receiver daemon, so it cannot register the session in
 * the daemon's memory directly. Instead it:
 *   1. loads the same credentials/config as ws_client.js (agent id + key,
 *      coordinator URL, the Ed25519 private key at AGENT_KEY_PATH),
 *   2. mints nonce_i, builds + signs the `session.request` string (§6),
 *   3. POSTs /sessions (X-Agent-Key) to run the 5-layer establishment gate,
 *   4. on 200, writes a pending-handoff file
 *      <connectorHome()>/sessions/pending/<session_id>.json (chmod 600) — the
 *      IPC the running daemon reads when the coordinator's `session.open`
 *      arrives (SessionEngine.#tryAdoptPending).
 *
 * Lib vs entry are separated (import.meta.url main guard) so the build steps are
 * unit-testable without spawning a process — matching the rest of the repo.
 *
 * Cross-platform: node:fs / node:path / node:url / node:crypto + global fetch.
 * No new dependency; no hardcoded/host-specific values.
 */

import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import {
  AGENT_ID,
  AGENT_KEY,
  AGENT_KEY_PATH,
  COORDINATOR_URL,
  connectorHome,
} from "./core/config.js";
import * as signingModule from "./core/signing.js";
import { pendingDir, pendingFilePath } from "./core/files.js";

const USAGE = 'usage: node receiver/session_cli.js <responder_agent_id> "<purpose>" [--community <slug>]';

// Parse argv (already sliced past node + script). `--community <slug>` is the
// only flag; the two positionals are responder id + purpose.
export function parseArgs(argv = []) {
  const args = [...argv];
  let community;
  const positional = [];
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === "--community") {
      community = args[i + 1];
      i += 1;
      continue;
    }
    positional.push(args[i]);
  }
  return { responderId: positional[0], purpose: positional[1], community };
}

/**
 * Build the signed `POST /sessions` request pieces (pure — no I/O).
 * @param {object} config  { agentId, agentKey, coordinatorUrl, privateKey, signing?, nonce? }
 * @param {object} args    { responderId, purpose, community? }
 * @returns {{ url, headers, body, nonceI }}
 */
export function buildSessionRequest(config = {}, args = {}) {
  const signing = config.signing || signingModule;
  const nonceI = config.nonce || signing.makeNonce();
  const requestString = signing.buildRequestString({
    initiatorId: config.agentId,
    responderId: args.responderId,
    nonceI,
    purpose: args.purpose,
  });
  const sig = signing.signString(config.privateKey, requestString);

  const body = {
    responder_agent_id: args.responderId,
    purpose: args.purpose,
    nonce: nonceI,
    sig,
  };
  if (args.community) body.community_slug = args.community;

  const base = String(config.coordinatorUrl || "").replace(/\/+$/, "");
  return {
    url: `${base}/sessions`,
    headers: { "Content-Type": "application/json", "X-Agent-Key": config.agentKey },
    body,
    nonceI,
  };
}

/**
 * Write the pending-handoff file (chmod 600) the daemon adopts on session.open.
 * Returns the path written.
 */
export function writePendingFile(home, session = {}) {
  mkdirSync(pendingDir(home), { recursive: true });
  const path = pendingFilePath(home, session.session_id);
  const payload = {
    session_id: session.session_id,
    responder_agent_id: session.responder_agent_id,
    purpose: session.purpose,
    nonce_i: session.nonce_i,
    community_slug: session.community_slug,
    created_at: session.created_at || new Date().toISOString(),
  };
  writeFileSync(path, JSON.stringify(payload, null, 2), { mode: 0o600 });
  try {
    chmodSync(path, 0o600); // re-assert (umask can widen the create mode)
  } catch {
    /* best-effort on platforms without POSIX perms (Windows) */
  }
  return path;
}

/**
 * Full CLI flow. Returns a process exit code (0 ok, 1 error, 2 usage).
 * `deps` overrides for tests: { fetch, log, err, agentId, agentKey,
 * coordinatorUrl, keyPath, home, signing }.
 */
export async function runCli(argv = [], deps = {}) {
  const fetchImpl = deps.fetch || ((url, opts) => globalThis.fetch(url, opts));
  const log = deps.log || ((...a) => console.log(...a));
  const err = deps.err || ((...a) => console.error(...a));
  const signing = deps.signing || signingModule;

  const { responderId, purpose, community } = parseArgs(argv);
  if (!responderId || !purpose) {
    err(USAGE);
    return 2;
  }

  const agentId = deps.agentId || AGENT_ID;
  const agentKey = deps.agentKey || AGENT_KEY;
  if (!agentId || !agentKey) {
    err("[ammunity-session] Missing AMMUNITY_AGENT_ID / AMMUNITY_AGENT_KEY (set them in the repo-root .env).");
    return 1;
  }

  let privateKey;
  try {
    privateKey = signing.loadPrivateKey(deps.keyPath || AGENT_KEY_PATH);
  } catch (e) {
    err(`[ammunity-session] ${e && e.message ? e.message : e} (re-run the installer to generate agent.key).`);
    return 1;
  }

  const req = buildSessionRequest(
    {
      agentId,
      agentKey,
      coordinatorUrl: deps.coordinatorUrl || COORDINATOR_URL,
      privateKey,
      signing,
    },
    { responderId, purpose, community }
  );

  let res;
  let data;
  try {
    res = await fetchImpl(req.url, { method: "POST", headers: req.headers, body: JSON.stringify(req.body) });
    data = await res.json().catch(() => ({}));
  } catch (e) {
    err(`[ammunity-session] request failed: ${e && e.message ? e.message : e}`);
    return 1;
  }

  if (!res.ok) {
    // Print the coordinator's rejection detail verbatim (community_required, etc.).
    const detail = data && (data.detail || data.error);
    err(detail ? String(detail) : `HTTP ${res.status}`);
    return 1;
  }

  const home = deps.home || connectorHome();
  const path = writePendingFile(home, {
    session_id: data.session_id,
    responder_agent_id: responderId,
    purpose,
    nonce_i: req.nonceI,
    community_slug: community,
  });

  log(`session ${data.session_id} — status ${data.status || "requested"}`);
  log(`pending handoff written: ${path}`);
  log("the running receiver daemon will pick it up on session.open (after the responder consents).");
  return 0;
}

// ── entry (guarded so importing this file for tests has no side effects) ──────
if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  runCli(process.argv.slice(2)).then((code) => process.exit(code));
}
