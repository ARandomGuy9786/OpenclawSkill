/**
 * Receiver daemon — configuration & credentials (framework-agnostic core).
 *
 * Credentials come from the repo-root .env (shared with the sender skill):
 *   AMMUNITY_AGENT_ID, AMMUNITY_AGENT_KEY        (required)
 *   AMMUNITY_COORDINATOR_URL                     (optional, defaults to prod)
 *   AMMUNITY_BRAIN   (optional, default "openclaw"; selects the brain adapter)
 *
 * Per-adapter env (e.g. OPENCLAW_BIN / OPENCLAW_AGENT) lives with its adapter.
 */

import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadDotEnvIfPresent } from "../../lib/loadEnv.js";

loadDotEnvIfPresent();

export const COORDINATOR_URL =
  process.env.AMMUNITY_COORDINATOR_URL ||
  "https://ammunity-coordinator-production.up.railway.app";
export const AGENT_ID = process.env.AMMUNITY_AGENT_ID;
export const AGENT_KEY = process.env.AMMUNITY_AGENT_KEY;
export const BRAIN = process.env.AMMUNITY_BRAIN || "openclaw";

// The connector's runtime home = the repo/install root (where `.env` and the
// Ed25519 `agent.key` both live) = two levels up from receiver/core/. This is
// exactly where the installer places them (installer/runtime.js `defaultHome`
// + installer/keygen.js `keyPath`), so it resolves right whether the daemon
// runs from a checkout or the placed `~/.ammunity/connector` home.
export function connectorHome() {
  return resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
}

// Where the Ed25519 private key is loaded from for Tier-2 session signing.
// Overridable via AMMUNITY_AGENT_KEY_PATH; defaults to <connector home>/agent.key
// (consistent with installer/keygen.js's placement). Sessions are disabled when
// this file doesn't exist (Tier-1 is unaffected).
export const AGENT_KEY_PATH =
  process.env.AMMUNITY_AGENT_KEY_PATH || join(connectorHome(), "agent.key");

// Derive ws(s):// from the coordinator's http(s):// base URL.
export function wsUrl() {
  const base = COORDINATOR_URL.replace(/^http/, "ws").replace(/\/+$/, "");
  return `${base}/ws/agent`;
}

export function requireCreds() {
  const missing = [];
  if (!AGENT_ID) missing.push("AMMUNITY_AGENT_ID");
  if (!AGENT_KEY) missing.push("AMMUNITY_AGENT_KEY");
  if (missing.length) {
    console.error(
      `[ammunity-receiver] Missing required env var(s): ${missing.join(", ")}. ` +
        `Set them in the repo-root .env (see .env.example).`
    );
    process.exit(1);
  }
}
