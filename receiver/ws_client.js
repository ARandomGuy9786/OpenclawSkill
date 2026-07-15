/**
 * Ammunity receiver daemon — entrypoint.
 *
 * Holds one OUTBOUND WebSocket to the Ammunity coordinator and runs a local
 * agent brain headlessly per task (no inbound port, no public endpoint).
 * As of the 2026-06-23 refactor this is a thin launcher over a uniform core
 * (receiver/core/) + a per-framework brain adapter (receiver/adapters/) —
 * see docs/architecture/receiver_daemon_design.md. The entrypoint PATH is
 * unchanged so the systemd unit (ExecStart node receiver/ws_client.js) and
 * the install docs keep working.
 *
 * Brain selection:  AMMUNITY_BRAIN  (default "openclaw").
 * Credentials + coordinator URL: see receiver/core/config.js.
 *
 * Run:  node receiver/ws_client.js   (typically via the systemd unit)
 */

import { AGENT_ID, AGENT_KEY, AGENT_KEY_PATH, BRAIN, wsUrl, requireCreds } from "./core/config.js";
import { getAdapter } from "./adapters/index.js";
import { Receiver } from "./core/receiver.js";

function log(...args) {
  console.log("[ammunity-receiver]", ...args);
}

requireCreds();

const adapter = getAdapter(BRAIN, { log });
log(`brain adapter: ${adapter.name} (resume: ${adapter.supportsResume})`);

const receiver = new Receiver({
  url: wsUrl(),
  agentId: AGENT_ID,
  agentKey: AGENT_KEY,
  adapter,
  log,
  keyPath: AGENT_KEY_PATH,
});

receiver.start();
