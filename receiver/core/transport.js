/**
 * Receiver daemon — transport (framework-agnostic core).
 *
 * Holds one OUTBOUND WebSocket to the Ammunity coordinator `/ws/agent` (no
 * inbound port, no public endpoint), authenticated by `X-Agent-Key`. Owns
 * connect / reconnect / heartbeat / liveness-watchdog. Parses inbound frames
 * and forwards them to `onMessage`; exposes `send()` for outbound frames.
 *
 * The reconnect/heartbeat logic is the proven fix for the 2026-06-08 ~21h
 * silent-outage bug (handshake timeout + idempotent reconnect on error+close
 * + ping/pong watchdog). The coordinator-side `1006` churn is a separate
 * open issue (see flags.md).
 */

import WebSocket from "ws";

const HEARTBEAT_MS = 20_000;
const RECONNECT_BASE_MS = 1_000;
const RECONNECT_MAX_MS = 30_000;
// Cap how long a single connection attempt may sit in the handshake. Without
// this, a connect that stalls (e.g. coordinator mid-redeploy) emits NO event
// at all and the client hangs forever — the exact bug that left the receiver
// dead for ~21h. With it, `ws` emits 'error' (+ 'close') after the timeout so
// the reconnect loop can proceed.
const HANDSHAKE_TIMEOUT_MS = 15_000;

// Capabilities advertised in the `hello` frame (SYNC-3 §10). This is the
// capability-negotiation seam: the coordinator fails a session request fast
// (`responder_no_session_support`) against a connector that doesn't advertise
// "sessions". Additive under envelope v1 — no back-compat shim beyond this.
const HELLO_FEATURES = ["sessions"];

export class Transport {
  constructor({ url, agentId, agentKey, onMessage, log }) {
    this.url = url;
    this.agentId = agentId;
    this.agentKey = agentKey;
    this.onMessage = onMessage;
    this.log = log || (() => {});

    this.ws = null;
    this.heartbeat = null;
    this.reconnectDelay = RECONNECT_BASE_MS;
    this.reconnectTimer = null;
    // Liveness flag for the WS-level ping/pong watchdog. Set true on every pong;
    // the heartbeat tick clears it before pinging, so a missed pong is detectable.
    this.isAlive = true;
  }

  start() {
    this.connect();
  }

  send(obj) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(obj));
    }
  }

  clearHeartbeat() {
    if (this.heartbeat) {
      clearInterval(this.heartbeat);
      this.heartbeat = null;
    }
  }

  // App-level heartbeat (keeps the coordinator's last_seen_at fresh) PLUS a
  // WS-level ping/pong liveness check. If a pong doesn't come back within one
  // interval, the socket is half-open/dead — terminate it to force a reconnect
  // (a half-open socket otherwise looks "connected" forever).
  startHeartbeat() {
    this.clearHeartbeat();
    this.isAlive = true;
    this.heartbeat = setInterval(() => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
      if (!this.isAlive) {
        this.log("no pong within heartbeat interval; terminating to force reconnect");
        try {
          this.ws.terminate();
        } catch {
          // ignore — 'close' will fire and trigger the reconnect
        }
        return;
      }
      this.isAlive = false;
      try {
        this.ws.ping();
      } catch {
        // ignore
      }
      this.send({ type: "heartbeat" });
    }, HEARTBEAT_MS);
  }

  // Schedule a single reconnect with exponential backoff. Idempotent — safe to
  // call from both 'error' and 'close' (and the watchdog); only one reconnect is
  // ever pending. This is the core fix: a connect attempt that fails BEFORE
  // 'open' (handshake timeout, refused, coordinator mid-redeploy) emits 'error'
  // but may NOT emit 'close', so relying on 'close' alone left the client stuck.
  scheduleReconnect(reason) {
    this.clearHeartbeat();
    if (this.reconnectTimer) return; // a reconnect is already pending
    const delay = this.reconnectDelay;
    this.log(`reconnecting in ${delay}ms (${reason})`);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
    this.reconnectDelay = Math.min(this.reconnectDelay * 2, RECONNECT_MAX_MS);
  }

  connect() {
    this.log(`connecting to ${this.url} as agent ${this.agentId}`);
    this.ws = new WebSocket(this.url, {
      headers: { "X-Agent-Key": this.agentKey },
      handshakeTimeout: HANDSHAKE_TIMEOUT_MS,
    });

    this.ws.on("open", () => {
      this.log("connected");
      this.reconnectDelay = RECONNECT_BASE_MS;
      this.send({ type: "hello", agent_id: this.agentId, features: HELLO_FEATURES });
      this.startHeartbeat();
    });

    // Coordinator (or the ws lib auto-pong) replies to our ping → connection live.
    this.ws.on("pong", () => {
      this.isAlive = true;
    });

    this.ws.on("message", (raw) => {
      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        return;
      }
      this.onMessage(msg);
    });

    // Server rejected the upgrade (closed before accept) — almost always a
    // config error. Auth/mode failures are fatal; anything else falls through to
    // 'error'/'close' and reconnects (e.g. a transient 5xx during a redeploy).
    this.ws.on("unexpected-response", (_req, res) => {
      console.error(
        `[ammunity-receiver] handshake rejected: HTTP ${res.statusCode}. ` +
          `Check AMMUNITY_AGENT_KEY, that the agent is approved, and that its delivery_mode is 'ws'.`
      );
      if (res.statusCode === 401 || res.statusCode === 403) {
        process.exit(1);
      }
    });

    this.ws.on("close", (code) => {
      // Custom application close codes for auth/mode failures — fatal, don't retry.
      if (code === 4401 || code === 4403) {
        console.error(
          `[ammunity-receiver] coordinator closed the connection (code ${code}): ` +
            `auth or delivery_mode problem. Fix the .env / agent record and restart.`
        );
        process.exit(1);
      }
      this.log(`disconnected (code ${code})`);
      this.scheduleReconnect(`closed code ${code}`);
    });

    this.ws.on("error", (e) => {
      // A connect-time error (handshake timeout, refused, coordinator
      // mid-redeploy) may NOT be followed by 'close', so reconnect from here too.
      // scheduleReconnect is idempotent, so a later 'close' won't double-schedule.
      console.error(`[ammunity-receiver] socket error: ${e.message}`);
      this.scheduleReconnect(`error ${e.message}`);
    });
  }
}
