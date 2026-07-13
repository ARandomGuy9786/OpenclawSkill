#!/usr/bin/env node
/**
 * Ammunity connector installer — `npx @ammunity/connector` (or the GitHub
 * source `npx github:ARandomGuy9786/ammunity-connector` as a fallback).
 *
 * One interactive installer, branches on role (send / receive / both):
 *   - receive: places the uniform receiver daemon in a stable home, installs
 *     deps, writes an isolated .env (chmod 600), then GENERATES + installs +
 *     starts a per-OS service (systemd --user on Linux, a launchd LaunchAgent
 *     on macOS) so it survives reboots. Falls back to printing the manual run
 *     command if the service can't be installed (unsupported OS, no
 *     systemd/launchctl, etc).
 *   - send: prints the MCP-add snippet (full multi-platform issuer = the
 *     dashboard Connect panel / piece E).
 *
 * Security posture (design §6.2): interactive HIDDEN credential entry — no
 * secret in the URL, the command, or shell history. Service files are GENERATED
 * per-host, never shipped (the 2026-06-29 leak). This is piece A+B+C+D of
 * agent_install.md §6.1.
 */

import { existsSync, mkdirSync, rmSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { ask, askHidden, askSelect, confirm, readStdinLine } from "../installer/prompts.js";
import { preflight, hasClaudeLogin } from "../installer/system.js";
import { defaultHome, placeRuntime, installDeps, writeEnv } from "../installer/runtime.js";
import { installService, uninstallService } from "../installer/service.js";
import { ensureAndUploadKey } from "../installer/keygen.js";

// Single source of truth: read the version from package.json so the CLI's
// --version can never drift from the published package version.
const VERSION = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../package.json"), "utf8")
).version;
const COORDINATOR_DEFAULT = "https://ammunity-coordinator-production.up.railway.app";
// The hosted MCP send endpoint — the trailing slash is MANDATORY (no-slash
// 307-redirects to plaintext http:// and can drop the auth header).
const MCP_URL = `${COORDINATOR_DEFAULT}/mcp/`;

// ── tiny arg parser ────────────────────────────────────────────────────────
function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq !== -1) {
        out[a.slice(2, eq)] = a.slice(eq + 1);
      } else {
        const key = a.slice(2);
        const next = argv[i + 1];
        if (next && !next.startsWith("-")) {
          out[key] = next;
          i++;
        } else {
          out[key] = true;
        }
      }
    } else if (a === "-y") out["non-interactive"] = true;
    else if (a === "-h") out.help = true;
    else if (a === "-v") out.version = true;
    else out._.push(a);
  }
  return out;
}

const log = (...a) => console.log("›", ...a);
const ok = (...a) => console.log("✓", ...a);
const warn = (...a) => console.log("⚠", ...a);

function printHelp() {
  console.log(`
Ammunity connector installer (v${VERSION})

Usage:
  npx @ammunity/connector                interactive (recommended)
  npx github:ARandomGuy9786/ammunity-connector    (GitHub source fallback)

Options:
  --role <send|receive|both>     what this host does
  --brain <openclaw|claude>      (receive) which agent brain runs tasks
  --agent-id <uuid>              the agent's Ammunity ID
  --coordinator-url <url>        override the coordinator (default: production)
  --claude-auth <login|apikey>   (claude brain) auth mode
  --home <dir>                   install home (default: ~/.ammunity/connector)
  --start                        (receive) run the daemon in the foreground after install
  --skip-deps                    don't run npm install
  --rotate-key                   generate a FRESH agent keypair (default: reuse the existing one)
  --no-service                   (receive) don't install a systemd/launchd service
  --non-interactive, -y          don't prompt; take values from flags/env
  --uninstall                    remove the install home (and its service, if any)
  --help, -h                     this help
  --version, -v                  print version

Credentials are entered HIDDEN at a prompt (never on the command line). For
automation, pass the key via the AMMUNITY_AGENT_KEY env var or on stdin.
`);
}

async function getRole(args, interactive) {
  if (args.role) return String(args.role).toLowerCase();
  if (!interactive) return "receive";
  return askSelect(
    "What should this host do?",
    [
      { value: "receive", label: "receive — do work for the network (runs a daemon)" },
      { value: "send", label: "send — delegate tasks out (MCP, no daemon)" },
      { value: "both", label: "both" },
    ],
    "receive"
  );
}

async function getBrain(args, interactive) {
  if (args.brain) return String(args.brain).toLowerCase();
  if (!interactive) return "openclaw";
  return askSelect(
    "Which agent brain runs received tasks?",
    [
      { value: "openclaw", label: "OpenClaw" },
      { value: "claude", label: "Claude Code" },
      { value: "codex", label: "Codex", disabled: true, note: "adapter lands later" },
    ],
    "openclaw"
  );
}

async function getKey(args, interactive) {
  if (process.env.AMMUNITY_AGENT_KEY) return process.env.AMMUNITY_AGENT_KEY.trim();
  if (!interactive) return (await readStdinLine()).trim();
  return askHidden("API key (hidden — starts with ammu_)");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) return printHelp();
  if (args.version) return console.log(VERSION);

  const interactive = !args["non-interactive"];
  const home = args.home ? String(args.home) : defaultHome();

  console.log(`\n  Ammunity connector installer  ·  v${VERSION}\n`);

  if (args.uninstall) {
    if (interactive && existsSync(home) && !(await confirm(`Remove the install home ${home} (and its service, if any)?`, false)))
      return log("cancelled.");
    // Stop + remove the service BEFORE deleting its files, so the service
    // manager doesn't keep trying to restart a daemon whose code is gone.
    uninstallService(log);
    if (existsSync(home)) {
      rmSync(home, { recursive: true, force: true });
      ok(`removed ${home}.`);
    } else {
      ok(`nothing to remove (${home} doesn't exist).`);
    }
    return;
  }

  // ── collect answers ────────────────────────────────────────────────────
  const role = await getRole(args, interactive);
  if (!["send", "receive", "both"].includes(role)) {
    console.error(`Invalid --role "${role}". Use send | receive | both.`);
    process.exit(1);
  }
  const brain = role === "send" ? null : await getBrain(args, interactive);
  if (brain && !["openclaw", "claude"].includes(brain)) {
    console.error(`Invalid --brain "${brain}". v1 supports openclaw | claude (codex later).`);
    process.exit(1);
  }

  // Preflight (after role/brain so we can check the right brain binary).
  const pre = preflight({ role, brain });
  log(`detected ${pre.os.label} (service manager: ${pre.os.service})`);
  for (const w of pre.warnings) warn(w);
  if (!pre.ok) {
    for (const e of pre.errors) console.error("✗", e);
    process.exit(1);
  }

  const agentId = args["agent-id"] ? String(args["agent-id"]) : interactive ? await ask("Agent ID (UUID)") : "";
  if (!agentId) {
    console.error("✗ Agent ID is required (register the agent on the dashboard first).");
    process.exit(1);
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(agentId)) {
    warn(`"${agentId}" doesn't look like a UUID — continuing, but double-check it.`);
  }

  const agentKey = await getKey(args, interactive);
  if (!agentKey) {
    console.error("✗ API key is required (generate one on the agent's manage page).");
    process.exit(1);
  }
  if (!agentKey.startsWith("ammu_")) warn("the key doesn't start with `ammu_` — double-check you copied the agent key.");

  const coordinatorUrl =
    args["coordinator-url"] && String(args["coordinator-url"]) !== COORDINATOR_DEFAULT
      ? String(args["coordinator-url"])
      : null;

  // Claude auth (receive + claude brain only).
  let claudeAuth = null;
  let claudeApiKey = null;
  if ((role === "receive" || role === "both") && brain === "claude") {
    claudeAuth = args["claude-auth"]
      ? String(args["claude-auth"]).toLowerCase()
      : interactive
        ? await askSelect(
            "How should the Claude receiver authenticate?",
            [
              {
                value: "login",
                label: hasClaudeLogin() ? "use my existing ~/.claude login (free)" : "use my ~/.claude login (none found yet)",
              },
              { value: "apikey", label: "isolated home + Anthropic API key (per-token billing)" },
            ],
            "login"
          )
        : "login";
    if (claudeAuth === "apikey") {
      claudeApiKey =
        process.env.AMMUNITY_CLAUDE_API_KEY ||
        process.env.ANTHROPIC_API_KEY ||
        (interactive ? await askHidden("Anthropic API key (hidden — starts with sk-ant-)") : "");
      if (!claudeApiKey) warn("no Anthropic API key provided — set ANTHROPIC_API_KEY before starting, or the receiver will report 'Not logged in'.");
    }
  }

  // Idempotent re-run guard.
  if (existsSync(join(home, ".env")) && interactive) {
    if (!(await confirm(`An install already exists at ${home}. Reconfigure it?`, true))) return log("cancelled — existing install untouched.");
  }

  const answers = { role, brain, agentId, agentKey, coordinatorUrl, brainBin: pre.brainBin, claudeAuth, claudeApiKey };

  // ── do the work ─────────────────────────────────────────────────────────
  console.log("");
  let placedHome = home;
  if (role === "receive" || role === "both") {
    const placed = placeRuntime(home, log);
    placedHome = placed.home;
    if (!args["skip-deps"]) installDeps(placedHome, log);
    else log("skipping npm install (--skip-deps)");
    writeEnv(placedHome, answers, log);
  } else {
    // send-only: still write the .env into the home so the key has one home,
    // but the daemon isn't placed (send uses MCP, not the daemon).
    mkdirSync(home, { recursive: true });
    writeEnv(home, answers, log);
  }

  // ── keypair (Phase 2.1) ──────────────────────────────────────────────────
  // The connector owns all crypto: generate (or reuse) an Ed25519 keypair in
  // the install home, then upload ONLY the public key. The private key
  // (agent.key, chmod 600) never leaves the host and is never logged. Reuses
  // an existing key unless --rotate-key is passed; a corrupt key regenerates.
  // Non-fatal: an upload failure warns but doesn't block the install.
  await ensureAndUploadKey(
    {
      home: placedHome,
      coordinatorUrl: coordinatorUrl || COORDINATOR_DEFAULT,
      agentId,
      agentKey,
      rotate: Boolean(args["rotate-key"]),
    },
    (m) => log(m)
  );

  // ── report + next steps ───────────────────────────────────────────────
  console.log("");
  ok("install complete.\n");

  if (role === "send" || role === "both") {
    console.log("SEND — sending is a one-line MCP setup specific to your agent host (this installer");
    console.log("is for the RECEIVE daemon; sending needs no daemon). For Claude Code:\n");
    console.log(`  claude mcp add --transport http ammunity \\`);
    console.log(`    ${MCP_URL} \\`);
    console.log(`    --header "Authorization: Bearer <YOUR_AMMUNITY_KEY>"\n`);
    console.log(`  Your key is saved in ${join(home, ".env")} (AMMUNITY_AGENT_KEY) — paste it in place of`);
    console.log("  <YOUR_AMMUNITY_KEY>. For the exact, key-filled command for your host (Claude Code,");
    console.log("  Codex, Cursor, or OpenClaw), open your agent's page on the Ammunity dashboard.\n");
  }

  if (role === "receive" || role === "both") {
    // --start: explicit foreground run (for watching/testing). Skips the
    // service — a background service AND a foreground copy would be two
    // daemons connecting on the same agent key.
    if (args.start) {
      log("starting the receiver in the foreground (Ctrl-C to stop)…\n");
      const child = spawn("node", ["receiver/ws_client.js"], { cwd: placedHome, stdio: "inherit" });
      child.on("exit", (code) => process.exit(code ?? 0));
      return; // hand the process over to the daemon
    }

    // Default: GENERATE + install + start a per-OS service so the receiver
    // survives reboots. --no-service opts out and prints the manual command.
    let serviced = false;
    if (!args["no-service"]) {
      const svc = installService(placedHome, log);
      if (svc === null) {
        warn(`no service manager for ${pre.os.label} yet (Windows service is a fast-follow) — run it manually below.`);
      } else if (svc.ok) {
        ok(`service installed and started (${svc.detail}) — it will restart on boot.`);
        serviced = true;
      } else if (svc.installed) {
        warn(`service was generated but isn't active yet (${svc.detail}). Check it, or run it manually below.`);
      } else {
        warn(`couldn't install a service (${svc.detail}) — run it manually below.`);
      }
    }

    console.log("");
    console.log(`RECEIVE — the daemon is installed at ${placedHome}.\n`);
    if (serviced) {
      const logsHint =
        process.platform === "darwin"
          ? `tail -f ${join(placedHome, "logs", "receiver.log")}`
          : `journalctl --user -u ammunity-receiver -f`;
      console.log("It's running now as a background service. Follow its logs with:\n");
      console.log(`  ${logsHint}\n`);
    } else {
      console.log("Run it in the foreground with:\n");
      console.log(`  cd ${placedHome} && node receiver/ws_client.js\n`);
      console.log("  (or re-run this installer with --start to launch it in the foreground.)\n");
    }
  }
}

main().catch((e) => {
  console.error("\n✗ installer error:", e && e.message ? e.message : e);
  process.exit(1);
});
