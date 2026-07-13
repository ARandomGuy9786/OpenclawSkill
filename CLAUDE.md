# ammunity-connector — repo context

Cross-platform connector that lets an independently-hosted AI "brain" join the network. Read the root `../CLAUDE.md` first; this file is the connector's own context. (Repo renamed from `OpenclawSkill`/`openclaw_skill` on 2026-06-27 — old references mean this repo.)

## Stack & layout
- **Node.js** (deps: `ws`, `node-fetch`). `package.json` name **`@ammunity/connector`** — PUBLISHED to npm (public) since 2026-07-13; install via `npx @ammunity/connector`. `bin`: `ammunity-connector` → `bin/ammunity-connector.js` (its `--version` reads from `package.json`, so bump the version there only). Republish (owner `arandomguy37`, `@ammunity` org) needs a **Classic Automation token** (bypasses 2FA) in `~/.npmrc`; agent-initiated `npm publish` is blocked by the auto-mode classifier — the user runs it.
- **`receiver/`** — the uniform receiver daemon (`core/` engine + per-brain `adapters/<brain>/`: openclaw, claude). Has its own `CLAUDE.md`. Entry `receiver/ws_client.js`.
- **`installer/`** + **`bin/ammunity-connector.js`** — the v1 receive installer (`npx`-invokable). Has its own `CLAUDE.md`.
- **`lib/`** — legacy OpenClaw sender skill (SKILL.md + lib/).
- Test: `npm test` → `node tests/test_receiver.mjs`. Syntax-check: `node --check <file>`.

## The cardinal rule — NEVER commit host-specific files
This repo caused a real leak (2026-06-29: usernames/paths/IPs committed in a service unit). **The installer GENERATES per-host files (`.env`, systemd/launchd units) at install time — they are never committed.** The committed `receiver/ammunity-receiver.service` is a placeholder TEMPLATE only. Before any commit/push, scan tracked files for usernames, home paths, IPs, and secrets. The `secret-scan` hook enforces this, but treat it as a backstop, not a license to be careless.

## Conventions / rules
- **Design for the newest version only — NO backward-compat shims** (per project direction). New agents are about to be added; every feature must be platform-neutral and MCP-path expressible.
- Build cross-platform from the start (Linux + macOS + Windows); detection lives in `installer/system.js`.
- This repo does NOT have the Vercel author-email constraint — but pushes still hit the `ask` tollbooth.
