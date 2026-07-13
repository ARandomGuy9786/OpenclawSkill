#!/bin/sh
# Ammunity connector — one-line install wrapper (Unix / macOS).  Piece F.
#
# Usage:
#   curl -fsSL https://<host>/install | sh
#   curl -fsSL https://<host>/install | sh -s -- --role receive --brain claude
#
# What it does: ensures Node >= 18 is present, then runs the real installer via
# `npx`. This script contains NO secrets — the installer prompts for the agent
# key (hidden, over the terminal). Design: agent_install.md §6.1 piece F.
#
# Security note (§6.2): a piped `curl | sh` inherently trusts this host. It is
# served HTTPS-only and pulls the connector from GitHub over HTTPS; hardening
# (a pinned tag + npm provenance once @ammunity/connector is published) is the
# follow-on. Nothing here writes outside what `npx` + the installer do.

set -e

# Published package on npm. (Pre-publish fallback: the GitHub source
# `github:ARandomGuy9786/ammunity-connector` runs the same installer.)
REPO="@ammunity/connector"
MIN_NODE=18

info() { printf '  %s\n' "$*"; }
die()  { printf 'Error: %s\n' "$*" >&2; exit 1; }

# 1. Node present?
command -v node >/dev/null 2>&1 || {
  printf 'Error: Node.js is required but was not found.\n' >&2
  info "Install Node ${MIN_NODE}+ (https://nodejs.org, your package manager, or nvm), then re-run:"
  info "  curl -fsSL <this-url> | sh"
  exit 1
}

# 2. Node new enough? (global fetch / stable ESM need >= 18)
NODE_MAJOR=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)
[ "$NODE_MAJOR" -ge "$MIN_NODE" ] || die "Node $(node -v) is too old — Ammunity needs Node ${MIN_NODE}+. Upgrade, then re-run."

# 3. npx present? (ships with npm)
command -v npx >/dev/null 2>&1 || die "npx not found (it ships with npm). Install npm, then re-run."

info "Launching the Ammunity connector installer…"
echo

# Run the installer, forwarding any args (from `sh -s -- …`). The installer
# needs an interactive terminal for its hidden key prompt, but when this script
# arrives via `curl | sh` our stdin is the pipe, not the tty. So:
#   - stdin already a terminal (script downloaded + run directly) → use it as-is
#   - stdin is a pipe but a controlling terminal exists          → borrow /dev/tty
#   - no controlling terminal (CI)                               → inherit the pipe
#     (the installer's non-TTY path reads the key from env/stdin)
# The `(: < /dev/tty)` probe opens the tty in a SUBSHELL so a failure can't kill
# this script (an `exec`-based probe would abort a non-interactive shell).
if [ -t 0 ]; then
  npx -y "$REPO" "$@"
elif (: < /dev/tty) 2>/dev/null; then
  npx -y "$REPO" "$@" < /dev/tty
else
  npx -y "$REPO" "$@"
fi
