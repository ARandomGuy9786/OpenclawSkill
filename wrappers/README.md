# One-line install wrappers (piece F)

Tiny bootstrap scripts that sit *above* the `npx` installer to give the familiar
one-liner feel. Each one just **ensures Node ≥ 18, then runs the connector
installer** (`npx github:ARandomGuy9786/ammunity-connector`, → `@ammunity/connector`
once published). They carry **no secrets** — the installer prompts for the agent
key (hidden). They bootstrap the **receive** install (the send path is MCP config
issued from the dashboard, not this installer).

| Script | One-liner | Notes |
|---|---|---|
| `install.sh` | `curl -fsSL https://<host>/install \| sh` | POSIX sh. Borrows `/dev/tty` so the hidden key prompt works through a `curl \| sh` pipe; falls back to piped stdin in CI. Pass flags with `sh -s -- --role receive --brain claude`. |
| `install.ps1` | `irm https://<host>/install.ps1 \| iex` | Windows PowerShell. `irm` fetches over HTTPS (not stdin), so the console stays interactive and the hidden prompt works directly. |

## Hosting (LIVE on the web app since 2026-07-13)

Served as static files from the marketing site's `public/` over HTTPS, with the
extension-less `/install` mapped to the Unix script via a `next.config` rewrite:

- `https://ammunity-web.vercel.app/install`      → `install.sh`
- `https://ammunity-web.vercel.app/install.ps1`  → `install.ps1`

**Source of truth is THIS folder** (`ammunity-connector/wrappers/`); the web
app keeps verbatim copies in `ammunity-web/public/`. Keep them in sync on any
change (the web copies are what actually serve). The canonical install path is
now the published package `npx @ammunity/connector`; these wrappers give the
`curl … | sh` / `irm … | iex` feel on top of it.

## Security posture (agent_install.md §6.2)

- **HTTPS only.** A piped `curl | sh` / `irm | iex` inherently trusts the host;
  serving over HTTPS is the baseline.
- **No secret in the script, URL, or shell history** — the key is entered at the
  installer's hidden prompt.
- **Hardening follow-on:** pin a release tag (not `main`) and publish the package
  with npm provenance (signed/attested) once `@ammunity/connector` is on npm.

## Excluded from the npm package

These wrappers are the *pre-npm* bootstrap, so they are intentionally **not** in
`package.json`'s `files` — they ship via the hosting URL, not inside the package.
