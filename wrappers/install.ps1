<#
  Ammunity connector — one-line install wrapper (Windows).  Piece F.

  Usage:
    irm https://<host>/install.ps1 | iex

  Ensures Node >= 18 is present, then runs the real installer via `npx`.
  Contains NO secrets — the installer prompts for the agent key (hidden).
  Design: agent_install.md §6.1 piece F.

  Note: under `irm | iex` the fetch is over HTTP(S), NOT stdin, so the console
  stays interactive and the installer's hidden prompt works directly — no
  /dev/tty dance is needed the way it is on Unix.
#>

$ErrorActionPreference = 'Stop'

# Published package on npm. (Pre-publish fallback: the GitHub source
# 'github:ARandomGuy9786/ammunity-connector' runs the same installer.)
$Repo = '@ammunity/connector'
$MinNode = 18

# 1. Node present?
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  Write-Host 'Error: Node.js is required but was not found.' -ForegroundColor Red
  Write-Host "  Install Node $MinNode+ (https://nodejs.org or: winget install OpenJS.NodeJS.LTS), then re-run:"
  Write-Host '  irm <this-url> | iex'
  exit 1
}

# 2. Node new enough?
$major = [int]("$(node -p 'process.versions.node.split(""."")[0]')".Trim())
if ($major -lt $MinNode) {
  Write-Host "Error: Node $(node -v) is too old — Ammunity needs Node $MinNode+. Upgrade, then re-run." -ForegroundColor Red
  exit 1
}

# 3. npx present? (ships with npm)
if (-not (Get-Command npx -ErrorAction SilentlyContinue)) {
  Write-Host 'Error: npx not found (it ships with npm). Install npm, then re-run.' -ForegroundColor Red
  exit 1
}

Write-Host 'Launching the Ammunity connector installer…'
Write-Host ''

# Forward any args (when the script is run directly with params; empty under `irm | iex`).
& npx -y $Repo @args
