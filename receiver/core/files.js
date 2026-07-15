/**
 * Receiver core — Tier-2 session file helpers (SYNC-3 §7, §9).
 *
 * Pure(-ish) helpers that keep sessions.js readable: per-session workdir paths +
 * lazy creation/teardown, a minimal extension→MIME map, byte hashing, the
 * outbound path-traversal guard, inbound filename sanitisation + collision
 * handling, and the initiator pending-handoff paths.
 *
 * The HTTP orchestration (upload/download, signed URLs, error frames) stays in
 * sessions.js where the signing key + transport live; this module is I/O on the
 * local filesystem only. Cross-platform: node:path / node:fs / node:crypto only,
 * no new dependency, no hardcoded paths.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { basename, extname, join, resolve, sep } from "node:path";

// Minimal, sensible extension→MIME map (SYNC-3 §7). Anything else defaults to
// application/octet-stream so an unknown type is still transferable.
const MIME_BY_EXT = {
  ".txt": "text/plain",
  ".md": "text/markdown",
  ".json": "application/json",
  ".js": "text/javascript",
  ".py": "text/x-python",
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".csv": "text/csv",
  ".zip": "application/zip",
};

export function mimeForName(name) {
  return MIME_BY_EXT[extname(String(name || "")).toLowerCase()] || "application/octet-stream";
}

/** Lowercase hex SHA-256 of raw bytes (Buffer/Uint8Array). */
export function sha256HexBytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

// ── per-session workdir paths (SYNC-3 §7 — the isolated workdir) ─────────────

export function sessionWorkdir(home, sessionId) {
  return join(home, "sessions", String(sessionId));
}

export function sessionFilesDir(home, sessionId) {
  return join(sessionWorkdir(home, sessionId), "files");
}

/** Create <home>/sessions/<id>/files/ (recursive, idempotent). Returns paths. */
export function ensureSessionWorkdir(home, sessionId) {
  const workdir = sessionWorkdir(home, sessionId);
  const filesDir = sessionFilesDir(home, sessionId);
  mkdirSync(filesDir, { recursive: true });
  return { workdir, filesDir };
}

/** Best-effort recursive removal of a session's workdir (no-op if absent). */
export function removeSessionWorkdir(home, sessionId) {
  try {
    rmSync(sessionWorkdir(home, sessionId), { recursive: true, force: true });
  } catch {
    /* best-effort — the workdir is disposable */
  }
}

// ── outbound path-traversal guard (SYNC-3 §9) ────────────────────────────────

/**
 * Resolve a brain-supplied `FILE: <path>` against the session workdir. Relative
 * paths resolve under the workdir; an absolute path is accepted ONLY if it
 * still resolves inside the workdir. Returns { ok, absPath }; ok=false means the
 * path escaped the workspace (`..` traversal or an outside absolute path).
 */
export function resolveInWorkdir(workdir, rawPath) {
  const base = resolve(workdir);
  const abs = resolve(base, String(rawPath || ""));
  const ok = abs === base || abs.startsWith(base + sep);
  return { ok, absPath: abs };
}

/** Read an accepted outbound file: its bytes + size (from stat, per §7). */
export function readOutboundFile(absPath) {
  const bytes = readFileSync(absPath);
  const size = statSync(absPath).size;
  return { bytes, size };
}

// ── inbound filename sanitisation + collision handling (SYNC-3 §7) ───────────

/** basename only, path separators stripped; never empty / a dotfile-nav name. */
export function sanitizeFilename(name) {
  let n = basename(String(name || "")).replace(/[/\\]/g, "").trim();
  if (!n || n === "." || n === "..") n = "file";
  return n;
}

/**
 * A non-colliding path under filesDir for the (sanitised) name. On a collision
 * append -1, -2, … before the extension. Returns { path, name }.
 */
export function uniquePath(filesDir, name) {
  const safe = sanitizeFilename(name);
  if (!existsSync(join(filesDir, safe))) return { path: join(filesDir, safe), name: safe };
  const ext = extname(safe);
  const stem = safe.slice(0, safe.length - ext.length);
  let i = 1;
  while (existsSync(join(filesDir, `${stem}-${i}${ext}`))) i += 1;
  const finalName = `${stem}-${i}${ext}`;
  return { path: join(filesDir, finalName), name: finalName };
}

// ── initiator pending-handoff paths (SYNC-3 §10 — CLI → daemon IPC) ──────────

export function pendingDir(home) {
  return join(home, "sessions", "pending");
}

export function pendingFilePath(home, sessionId) {
  return join(pendingDir(home), `${sessionId}.json`);
}
