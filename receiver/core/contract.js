/**
 * Receiver daemon — action-contract rendering & parsing (framework-agnostic).
 *
 * The verb set is platform-neutral plain text (SYNC-1): the brain learns only
 * `ASK:` (ask one clarifying question) and DONE (any normal reply). The brain
 * never sees frames, keys, or protocol (principle 4) — this core renders the
 * task into a prompt and parses the brain's reply back into a verb.
 *
 * Three render modes, because continuity is achieved two different ways:
 *   - renderFresh      — first delivery (task + the always-on ASK convention).
 *   - renderReplay     — re-delivery for REPLAY adapters (OpenClaw) or the
 *                        resume fallback: the FULL task re-stated + the prior
 *                        Q&A, since the brain has no memory of the first turn.
 *   - renderAnswerTurn — re-delivery for NATIVE-RESUME adapters (Claude/Codex):
 *                        ONLY the answer, because the resumed session already
 *                        holds the original task + the brain's question.
 *
 * Kept short on purpose (progressive disclosure — SYNC-1 / principle 7).
 */

function taskText(msg) {
  return `${msg.task_description || ""}. ${msg.payload?.message || ""}`.trim();
}

function rounds(msg) {
  return Array.isArray(msg.context?.rounds) ? msg.context.rounds : [];
}

// First delivery: the task plus the tiny always-on action-contract.
export function renderFresh(msg) {
  return (
    `${taskText(msg)}\n\n` +
    `If — and only if — you genuinely cannot complete this without ONE specific ` +
    `missing detail, reply with exactly one line:\n` +
    `ASK: <your single question>\n` +
    `and nothing else. Otherwise, just complete the task and reply with the result.`
  );
}

// Re-delivery for REPLAY adapters (no native memory of the first turn): re-state
// the whole task and fold in the prior Q&A (restart-with-context).
export function renderReplay(msg) {
  const qa = rounds(msg)
    .filter((r) => r && r.answer != null)
    .map((r) => `You asked: "${r.question}"\nThe requester answered: "${r.answer}"`)
    .join("\n\n");
  return (
    `${taskText(msg)}\n\n` +
    `Earlier you needed more information to do this.\n${qa}\n\n` +
    `Now complete the original task using that answer. ` +
    `Do not ask any more questions — give your best result.`
  );
}

// Re-delivery for NATIVE-RESUME adapters: the session already has the task and
// the brain's own question, so feed ONLY the answer (the latest round).
export function renderAnswerTurn(msg) {
  const rs = rounds(msg).filter((r) => r && r.answer != null);
  const last = rs[rs.length - 1] || {};
  return (
    `The requester answered your question.\n` +
    `You asked: "${last.question || ""}"\n` +
    `They answered: "${last.answer || ""}"\n\n` +
    `Now complete the original task using that answer. ` +
    `Do not ask any more questions — give your best result.`
  );
}

// First-line-only `ASK:` detection (SYNC-1 §8.2). Returns the question, or null
// if the reply is a normal (DONE) result.
export function parseAsk(text) {
  const firstLine = String(text == null ? "" : text)
    .replace(/^\s+/, "")
    .split(/\r?\n/, 1)[0]
    .trim();
  const m = /^ASK:\s*(.+)$/i.exec(firstLine);
  return m ? m[1].trim() : null;
}

// ── Tier-2 session verbs (SYNC-3 §9) ─────────────────────────────────────────
// Three additions to the brain's plain-text vocabulary — taught by the connector
// with progressive disclosure. The brain still never sees frames, keys, nonces,
// or signatures (principle 4). Verbs:
//   - consent to an invite: first line `ACCEPT`  or  `DECLINE: <reason>`
//   - end an open session:  first line `CLOSE: <closing note>`
//   - send a file:          any line  `FILE: <path>`  (A3 — not sent this build)

// Helper: the trimmed first non-empty-prefixed line of a reply.
function firstLine(text) {
  return String(text == null ? "" : text)
    .replace(/^\s+/, "")
    .split(/\r?\n/, 1)[0]
    .trim();
}

// Render a `session.invite` for the brain (layer-4 runtime consent). Plain text:
// WHO is asking, the purpose, the community, and the EXACT reply convention.
export function renderInvite({ partnerName, partnerAgentId, ownerLabel, purpose, communitySlug }) {
  const who = partnerName || partnerAgentId || "another agent";
  const owner = ownerLabel ? ` (operated by ${ownerLabel})` : "";
  const community = communitySlug ? `\nCommunity: ${communitySlug}` : "";
  return (
    `${who}${owner} wants to open a live, multi-turn session with you.` +
    community +
    `\n\nWhat they want to do:\n${purpose || "(no purpose given)"}` +
    `\n\nDo you want to accept this session? Reply with EXACTLY one line, and nothing else:\n` +
    `  ACCEPT\n` +
    `  DECLINE: <short reason>\n` +
    `Anything whose first line is not exactly "ACCEPT" is treated as a decline (fail-closed).`
  );
}

// Parse the consent reply. First-line `ACCEPT` (exact word, case-insensitive) =
// accept. `DECLINE: <reason>` captures the reason. ANYTHING ELSE is a decline
// (fail-closed, SYNC-3 §9) with the whole reply text as the reason.
export function parseConsent(text) {
  const raw = String(text == null ? "" : text);
  const first = firstLine(raw);
  if (/^ACCEPT$/i.test(first)) return { accept: true, reason: "" };
  const m = /^DECLINE:\s*(.*)$/i.exec(first);
  if (m) return { accept: false, reason: m[1].trim() };
  return { accept: false, reason: raw.trim() };
}

// Render an in-session turn for the brain: the purpose, the running transcript
// (You:/Partner: lines), the new inbound message, and the two in-session verbs.
// For the initiator's OPENING turn (inbound == null) there is no partner message
// yet, so the brain is told to open the conversation toward the purpose.
export function renderSessionTurn({ purpose, partnerName, transcript, inbound }) {
  const who = partnerName || "your partner";
  const lines = [`You are in a live session with ${who}.`];
  if (purpose) lines.push(`Session purpose: ${purpose}`);

  const t = Array.isArray(transcript) ? transcript : [];
  if (t.length) {
    lines.push("", "Conversation so far:");
    for (const turn of t) {
      lines.push(`${turn.who === "You" ? "You" : "Partner"}: ${turn.text}`);
    }
  }

  lines.push("");
  if (inbound == null) {
    lines.push(`Open the conversation: send ${who} a first message that moves toward the purpose above.`);
  } else {
    lines.push(`${who} just said:`, inbound, "", "Reply to continue the session.");
  }

  lines.push(
    "",
    "How your reply is handled:",
    "- Normal text is sent to your partner as your next message.",
    "- To END the session, make the FIRST line exactly: CLOSE: <short closing note>.",
    "- To send a file, put FILE: <path> on its own line (within your session workdir)."
  );
  return lines.join("\n");
}

// Parse an in-session reply. `CLOSE:` on the FIRST line ends the session (the
// note becomes the close reason). `FILE:` on ANY line is extracted (A3); the
// remaining text is the message body.
export function parseSessionReply(text) {
  const raw = String(text == null ? "" : text);
  const closeMatch = /^CLOSE:\s*(.*)$/i.exec(firstLine(raw));

  const fileLines = [];
  const kept = [];
  for (const line of raw.split(/\r?\n/)) {
    const fm = /^\s*FILE:\s*(.+)$/i.exec(line);
    if (fm) {
      fileLines.push(fm[1].trim());
      continue;
    }
    kept.push(line);
  }

  if (closeMatch) {
    return { close: true, closeNote: closeMatch[1].trim(), fileLines, body: "" };
  }
  return { close: false, closeNote: "", fileLines, body: kept.join("\n").trim() };
}
