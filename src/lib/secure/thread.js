// What a conversation shows, worked out on this device from the messages it has opened.
// Pure functions: no network, no storage, no React. Tested in tests/thread.test.mjs.
//
// Replies, reactions and edits are ordinary encrypted messages. A reaction or an edit never
// shows on its own: it changes the message it points at, and only if it checks out.
import { emojiOrder } from "../emoji.js";
import { tallyPoll } from "./polls.js";

/** How long after sending a message can still be edited. */
export const EDIT_WINDOW_MS = 24 * 3600_000;

// A scheduled message was written (and signed) earlier than it arrived: it goes where it was
// delivered, so nobody misses it far up the history.
const sentTime = (m) => {
  const t = m.scheduled ? Date.parse(m.created_date) : Date.parse(m.sent_at);
  return Number.isFinite(t) ? t : Date.parse(m.created_date) || 0;
};

/** Later first by the sender's signed time, then by id, so every member settles on the same answer. */
const later = (a, b) => sentTime(a) - sentTime(b) || String(a.msg_id).localeCompare(String(b.msg_id));

/**
 * When a message stops showing: the earlier of when the server deletes it and when the sender's
 * own signed timer runs out. null: it doesn't disappear.
 */
export function hideAt(m, result) {
  const times = [];
  if (m.expires_at) times.push(Date.parse(m.expires_at));
  const seconds = result?.content?.expire_seconds;
  if (seconds > 0) times.push(sentTime(m) + seconds * 1000);
  const valid = times.filter(Number.isFinite);
  return valid.length ? Math.min(...valid) : null;
}

export const isShowing = (m, result, now) => {
  const t = hideAt(m, result);
  return t === null || t > now;
};

const readable = (r) => r && (r.status === "ok" || r.status === "unverified");

/**
 * The conversation as it should be shown.
 * list: the conversation's messages as stored, oldest first. opened: { [id]: result of openItem }.
 * Returns rows, oldest first: { m, result, text, edited, editedAt, reactions, replyTo, canEdit }.
 * reactions: [{ emoji, count, mine, people }] in the order they're offered.
 * replyTo: null, { row } for a message that's here, or { missing: true }.
 */
export function buildThread(list, opened, { userId, now = Date.now() } = {}) {
  const live = list.filter((m) => isShowing(m, opened[m.id], now));
  const rows = [];
  const byMsgId = new Map();
  for (const m of live) {
    const result = opened[m.id];
    const type = result?.content?.type;
    if (type === "reaction" || type === "edit" || type === "vote") continue;
    const row = { m, result, text: readable(result) ? result.text : "", attachments: readable(result) && type === "text" && !m.deleted ? result.content.attachments || [] : [], edited: false, editedAt: null, reactions: [], replyTo: null, canEdit: false, poll: null };
    rows.push(row);
    if (m.msg_id) byMsgId.set(m.msg_id, row);
  }

  // Edits: only the original's own sender, only when both check out, and within the edit window.
  // The latest one wins.
  const latestEdit = new Map();
  for (const m of live) {
    const r = opened[m.id];
    if (r?.status !== "ok" || r.content?.type !== "edit") continue;
    const row = byMsgId.get(r.content.target);
    if (!row || row.m.deleted || row.result?.status !== "ok" || row.m.sender_id !== m.sender_id) continue;
    if (sentTime(m) - sentTime(row.m) > EDIT_WINDOW_MS) continue;
    const prev = latestEdit.get(r.content.target);
    if (!prev || later(m, prev.m) > 0) latestEdit.set(r.content.target, { m, text: r.content.text });
  }
  for (const [target, edit] of latestEdit) {
    const row = byMsgId.get(target);
    row.text = edit.text;
    row.edited = true;
    row.editedAt = edit.m.sent_at;
  }

  // Reactions: for each person, message and emoji, their latest reaction says whether it stands.
  const latestReaction = new Map();
  for (const m of live) {
    const r = opened[m.id];
    if (r?.status !== "ok" || r.content?.type !== "reaction") continue;
    const row = byMsgId.get(r.content.target);
    if (!row || row.m.deleted) continue;
    const key = `${m.sender_id}\u0000${r.content.target}\u0000${r.content.emoji}`;
    const prev = latestReaction.get(key);
    if (!prev || later(m, prev.m) > 0) latestReaction.set(key, { m, content: r.content });
  }
  const tally = new Map();
  for (const { m, content } of latestReaction.values()) {
    if (content.remove) continue;
    if (!tally.has(content.target)) tally.set(content.target, new Map());
    const perEmoji = tally.get(content.target);
    if (!perEmoji.has(content.emoji)) perEmoji.set(content.emoji, []);
    perEmoji.get(content.emoji).push(m.sender_id);
  }
  for (const [target, perEmoji] of tally) {
    const row = byMsgId.get(target);
    row.reactions = [...perEmoji.keys()].sort((a, b) => emojiOrder(a) - emojiOrder(b)).map((emoji) => {
      const people = perEmoji.get(emoji);
      return { emoji, count: people.length, mine: people.includes(userId), people };
    });
  }

  // Polls: everyone's latest vote before the end counts.
  const votesFor = new Map();
  for (const m of live) {
    const r = opened[m.id];
    if (r?.status !== "ok" || r.content?.type !== "vote") continue;
    if (!votesFor.has(r.content.target)) votesFor.set(r.content.target, []);
    votesFor.get(r.content.target).push({ m, content: r.content });
  }
  for (const row of rows) {
    if (row.result?.content?.type !== "poll" || !readable(row.result) || row.m.deleted) continue;
    row.poll = tallyPoll(row.result.content, row, votesFor.get(row.m.msg_id) || [], { userId, now, sentTime, later });
  }

  for (const row of rows) {
    const replyTo = row.result?.content?.reply_to;
    if (replyTo && readable(row.result)) {
      const target = byMsgId.get(replyTo);
      row.replyTo = target ? { row: target } : { missing: true };
    }
    row.canEdit = row.m.sender_id === userId && !row.m.deleted && row.result?.status === "ok" && now - sentTime(row.m) < EDIT_WINDOW_MS;
  }
  return rows;
}

/** The last thing to show in a conversation list, or null. */
export function lastRow(list, opened, options) {
  const rows = buildThread(list, opened, options);
  return rows.length ? rows[rows.length - 1] : null;
}

const fold = (s) => String(s || "").normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase();

/**
 * Messages whose current text contains the query, newest first. Runs only over what this
 * device has already decrypted; the query never leaves it.
 * threads: [{ conversation, rows }].
 */
export function searchThreads(threads, query, { limit = 50 } = {}) {
  const q = fold(query).trim();
  if (q.length < 2) return [];
  const hits = [];
  for (const { conversation, rows } of threads) {
    for (const row of rows) {
      if (!readable(row.result) || row.m.deleted || !row.text) continue;
      const text = fold(row.text);
      const at = text.indexOf(q);
      if (at < 0) continue;
      const start = Math.max(0, at - 40);
      const snippet = `${start > 0 ? "…" : ""}${row.text.slice(start, at + q.length + 60).replace(/\s+/g, " ")}${at + q.length + 60 < row.text.length ? "…" : ""}`;
      hits.push({ conversation, row, snippet });
    }
  }
  hits.sort((a, b) => later(b.row.m, a.row.m));
  return hits.slice(0, limit);
}

/** "1 day", "1 week", "4 weeks" or "Off", for a timer in seconds. */
export function timerLabel(seconds) {
  if (!seconds) return "Off";
  if (seconds === 86_400) return "1 day";
  if (seconds === 604_800) return "1 week";
  if (seconds === 2_419_200) return "4 weeks";
  const days = Math.round(seconds / 86_400);
  return `${days} days`;
}
