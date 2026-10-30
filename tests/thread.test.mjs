// How a conversation is put together on the device: replies, reactions, edits, timers, search.
import test from "node:test";
import assert from "node:assert/strict";
import { EDIT_WINDOW_MS, buildThread, hideAt, lastRow, searchThreads, timerLabel } from "../src/lib/secure/thread.js";
import { REACTIONS } from "../src/lib/secure/protocol.js";

const [THUMBS, HEART] = REACTIONS;
const T0 = Date.parse("2026-10-30T12:00:00.000Z");
let n = 0;

/** One stored message and how it opened. */
function msg(sender, content, { at = T0 + (n += 1) * 1000, status = "ok", deleted = false, expires_at = null } = {}) {
  const id = `row${String(n).padStart(4, "0")}`;
  const msg_id = `msg_${String(n).padStart(16, "0")}`;
  const m = { id, msg_id, sender_id: sender, sent_at: new Date(at).toISOString(), created_date: new Date(at).toISOString().replace("Z", ""), deleted, expires_at };
  const result = deleted ? { status: "deleted" } : { status, text: content.type === "reaction" ? "" : content.text, content };
  return { m, result };
}

function thread(items, options = {}) {
  const list = items.map((i) => i.m);
  const opened = Object.fromEntries(items.map((i) => [i.m.id, i.result]));
  return buildThread(list, opened, { userId: "alice", now: T0 + 3600_000, ...options });
}

const text = (t, extra = {}) => ({ type: "text", text: t, ...extra });

test("replies point at the message they answer, by id only", () => {
  const first = msg("bob", text("Lunch?"));
  const reply = msg("alice", text("Yes!", { reply_to: first.m.msg_id }));
  const orphan = msg("alice", text("About that…", { reply_to: "msg_gone000000000000" }));
  const rows = thread([first, reply, orphan]);
  assert.equal(rows.length, 3);
  assert.equal(rows[1].replyTo.row.m.id, first.m.id);
  assert.deepEqual(rows[2].replyTo, { missing: true }, "an earlier or deleted message is just 'not here'");
  assert.equal(rows[0].replyTo, null);
});

test("reactions: the latest from each person counts, taking one back removes it, and they never show as messages", () => {
  const target = msg("alice", text("Passed my exam"));
  const items = [
    target,
    msg("bob", { type: "reaction", target: target.m.msg_id, emoji: THUMBS }),
    msg("carol", { type: "reaction", target: target.m.msg_id, emoji: THUMBS }),
    msg("alice", { type: "reaction", target: target.m.msg_id, emoji: HEART }),
    msg("carol", { type: "reaction", target: target.m.msg_id, emoji: THUMBS, remove: true }),
    msg("dave", { type: "reaction", target: target.m.msg_id, emoji: HEART }, { status: "unverified" }),
  ];
  const rows = thread(items);
  assert.equal(rows.length, 1, "reactions don't show on their own");
  assert.deepEqual(rows[0].reactions, [
    { emoji: THUMBS, count: 1, mine: false, people: ["bob"] },
    { emoji: HEART, count: 1, mine: true, people: ["alice"] },
  ], "Carol took hers back; Dave's can't be vouched for, so it doesn't count");
});

test("edits: only the sender's own, only within a day, and the latest wins", () => {
  const original = msg("alice", text("See you at 6"));
  const items = [
    original,
    msg("alice", { type: "edit", target: original.m.msg_id, text: "See you at 7" }),
    msg("bob", { type: "edit", target: original.m.msg_id, text: "Bob rewrote this" }),
    msg("alice", { type: "edit", target: original.m.msg_id, text: "See you at 8" }, { status: "unverified" }),
  ];
  let rows = thread(items);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].text, "See you at 7");
  assert.equal(rows[0].edited, true);
  assert.equal(rows[0].canEdit, true);

  const late = msg("alice", { type: "edit", target: original.m.msg_id, text: "Much later" }, { at: T0 + EDIT_WINDOW_MS + 60_000 });
  rows = thread([...items, late], { now: T0 + EDIT_WINDOW_MS + 120_000 });
  assert.equal(rows[0].text, "See you at 7", "too late to change it");
  assert.equal(rows[0].canEdit, false);

  const theirs = msg("bob", text("Bob's message"));
  assert.equal(thread([theirs])[0].canEdit, false, "only your own");
});

test("a deleted message takes its reactions and edits with it", () => {
  const gone = msg("alice", text("oops"), { deleted: true });
  const rows = thread([gone, msg("bob", { type: "reaction", target: gone.m.msg_id, emoji: THUMBS }), msg("alice", { type: "edit", target: gone.m.msg_id, text: "fixed" })]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].result.status, "deleted");
  assert.deepEqual(rows[0].reactions, []);
  assert.equal(rows[0].edited, false);
});

test("disappearing messages hide at the earlier of the server's time and the sender's own timer", () => {
  const timed = msg("bob", text("burn after reading", { expire_seconds: 86_400 }), { at: T0 });
  assert.equal(hideAt(timed.m, timed.result), T0 + 86_400_000);
  const serverSooner = msg("bob", text("x", { expire_seconds: 86_400 }), { at: T0, expires_at: new Date(T0 + 3600_000).toISOString() });
  assert.equal(hideAt(serverSooner.m, serverSooner.result), T0 + 3600_000);
  const serverLater = msg("bob", text("y", { expire_seconds: 86_400 }), { at: T0, expires_at: new Date(T0 + 9 * 86_400_000).toISOString() });
  assert.equal(hideAt(serverLater.m, serverLater.result), T0 + 86_400_000, "the server can't keep it showing longer than the sender chose");
  assert.equal(hideAt(msg("bob", text("kept")).m, msg("bob", text("kept")).result), null);

  const kept = msg("alice", text("kept"));
  assert.deepEqual(thread([timed, kept], { now: T0 + 86_400_000 + 1 }).map((r) => r.text), ["kept"]);
  assert.deepEqual(thread([timed, kept], { now: T0 + 1000 }).map((r) => r.text), ["burn after reading", "kept"]);
});

test("the conversation list shows the last message as it now reads", () => {
  const a = msg("bob", text("first"));
  const b = msg("bob", text("second"));
  const reaction = msg("alice", { type: "reaction", target: b.m.msg_id, emoji: THUMBS });
  const edit = msg("bob", { type: "edit", target: b.m.msg_id, text: "second, edited" });
  const list = [a, b, reaction, edit];
  const row = lastRow(list.map((i) => i.m), Object.fromEntries(list.map((i) => [i.m.id, i.result])), { userId: "alice", now: T0 + 3600_000 });
  assert.equal(row.text, "second, edited");
});

test("search runs over what's been decrypted, finds text as edited, and ignores accents and case", () => {
  const conv = { id: "c1" };
  const rows = thread([msg("bob", text("Meet at the Café Rouge")), msg("alice", text("ok")), msg("bob", text("locked"), { status: "locked" })]);
  assert.deepEqual(searchThreads([{ conversation: conv, rows }], "cafe rouge").map((h) => h.row.text), ["Meet at the Café Rouge"]);
  assert.deepEqual(searchThreads([{ conversation: conv, rows }], "o"), [], "at least two characters");
  assert.deepEqual(searchThreads([{ conversation: conv, rows }], "locked"), [], "only what could be read");
});

test("timer labels", () => {
  assert.equal(timerLabel(0), "Off");
  assert.equal(timerLabel(86_400), "1 day");
  assert.equal(timerLabel(604_800), "1 week");
  assert.equal(timerLabel(2_419_200), "4 weeks");
});
