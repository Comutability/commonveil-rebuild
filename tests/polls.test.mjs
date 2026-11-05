// Polls, votes and the wider emoji list.
import test from "node:test";
import assert from "node:assert/strict";

import { POLL_LIMITS, cleanPoll, cleanVote, pollPayload, votePayload } from "../src/lib/secure/polls.js";
import { buildThread } from "../src/lib/secure/thread.js";
import { serverMessageContent, kindOfPayload } from "../src/lib/secure/serverProtocol.js";
import { EMOJI, QUICK_REACTIONS, isReactionEmoji } from "../src/lib/emoji.js";

const id = (n) => `msg${String(n).padStart(20, "0")}`;
const at = (minutes) => new Date(Date.UTC(2026, 10, 5, 12, minutes)).toISOString();
const row = (n, sender, minutes, content) => ({
  m: { id: `row${n}`, msg_id: id(n), sender_id: sender, sent_at: at(minutes), created_date: at(minutes) },
  r: { status: "ok", content, text: content.type === "poll" ? content.question : content.text || "" },
});
const thread = (items, userId = "alice", now = Date.parse(at(30))) =>
  buildThread(items.map((x) => x.m), Object.fromEntries(items.map((x) => [x.m.id, x.r])), { userId, now });

test("a poll needs a question, two to ten different answers and a set length", () => {
  const now = Date.parse(at(0));
  const p = pollPayload({ question: " Lunch? ", options: ["Pizza", " Sushi ", ""], multi: false, durationSeconds: 3600, now });
  assert.deepEqual(p, { type: "poll", question: "Lunch?", options: ["Pizza", "Sushi"], multi: false, ends_at: at(60) });
  assert.throws(() => pollPayload({ question: "", options: ["a", "b"] }), /question/);
  assert.throws(() => pollPayload({ question: "q", options: ["a"] }), /two/);
  assert.throws(() => pollPayload({ question: "q", options: ["a", "A"] }), /different/);
  assert.throws(() => pollPayload({ question: "q", options: Array.from({ length: 11 }, (_, i) => `o${i}`) }), /up to/);
  assert.throws(() => pollPayload({ question: "q", options: ["a", "b"], durationSeconds: 5 }), /how long/);
  assert.equal(cleanPoll({ ...p, options: ["only one"] }), null);
  assert.equal(cleanPoll({ ...p, extra: "dropped" }).extra, undefined);
  assert.deepEqual(votePayload(id(1), [2, 0, 2, -1, 99]), { type: "vote", target: id(1), choices: [0, 2] });
  assert.equal(cleanVote({ type: "vote", target: "short", choices: [0] }), null);
  assert.ok(POLL_LIMITS.maxOptions === 10);
});

test("each person's latest vote before the end counts, and single-answer polls take one answer", () => {
  const poll = pollPayload({ question: "Pick", options: ["A", "B", "C"], durationSeconds: 3600, now: Date.parse(at(0)) });
  const items = [
    row(1, "bob", 0, poll),
    row(2, "alice", 1, votePayload(id(1), [0])),
    row(3, "alice", 2, votePayload(id(1), [1])), // changed her mind
    row(4, "carol", 3, votePayload(id(1), [0, 2])), // only the first counts
    row(5, "dave", 4, votePayload(id(1), [2])),
    row(6, "dave", 5, votePayload(id(1), [])), // took it back
    row(7, "erin", 61, votePayload(id(1), [2])), // after the end
  ];
  const [r] = thread(items, "alice", Date.parse(at(90)));
  assert.equal(r.poll.voters, 2);
  assert.deepEqual(r.poll.options.map((o) => o.count), [1, 1, 0]);
  assert.deepEqual(r.poll.mine, [1]);
  assert.equal(r.poll.closed, true);
  assert.equal(thread(items).length, 1, "votes don't show as messages");
});

test("multiple-answer polls count every choice", () => {
  const poll = pollPayload({ question: "Pick any", options: ["A", "B"], multi: true, durationSeconds: 86_400, now: Date.parse(at(0)) });
  const [r] = thread([row(1, "bob", 0, poll), row(2, "alice", 1, votePayload(id(1), [0, 1])), row(3, "bob", 2, votePayload(id(1), [1]))]);
  assert.deepEqual(r.poll.options.map((o) => o.count), [1, 2]);
  assert.equal(r.poll.voters, 2);
  assert.equal(r.poll.closed, false);
});

test("the service files polls as messages and votes as reactions, and the two must agree", () => {
  const poll = pollPayload({ question: "q", options: ["a", "b"] });
  const vote = votePayload(id(1), [0]);
  assert.equal(kindOfPayload(poll), "message");
  assert.equal(kindOfPayload(vote), "reaction");
  assert.ok(serverMessageContent(poll, "message"));
  assert.ok(serverMessageContent(vote, "reaction"));
  assert.equal(serverMessageContent(vote, "message"), null);
  assert.equal(serverMessageContent(poll, "reaction"), null);
});

test("reactions can be any emoji on the fixed list, quick ones first, and nothing else", () => {
  assert.ok(EMOJI.length > 150);
  for (const e of QUICK_REACTIONS) assert.ok(isReactionEmoji(e));
  assert.ok(isReactionEmoji("🎉"));
  assert.equal(isReactionEmoji("hello"), false);
  assert.equal(isReactionEmoji("😀😀"), false);
  const msg = row(1, "bob", 0, { type: "text", text: "hi" });
  const react = (n, who, emoji) => row(n, who, n, { type: "reaction", target: id(1), emoji, remove: false });
  const [r] = thread([msg, react(2, "alice", "🎉"), react(3, "bob", "👍"), react(4, "carol", "🎉")]);
  assert.deepEqual(r.reactions.map((x) => [x.emoji, x.count]), [["👍", 1], ["🎉", 2]]);
  assert.equal(serverMessageContent({ type: "reaction", target: id(1), emoji: "not an emoji" }, "reaction"), null);
});
