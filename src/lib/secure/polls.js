// Polls. A poll is an encrypted message; a vote is an encrypted item the service files as a
// reaction, so it can't tell votes from reactions, or see the question, the options or who
// chose what. Members' apps count the votes: each person's latest signed vote stands, and
// votes signed after the poll's end are ignored.

const ITEM_ID_RE = /^[A-Za-z0-9_-]{16,64}$/;
const isItemId = (v) => typeof v === "string" && ITEM_ID_RE.test(v);

export const POLL_LIMITS = Object.freeze({ question: 300, option: 100, minOptions: 2, maxOptions: 10 });
/** How long a poll can run, in seconds (1 hour to 1 week). */
export const POLL_DURATIONS = Object.freeze([3600, 4 * 3600, 8 * 3600, 86_400, 3 * 86_400, 7 * 86_400]);

const oneLine = (s, max) => String(s ?? "").replace(/[\r\n]+/g, " ").trim().slice(0, max);

/** A new poll, checked. Throws with a message for people. */
export function pollPayload({ question, options, multi = false, durationSeconds = 86_400, now = Date.now() }) {
  const q = oneLine(question, POLL_LIMITS.question);
  if (!q) throw new Error("Ask a question.");
  const opts = (options || []).map((o) => oneLine(o, POLL_LIMITS.option)).filter(Boolean);
  if (opts.length < POLL_LIMITS.minOptions) throw new Error("Give at least two answers.");
  if (opts.length > POLL_LIMITS.maxOptions) throw new Error(`A poll can have up to ${POLL_LIMITS.maxOptions} answers.`);
  if (new Set(opts.map((o) => o.toLowerCase())).size !== opts.length) throw new Error("Each answer needs to be different.");
  if (!POLL_DURATIONS.includes(durationSeconds)) throw new Error("Choose how long the poll runs.");
  return { type: "poll", question: q, options: opts, multi: Boolean(multi), ends_at: new Date(now + durationSeconds * 1000).toISOString() };
}

/** Your answer to a poll: the options you chose (none takes your vote back). */
export function votePayload(target, choices) {
  if (!isItemId(target)) throw new Error("That poll can't be answered.");
  const picks = [...new Set((choices || []).filter((c) => Number.isInteger(c) && c >= 0 && c < POLL_LIMITS.maxOptions))].sort((a, b) => a - b);
  return { type: "vote", target, choices: picks };
}

/** A decrypted poll, field by field, or null. */
export function cleanPoll(p) {
  if (!p || p.type !== "poll" || typeof p.question !== "string" || !Array.isArray(p.options)) return null;
  const options = p.options.filter((o) => typeof o === "string" && o.trim()).map((o) => oneLine(o, POLL_LIMITS.option)).slice(0, POLL_LIMITS.maxOptions);
  if (options.length < POLL_LIMITS.minOptions || !p.question.trim()) return null;
  const ends = Date.parse(p.ends_at);
  return { type: "poll", question: oneLine(p.question, POLL_LIMITS.question), options, multi: p.multi === true, ends_at: Number.isFinite(ends) ? new Date(ends).toISOString() : null };
}

/** A decrypted vote, or null. */
export function cleanVote(p) {
  if (!p || p.type !== "vote" || !isItemId(p.target) || !Array.isArray(p.choices)) return null;
  const choices = [...new Set(p.choices.filter((c) => Number.isInteger(c) && c >= 0 && c < POLL_LIMITS.maxOptions))].sort((a, b) => a - b);
  return { type: "vote", target: p.target, choices };
}

/**
 * Count a poll's votes. votes: [{ m, content }] already filtered to this poll, readable and
 * checked. sentTime(m) gives a vote's signed time; later(a, b) orders two votes.
 */
export function tallyPoll(poll, pollRow, votes, { userId, now = Date.now(), sentTime, later }) {
  const ends = poll.ends_at ? Date.parse(poll.ends_at) : null;
  const latest = new Map();
  for (const v of votes) {
    if (ends && sentTime(v.m) > ends) continue;
    if (sentTime(v.m) < sentTime(pollRow.m) - 60_000) continue;
    const prev = latest.get(v.m.sender_id);
    if (!prev || later(v.m, prev.m) > 0) latest.set(v.m.sender_id, v);
  }
  const counts = poll.options.map(() => []);
  let voters = 0;
  let mine = [];
  for (const [sender, v] of latest) {
    let choices = v.content.choices.filter((c) => c < poll.options.length);
    if (!poll.multi) choices = choices.slice(0, 1);
    if (!choices.length) continue;
    voters += 1;
    for (const c of choices) counts[c].push(sender);
    if (sender === userId) mine = choices;
  }
  const closed = ends !== null && now > ends;
  return {
    question: poll.question,
    multi: poll.multi,
    endsAt: poll.ends_at,
    closed,
    voters,
    mine,
    options: poll.options.map((text, i) => ({ text, count: counts[i].length, people: counts[i], mine: mine.includes(i) })),
  };
}
