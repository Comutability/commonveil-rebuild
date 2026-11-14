// The proposals forum (docs/SNIP_FORUM.md): one forum post in the community server for every
// Secure Net Improvement Proposal (SNIP) on GitHub.
//
// The site reads GitHub and reports where things stand (the snips function); posts are
// end-to-end encrypted, so they are written here, on the device of whichever community admin has
// the app open. planSnipSync is pure, so it can be tested; runSnipSync carries a plan out.
import { MAX_POST_TITLE } from "./serverProtocol.js";

export const SNIP_CHANNEL_KEY = "snips";
/** Fixed ids, the same as the server computes: a proposal can only ever have one post. */
export const snipThreadId = (snipId) => `${snipId}-thread-v1`;
export const snipClosedNoteId = (snipId) => `${snipId}-closed-v1`;
/** How much one pass does, so a long backlog is spread out and never floods the channel. */
export const MAX_STEPS = 8;

const clip = (s, max) => (s.length > max ? `${s.slice(0, max - 1).trimEnd()}…` : s);

export function snipPost(snip) {
  return {
    title: clip(`${snip.id}: ${snip.title}`, MAX_POST_TITLE),
    text: [
      `Status on GitHub: ${snip.status || "not stated"}`,
      `Read the proposal: ${snip.url}`,
      "This thread is for discussing it. The proposal itself, and any decision on it, is recorded on GitHub.",
    ].join("\n\n"),
  };
}

export const snipClosedNote = (snip) => `This proposal is now: ${snip.status || "closed"}. This thread is closed. The record stays on GitHub: ${snip.url}`;

/**
 * What to do, given the site's report (snips.status). Steps, in order:
 *   { do: "forum" }               make the forum channel
 *   { do: "post", snip }          start a proposal's thread
 *   { do: "close", snip, note }   leave a closing note (if note) and lock the thread
 * Nothing is done from a stale report (GitHub couldn't be read), and a thread someone locked by
 * hand is never unlocked.
 */
export function planSnipSync(report) {
  if (!report?.enabled || !report.manager || report.stale || !Array.isArray(report.snips)) return [];
  if (!report.channel) return [{ do: "forum" }];
  const steps = [];
  for (const snip of report.snips) {
    const thread = report.threads?.[snip.id];
    if (!thread) steps.push({ do: "post", snip });
    else if (snip.closed && !thread.locked) steps.push({ do: "close", snip, note: !report.notes?.[snip.id] });
  }
  return steps.slice(0, MAX_STEPS);
}

/**
 * Carry out one pass. io: { status(), ensureForum(), channelOf(id), post(channel, payload, opts),
 * lock(channel, msgId) }. A duplicate (another admin's app got there first) counts as done.
 * Returns what was done.
 */
export async function runSnipSync(io) {
  const done = { forum: false, posted: [], closed: [] };
  let report = await io.status();
  let steps = planSnipSync(report);
  if (steps[0]?.do === "forum") {
    await io.ensureForum();
    done.forum = true;
    report = await io.status();
    steps = planSnipSync(report);
  }
  if (!report?.channel) return done;
  const channel = await io.channelOf(report.channel.id);
  if (!channel) return done; // this device hasn't loaded the new channel yet: next pass
  const tolerate = async (fn) => {
    try {
      await fn();
      return true;
    } catch (err) {
      if (err?.code === "DUPLICATE_ID") return true;
      throw err;
    }
  };
  for (const step of steps) {
    if (step.do === "post") {
      const { title, text } = snipPost(step.snip);
      await tolerate(() => io.post(channel, { type: "post", title, text }, { kind: "post", itemId: snipThreadId(step.snip.id) }));
      done.posted.push(step.snip.id);
    } else if (step.do === "close") {
      if (step.note) await tolerate(() => io.post(channel, { type: "text", text: snipClosedNote(step.snip) }, { kind: "message", threadId: snipThreadId(step.snip.id), itemId: snipClosedNoteId(step.snip.id) }));
      await io.lock(channel, snipThreadId(step.snip.id));
      done.closed.push(step.snip.id);
    }
  }
  return done;
}
