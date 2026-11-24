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
export const MAX_STEPS = 1;

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

export const snipClosedNote = (snip) => {
  if (snip.closure === "merged_to_main" || snip.where === "main") {
    return [
      "GitHub outcome: MERGED into the default branch. This Commonveil discussion is closed.",
      "SNIP governance status: " + (snip.status || "not stated") + ". A source-code merge is NOT standards acceptance, ratification or security review.",
      "PR author's stated purpose (not a formal approval reason): " + (snip.reason || "No separately recorded merge rationale was found. Consult the GitHub file history."),
      "Source: " + (snip.reason_source || snip.merged_url || snip.url),
      "Proposal: " + snip.url,
    ].join("\n\n");
  }
  if (snip.closure === "closed_unmerged") {
    return [
      "GitHub outcome: CLOSED WITHOUT MERGE (declined or withdrawn). This Commonveil discussion is closed.",
      "Recorded maintainer reason: " + (snip.reason || "No maintainer reason recorded on the public GitHub pull request."),
      "Reason source: " + (snip.reason_source || snip.url),
      "This is not an adopted Secure Net standard.",
    ].join("\n\n");
  }
  return "GitHub outcome: proposal finalised as " + (snip.status || "closed") +
    ". This Commonveil discussion is closed. A GitHub status alone is not a substitute for a recorded community decision. Source: " + snip.url;
};

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
  const posts = [];
  const closures = [];
  for (const snip of report.snips) {
    const thread = report.threads?.[snip.id];
    if (!thread) posts.push({ do: "post", snip });
    else if (snip.closed && !thread.locked) closures.push({ do: "close", snip, note: !report.notes?.[snip.id] });
  }
  // Recover missing proposal threads (including 0007 and 0008) before the
  // older closure backlog. Limit each pass to a single signed operation
  // group, allowing the host's shared rate limit time to recover.
  return [...posts, ...closures].slice(0, MAX_STEPS);
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
      // A merged or rejected proposal can get a signed closing note and lock
      // immediately after the authorised device creates its missing thread.
      if (step.snip.closed) {
        await tolerate(() => io.post(channel, { type: "text", text: snipClosedNote(step.snip) }, { kind: "message", threadId: snipThreadId(step.snip.id), itemId: snipClosedNoteId(step.snip.id) }));
        await io.lock(channel, snipThreadId(step.snip.id));
        done.closed.push(step.snip.id);
      }
    } else if (step.do === "close") {
      if (step.note) await tolerate(() => io.post(channel, { type: "text", text: snipClosedNote(step.snip) }, { kind: "message", threadId: snipThreadId(step.snip.id), itemId: snipClosedNoteId(step.snip.id) }));
      await io.lock(channel, snipThreadId(step.snip.id));
      done.closed.push(step.snip.id);
    }
  }
  return done;
}
