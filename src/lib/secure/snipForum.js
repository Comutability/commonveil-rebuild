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
export const MAX_CACHED_POST_AGE_MS = 12 * 60 * 60_000;

const clip = (s, max) => (s.length > max ? `${s.slice(0, max - 1).trimEnd()}…` : s);

export function snipPost(snip) {
  return {
    title: clip(`${snip.id}: ${snip.title}`, MAX_POST_TITLE),
    text: [
      `Status on GitHub: ${snip.status || "not stated"}`,
      `Read the proposal: ${snip.url}`,
      ...(snip._cached_from ? ["This discussion was created from a recent, last-known GitHub snapshot (" + snip._cached_from + "). Its status has not been refreshed yet."] : []),
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
export function planSnipSync(report, maxSteps = MAX_STEPS) {
  if (!report?.enabled || !report.manager || !Array.isArray(report.snips)) return [];
  const age = Date.now() - Date.parse(report.fetched_at || "");
  const recentCache = report.stale && Number.isFinite(age) && age >= 0 && age <= MAX_CACHED_POST_AGE_MS;
  // Introduce a missing discussion from a recently verified main-branch file
  // even if a fresh GitHub read failed. NEVER close or ratify it from stale
  // information. A missing open-PR-only draft requires a fresh GitHub check.
  if (report.stale && !recentCache) return [];
  if (!report.channel) return report.stale ? [] : [{ do: "forum" }];
  const posts = [];
  const closures = [];
  for (const snip of report.snips) {
    const thread = report.threads?.[snip.id];
    if (!thread && (!report.stale || snip.where === "main")) {
      posts.push({
        do: "post",
        snip: report.stale ? { ...snip, closed: false, _cached_from: report.fetched_at } : snip,
        cached: Boolean(report.stale),
      });
    } else if (!report.stale && thread && snip.closed && !thread.locked) {
      closures.push({ do: "close", snip, note: !report.notes?.[snip.id] });
    }
  }
  return [...posts, ...closures].slice(0, maxSteps);
}

/**
 * Carry out one pass. io: { status(), ensureForum(), channelOf(id), post(channel, payload, opts),
 * lock(channel, msgId) }. A duplicate (another admin's app got there first) counts as done.
 * Returns what was done.
 */
export async function runSnipSync(io) {
  const done = { forum: false, posted: [], closed: [] };
  let report = await io.status();
  if (report?.enabled && report.manager === false) {
    throw Object.assign(new Error("This account cannot manage proposals on the default server. A site-owner role does not automatically grant community-forum permissions."), { code: "SNIP_FORUM_PERMISSION" });
  }
  let steps = planSnipSync(report);
  if (steps[0]?.do === "forum") {
    await io.ensureForum();
    done.forum = true;
    report = await io.status();
    steps = planSnipSync(report);
  }
  if (!report?.channel || !steps.length) return done;
  const channel = await io.channelOf(report.channel.id);
  if (!channel) {
    throw Object.assign(new Error("The SNIP forum channel has not loaded on this device. Unlock or reload the default server before trying again."), { code: "SNIP_FORUM_CHANNEL_NOT_LOADED" });
  }
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
