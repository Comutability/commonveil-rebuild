// The proposals forum (docs/SNIP_FORUM.md): a forum channel in the community server with one
// post for every Secure Net Improvement Proposal (SNIP) on GitHub.
//
// The server can't write posts: channels are end-to-end encrypted with keys it doesn't hold. So
// its part is to read the proposals from GitHub (public data, cached), to make the empty forum
// channel when an admin's app asks, and to say which proposals already have a post and whether
// it's locked. The posts themselves are written, and locked, by the app of whichever community
// admin is online (src/lib/secure/snipForum.js), like anything else an admin posts.
//
// A proposal's post has a fixed id made from its number, so two admins' apps can't both make
// one: the second is refused as a duplicate.
import { ApiError, type Actions } from "../http.ts";
import { signedByActiveDevice } from "../deviceAuth.ts";
import { P, has } from "../permissions.ts";
import { audit, channelOut, permsOf, requireMember, serverParts, touchServer } from "../servers/model.ts";
import { byAge } from "../store.ts";

export type SnipConfig = { enabled: () => boolean; repo?: () => string; token?: () => string };

export const SNIP_CHANNEL_KEY = "snips";
const API = "https://api.github.com";
const RAW = "https://raw.githubusercontent.com";
const SNIP_FILE = /^snips\/(SNIP-\d{4})\.md$/;
const REPO_RE = /^[A-Za-z0-9_.-]{1,60}\/[A-Za-z0-9_.-]{1,60}$/;
const MAX_SNIPS = 200;
const MAX_PRS = 10;

/** The post for a proposal, and the note left when it closes: fixed ids, so they can only exist once. */
export const snipThreadId = (snipId: string) => `${snipId}-thread-v1`;
export const snipClosedNoteId = (snipId: string) => `${snipId}-closed-v1`;

/** A proposal is finished when its own Status line says so (GOVERNANCE.md's states). */
const DONE = /^(accepted|rejected|implemented|released|withdrawn)\b/i;
export const isClosedStatus = (status: string) => DONE.test(String(status || "").trim());

const text = (v: unknown, max: number) => (typeof v === "string" ? v.replace(/[\u0000-\u001f]+/g, " ").trim().slice(0, max) : "");

/** A proposal's title and status, from the top of its file. */
export function parseSnip(id: string, md: string | null) {
  const title = text((md || "").match(/^#\s+(.+)$/m)?.[1]?.replace(/^SNIP-\d+:\s*/, "") || id, 160);
  const status = text((md || "").match(/^\|\s*Status\s*\|\s*([^|]+)\|/m)?.[1] || "", 200);
  return { title, status };
}

async function fetchSnips(repo: string, token: string, fetcher: typeof fetch) {
  const headers: Record<string, string> = { Accept: "application/vnd.github+json", "User-Agent": "commonveil", "X-GitHub-Api-Version": "2022-11-28", ...(token ? { Authorization: `Bearer ${token}` } : {}) };
  const gh = async (path: string) => {
    const res = await fetcher(`${API}/repos/${repo}${path}`, { headers, signal: AbortSignal.timeout(10_000) });
    if (!res.ok) throw new Error(`GitHub ${path}: HTTP ${res.status}`);
    return res.json();
  };
  const raw = async (ref: string, path: string) => {
    const res = await fetcher(`${RAW}/${repo}/${ref}/${path}`, { headers: { "User-Agent": "commonveil" }, signal: AbortSignal.timeout(10_000) });
    return res.ok ? res.text() : null;
  };
  const out = new Map<string, any>();
  // 1. Proposals on the default branch.
  const names: string[] = (await gh("/contents/snips")).map((f: any) => `snips/${f.name}`).filter((n: string) => SNIP_FILE.test(n)).sort().slice(0, MAX_SNIPS);
  await Promise.all(names.map(async (path) => {
    const id = SNIP_FILE.exec(path)![1];
    const { title, status } = parseSnip(id, await raw("HEAD", path));
    out.set(id, { id, title, status, url: `https://github.com/${repo}/blob/HEAD/${path}`, where: "main", closed: isClosedStatus(status) });
  }));
  // 2. Proposals that so far exist only in a pull request: open ones, then ones closed without merging.
  const inPull = async (pr: any, open: boolean) => {
    const files: any[] = await gh(`/pulls/${pr.number}/files?per_page=100`);
    for (const f of files) {
      const m = SNIP_FILE.exec(f.filename || "");
      if (!m || f.status === "removed" || out.has(m[1])) continue;
      const { title, status } = parseSnip(m[1], await raw(pr.head.sha, f.filename));
      out.set(m[1], {
        id: m[1], title, status: open ? status : "Closed without merging", url: pr.html_url, where: "pull", pull: pr.number,
        closed: !open || isClosedStatus(status),
      });
    }
  };
  const open: any[] = await gh(`/pulls?state=open&per_page=${MAX_PRS}&sort=updated&direction=desc`);
  for (const pr of open) await inPull(pr, true);
  const shut: any[] = (await gh(`/pulls?state=closed&per_page=20&sort=updated&direction=desc`)).filter((p: any) => !p.merged_at).slice(0, 5);
  for (const pr of shut) await inPull(pr, false);
  return [...out.values()].sort((a, b) => a.id.localeCompare(b.id));
}

export function snipActions(config: SnipConfig, { fetcher = fetch }: { fetcher?: typeof fetch } = {}): Actions {
  const repo = () => {
    const r = config.repo?.() || "Comutability/secure-net";
    return REPO_RE.test(r) ? r : "Comutability/secure-net";
  };
  /** GitHub allows 60 anonymous requests an hour and a refresh can take 15; with a token, far more. */
  const refreshMs = () => (config.token?.() ? 3 : 20) * 60_000;

  async function proposals(sr: any, now: Date) {
    const [row] = await sr.entities.SnipCache.filter({ key: repo() }, "-fetched_at", 1);
    if (row && now.getTime() - Date.parse(row.fetched_at) < refreshMs()) return { snips: JSON.parse(row.data), fetched_at: row.fetched_at, stale: false };
    try {
      const snips = await fetchSnips(repo(), config.token?.() || "", fetcher);
      const record = { key: repo(), fetched_at: now.toISOString(), data: JSON.stringify(snips) };
      if (row) await sr.entities.SnipCache.update(row.id, record);
      else await sr.entities.SnipCache.create(record);
      return { snips, fetched_at: record.fetched_at, stale: false };
    } catch (e) {
      // GitHub can't be reached or is over its limit: carry on with what we had, and never
      // treat a failed read as "these proposals are gone".
      if (row) return { snips: JSON.parse(row.data), fetched_at: row.fetched_at, stale: true };
      throw new ApiError(503, "GITHUB_UNAVAILABLE", "GitHub can't be read right now.");
    }
  }

  const defaultServer = async (sr: any) => (await sr.entities.Server.filter({ is_default: true }, "created_date", 5)).filter((s: any) => s.status !== "deleting").sort(byAge)[0] || null;
  const forumOf = async (sr: any, serverId: string) => (await sr.entities.Channel.filter({ server_id: serverId, template_key: SNIP_CHANNEL_KEY }, "created_date", 5)).sort(byAge)[0] || null;

  return {
    /**
     * Where the forum stands, for a community admin's app: the proposals on GitHub, the forum
     * channel if it exists, and which proposals already have a post (and whether it's locked).
     * Members who can't manage it are told only whether it's on.
     */
    async status({ sr, own, user, now }: any) {
      if (!config.enabled()) return { enabled: false };
      const server = await defaultServer(sr);
      if (!server) return { enabled: false };
      const member = await requireMember(own, server.id, user.id).catch(() => null);
      if (!member) return { enabled: true, manager: false };
      const parts = await serverParts(sr, server.id);
      const perms = permsOf(parts, member);
      if (!(has(perms, P.MANAGE_CHANNELS) && has(perms, P.MANAGE_THREADS))) return { enabled: true, manager: false };
      const { snips, fetched_at, stale } = await proposals(sr, now);
      const channel = await forumOf(sr, server.id);
      const threads: Record<string, { locked: boolean }> = {};
      const notes: Record<string, boolean> = {};
      if (channel) {
        for (const s of snips) {
          const [post] = await sr.entities.ServerMessage.filter({ channel_id: channel.id, msg_id: snipThreadId(s.id) }, "created_date", 1);
          if (post && !post.deleted) threads[s.id] = { locked: Boolean(post.thread_locked) };
          if (post && s.closed) notes[s.id] = (await sr.entities.ServerMessage.filter({ channel_id: channel.id, msg_id: snipClosedNoteId(s.id) }, "created_date", 1)).length > 0;
        }
      }
      return { enabled: true, manager: true, server_id: server.id, repo: repo(), fetched_at, stale, channel: channel ? channelOut(channel) : null, snips, threads, notes };
    },

    /**
     * Make the forum channel in the community server, once. Its name comes from the app (like the
     * server's other built-in channels), so the server never needs the keys. Everyone can read
     * and reply; only people who manage threads start posts, so there is one post per proposal.
     */
    async ensure_forum(ctx: any) {
      const { sr, own, user, now } = ctx;
      if (!config.enabled()) throw new ApiError(404, "NOT_ENABLED", "The proposals forum isn't turned on for this site.");
      await signedByActiveDevice(ctx, "ensure_forum");
      const server = await defaultServer(sr);
      if (!server) throw new ApiError(404, "SERVER_NOT_FOUND", "There is no community server.");
      const member = await requireMember(own, server.id, user.id);
      const parts = await serverParts(sr, server.id);
      if (!has(permsOf(parts, member), P.MANAGE_CHANNELS)) throw new ApiError(403, "FORBIDDEN", "You need permission to manage channels.");
      const existing = await forumOf(sr, server.id);
      if (existing) return { channel: channelOut(existing), created: false };
      const everyone = parts.roles.find((r: any) => r.is_everyone);
      const position = Math.max(0, ...parts.channels.map((c: any) => Number(c.position) || 0)) + 1;
      const made = await sr.entities.Channel.create({
        server_id: server.id, audience_id: server.id, kind: "forum", parent_id: "", position, template_key: SNIP_CHANNEL_KEY, history: "full",
        private: false, overwrites: everyone ? [{ role_id: everyone.id, allow: 0, deny: P.CREATE_POSTS }] : [], slowmode_seconds: 0, expire_seconds: 0, sensitive: false, creator_id: user.id,
      });
      // Two admins' apps at the same moment: the older channel stays.
      const all = (await sr.entities.Channel.filter({ server_id: server.id, template_key: SNIP_CHANNEL_KEY }, "created_date", 5)).sort(byAge);
      const keep = all[0] && all[0].id !== made.id ? all[0] : made;
      if (keep.id !== made.id) await sr.entities.Channel.delete(made.id).catch(() => null);
      else {
        await touchServer(sr, server.id, now);
        await audit(sr, parts.server, user.id, "channel_create", "channel", made.id, "forum", now);
      }
      return { channel: channelOut(keep), created: keep.id === made.id };
    },
  };
}
