// Servers (communities) for the signed-in, set-up account: which servers you're in, each one's
// layout, its keys, channel messages, unread state, and what you can do there.
//
// Everything a server says (its name, channel names, messages) is encrypted on members' devices
// with the server's shared keys (crypto/serverKeys.js). This device holds those keys in memory
// only, opened from the copies (grants) sealed to your account, and only accepts a key whose
// generation and copy were signed by a device that a member's verified key history certifies.
// Members' apps hand keys to people waiting for them; that runs here in the background.
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, callFn } from "@/lib/api";
import { useSecure } from "./SecureContext.jsx";
import { useChat } from "./ChatContext.jsx";
import * as SP from "./serverProtocol.js";
import { P, basePermissions, channelPermissions, has, isStaff, topPosition } from "./permissions.js";
import { useNavigate } from "react-router-dom";
import { buildThread } from "./thread.js";
import { isQuiet, showAlert } from "./alerts.js";
import { votePayload } from "./polls.js";
import { copyAttachments, uploadAttachments } from "./fileTransfer.js";
import { EMPTY_AUTOMOD, automodReason } from "./automod.js";
import * as P2 from "./protocol.js";
import { randomId } from "../crypto/encoding.js";
import { ChainKeys, ServerKeyError, newInviteSecret, openInvitePreview, sealInvitePreview, stepAt } from "../crypto/serverKeys.js";
import * as S from "./store.js";
import { templateChannel, templateRole, templateServer } from "./serverTemplates.js";

const ServerContext = createContext(null);

export function useServers() {
  const ctx = useContext(ServerContext);
  if (!ctx) throw new Error("useServers must be used inside ServerProvider");
  return ctx;
}

/** Channels people post messages in. */
export const MESSAGE_KINDS = new Set(["text", "announcement", "rules", "forum"]);

/** How often server changes (layout, settings, who's waiting for keys) ride along on the poll. */
const CHANGES_EVERY_MS = 30_000;
/** While waiting for keys: look again after this long, doubling up to the maximum. */
const WAIT_FIRST_MS = 20_000;
const WAIT_MAX_MS = 5 * 60_000;
const MAX_ROWS_PER_CHANNEL = 600;
const MEMBERS_TTL_MS = 60_000;
const SEND_RETRY_MS = [1_500, 4_000, 8_000];
const INVITE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const isTransient = (err) => err instanceof ApiError && (err.code === "UPSTREAM_BUSY" || err.code === "NETWORK");

/** A platform time (with or without a zone) in milliseconds; 0 if there isn't one. */
export function ts(value) {
  if (!value) return 0;
  const s = String(value);
  const t = Date.parse(/Z$|[+-]\d{2}:\d{2}$/.test(s) ? s : `${s}Z`);
  return Number.isFinite(t) ? t : 0;
}

const readable = (r) => r && (r.status === "ok" || r.status === "unverified");

async function withRetry(fn) {
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await fn();
    } catch (err) {
      if (!isTransient(err) || attempt >= SEND_RETRY_MS.length) throw err;
      await sleep(SEND_RETRY_MS[attempt]);
    }
  }
}

function inviteCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  return [...bytes].map((b) => INVITE_ALPHABET[b % INVITE_ALPHABET.length]).join("");
}

/** Errors from the key code, in words for people. */
function friendly(err) {
  if (err instanceof ServerKeyError) {
    if (err.code === "NO_KEY") return new Error("Your keys for this channel haven't arrived yet. Members' apps hand them out, usually within a minute or two of someone being online.");
    if (err.code === "NO_KEYS_YET") return new Error("This server's encryption is still being set up. Try again in a moment.");
  }
  return err;
}

/** Whether this member's app hands out keys here: any member, or only those with MANAGE_KEYS. */
const canHandOut = (e) => e.server?.settings?.key_handout !== "staff" || has(basePermissions(e.server, e.roles, e.member), P.MANAGE_KEYS);

function canReadChain(e, chain) {
  if (chain.kind !== "c") return true;
  const ch = (e.channels || []).find((c) => c.id === chain.channel_id);
  return Boolean(ch && has(channelPermissions(e.server, e.roles, e.member, ch), P.VIEW_CHANNEL));
}

/** Paging cursors are kept per view: a channel, a forum's post list, or one post's replies. */
export const viewKey = (channelId, { threadId = "", posts = false } = {}) => (posts ? `${channelId}#posts` : threadId ? `${channelId}@${threadId}` : channelId);

/** Whether a decrypted message mentions this member. */
function mentionsMe(result, userId, roleIds) {
  const m = readable(result) ? result.content?.mentions : null;
  if (!m) return false;
  return Boolean(m.everyone || m.users?.includes(userId) || m.roles?.some((r) => roleIds.includes(r)));
}

export function ServerProvider({ children }) {
  const { userId, device, keyring, peers, loadPeers, chainOf, devicesOf, latestChainOf, chainsFor, ownMinCertVersion, me } = useSecure();
  const { addPollExtension, touchActivity, loadProfiles, profiles, refreshConversation, alerts } = useChat();
  const navigate = useNavigate();

  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [servers, setServers] = useState({});
  const serversRef = useRef({});
  const keysRef = useRef({});
  const [keysTick, setKeysTick] = useState(0);
  const keysTickRef = useRef(0);
  const [items, setItems] = useState({});
  const itemsRef = useRef({});
  const [rows, setRows] = useState({});
  const rowsRef = useRef({});
  const [opened, setOpened] = useState({});
  const openedRef = useRef({});
  const [hasMore, setHasMore] = useState({});
  const olderRef = useRef({});
  const [readState, setReadState] = useState({});
  const readRef = useRef({});
  const [prefs, setPrefs] = useState({});
  const prefsRef = useRef({});
  const [memberLists, setMemberLists] = useState({});
  const memberListsRef = useRef({});
  const cursors = useRef({ messages: null, changes: null, changesAt: 0, needChanges: false });
  const workers = useRef({});
  const vouched = useRef(new Set());
  const requested = useRef(new Set());
  const refetched = useRef(new Set());
  const waits = useRef({});
  const activeChannel = useRef(null);
  const saveReadTimer = useRef(null);
  // The latest versions of functions that long-lived effects and background work call, so those
  // don't restart every time someone's keys load (which changes these functions).
  const latest = useRef({});

  // ---------- small state helpers (refs first, so async work always sees the latest) ----------

  const putServer = useCallback((id, patch) => {
    const next = { ...serversRef.current, [id]: { ...(serversRef.current[id] || {}), ...patch } };
    serversRef.current = next;
    setServers(next);
  }, []);

  const dropServer = useCallback((id) => {
    if (!serversRef.current[id]) return;
    const next = { ...serversRef.current };
    const entry = next[id];
    delete next[id];
    serversRef.current = next;
    setServers(next);
    keysRef.current[id]?.clear();
    delete keysRef.current[id];
    const channelIds = new Set((entry?.channels || []).map((c) => c.id));
    if (channelIds.size) {
      const nextRows = { ...rowsRef.current };
      for (const cid of channelIds) delete nextRows[cid];
      rowsRef.current = nextRows;
      setRows(nextRows);
    }
  }, []);

  const bumpKeys = useCallback(() => {
    keysTickRef.current += 1;
    setKeysTick(keysTickRef.current);
  }, []);

  const savePrefs = useCallback((change) => {
    const next = change(prefsRef.current || {});
    prefsRef.current = next;
    setPrefs(next);
    S.saveServerPrefs(userId, next).catch(() => {});
  }, [userId]);

  const mergeRows = useCallback((list) => {
    if (!list?.length) return;
    const next = { ...rowsRef.current };
    const touched = new Set();
    for (const m of list) {
      if (!touched.has(m.channel_id)) {
        next[m.channel_id] = [...(next[m.channel_id] || [])];
        touched.add(m.channel_id);
      }
      const current = next[m.channel_id];
      const i = current.findIndex((x) => x.id === m.id);
      if (i >= 0) current[i] = m;
      else current.push(m);
    }
    for (const cid of touched) {
      const list2 = next[cid];
      list2.sort((a, b) => ts(a.created_date) - ts(b.created_date) || String(a.id).localeCompare(String(b.id)));
      if (list2.length > MAX_ROWS_PER_CHANNEL) {
        const dropped = list2.splice(0, list2.length - MAX_ROWS_PER_CHANNEL);
        // What was dropped can be fetched again with "load earlier".
        olderRef.current[cid] = list2[0]?.created_date || dropped[dropped.length - 1].created_date;
        setHasMore((prev) => ({ ...prev, [cid]: true }));
      }
    }
    rowsRef.current = next;
    setRows(next);
  }, []);

  // ---------- keys ----------

  /** True once a generation or grant has checked out; only successes are remembered. */
  const check = useCallback(async (tag, fn) => {
    if (vouched.current.has(tag)) return true;
    const ok = await fn().catch(() => false);
    if (ok) vouched.current.add(tag);
    return ok;
  }, []);

  /**
   * Open the grants in a server's state into this device's keys. Only generations signed by a
   * device a member's key history certifies, and grants sealed by one, count.
   */
  const absorbKeys = useCallback(async (serverId, st) => {
    const keys = keysRef.current[serverId] || new ChainKeys();
    keysRef.current[serverId] = keys;
    const others = [...new Set([...st.grants.map((g) => g.grantor_id), ...st.generations.map((g) => g.creator_id)])].filter((x) => x && x !== userId);
    if (others.length) await loadPeers(others).catch(() => {});
    const gens = [];
    for (const g of st.generations) {
      const ok = await check(`g:${g.signature}`, () => SP.generationIsVouched({ generation: g, creatorChain: latestChainOf(g.creator_id), creatorDevices: devicesOf(g.creator_id) }));
      if (ok) gens.push(g);
    }
    const fresh = [];
    for (const gr of st.grants) {
      if (keys.has(gr.chain_id, gr.generation) && keys.firstStep(gr.chain_id, gr.generation) <= gr.step) continue;
      const ok = await check(`k:${gr.signature}`, () => SP.grantIsVouched({ grant: gr, grantorChain: latestChainOf(gr.grantor_id), grantorDevices: devicesOf(gr.grantor_id) }));
      if (ok) fresh.push(gr);
    }
    if (!fresh.length) return;
    const { unreadable } = await SP.openGrants({ grants: fresh, generations: gens, userId, keyring, keys });
    bumpKeys();
    // Copies sealed to keys this account no longer has (after a reset): ask for new ones, once.
    const ask = unreadable.filter((gid) => !requested.current.has(gid));
    if (ask.length) {
      ask.forEach((gid) => requested.current.add(gid));
      callFn("servers", await SP.serverRequest({ userId, device, action: "request_keys", payload: { server_id: serverId, grant_ids: ask } })).catch(() => {});
    }
  }, [userId, device, keyring, loadPeers, latestChainOf, devicesOf, check, bumpKeys]);

  /** A server's full state: layout, roles, keys. Reads with your own access. */
  const loadState = useCallback(async (serverId) => {
    let st;
    if (serversRef.current[serverId] && !serversRef.current[serverId].roles) putServer(serverId, { status: "loading" });
    try {
      st = await withRetry(() => callFn("servers", { action: "state", server_id: serverId }));
    } catch (err) {
      if (err instanceof ApiError && err.code === "SERVER_NOT_FOUND") {
        dropServer(serverId);
        return null;
      }
      putServer(serverId, { status: serversRef.current[serverId]?.roles ? "ready" : "error", error: err.message });
      throw err;
    }
    await absorbKeys(serverId, st);
    putServer(serverId, { ...st, loadedAt: Date.now(), status: "ready", error: null });
    latest.current.scheduleWorker?.(serverId);
    return st;
  }, [absorbKeys, putServer, dropServer]);

  /** A new generation of one chain, made here, with a copy for this account. Everyone else gets theirs by hand-out. */
  const createGeneration = useCallback(async (serverId, chainId, generation) => {
    const chains = chainsFor([userId]);
    const { request } = await SP.prepareGeneration({ serverId, chainId, generation, userId, device, chains, recipientIds: [] });
    await callFn("servers", request);
  }, [userId, device, chainsFor]);

  /**
   * The background key work for one server: set up chains with no keys yet, renew keys after
   * someone was removed (MANAGE_KEYS), and seal keys for members who are waiting.
   */
  const serviceKeys = useCallback(async (serverId) => {
    const w = (workers.current[serverId] ||= { busy: false, again: false });
    if (w.busy) {
      w.again = true;
      return;
    }
    w.busy = true;
    try {
      for (let round = 0; round < 8; round += 1) {
        const e = serversRef.current[serverId];
        if (!e?.roles || !e.member) return;
        const perms = basePermissions(e.server, e.roles, e.member);
        const handOut = canHandOut(e);
        let changed = false;
        for (const c of e.chains || []) {
          if (!canReadChain(e, c)) continue;
          const latest = SP.latestGeneration(e.generations, c.chain_id);
          try {
            if (!latest && handOut) {
              await createGeneration(serverId, c.chain_id, 0);
              changed = true;
            } else if (latest && c.rotation_needed && has(perms, P.MANAGE_KEYS)) {
              await createGeneration(serverId, c.chain_id, latest.generation + 1);
              changed = true;
            }
          } catch (err) {
            if (err?.code === "GENERATION_TAKEN") changed = true;
            else if (err?.code !== "MISSING_PERMISSION") throw err;
          }
        }
        if (changed) {
          await loadState(serverId);
          continue;
        }
        if (!handOut || !e.server.keys_pending_at) break;
        const pending = await callFn("servers", { action: "pending_grants", server_id: serverId });
        if (!pending.items?.length) break;
        const ids = Object.keys(pending.recipients || {});
        const stale = ids.filter((uid) => latestChainOf(uid)?.latest?.version !== pending.recipients[uid]);
        await loadPeers(ids).catch(() => {});
        if (stale.length) await loadPeers(stale, { force: true }).catch(() => {});
        const chains = new Map();
        for (const uid of ids) {
          const c = latestChainOf(uid);
          if (c && c.latest.version === pending.recipients[uid]) chains.set(uid, c);
        }
        const request = await SP.prepareGrants({ serverId, items: pending.items, keys: keysRef.current[serverId] || new ChainKeys(), chains, userId, device });
        if (!request) break;
        const res = await callFn("servers", request);
        if (!res.accepted) break;
      }
    } finally {
      w.busy = false;
      if (w.again) {
        w.again = false;
        setTimeout(() => serviceKeys(serverId).catch(() => {}), 1000);
      }
    }
  }, [userId, device, loadState, createGeneration, loadPeers, latestChainOf]);

  const scheduleWorker = useCallback((serverId) => {
    setTimeout(() => serviceKeys(serverId).catch(() => {}), 0);
  }, [serviceKeys]);

  /**
   * Start new key generations for every chain this device can read (MANAGE_KEYS). Everyone who
   * still belongs gets the new keys by hand-out; anyone removed meanwhile doesn't.
   */
  const renewKeys = useCallback(async (serverId) => {
    const e = serversRef.current[serverId];
    if (!e?.chains) return;
    for (const c of e.chains) {
      if (!canReadChain(e, c)) continue;
      const latestGen = SP.latestGeneration(e.generations, c.chain_id);
      if (!latestGen) continue;
      try {
        await createGeneration(serverId, c.chain_id, latestGen.generation + 1);
      } catch (err) {
        if (err?.code !== "GENERATION_TAKEN") throw err;
      }
    }
    await loadState(serverId);
    await serviceKeys(serverId);
  }, [createGeneration, loadState, serviceKeys]);

  // ---------- loading ----------

  const applyList = useCallback((res) => {
    const mine = new Map(res.members.map((m) => [m.server_id, m]));
    const ids = new Set(res.servers.map((s) => s.id));
    for (const id of Object.keys(serversRef.current)) if (!ids.has(id)) dropServer(id);
    for (const s of res.servers) {
      const prev = serversRef.current[s.id];
      // The list leaves out emoji and stickers (they're big); keep the ones the server's state brought.
      const server = s.sets_omitted ? { ...s, emoji: prev?.server?.emoji, stickers: prev?.server?.stickers } : s;
      putServer(s.id, { server, member: mine.get(s.id) || prev?.member, status: prev?.status || "listed" });
    }
  }, [putServer, dropServer]);

  const loadAll = useCallback(async () => {
    const res = await callFn("servers", { action: "list" });
    applyList(res);
    setLoaded(true);
    setLoadError("");
    // Layouts and keys, one server at a time: the one you're looking at first.
    const ids = res.servers.map((s) => s.id);
    const active = activeChannel.current?.serverId;
    ids.sort((a, b) => (a === active ? -1 : b === active ? 1 : 0));
    for (const id of ids) {
      try {
        await loadState(id);
      } catch {
        /* shown on that server; tried again when it changes */
      }
    }
  }, [applyList, loadState]);

  latest.current = { loadAll, loadState, scheduleWorker };

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const [read, p] = await Promise.all([S.loadServerRead(userId).catch(() => ({})), S.loadServerPrefs(userId).catch(() => ({}))]);
      if (cancelled) return;
      readRef.current = read;
      setReadState(read);
      prefsRef.current = p;
      setPrefs(p);
      for (let attempt = 0; !cancelled; attempt += 1) {
        try {
          const start = await callFn("messages", { action: "poll" });
          cursors.current = { messages: start.servers_cursor, changes: start.server_changes_cursor || start.servers_cursor, changesAt: Date.now(), needChanges: false };
          await latest.current.loadAll();
          return;
        } catch (err) {
          if (cancelled) return;
          setLoadError(err.message);
          await sleep(Math.min(60_000, 3_000 * 2 ** attempt));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [userId]);

  // Keys stay in memory only, and go when this unmounts (locking, signing out).
  useEffect(() => () => {
    for (const k of Object.values(keysRef.current)) k.clear();
    keysRef.current = {};
  }, []);

  // ---------- polling (rides on the messages poll) ----------

  const onPage = useRef(null);
  onPage.current = (page) => {
    const c = cursors.current;
    if (page.servers_cursor) c.messages = page.servers_cursor;
    const incoming = page.server_messages || [];
    if (incoming.length) {
      mergeRows(incoming);
      const known = new Set(Object.values(serversRef.current).flatMap((e) => (e.channels || []).map((ch) => ch.id)));
      if (incoming.some((m) => !known.has(m.channel_id))) c.needChanges = true;
      const active = activeChannel.current;
      if (active && incoming.some((m) => m.channel_id === active.channelId && m.sender_id !== userId)) touchActivity();
    }
    if (page.server_ids) {
      c.changes = page.server_changes_cursor || c.changes;
      c.changesAt = Date.now();
      c.needChanges = false;
      const before = serversRef.current;
      const now = new Set(page.server_ids);
      for (const id of Object.keys(before)) if (!now.has(id)) dropServer(id);
      for (const s of page.servers || []) {
        const prev = before[s.id];
        if (!prev) continue;
        // Emoji and stickers aren't in changes; a new set changes changed_at, which reloads the state below.
        putServer(s.id, { server: s.sets_omitted ? { ...s, emoji: prev.server?.emoji, stickers: prev.server?.stickers } : s });
        const layoutChanged = prev.server && prev.server.changed_at !== s.changed_at;
        if (layoutChanged || prev.status === "error") loadState(s.id).catch(() => {});
        else if (s.keys_pending_at) scheduleWorker(s.id);
        // A change here may mean keys arrived for someone waiting.
        if (waits.current[s.id]) waits.current[s.id].next = 0;
      }
      const added = page.server_ids.filter((id) => !before[id]);
      if (added.length) {
        callFn("servers", { action: "list" })
          .then(async (res) => {
            applyList(res);
            for (const id of added) await loadState(id).catch(() => {});
          })
          .catch(() => {});
      }
    }
  };

  useEffect(() => addPollExtension({
    params: () => {
      const c = cursors.current;
      if (!c.messages) return {};
      const out = { servers_since: c.messages };
      if (c.needChanges || Date.now() - c.changesAt > CHANGES_EVERY_MS) out.server_changes_since = c.changes || c.messages;
      return out;
    },
    onPage: (page) => onPage.current(page),
    more: (page) => Boolean(page.servers_more),
  }), [addPollExtension]);

  // Waiting for keys: look again now and then, less often the longer it takes.
  useEffect(() => {
    const t = setInterval(() => {
      if (document.visibilityState !== "visible") return;
      const now = Date.now();
      for (const [id, e] of Object.entries(serversRef.current)) {
        const waiting = e.status === "ready" && e.member?.key_status === "pending";
        if (!waiting) {
          delete waits.current[id];
          continue;
        }
        const w = (waits.current[id] ||= { next: now + WAIT_FIRST_MS, gap: WAIT_FIRST_MS });
        if (now < w.next) continue;
        w.gap = Math.min(WAIT_MAX_MS, w.gap * 2);
        w.next = now + w.gap;
        latest.current.loadState(id).catch(() => {});
      }
    }, 5_000);
    return () => clearInterval(t);
  }, []);

  // ---------- decrypting ----------

  // Server-wide items: the server's name and rules, channel and role names, nicknames.
  useEffect(() => {
    if (!keyring) return undefined;
    let cancelled = false;
    (async () => {
      const todo = [];
      for (const [sid, e] of Object.entries(servers)) {
        if (!keysRef.current[sid]) continue;
        if (e.server?.profile) todo.push({ key: `server:${sid}`, kind: "server", item: e.server.profile, sid });
        if (e.server?.rules) todo.push({ key: `rules:${sid}`, kind: "rules", item: e.server.rules, sid });
        for (const slot of ["emoji", "stickers", "automod"]) if (e.server?.[slot]) todo.push({ key: `${slot}:${sid}`, kind: slot, item: e.server[slot], sid });
        for (const c of e.channels || []) if (c.name) todo.push({ key: `channel:${c.id}`, kind: "channel", item: c.name, sid });
        for (const r of e.roles || []) if (r.name) todo.push({ key: `role:${r.id}`, kind: "role", item: r.name, sid });
        if (e.member?.nick) todo.push({ key: `nick:${sid}:${userId}`, kind: "nick", item: e.member.nick, sid });
      }
      for (const [sid, list] of Object.entries(memberLists)) {
        if (!keysRef.current[sid]) continue;
        for (const m of list.members || []) if (m.nick) todo.push({ key: `nick:${sid}:${m.user_id}`, kind: "nick", item: m.nick, sid });
      }
      const results = {};
      const needPeers = new Set();
      for (const t of todo) {
        if (cancelled) break;
        const prev = itemsRef.current[t.key];
        if (prev && prev.itemId === t.item.item_id && !(prev.status === "waiting" && prev.tick !== keysTick)) continue;
        const sender = t.item.sender_id;
        if (sender !== userId && peers[sender]?.ready === undefined) {
          needPeers.add(sender);
          continue;
        }
        const r = await SP.openServerItem({
          kind: t.kind, item: t.item, serverId: t.sid, channelId: "", keys: keysRef.current[t.sid],
          senderChain: chainOf(sender), senderDevices: devicesOf(sender), minCertVersion: sender === userId ? ownMinCertVersion : 1,
        });
        results[t.key] = { ...r, itemId: t.item.item_id, tick: keysTick };
      }
      if (needPeers.size) loadPeers([...needPeers]).catch(() => {});
      if (Object.keys(results).length) {
        itemsRef.current = { ...itemsRef.current, ...results };
        setItems(itemsRef.current);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [servers, memberLists, keysTick, peers, keyring, userId, chainOf, devicesOf, ownMinCertVersion, loadPeers]);

  // Channel messages.
  useEffect(() => {
    if (!keyring) return undefined;
    let cancelled = false;
    (async () => {
      const results = {};
      const needPeers = new Set();
      for (const list of Object.values(rows)) {
        for (const m of list) {
          if (cancelled) break;
          const cacheKey = `${m.deleted ? "d" : "v"}:${m.envelope ? m.envelope.length : 0}:${m.signature || ""}`;
          const prev = openedRef.current[m.id];
          if (prev && prev.cacheKey === cacheKey && !(prev.status === "waiting" && prev.tick !== keysTick)) continue;
          const keys = keysRef.current[m.server_id];
          if (!keys) continue;
          if (!m.deleted) {
            if (m.sender_id !== userId && peers[m.sender_id]?.ready === undefined) {
              needPeers.add(m.sender_id);
              continue;
            }
            const knows = devicesOf(m.sender_id).some((d) => d.device_id === m.device_id);
            const tag = `${m.sender_id}:${m.device_id}`;
            if (!knows && !refetched.current.has(tag) && m.sender_id !== userId) {
              refetched.current.add(tag);
              loadPeers([m.sender_id], { force: true }).catch(() => {});
              continue;
            }
          }
          const r = await SP.openServerItem({
            kind: "message", item: m, serverId: m.server_id, channelId: m.channel_id, keys,
            senderChain: chainOf(m.sender_id), senderDevices: devicesOf(m.sender_id), minCertVersion: m.sender_id === userId ? ownMinCertVersion : 1,
          });
          results[m.id] = { ...r, cacheKey, tick: keysTick };
        }
      }
      if (needPeers.size) {
        const ids = [...needPeers];
        loadPeers(ids).catch(() => {});
        loadProfiles(ids).catch(() => {});
      }
      if (Object.keys(results).length) {
        openedRef.current = { ...openedRef.current, ...results };
        setOpened(openedRef.current);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [rows, keysTick, peers, keyring, userId, chainOf, devicesOf, ownMinCertVersion, loadPeers, loadProfiles]);

  // ---------- names and looks ----------

  const itemContent = useCallback((key) => {
    const it = items[key];
    return readable(it) ? it.content : null;
  }, [items]);

  /** A server's name, icon, colour and description: its encrypted profile, else its public card, else its template's. */
  const serverLook = useCallback((sid) => {
    const e = servers[sid];
    const enc = itemContent(`server:${sid}`);
    const pub = e?.server?.public;
    const tpl = templateServer(e?.server?.template);
    return {
      name: enc?.name || pub?.name || tpl?.name || "New server",
      description: enc?.description || pub?.description || tpl?.description || "",
      icon: enc?.icon || pub?.icon || tpl?.icon || "",
      color: enc?.color || pub?.color || tpl?.color || "",
      banner: enc?.banner || "",
      unverified: items[`server:${sid}`]?.status === "unverified",
    };
  }, [servers, items, itemContent]);

  const serverName = useCallback((sid) => serverLook(sid).name, [serverLook]);

  const channelName = useCallback((channel) => {
    if (!channel) return "";
    const enc = itemContent(`channel:${channel.id}`);
    return enc?.name || templateChannel(channel.template_key)?.name || (channel.kind === "voice" ? "Voice" : channel.kind === "stage" ? "Stage" : channel.kind === "category" ? "Channels" : "channel");
  }, [itemContent]);

  const channelTopic = useCallback((channel) => {
    if (!channel) return "";
    const enc = itemContent(`channel:${channel.id}`);
    if (enc) return enc.topic || "";
    return templateChannel(channel.template_key)?.topic || "";
  }, [itemContent]);

  const roleName = useCallback((role) => {
    if (!role) return "";
    if (role.is_everyone) return "@everyone";
    return itemContent(`role:${role.id}`)?.name || templateRole(role.template_key)?.name || "New role";
  }, [itemContent]);

  const roleColor = useCallback((role) => {
    if (!role || role.is_everyone) return "";
    const enc = itemContent(`role:${role.id}`);
    return enc ? enc.color || "" : templateRole(role.template_key)?.color || "";
  }, [itemContent]);

  /** Rules: the server's own (encrypted), else its template's. */
  const serverRules = useCallback((sid) => {
    const e = servers[sid];
    const enc = itemContent(`rules:${sid}`);
    const tpl = templateServer(e?.server?.template);
    return { rules: enc?.rules?.length ? enc.rules : tpl?.rules || [], intro: enc ? enc.intro || "" : tpl?.intro || "", custom: Boolean(enc) };
  }, [servers, itemContent]);

  /** The server's own emoji and stickers: { emoji: [...], stickers: [...], byId: Map }. */
  const serverEmoji = useCallback((sid) => {
    const emoji = itemContent(`emoji:${sid}`)?.items || [];
    const stickers = itemContent(`stickers:${sid}`)?.items || [];
    return { emoji, stickers, byId: new Map([...emoji, ...stickers].map((x) => [x.id, x])) };
  }, [itemContent]);

  const automodOf = useCallback((sid) => itemContent(`automod:${sid}`) || EMPTY_AUTOMOD, [itemContent]);

  const profileOf = useCallback((sid, uid) => {
    if (uid === userId && me?.profile) return me.profile;
    return memberLists[sid]?.profiles?.[uid] || profiles[uid] || null;
  }, [userId, me, memberLists, profiles]);

  /** Someone's nickname in a server, decrypted, or "". */
  const nickOf = useCallback((sid, uid) => itemContent(`nick:${sid}:${uid}`)?.nick || "", [itemContent]);

  /** What to call someone here: their nickname, else display name, else username. */
  const memberName = useCallback((sid, uid) => {
    const nick = itemContent(`nick:${sid}:${uid}`)?.nick;
    if (nick) return nick;
    const p = profileOf(sid, uid);
    return p ? p.display_name || p.username : "Member";
  }, [itemContent, profileOf]);

  // ---------- permissions ----------

  const permsFor = useCallback((sid, channel = null) => {
    const e = servers[sid];
    if (!e?.roles || !e.member) return 0;
    return channel ? channelPermissions(e.server, e.roles, e.member, channel) : basePermissions(e.server, e.roles, e.member);
  }, [servers]);

  const can = useCallback((sid, bit, channel = null) => has(permsFor(sid, channel), bit), [permsFor]);
  const permsForRef = useRef(permsFor);
  permsForRef.current = permsFor;
  const automodRef = useRef(automodOf);
  automodRef.current = automodOf;

  /** Roles of a member (other than @everyone), highest first. */
  const rolesOfMember = useCallback((sid, member) => {
    const e = servers[sid];
    if (!e?.roles || !member) return [];
    const ids = new Set(member.role_ids || []);
    return e.roles.filter((r) => !r.is_everyone && ids.has(r.id)).sort((a, b) => b.position - a.position);
  }, [servers]);

  /** The colour of someone's name: their highest coloured role. */
  const memberColor = useCallback((sid, member) => {
    for (const r of rolesOfMember(sid, member)) {
      const c = roleColor(r);
      if (c) return c;
    }
    return "";
  }, [rolesOfMember, roleColor]);

  const myTop = useCallback((sid) => {
    const e = servers[sid];
    return e?.roles ? topPosition(e.server, e.roles, e.member) : -1;
  }, [servers]);

  // ---------- key state of a channel ----------

  /** "ready" (this device can read and post), "waiting" (keys not here yet) or "setup" (no keys made yet). */
  const keyState = useCallback((sid, channel) => {
    const e = servers[sid];
    if (!e?.generations || !channel) return "setup";
    const chainId = SP.chainForChannel(sid, channel);
    const gen = SP.latestGeneration(e.generations, chainId);
    if (!gen) return "setup";
    const keys = keysRef.current[sid];
    try {
      keys?.get(chainId, gen.generation, stepAt(chainId, gen.started_at, Date.now()));
      return keys ? "ready" : "waiting";
    } catch {
      return "waiting";
    }
    // keysTick: re-run when keys arrive.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [servers, keysTick]);

  // ---------- calls ----------

  /** The chain, generation and step a channel's newest items use right now (a call's audio key follows it). */
  const voiceEpoch = useCallback((sid, channel) => {
    const e = servers[sid];
    const chainId = SP.chainForChannel(sid, channel);
    const gen = SP.latestGeneration(e?.generations, chainId);
    if (!gen) throw new ServerKeyError("NO_KEY", "This channel's keys aren't set up yet.");
    return { chainId, generation: gen.generation, step: stepAt(chainId, gen.started_at, Date.now()) };
  }, [servers]);

  /** A copy of a chain's key at a generation and step. Throws if this device doesn't hold it. */
  const chainKeyAt = useCallback((sid, chainId, generation, step) => {
    const keys = keysRef.current[sid];
    if (!keys) throw new ServerKeyError("NO_KEY", "This device hasn't been given this server's keys yet.");
    return keys.get(chainId, generation, step).slice();
  }, []);

  // ---------- messages ----------

  /** The newest page of a channel, a forum's posts, or a post's replies. */
  const openView = useCallback(async (sid, channelId, opts = {}) => {
    const key = viewKey(channelId, opts);
    const res = await withRetry(() => callFn("channels", {
      action: "list", server_id: sid, channel_id: channelId, ...(opts.threadId ? { thread_id: opts.threadId } : {}), ...(opts.posts ? { posts: true } : {}),
    }));
    mergeRows(res.messages);
    if (!(key in olderRef.current)) {
      olderRef.current[key] = res.has_more ? res.before : null;
      setHasMore((prev) => ({ ...prev, [key]: res.has_more }));
    }
    return res.messages.length;
  }, [mergeRows]);

  const loadOlder = useCallback(async (sid, channelId, opts = {}) => {
    const key = viewKey(channelId, opts);
    const before = olderRef.current[key];
    if (!before) return 0;
    const res = await withRetry(() => callFn("channels", {
      action: "list", server_id: sid, channel_id: channelId, before, ...(opts.threadId ? { thread_id: opts.threadId } : {}), ...(opts.posts ? { posts: true } : {}),
    }));
    mergeRows(res.messages);
    olderRef.current[key] = res.has_more ? res.before : null;
    setHasMore((prev) => ({ ...prev, [key]: res.has_more }));
    return res.messages.length;
  }, [mergeRows]);

  /** A channel (or one forum post's thread) as it reads now: edits applied, reactions gathered. */
  const threadOf = useCallback((channelId, threadId = "") => {
    const list = (rows[channelId] || []).filter((m) => (threadId ? m.thread_id === threadId || (!m.thread_id && (m.kind === "post" || m.kind === "message") && m.msg_id === threadId) : !m.thread_id && m.kind !== "post"));
    return buildThread(list, opened, { userId, now: Date.now() });
  }, [rows, opened, userId]);

  /** A forum's posts, latest activity first. */
  const postsOf = useCallback((channelId) => {
    const list = rows[channelId] || [];
    const posts = list.filter((m) => m.kind === "post" && !m.thread_id);
    const extras = list.filter((m) => m.thread_id && (m.kind === "reaction" || m.kind === "edit") && posts.some((p) => p.msg_id === m.thread_id));
    const built = buildThread([...posts, ...extras], opened, { userId, now: Date.now() }).filter((r) => r.m.kind === "post");
    return built.sort((a, b) => ts(b.m.last_reply_at || b.m.created_date) - ts(a.m.last_reply_at || a.m.created_date));
  }, [rows, opened, userId]);

  const sendBuilt = useCallback(async (sid, channel, payload, { kind = "message", threadId = "", itemId = null } = {}) => {
    touchActivity();
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const e = serversRef.current[sid];
      const keys = keysRef.current[sid];
      if (!e?.generations || !keys) throw new Error("This server is still loading. Try again in a moment.");
      try {
        const body = await SP.buildChannelMessage({ serverId: sid, channel, generations: e.generations, keys, userId, device, payload, kind, threadId, itemId });
        const res = await withRetry(() => callFn("channels", body));
        mergeRows([res.message]);
        return res.message;
      } catch (err) {
        if (attempt === 0 && ((err instanceof ApiError && (err.code === "STALE_SERVER_KEYS" || err.code === "NO_KEYS_YET")) || (err instanceof ServerKeyError && err.code === "NO_KEY"))) {
          await loadState(sid);
          continue;
        }
        throw friendly(err);
      }
    }
    return null;
  }, [touchActivity, userId, device, mergeRows, loadState]);

  const markChannelRead = useCallback((channelId, at = null) => {
    const list = rowsRef.current[channelId] || [];
    const last = list.length ? list[list.length - 1].created_date : null;
    const target = [at, last, readRef.current[channelId]].filter(Boolean).sort((a, b) => ts(b) - ts(a))[0];
    if (!target || readRef.current[channelId] === target) return;
    readRef.current = { ...readRef.current, [channelId]: target };
    setReadState(readRef.current);
    clearTimeout(saveReadTimer.current);
    saveReadTimer.current = setTimeout(() => S.saveServerRead(userId, readRef.current).catch(() => {}), 800);
  }, [userId]);

  /**
   * files: [{ file, voice?, duration?, spoiler? }] to seal and attach; forwardFiles: attachments
   * from another message, copied here as they are. onProgress(done, total) while uploading.
   */
  const sendText = useCallback(async (sid, channel, text, { replyTo = null, mentions = null, threadId = "", forwarded = false, files = [], forwardFiles = [], onProgress = null, sticker = null } = {}) => {
    touchActivity();
    const blocked = !has(permsForRef.current(sid, channel), P.MANAGE_MESSAGES) && automodReason(automodRef.current(sid), text, mentions);
    if (blocked) throw new Error(`AutoMod stopped this message. ${blocked}`);
    const itemId = randomId(16);
    const place = { scope: "server", server_id: sid, channel_id: channel.id };
    let attachments = [];
    try {
      if (files.length) attachments = await uploadAttachments({ userId, device, place, msgId: itemId, items: files, onProgress });
      if (forwardFiles.length) attachments = [...attachments, ...(await copyAttachments({ userId, device, place, msgId: itemId, attachments: forwardFiles }))];
    } catch (err) {
      throw friendly(err);
    }
    const m = await sendBuilt(sid, channel, SP.textPayload(text, { replyTo, mentions, forwarded, attachments, sticker }), { kind: "message", threadId, itemId });
    if (m) markChannelRead(channel.id, m.created_date);
    return m;
  }, [sendBuilt, markChannelRead, touchActivity, userId, device]);

  const sendPost = useCallback(async (sid, channel, title, text, { mentions = null } = {}) => {
    const m = await sendBuilt(sid, channel, SP.postPayload(title, text, { mentions }), { kind: "post" });
    if (m) markChannelRead(channel.id, m.created_date);
    return m;
  }, [sendBuilt, markChannelRead]);

  const react = useCallback((sid, channel, row, emoji, remove = false) =>
    sendBuilt(sid, channel, SP.reactionPayload(row.m.msg_id, emoji, remove), { kind: "reaction", threadId: row.m.kind === "post" ? row.m.msg_id : row.m.thread_id || "" }),
  [sendBuilt]);

  /** A poll (made with polls.js pollPayload). The service files it as an ordinary message. */
  const sendPoll = useCallback(async (sid, channel, poll, { threadId = "" } = {}) => {
    const m = await sendBuilt(sid, channel, poll, { kind: "message", threadId });
    if (m) markChannelRead(channel.id, m.created_date);
    return m;
  }, [sendBuilt, markChannelRead]);

  /** Your answer to a poll. The service files it as a reaction, so it can't tell the two apart. */
  const vote = useCallback((sid, channel, row, choices) =>
    sendBuilt(sid, channel, votePayload(row.m.msg_id, choices), { kind: "reaction", threadId: row.m.kind === "post" ? row.m.msg_id : row.m.thread_id || "" }),
  [sendBuilt]);

  const edit = useCallback((sid, channel, row, text) =>
    sendBuilt(sid, channel, SP.editPayload(row.m.msg_id, text), { kind: "edit", threadId: row.m.kind === "post" ? row.m.msg_id : row.m.thread_id || "" }),
  [sendBuilt]);

  const signed = useCallback(async (fn, action, payload) => callFn(fn, await SP.serverRequest({ userId, device, action, payload })), [userId, device]);

  const deleteMessage = useCallback(async (sid, row) => {
    await signed("channels", "delete_server_message", { server_id: sid, channel_id: row.m.channel_id, msg_id: row.m.msg_id });
    mergeRows([{ ...row.m, deleted: true, envelope: null, signature: null, pinned: false }]);
  }, [signed, mergeRows]);

  const pinMessage = useCallback(async (sid, row, pinned) => {
    await signed("channels", "pin_server_message", { server_id: sid, channel_id: row.m.channel_id, msg_id: row.m.msg_id, pinned });
    mergeRows([{ ...row.m, pinned }]);
  }, [signed, mergeRows]);

  /** Lock or unlock a thread or forum post (row is its first message). */
  const lockThread = useCallback(async (sid, row, locked) => {
    await signed("channels", "lock_thread", { server_id: sid, channel_id: row.m.channel_id, msg_id: row.m.msg_id, locked });
    mergeRows([{ ...row.m, thread_locked: locked }]);
  }, [signed, mergeRows]);

  const loadPins = useCallback(async (sid, channelId) => {
    const res = await callFn("channels", { action: "pins", server_id: sid, channel_id: channelId });
    mergeRows(res.messages);
    return res.messages.map((m) => m.id);
  }, [mergeRows]);

  // ---------- unread ----------

  const muted = useCallback((id) => Boolean(prefs.muted?.[id]), [prefs]);

  const unread = useMemo(() => {
    const channels = {};
    const out = {};
    for (const [sid, e] of Object.entries(servers)) {
      if (!e.channels || !e.member) continue;
      const joined = ts(e.member.joined_at);
      const roleIds = e.member.role_ids || [];
      let any = false;
      let mentions = 0;
      for (const c of e.channels) {
        if (!MESSAGE_KINDS.has(c.kind)) continue;
        if (!has(channelPermissions(e.server, e.roles, e.member, c), P.VIEW_CHANNEL)) continue;
        const read = Math.max(ts(readState[c.id]), joined);
        let last = ts(c.last_message_at);
        let count = 0;
        for (const m of rows[c.id] || []) {
          if (m.sender_id === userId || m.deleted) continue;
          const t = ts(m.created_date);
          if (m.kind === "message" || m.kind === "post") last = Math.max(last, t);
          if (t > read && mentionsMe(opened[m.id], userId, roleIds)) count += 1;
        }
        const isUnread = last > read;
        channels[c.id] = { unread: isUnread, mentions: count };
        if (isUnread && !prefs.muted?.[c.id] && !prefs.muted?.[sid]) any = true;
        mentions += count;
      }
      out[sid] = { unread: any, mentions };
    }
    return { channels, servers: out };
  }, [servers, rows, opened, readState, prefs, userId]);

  const markServerRead = useCallback((sid) => {
    const e = serversRef.current[sid];
    const at = new Date().toISOString();
    const next = { ...readRef.current };
    for (const c of e?.channels || []) if (MESSAGE_KINDS.has(c.kind)) next[c.id] = at;
    readRef.current = next;
    setReadState(next);
    S.saveServerRead(userId, next).catch(() => {});
  }, [userId]);

  const setActiveChannel = useCallback((serverId, channelId) => {
    activeChannel.current = serverId ? { serverId, channelId } : null;
    if (serverId && channelId) savePrefs((p) => (p.last?.[serverId] === channelId ? p : { ...p, last: { ...(p.last || {}), [serverId]: channelId } }));
  }, [savePrefs]);

  const toggleMute = useCallback((id) => savePrefs((p) => {
    const mutedNext = { ...(p.muted || {}) };
    if (mutedNext[id]) delete mutedNext[id];
    else mutedNext[id] = true;
    return { ...p, muted: mutedNext };
  }), [savePrefs]);

  const toggleCollapsed = useCallback((id) => savePrefs((p) => {
    const collapsed = { ...(p.collapsed || {}) };
    if (collapsed[id]) delete collapsed[id];
    else collapsed[id] = true;
    return { ...p, collapsed };
  }), [savePrefs]);

  const moveServer = useCallback((sid, delta) => savePrefs((p) => {
    const current = (p.order || []).filter((id) => serversRef.current[id]);
    for (const id of Object.keys(serversRef.current)) if (!current.includes(id)) current.push(id);
    const i = current.indexOf(sid);
    const j = Math.max(0, Math.min(current.length - 1, i + delta));
    if (i < 0 || i === j) return p;
    current.splice(i, 1);
    current.splice(j, 0, sid);
    return { ...p, order: current };
  }), [savePrefs]);

  /** Servers in the order they're shown: the community server first, then yours as you arranged them. */
  const order = useMemo(() => {
    const ids = Object.keys(servers).filter((id) => servers[id].server);
    const saved = prefs.order || [];
    const rank = (id) => {
      const i = saved.indexOf(id);
      return i < 0 ? saved.length + ts(servers[id].member?.joined_at) / 1e13 : i;
    };
    return ids.sort((a, b) => (servers[b].server.is_default ? 1 : 0) - (servers[a].server.is_default ? 1 : 0) || rank(a) - rank(b));
  }, [servers, prefs.order]);

  // ---------- notifications, saved messages, notes, folders (all only on this device) ----------

  /** "all", "mentions" or "none" for a channel or server, or null to follow the server (or the default). */
  const notifyLevel = useCallback((id) => prefs.notify?.[id] || null, [prefs]);
  const setNotifyLevel = useCallback((id, level) => savePrefs((p) => {
    const notify = { ...(p.notify || {}) };
    if (level) notify[id] = level;
    else delete notify[id];
    return { ...p, notify };
  }), [savePrefs]);
  /** What actually applies to a channel: its own choice, else its server's, else everything (mentions in the community server). */
  const effectiveLevel = useCallback((sid, channelId) => {
    if (prefs.muted?.[sid] || prefs.muted?.[channelId]) return "none";
    return prefs.notify?.[channelId] || prefs.notify?.[sid] || (serversRef.current[sid]?.server?.is_default ? "mentions" : "all");
  }, [prefs]);

  const savedList = useMemo(() => prefs.saved || [], [prefs.saved]);
  const isSaved = useCallback((msgId) => savedList.some((x) => x.m === msgId), [savedList]);
  /** Save a message for later: only where it is, never its text. */
  const toggleSaved = useCallback(({ serverId: sid, channelId, threadId = "", msgId }) => savePrefs((p) => {
    const list = p.saved || [];
    if (list.some((x) => x.m === msgId)) return { ...p, saved: list.filter((x) => x.m !== msgId) };
    return { ...p, saved: [{ s: sid, c: channelId, t: threadId, m: msgId, at: new Date().toISOString() }, ...list].slice(0, 500) };
  }), [savePrefs]);

  const noteOf = useCallback((uid) => prefs.notes?.[uid] || "", [prefs]);
  const setNote = useCallback((uid, text) => savePrefs((p) => {
    const notes = { ...(p.notes || {}) };
    const clean = String(text || "").slice(0, 500);
    if (clean.trim()) notes[uid] = clean;
    else delete notes[uid];
    return { ...p, notes };
  }), [savePrefs]);

  /** Folders in the server list: [{ id, name, color, servers: [serverId] }]. */
  const folders = useMemo(() => (prefs.folders || []).map((f) => ({ ...f, servers: f.servers.filter((id) => servers[id]) })).filter((f) => f.servers.length), [prefs.folders, servers]);
  const moveToFolder = useCallback((sid, folderId, newName = "") => savePrefs((p) => {
    let list = (p.folders || []).map((f) => ({ ...f, servers: f.servers.filter((x) => x !== sid) }));
    if (folderId === "new") list.push({ id: `f${Date.now().toString(36)}`, name: newName.slice(0, 40) || "Folder", color: "", servers: [sid] });
    else if (folderId) list = list.map((f) => (f.id === folderId ? { ...f, servers: [...f.servers, sid] } : f));
    return { ...p, folders: list.filter((f) => f.servers.length) };
  }), [savePrefs]);
  const renameFolder = useCallback((folderId, name) => savePrefs((p) => ({ ...p, folders: (p.folders || []).map((f) => (f.id === folderId ? { ...f, name: name.slice(0, 40) || f.name } : f)) })), [savePrefs]);

  // Browser notifications for server messages, only if you turned alerts on, following each
  // channel's notification setting. Worked out here, after decrypting: nothing tells the service.
  const alerted = useRef(new Set());
  const alertsFrom = useRef(Date.now());
  useEffect(() => {
    if (!alerts?.notify) return;
    for (const [cid, list] of Object.entries(rows)) {
      for (const m of list) {
        if (alerted.current.has(m.id)) continue;
        if (ts(m.created_date) < alertsFrom.current || m.sender_id === userId || m.deleted || (m.kind !== "message" && m.kind !== "post")) {
          alerted.current.add(m.id);
          continue;
        }
        const r = opened[m.id];
        if (!r) continue;
        alerted.current.add(m.id);
        const sid = m.server_id || Object.keys(serversRef.current).find((id) => serversRef.current[id]?.channels?.some((c) => c.id === cid));
        if (!sid) continue;
        const level = effectiveLevel(sid, cid);
        const e = serversRef.current[sid];
        if (level === "none" || (level === "mentions" && !mentionsMe(r, userId, e?.member?.role_ids || []))) continue;
        if (document.visibilityState === "visible" && activeChannel.current?.channelId === cid) continue;
        if (isQuiet(alerts)) continue;
        showAlert({ body: alerts.showSender ? "New message in one of your servers" : "New message", tag: `server-${cid}`, onClick: () => navigate(`/app/s/${sid}/${cid}`) });
      }
    }
  }, [rows, opened, alerts, userId, effectiveLevel, navigate]);

  // ---------- members ----------

  const loadMembers = useCallback(async (sid, { force = false } = {}) => {
    const cached = memberListsRef.current[sid];
    if (cached && !force && Date.now() - cached.at < MEMBERS_TTL_MS) return cached;
    const res = await callFn("servers", { action: "members", server_id: sid });
    const entry = { members: res.members, profiles: Object.fromEntries(res.profiles.filter(Boolean).map((p) => [p.user_id, p])), count: res.count, at: Date.now() };
    memberListsRef.current = { ...memberListsRef.current, [sid]: entry };
    setMemberLists(memberListsRef.current);
    return entry;
  }, []);

  const memberCard = useCallback(async (sid, uid) => {
    const res = await callFn("servers", { action: "member", server_id: sid, user_id: uid });
    if (res.profile) {
      const cur = memberListsRef.current[sid] || { members: [], profiles: {}, count: 0, at: 0 };
      memberListsRef.current = { ...memberListsRef.current, [sid]: { ...cur, profiles: { ...cur.profiles, [uid]: res.profile } } };
      setMemberLists(memberListsRef.current);
    }
    return res;
  }, []);

  // ---------- encrypted items and signed actions ----------

  /** Encrypt something server-wide (a name, rules, a nickname) with the server's history key. */
  const makeItem = useCallback(async (sid, kind, payload) => {
    const e = serversRef.current[sid];
    const keys = keysRef.current[sid];
    if (!e?.generations || !keys) throw new Error("This server is still loading. Try again in a moment.");
    try {
      return await SP.buildServerItem({ kind, serverId: sid, channelId: "", chainId: SP.historyChain(sid), generations: e.generations, keys, userId, device, payload });
    } catch (err) {
      throw friendly(err);
    }
  }, [userId, device]);

  // ---------- events ----------

  /** Open one encrypted server item (an event, an answer) with this server's keys. */
  const openItemOf = useCallback(async (sid, kind, item) => {
    const keys = keysRef.current[sid];
    if (!keys || !item) return { status: "waiting" };
    const sender = item.sender_id;
    if (sender !== userId && !chainOf(sender)) await loadPeers([sender]).catch(() => {});
    return SP.openServerItem({ kind, item, serverId: sid, channelId: "", keys, senderChain: chainOf(sender), senderDevices: devicesOf(sender), minCertVersion: sender === userId ? ownMinCertVersion : 1 });
  }, [userId, chainOf, devicesOf, loadPeers, ownMinCertVersion]);

  const loadEvents = useCallback((sid) => callFn("events", { action: "list", server_id: sid }), []);

  const eventCall = useCallback(async (sid, action, kind, content, payload = {}) => {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const item = content === null ? null : await makeItem(sid, kind, content);
        return await signed("events", action, { server_id: sid, ...payload, item });
      } catch (err) {
        if (attempt === 0 && err instanceof ApiError && err.code === "STALE_SERVER_KEYS") {
          await loadState(sid);
          continue;
        }
        throw err;
      }
    }
    return null;
  }, [makeItem, signed, loadState]);

  const createEvent = useCallback((sid, content) => eventCall(sid, "create_event", "event", content), [eventCall]);
  const updateEvent = useCallback((sid, eventId, content) => eventCall(sid, "update_event", "event", { ...content, event_id: eventId }, { event_id: eventId }), [eventCall]);
  const cancelEvent = useCallback((sid, eventId) => signed("events", "cancel_event", { server_id: sid, event_id: eventId }), [signed]);
  const rsvp = useCallback((sid, eventId, status) => eventCall(sid, "rsvp", "rsvp", status ? { status, event_id: eventId } : null, { event_id: eventId }), [eventCall]);

  /** A signed server action; reloads the server afterwards when it changes what members see. */
  const act = useCallback(async (sid, action, payload = {}, { reload = true } = {}) => {
    const res = await signed("servers", action, { server_id: sid, ...payload });
    if (reload) await loadState(sid).catch(() => {});
    return res;
  }, [signed, loadState]);

  /** The same, with an item built fresh (and built again once if the keys moved on meanwhile). */
  const actWithItem = useCallback(async (sid, action, kind, content, payload = {}, opts = {}) => {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const item = content === null ? null : await makeItem(sid, kind, content);
        return await act(sid, action, { ...payload, item }, opts);
      } catch (err) {
        if (attempt === 0 && err instanceof ApiError && err.code === "STALE_SERVER_KEYS") {
          await loadState(sid);
          continue;
        }
        throw err;
      }
    }
    return null;
  }, [makeItem, act, loadState]);

  const setServerProfile = useCallback((sid, profile) => actWithItem(sid, "set_server_profile", "server", {
    name: String(profile.name || "").slice(0, SP.MAX_NAME), description: String(profile.description || "").slice(0, 500), icon: String(profile.icon || "").slice(0, 8), color: profile.color || "", banner: profile.banner || "",
  }), [actWithItem]);

  /** Replace the server's emoji, stickers or AutoMod rules (slot), or clear them with null. */
  const setServerSet = useCallback((sid, slot, content) => actWithItem(sid, "set_server_set", slot, content, { slot }), [actWithItem]);

  const setServerRules = useCallback((sid, rules, intro) => actWithItem(sid, "set_server_rules", "rules", rules === null ? null : { rules, intro: intro || "" }), [actWithItem]);

  const updateSettings = useCallback((sid, changes) => act(sid, "update_server_settings", changes), [act]);

  const setNickname = useCallback((sid, nick, targetId = null) => actWithItem(sid, "set_nickname", "nick", nick ? { nick } : null, targetId && targetId !== userId ? { user_id: targetId } : {}), [actWithItem, userId]);

  const createChannel = useCallback(async (sid, { kind, name, topic = "", parentId = "", overwrites = [], history }) => {
    const res = await actWithItem(sid, "create_channel", "channel", { name, topic }, { kind, ...(parentId ? { parent_id: parentId } : {}), ...(overwrites.length ? { overwrites } : {}), ...(history ? { history } : {}) });
    // A private channel needs its own keys.
    scheduleWorker(sid);
    return res.channel;
  }, [actWithItem, scheduleWorker]);

  const updateChannel = useCallback(async (sid, channel, changes) => {
    const { name, topic, ...rest } = changes;
    const payload = { channel_id: channel.id, ...rest };
    let res;
    if (name !== undefined || topic !== undefined) {
      res = await actWithItem(sid, "update_channel", "channel", { name: name ?? channelName(channel), topic: topic ?? channelTopic(channel) }, payload);
    } else {
      res = await act(sid, "update_channel", payload);
    }
    if (rest.overwrites) scheduleWorker(sid);
    return res;
  }, [act, actWithItem, channelName, channelTopic, scheduleWorker]);

  const createRole = useCallback((sid, { name, color = "", permissions = 0, hoist = false, mentionable = false }) =>
    actWithItem(sid, "create_role", "role", { name, color }, { permissions, hoist, mentionable }), [actWithItem]);

  const updateRole = useCallback((sid, role, changes) => {
    const { name, color, ...rest } = changes;
    if ((name !== undefined || color !== undefined) && !role.is_everyone) {
      return actWithItem(sid, "update_role", "role", { name: name ?? roleName(role), color: color ?? roleColor(role) }, { role_id: role.id, ...rest });
    }
    return act(sid, "update_role", { role_id: role.id, ...rest });
  }, [act, actWithItem, roleName, roleColor]);

  // ---------- moderation ----------

  const modCall = useCallback((action, payload) => signed("moderation", action, payload), [signed]);

  /**
   * Report a member (and, if you choose, a message of theirs) to this server's moderators. It's
   * sealed to exactly the moderators the service names, with their keys, so only they can read it.
   */
  const reportToMods = useCallback(async (sid, { targetId, reason, note = "", quote = null, channelId = "", msgId = "" }) => {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const { recipients, moderators } = await callFn("moderation", { action: "report_recipients", server_id: sid, target_id: targetId });
      if (!moderators) throw new Error("This server has no moderators who can take reports yet. You can report to the Commonveil team instead.");
      await loadPeers(recipients.filter((u) => u !== userId));
      try {
        const item = await P2.buildReport({
          userId, device, serverId: sid, recipients, chains: chainsFor(recipients), keyring,
          payload: { type: "report", server_id: sid, target_id: targetId, reason, note, quote, channel_id: channelId, msg_id: msgId },
        });
        return await modCall("report", { server_id: sid, target_id: targetId, item });
      } catch (err) {
        if (attempt === 0 && err instanceof ApiError && ["RECIPIENTS_CHANGED", "STALE_KEYS", "MEMBER_NOT_READY"].includes(err.code)) continue;
        throw err;
      }
    }
    return null;
  }, [userId, device, keyring, chainsFor, loadPeers, modCall]);

  /** Names for people a moderator sees in reports and cases, who may not be in the member list. */
  const learnNames = useCallback((sid, ids) => {
    const known = memberListsRef.current[sid]?.profiles || {};
    for (const uid of [...new Set(ids)].filter((u) => u && u !== "system" && !known[u]).slice(0, 25)) memberCard(sid, uid).catch(() => {});
  }, [memberCard]);

  /** Reports you can read here, opened on this device. */
  const loadReports = useCallback(async (sid) => {
    const { reports, moderator } = await callFn("moderation", { action: "reports", server_id: sid });
    learnNames(sid, reports.flatMap((r) => [r.reporter_id, r.target_id, r.handled_by]));
    await loadPeers([...new Set(reports.map((r) => r.reporter_id))].filter((u) => u !== userId)).catch(() => {});
    const out = [];
    for (const r of reports) {
      const opened = await P2.openReport({ row: r, userId, keyring, senderChain: r.reporter_id === userId ? chainOf(userId) : chainOf(r.reporter_id), senderDevices: devicesOf(r.reporter_id) });
      out.push({ ...r, opened });
    }
    return { reports: out, moderator };
  }, [userId, keyring, chainOf, devicesOf, loadPeers, learnNames]);

  const caseItem = useCallback(async (sid, text) => (text && text.trim() ? makeItem(sid, "case", { reason: text.trim().slice(0, 1000) }) : null), [makeItem]);

  const warnMember = useCallback(async (sid, uid, reason, { reportId = "" } = {}) => {
    const res = await modCall("warn", { server_id: sid, user_id: uid, reason: await caseItem(sid, reason), ...(reportId ? { report_id: reportId } : {}) });
    if (res.applied) loadMembers(sid, { force: true }).catch(() => {});
    return res;
  }, [modCall, caseItem, loadMembers]);

  const addModNote = useCallback(async (sid, uid, text) => modCall("note", { server_id: sid, user_id: uid, reason: await caseItem(sid, text) }), [modCall, caseItem]);

  /** Cases, with their reasons opened here. */
  const loadCases = useCallback(async (sid, uid = null) => {
    const res = await callFn("moderation", { action: "cases", server_id: sid, ...(uid ? { user_id: uid } : {}) });
    learnNames(sid, res.cases.flatMap((c) => [c.actor_id, c.target_id]));
    const out = [];
    for (const c of res.cases) {
      const r = c.reason ? await openItemOf(sid, "case", c.reason) : null;
      out.push({ ...c, reasonText: r && (r.status === "ok" || r.status === "unverified") ? r.content.reason : "" });
    }
    return { cases: out, moderator: res.moderator };
  }, [openItemOf, learnNames]);

  const banMember = useCallback(async (sid, uid, { deleteSeconds = 0, reason = "", minutes = 0 } = {}) => {
    const payload = { user_id: uid, delete_seconds: deleteSeconds, minutes };
    if (reason.trim()) payload.reason = await makeItem(sid, "ban", { reason: reason.trim() });
    const res = await act(sid, "ban_member", payload);
    loadMembers(sid, { force: true }).catch(() => {});
    scheduleWorker(sid);
    return res;
  }, [act, makeItem, loadMembers, scheduleWorker]);

  const openBanReason = useCallback(async (sid, reason) => {
    if (!reason) return "";
    const sender = reason.sender_id;
    if (sender !== userId) await loadPeers([sender]).catch(() => {});
    const r = await SP.openServerItem({ kind: "ban", item: reason, serverId: sid, keys: keysRef.current[sid] || new ChainKeys(), senderChain: chainOf(sender), senderDevices: devicesOf(sender) });
    return readable(r) ? r.content.reason : "";
  }, [userId, loadPeers, chainOf, devicesOf]);

  // ---------- joining, leaving, creating ----------

  const joinServer = useCallback(async ({ code = null, serverId = null, site = "" }) => {
    const payload = code ? { invite_code: code } : { server_id: serverId };
    // A server on another site: our site relays the signed request there (docs/FEDERATION.md).
    const res = site
      ? await callFn("servers", { ...(await SP.serverRequest({ userId, device, action: "join_server", payload })), _site: site })
      : await signed("servers", "join_server", payload);
    const list = await callFn("servers", { action: "list" });
    applyList(list);
    await loadState(res.server_id).catch(() => {});
    return res.server_id;
  }, [signed, applyList, loadState, userId, device]);

  const leaveServer = useCallback(async (sid) => {
    await signed("servers", "leave_server", { server_id: sid });
    dropServer(sid);
  }, [signed, dropServer]);

  const deleteServer = useCallback(async (sid) => {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const res = await signed("servers", "delete_server", { server_id: sid, confirm: "DELETE" });
      if (res.done) {
        dropServer(sid);
        return;
      }
    }
    throw new Error("Deleting is taking longer than expected. Try again: it carries on where it stopped.");
  }, [signed, dropServer]);

  /** Make a server from a template, set up its keys here, then give it its (encrypted) name. */
  const createServer = useCallback(async ({ template, name, icon = "", color = "" }) => {
    const { server_id: sid } = await signed("servers", "create_server", { template });
    const list = await callFn("servers", { action: "list" });
    applyList(list);
    await loadState(sid);
    await serviceKeys(sid);
    if (!keysRef.current[sid]?.size) await loadState(sid);
    try {
      await setServerProfile(sid, { name, icon, color, description: "" });
    } catch {
      /* the server's there; it can be named in its settings */
    }
    return sid;
  }, [signed, applyList, loadState, serviceKeys, setServerProfile]);

  // ---------- invites ----------

  const createInvite = useCallback(async (sid, { maxAge = 604_800, maxUses = 0, channelId = "" } = {}) => {
    const look = serverLook(sid);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const code = inviteCode();
      const secret = newInviteSecret();
      const preview = await sealInvitePreview({ code, secret, preview: { name: look.name, description: look.description, icon: look.icon, color: look.color } });
      try {
        const res = await signed("servers", "create_invite", { server_id: sid, code, preview, max_age_seconds: maxAge, max_uses: maxUses, ...(channelId ? { channel_id: channelId } : {}) });
        return { ...res.invite, secret, url: `${window.location.origin}/invite/${code}#${secret}` };
      } catch (err) {
        if (err instanceof ApiError && err.code === "CODE_TAKEN") continue;
        throw err;
      }
    }
    throw new Error("Couldn't make an invite. Try again.");
  }, [serverLook, signed]);

  const listInvites = useCallback((sid) => callFn("servers", { action: "invites", server_id: sid }).then((r) => r.invites), []);
  const revokeInvite = useCallback((sid, code) => act(sid, "revoke_invite", { code }, { reload: false }), [act]);

  // ---------- discovery ----------

  const discover = useCallback((tag = null, site = "") => callFn("servers", { action: "discover", ...(tag ? { tag } : {}), ...(site ? { _site: site } : {}) }), []);

  // ---------- tickets ----------

  const listTickets = useCallback((sid) => callFn("servers", { action: "tickets", server_id: sid }).then((r) => r.tickets), []);

  const openTicket = useCallback(async (sid, channelId) => {
    const res = await signed("servers", "open_ticket", { server_id: sid, channel_id: channelId });
    const conversation = await refreshConversation(res.conversation_id);
    return { ...res, conversation };
  }, [signed, refreshConversation]);

  const setTicketStatus = useCallback((sid, conversationId, status) => act(sid, "set_ticket_status", { conversation_id: conversationId, status }, { reload: false }), [act]);

  // ---------- value ----------

  const value = useMemo(() => ({
    loaded,
    loadError,
    servers,
    order,
    rows,
    opened,
    hasMore,
    readState,
    prefs,
    unread,
    memberLists,
    keysTick,
    // names and looks
    serverLook,
    serverName,
    channelName,
    channelTopic,
    roleName,
    roleColor,
    serverRules,
    serverEmoji,
    automodOf,
    memberName,
    nickOf,
    memberColor,
    profileOf,
    rolesOfMember,
    // permissions and keys
    permsFor,
    can,
    myTop,
    keyState,
    voiceEpoch,
    chainKeyAt,
    isStaffIn: (sid, member) => {
      const e = servers[sid];
      return e?.roles ? isStaff(e.server, e.roles, member) : false;
    },
    // loading
    loadState,
    openView,
    loadOlder,
    viewKey,
    threadOf,
    postsOf,
    loadPins,
    loadMembers,
    memberCard,
    // on this device
    notifyLevel,
    setNotifyLevel,
    effectiveLevel,
    savedList,
    isSaved,
    toggleSaved,
    noteOf,
    setNote,
    folders,
    moveToFolder,
    renameFolder,
    // sending
    sendText,
    sendPost,
    sendPoll,
    vote,
    react,
    edit,
    deleteMessage,
    pinMessage, lockThread, openItemOf, modCall, reportToMods, loadReports, warnMember, addModNote, loadCases, caseItem, loadEvents, createEvent, updateEvent, cancelEvent, rsvp,
    // unread and local preferences
    markChannelRead,
    markServerRead,
    setActiveChannel,
    muted,
    toggleMute,
    toggleCollapsed,
    moveServer,
    // server management
    act,
    setServerProfile,
    setServerRules,
    setServerSet,
    updateSettings,
    setNickname,
    createChannel,
    updateChannel,
    createRole,
    updateRole,
    banMember,
    openBanReason,
    joinServer,
    leaveServer,
    deleteServer,
    createServer,
    createInvite,
    listInvites,
    revokeInvite,
    openInvitePreview,
    discover,
    listTickets,
    openTicket,
    setTicketStatus,
    renewKeys,
    retryKeys: (sid) => serviceKeys(sid),
  }), [
    notifyLevel, setNotifyLevel, effectiveLevel, savedList, isSaved, toggleSaved, noteOf, setNote, folders, moveToFolder, renameFolder,
    loaded, loadError, servers, order, rows, opened, hasMore, readState, prefs, unread, memberLists, keysTick,
    serverLook, serverName, channelName, channelTopic, roleName, roleColor, serverRules, serverEmoji, automodOf, memberName, nickOf, memberColor, profileOf, rolesOfMember,
    permsFor, can, myTop, keyState, loadState, openView, loadOlder, threadOf, postsOf, loadPins, loadMembers, memberCard,
    sendText, sendPost, sendPoll, vote, react, edit, deleteMessage, pinMessage, lockThread, openItemOf, modCall, reportToMods, loadReports, warnMember, addModNote, loadCases, caseItem, loadEvents, createEvent, updateEvent, cancelEvent, rsvp, markChannelRead, markServerRead, setActiveChannel, muted, toggleMute,
    toggleCollapsed, moveServer, act, setServerProfile, setServerRules, setServerSet, updateSettings, setNickname, createChannel, updateChannel,
    createRole, updateRole, banMember, openBanReason, joinServer, leaveServer, deleteServer, createServer, createInvite, listInvites,
    revokeInvite, discover, listTickets, openTicket, setTicketStatus, renewKeys, serviceKeys,
  ]);

  return <ServerContext.Provider value={value}>{children}</ServerContext.Provider>;
}
