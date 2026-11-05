// Conversations and messages for the signed-in, set-up account: polling,
// decryption with signature checks, sending with automatic key refresh.
// Replies, reactions and edits are messages too, put together on this device (thread.js).
// Disappearing timers and group admins are conversation settings the server enforces.
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError, callFn } from "@/lib/api";
import { useSecure } from "./SecureContext.jsx";
import * as P from "./protocol.js";
import * as S from "./store.js";
import { buildThread, hideAt, isShowing, searchThreads } from "./thread.js";
import { votePayload } from "./polls.js";
import { DEFAULT_ALERTS, alertText, cleanAlerts, showAlert } from "./alerts.js";

const ChatContext = createContext(null);

export function useChat() {
  const ctx = useContext(ChatContext);
  if (!ctx) throw new Error("useChat must be used inside ChatProvider");
  return ctx;
}

const byCreated = (a, b) => String(a.created_date).localeCompare(String(b.created_date));
const RETRYABLE = new Set(["STALE_KEYS", "RECIPIENTS_CHANGED"]);

// Base44 caps how many queries an app makes each minute, shared by everyone using it, so
// polling is frugal: quick while a conversation is active, slower when it's quiet, slow in the
// background, and backing off whenever the service says it's busy.
const POLL_ACTIVE_MS = 5_000;
const POLL_QUIET_MS = 15_000;
const POLL_HIDDEN_MS = 60_000;
const ACTIVE_FOR_MS = 2 * 60_000;
const CONVERSATIONS_EVERY_MS = 30_000;
const BACKOFF_MAX_MS = 60_000;
// A message that couldn't be delivered because the service was busy is sent again as the same
// message (same id), so it can't arrive twice.
const SEND_RETRY_MS = [1_500, 4_000, 8_000];
/** How often disappearing messages are checked and dropped from memory. */
const EXPIRY_CHECK_MS = 15_000;
/** Without any, the clock the conversation goes by (edit windows) is still moved on now and then. */
const CLOCK_MS = 5 * 60_000;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const isTransient = (err) => err instanceof ApiError && (err.code === "UPSTREAM_BUSY" || err.code === "NETWORK");

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

const deliver = (body) => withRetry(() => callFn("messages", body));

export function ChatProvider({ children }) {
  const { userId, device, keyring, peers, loadPeers, chainsFor, chainOf, devicesOf, ownMinCertVersion, refresh: refreshSecure } = useSecure();
  const navigate = useNavigate();
  const [conversations, setConversations] = useState([]);
  const [loaded, setLoaded] = useState(false);
  const [profiles, setProfiles] = useState({});
  const [messages, setMessages] = useState({});
  const [hasMore, setHasMore] = useState({});
  const [opened, setOpened] = useState({});
  const [titles, setTitles] = useState({});
  const [readState, setReadState] = useState({});
  const [memberPins, setMemberPins] = useState(null);
  const [now, setNow] = useState(() => Date.now());
  const [alerts, setAlerts] = useState(DEFAULT_ALERTS);
  const memberPinsRef = useRef(null);
  // Groups started from this browser: their members were chosen here, so they're pinned as they are.
  const startedHere = useRef(new Set());
  const cursor = useRef(null);
  const convCursor = useRef(null);
  const convCheckedAt = useRef(0);
  const needConversations = useRef(false);
  const lastActivity = useRef(Date.now());
  const conversationsRef = useRef([]);
  const polling = useRef(false);
  // Where "load earlier messages" carries on from, per conversation (the server's own paging cursor).
  const olderCursor = useRef({});
  // Messages that arrived after this point can raise an alert; nothing from before the page loaded does.
  const alertsFrom = useRef(null);
  const alerted = useRef(new Set());
  const alertsRef = useRef(DEFAULT_ALERTS);
  const activeConversation = useRef(null);
  const openedRef = useRef({});
  const messagesRef = useRef({});
  const navigateRef = useRef(navigate);
  // Sender devices we've already re-fetched keys for, so an unknown device triggers one refresh, not a loop.
  const refetchedDevices = useRef(new Set());
  // Others that ride along on the same poll request (servers): { params(), onPage(page), more(page) }.
  const pollExtensions = useRef(new Set());

  /** Add to every poll request, and get each page. Returns a function that removes it. */
  const addPollExtension = useCallback((ext) => {
    pollExtensions.current.add(ext);
    return () => pollExtensions.current.delete(ext);
  }, []);

  /** Something happened worth polling quickly for (used by servers too). */
  const touchActivity = useCallback(() => {
    lastActivity.current = Date.now();
  }, []);

  useEffect(() => {
    openedRef.current = opened;
  }, [opened]);

  useEffect(() => {
    messagesRef.current = messages;
  }, [messages]);

  useEffect(() => {
    navigateRef.current = navigate;
  }, [navigate]);

  useEffect(() => {
    let cancelled = false;
    S.loadAlerts(userId)
      .then((saved) => {
        if (cancelled) return;
        const clean = cleanAlerts(saved || DEFAULT_ALERTS);
        alertsRef.current = clean;
        setAlerts(clean);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [userId]);

  const updateAlerts = useCallback(async (changes) => {
    const next = cleanAlerts({ ...alertsRef.current, ...changes });
    alertsRef.current = next;
    setAlerts(next);
    await S.saveAlerts(userId, next);
    return next;
  }, [userId]);

  /**
   * True if we know the device that signed this item. If not, ask for fresh keys once
   * and let the caller wait, rather than caching an "unverified" result from stale data.
   */
  const knowsDevice = useCallback((senderId, deviceId) => {
    if (devicesOf(senderId).some((d) => d.device_id === deviceId)) return true;
    const tag = `${senderId}:${deviceId}`;
    if (refetchedDevices.current.has(tag)) return true;
    refetchedDevices.current.add(tag);
    if (senderId === userId) refreshSecure({ silent: true });
    else loadPeers([senderId], { force: true }).catch(() => {});
    return false;
  }, [devicesOf, userId, refreshSecure, loadPeers]);

  const saveMemberPins = useCallback(async (next) => {
    memberPinsRef.current = next;
    setMemberPins(next);
    await S.saveMemberPins(userId, next);
  }, [userId]);

  /** Pin the given members for a conversation, merged with what was already pinned. */
  const pinMembers = useCallback(async (conversationId, ids, { replace = false } = {}) => {
    const current = memberPinsRef.current || {};
    const base = replace ? [] : current[conversationId] || [];
    await saveMemberPins({ ...current, [conversationId]: [...new Set([...base, ...ids])] });
  }, [saveMemberPins]);

  /**
   * Why sending to this conversation should wait, or null. The server decides
   * membership, so anyone new must be seen by you before your words reach them.
   */
  const membershipProblem = useCallback((c) => {
    const pins = memberPinsRef.current;
    if (c.kind === "dm" && (c.member_ids.length !== 2 || !c.member_ids.includes(userId))) {
      return "This direct message has an unexpected member list, so sending is blocked.";
    }
    if (!pins || !pins[c.id]) return "Still checking who's in this conversation. Try again in a moment.";
    if (c.member_ids.some((id) => !pins[c.id].includes(id))) return "Someone new is in this conversation. Check who it is before sending.";
    return null;
  }, [userId]);

  const newMembersOf = useCallback((c) => {
    const pin = memberPins?.[c.id];
    return pin ? c.member_ids.filter((id) => !pin.includes(id)) : [];
  }, [memberPins]);

  const acknowledgeMembers = useCallback((c) => pinMembers(c.id, c.member_ids, { replace: true }), [pinMembers]);

  const sortConversations = (list) =>
    list.sort((a, b) => String(b.last_message_at || b.created_date).localeCompare(String(a.last_message_at || a.created_date)));

  const mergeConversations = useCallback((list, { replace = false } = {}) => {
    setConversations((prev) => {
      const map = new Map(replace ? [] : prev.map((c) => [c.id, c]));
      for (const c of list) map.set(c.id, c);
      return sortConversations([...map.values()]);
    });
  }, []);

  /** Note a new message without overwriting anything else that changed about the conversation meanwhile. */
  const touchConversation = useCallback((conversationId, at) => {
    setConversations((prev) => sortConversations(prev.map((c) =>
      c.id === conversationId && String(at) > String(c.last_message_at || "") ? { ...c, last_message_at: at } : c,
    )));
  }, []);

  const mergeMessages = useCallback((list) => {
    if (!list.length) return;
    setMessages((prev) => {
      const next = { ...prev };
      for (const m of list) {
        const current = next[m.conversation_id] || [];
        const i = current.findIndex((x) => x.id === m.id);
        const updated = i >= 0 ? current.map((x) => (x.id === m.id ? m : x)) : [...current, m];
        next[m.conversation_id] = updated.sort(byCreated);
      }
      return next;
    });
  }, []);

  // Disappearing messages: hidden the moment their time is up (the rows are worked out against
  // `now`), and dropped from memory too.
  useEffect(() => {
    let clockMovedAt = Date.now();
    const t = setInterval(() => {
      const at = Date.now();
      const all = Object.values(messagesRef.current).flat();
      const timed = all.some((m) => hideAt(m, openedRef.current[m.id]) !== null);
      if (timed || at - clockMovedAt >= CLOCK_MS) {
        clockMovedAt = at;
        setNow(at);
      }
      const gone = new Set(all.filter((m) => !isShowing(m, openedRef.current[m.id], at)).map((m) => m.id));
      if (!gone.size) return;
      setMessages((prev) => {
        const next = {};
        for (const [cid, list] of Object.entries(prev)) next[cid] = list.filter((m) => !gone.has(m.id));
        return next;
      });
      setOpened((prev) => {
        const next = { ...prev };
        for (const id of gone) delete next[id];
        return next;
      });
    }, EXPIRY_CHECK_MS);
    return () => clearInterval(t);
  }, []);

  const profilesRef = useRef({});
  useEffect(() => {
    profilesRef.current = profiles;
  }, [profiles]);

  // Stable, so the polling loop below isn't restarted every time a profile arrives.
  const loadProfiles = useCallback(async (ids) => {
    const missing = [...new Set(ids)].filter((id) => id && !profilesRef.current[id]);
    if (!missing.length) return;
    const { profiles: rows } = await callFn("profile", { action: "get_many", user_ids: missing.slice(0, 100) });
    setProfiles((prev) => {
      const next = { ...prev };
      for (const p of rows) next[p.user_id] = p;
      return next;
    });
  }, []);

  useEffect(() => {
    conversationsRef.current = conversations;
  }, [conversations]);

  /**
   * Starting cursors and the conversation list. Returns false if the service couldn't be
   * reached; the list keeps showing as loading (not as empty) until this works.
   */
  const loadStart = useCallback(async () => {
    try {
      const start = await callFn("messages", { action: "poll" });
      const { conversations: list } = await callFn("conversations", { action: "list" });
      const pins = await S.loadMemberPins(userId);
      memberPinsRef.current = pins;
      setMemberPins(pins);
      mergeConversations(list, { replace: true });
      setReadState(await S.loadReadState(userId));
      cursor.current = start.cursor;
      convCursor.current = start.conversations_cursor || start.cursor;
      convCheckedAt.current = Date.now();
      if (!alertsFrom.current) alertsFrom.current = start.cursor;
      setLoaded(true);
      const memberIds = list.flatMap((c) => c.member_ids);
      loadPeers(memberIds).catch(() => {});
      loadProfiles(memberIds).catch(() => {});
      return true;
    } catch {
      return false;
    }
  }, [userId, mergeConversations, loadPeers, loadProfiles]);

  // Poll for changes. The first round loads the start; after that, messages every few seconds
  // and conversation changes every half minute (sooner if a message arrives for one we don't have).
  useEffect(() => {
    let timer;
    let stopped = false;
    let backoff = 0;
    cursor.current = null;
    convCursor.current = null;
    const delay = () => {
      if (backoff) return backoff;
      if (document.visibilityState !== "visible") return POLL_HIDDEN_MS;
      return Date.now() - lastActivity.current < ACTIVE_FOR_MS ? POLL_ACTIVE_MS : POLL_QUIET_MS;
    };
    const schedule = (ms) => {
      clearTimeout(timer);
      if (!stopped) timer = setTimeout(tick, ms);
    };
    const pollOnce = async () => {
      let page;
      let more = false;
      do {
        const withConversations = needConversations.current || Date.now() - convCheckedAt.current > CONVERSATIONS_EVERY_MS;
        const extensions = [...pollExtensions.current];
        const extra = {};
        for (const ext of extensions) Object.assign(extra, ext.params?.() || {});
        page = await callFn("messages", {
          action: "poll",
          since: cursor.current,
          ...(withConversations ? { conversations_since: convCursor.current } : {}),
          ...extra,
        });
        cursor.current = page.cursor;
        for (const ext of extensions) {
          try {
            ext.onPage?.(page);
          } catch {
            /* one extension's trouble doesn't stop the others */
          }
        }
        more = extensions.some((ext) => ext.more?.(page));
        if (page.conversation_ids) {
          needConversations.current = false;
          convCheckedAt.current = Date.now();
          convCursor.current = page.conversations_cursor;
          if (page.conversations.length) {
            mergeConversations(page.conversations);
            const ids = page.conversations.flatMap((c) => c.member_ids);
            loadPeers(ids).catch(() => {});
            loadProfiles(ids).catch(() => {});
          }
          // Drop conversations we've left or been removed from.
          setConversations((prev) => prev.filter((c) => page.conversation_ids.includes(c.id)));
        }
        if (page.messages.length) {
          const known = new Set(conversationsRef.current.map((c) => c.id));
          if (!page.conversation_ids && page.messages.some((m) => !known.has(m.conversation_id))) needConversations.current = true;
          if (page.messages.some((m) => m.sender_id !== userId)) lastActivity.current = Date.now();
          mergeMessages(page.messages);
        }
      } while (page.has_more || more || (needConversations.current && !page.conversation_ids));
    };
    const tick = async () => {
      if (!polling.current) {
        polling.current = true;
        try {
          if (!cursor.current) {
            if (!(await loadStart())) throw new Error("not started");
          } else {
            await pollOnce();
          }
          backoff = 0;
        } catch {
          backoff = Math.min(BACKOFF_MAX_MS, backoff ? backoff * 2 : POLL_QUIET_MS);
        } finally {
          polling.current = false;
        }
      }
      schedule(delay());
    };
    const onVisible = () => {
      if (document.visibilityState === "visible" && !backoff) schedule(500);
    };
    document.addEventListener("visibilitychange", onVisible);
    schedule(0);
    return () => {
      stopped = true;
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [userId, loadStart, mergeConversations, mergeMessages, loadPeers, loadProfiles]);

  const nameOf = useCallback((id) => {
    if (id === userId) return "You";
    const p = profiles[id];
    return p ? p.display_name || p.username : "Member";
  }, [profiles, userId]);

  /**
   * A notification for a message that just arrived, if they're switched on and you're not
   * already looking at that conversation. Reactions and edits don't raise one.
   */
  const maybeAlert = useCallback((m, result) => {
    const settings = alertsRef.current;
    if (!settings.notify || m.sender_id === userId || alerted.current.has(m.id)) return;
    if (!alertsFrom.current || String(m.created_date) <= String(alertsFrom.current)) return;
    if (result.content?.type !== "text" || (result.status !== "ok" && result.status !== "unverified")) return;
    alerted.current.add(m.id);
    const looking = document.visibilityState === "visible" && document.hasFocus() && activeConversation.current === m.conversation_id;
    if (looking) return;
    const sender = profilesRef.current[m.sender_id];
    showAlert({
      body: alertText(settings, sender ? sender.display_name || sender.username : ""),
      tag: `commonveil-${m.conversation_id}`,
      onClick: () => navigateRef.current(`/app/c/${m.conversation_id}`),
    });
  }, [userId]);

  // Decrypt anything new once the sender's keys are known.
  useEffect(() => {
    if (!keyring) return;
    let cancelled = false;
    const membersOf = new Map(conversations.map((c) => [c.id, new Set(c.member_ids)]));
    (async () => {
      const results = {};
      const fresh = [];
      for (const list of Object.values(messages)) {
        for (const m of list) {
          const cacheKey = `${m.id}:${m.deleted ? "d" : "v"}`;
          const prev = opened[m.id];
          if (prev && prev.cacheKey === cacheKey) continue;
          const senderChain = chainOf(m.sender_id);
          // Wait for a current member's keys; someone who has left can't be looked up, so open without verification.
          const members = membersOf.get(m.conversation_id);
          if (!members) continue;
          const departed = !members.has(m.sender_id);
          const senderReady = m.sender_id === userId || peers[m.sender_id]?.ready !== undefined || departed;
          if (!senderReady && !m.deleted) continue;
          if (!m.deleted && !departed && !knowsDevice(m.sender_id, m.device_id)) continue;
          const r = await P.openItem({
            kind: "message",
            item: m,
            userId,
            keyring,
            senderChain,
            senderDevices: devicesOf(m.sender_id),
            minCertVersion: m.sender_id === userId ? ownMinCertVersion : 1,
          });
          results[m.id] = { ...r, cacheKey };
          if (!prev) fresh.push([m, r]);
          if (cancelled) return;
        }
      }
      if (!cancelled && Object.keys(results).length) {
        setOpened((prev) => ({ ...prev, ...results }));
        for (const [m, r] of fresh) maybeAlert(m, r);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [messages, conversations, keyring, peers, userId, chainOf, devicesOf, opened, knowsDevice, ownMinCertVersion, maybeAlert]);

  // Group names.
  useEffect(() => {
    if (!keyring) return;
    (async () => {
      const results = {};
      for (const c of conversations) {
        if (c.kind !== "group" || !c.title) continue;
        const key = `${c.title.item_id}`;
        if (titles[c.id]?.key === key) continue;
        if (c.title.sender_id !== userId && peers[c.title.sender_id]?.ready === undefined) continue;
        if (c.member_ids.includes(c.title.sender_id) && !knowsDevice(c.title.sender_id, c.title.device_id)) continue;
        const r = await P.openItem({
          kind: "title",
          item: { ...c.title, conversation_id: c.id },
          userId,
          keyring,
          senderChain: chainOf(c.title.sender_id),
          senderDevices: devicesOf(c.title.sender_id),
          minCertVersion: c.title.sender_id === userId ? ownMinCertVersion : 1,
        });
        results[c.id] = { ...r, key };
      }
      if (Object.keys(results).length) setTitles((prev) => ({ ...prev, ...results }));
    })();
  }, [conversations, keyring, peers, userId, chainOf, devicesOf, titles, knowsDevice, ownMinCertVersion]);

  // Membership pins. A direct message is pinned on first sight: it's always you and one other
  // person. A group first seen here pins only you, so everyone else in it is shown as new and
  // sending waits until you've looked (unless you started it from this browser). People who
  // leave drop out of the pin, so if they come back they're flagged again.
  useEffect(() => {
    const pins = memberPinsRef.current;
    if (!pins) return;
    let changed = false;
    const next = { ...pins };
    for (const c of conversations) {
      const current = c.member_ids || [];
      if (!next[c.id]) {
        next[c.id] = c.kind === "dm" || startedHere.current.has(c.id) ? [...current] : current.filter((id) => id === userId);
        changed = true;
        continue;
      }
      const kept = next[c.id].filter((id) => current.includes(id));
      if (kept.length !== next[c.id].length) {
        next[c.id] = kept;
        changed = true;
      }
    }
    if (changed) saveMemberPins(next).catch(() => {});
  }, [conversations, saveMemberPins, userId]);

  /** The newest page. If earlier pages were already loaded, where they left off still stands. */
  const openConversation = useCallback(async (conversationId) => {
    lastActivity.current = Date.now();
    activeConversation.current = conversationId;
    const res = await callFn("messages", { action: "list", conversation_id: conversationId });
    mergeMessages(res.messages);
    if (!(conversationId in olderCursor.current)) {
      olderCursor.current[conversationId] = res.before;
      setHasMore((prev) => ({ ...prev, [conversationId]: res.has_more }));
    }
  }, [mergeMessages]);

  const closeConversation = useCallback((conversationId) => {
    if (activeConversation.current === conversationId) activeConversation.current = null;
  }, []);

  /** One more page back. Returns how many messages came. */
  const loadOlder = useCallback(async (conversationId) => {
    const before = olderCursor.current[conversationId];
    if (!before) return 0;
    const res = await withRetry(() => callFn("messages", { action: "list", conversation_id: conversationId, before }));
    mergeMessages(res.messages);
    olderCursor.current[conversationId] = res.has_more ? res.before : null;
    setHasMore((prev) => ({ ...prev, [conversationId]: res.has_more }));
    return res.messages.length;
  }, [mergeMessages]);

  /**
   * For search: fetch earlier messages for every conversation, a few pages each, so they can be
   * decrypted and searched here. Returns false once there's nothing further back anywhere.
   */
  const loadHistory = useCallback(async ({ pages = 3 } = {}) => {
    let more = false;
    for (const c of conversationsRef.current) {
      if (!(c.id in olderCursor.current)) {
        const res = await withRetry(() => callFn("messages", { action: "list", conversation_id: c.id }));
        mergeMessages(res.messages);
        olderCursor.current[c.id] = res.has_more ? res.before : null;
        setHasMore((prev) => ({ ...prev, [c.id]: res.has_more }));
      }
      for (let i = 0; i < pages && olderCursor.current[c.id]; i += 1) await loadOlder(c.id);
      if (olderCursor.current[c.id]) more = true;
    }
    return more;
  }, [mergeMessages, loadOlder]);

  const markRead = useCallback(async (conversationId) => {
    const list = messages[conversationId] || [];
    const last = list[list.length - 1];
    if (!last || readState[conversationId] === last.created_date) return;
    const next = { ...readState, [conversationId]: last.created_date };
    setReadState(next);
    await S.saveReadState(userId, next);
  }, [messages, readState, userId]);

  const isUnread = useCallback((c) => {
    if (!c.last_message_at) return false;
    const seen = readState[c.id];
    const list = messages[c.id] || [];
    const last = list[list.length - 1];
    if (last && last.sender_id === userId && String(last.created_date) >= String(c.last_message_at)) return false;
    return !seen || String(c.last_message_at) > String(seen);
  }, [readState, messages, userId]);

  // The unread count in the tab title, if it's switched on. It never says from whom.
  useEffect(() => {
    if (!alerts.titleCount) return undefined;
    const count = conversations.filter(isUnread).length;
    document.title = count ? `(${count}) Commonveil` : "Commonveil";
    return () => {
      document.title = "Commonveil";
    };
  }, [alerts.titleCount, conversations, isUnread]);

  const refreshConversation = useCallback(async (conversationId) => {
    const { conversation } = await callFn("conversations", { action: "get", conversation_id: conversationId });
    mergeConversations([conversation]);
    await loadPeers(conversation.member_ids, { force: true });
    return conversation;
  }, [mergeConversations, loadPeers]);

  /**
   * Send something built for the conversation as it is right now. If the server says the
   * members or their keys changed, refresh once and build it again: the membership check
   * runs every time, so a refresh can't quietly add recipients.
   */
  const sendBuilt = useCallback(async (conversation, build) => {
    lastActivity.current = Date.now();
    let conv = conversation;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const problem = membershipProblem(conv);
      if (problem) throw new Error(problem);
      try {
        const body = await build(conv, chainsFor(conv.member_ids));
        const res = await deliver(body);
        mergeMessages([res.message]);
        touchConversation(conv.id, res.message.created_date);
        return res.message;
      } catch (err) {
        if (attempt === 0 && err instanceof ApiError && RETRYABLE.has(err.code)) {
          conv = await refreshConversation(conv.id);
          continue;
        }
        throw err;
      }
    }
    return null;
  }, [chainsFor, mergeMessages, touchConversation, refreshConversation, membershipProblem]);

  const send = useCallback((conversation, text, { replyTo = null } = {}) =>
    sendBuilt(conversation, (conv, chains) => P.buildMessage({ userId, device, conversation: conv, chains, text, keyring, replyTo })),
  [sendBuilt, userId, device, keyring]);

  const react = useCallback((conversation, message, emoji, remove = false) =>
    sendBuilt(conversation, (conv, chains) => P.buildReaction({ userId, device, conversation: conv, chains, keyring, target: message.msg_id, emoji, remove })),
  [sendBuilt, userId, device, keyring]);

  /** A poll (made with polls.js pollPayload), or a vote on one. */
  const sendPoll = useCallback((conversation, poll) =>
    sendBuilt(conversation, (conv, chains) => P.buildPayloadMessage({ userId, device, conversation: conv, chains, keyring, payload: poll })),
  [sendBuilt, userId, device, keyring]);

  const vote = useCallback((conversation, message, choices) =>
    sendBuilt(conversation, (conv, chains) => P.buildPayloadMessage({ userId, device, conversation: conv, chains, keyring, payload: votePayload(message.msg_id, choices) })),
  [sendBuilt, userId, device, keyring]);

  const editMessage = useCallback((conversation, message, text) =>
    sendBuilt(conversation, (conv, chains) => P.buildEdit({ userId, device, conversation: conv, chains, keyring, target: message.msg_id, text })),
  [sendBuilt, userId, device, keyring]);

  const setTitle = useCallback(async (conversation, title) => {
    const problem = membershipProblem(conversation);
    if (problem) throw new Error(problem);
    const body = await P.buildTitle({ userId, device, conversation, chains: chainsFor(conversation.member_ids), title, keyring });
    const res = await callFn("conversations", body);
    mergeConversations([res.conversation]);
    return res.conversation;
  }, [userId, device, keyring, chainsFor, mergeConversations, membershipProblem]);

  /** A conversation setting that needs this device's signature. */
  const conversationAction = useCallback(async (action, payload) => {
    const res = await callFn("conversations", await P.signedRequest({ userId, device, action, payload }));
    if (res.conversation) mergeConversations([res.conversation]);
    return res.conversation;
  }, [userId, device, mergeConversations]);

  const setExpiry = useCallback((c, seconds) => conversationAction("set_expiry", { conversation_id: c.id, seconds }), [conversationAction]);
  const setAdmin = useCallback((c, memberId, admin) => conversationAction("set_admin", { conversation_id: c.id, user_id: memberId, admin }), [conversationAction]);
  const removeMember = useCallback((c, memberId) => conversationAction("remove_member", { conversation_id: c.id, user_id: memberId }), [conversationAction]);

  const startDm = useCallback(async (username) => {
    const res = await callFn("conversations", await P.prepareCreateDm({ userId, device, username }));
    const conv = res.conversation;
    // A DM is exactly two people; anything else is refused before it's pinned.
    if (!memberPinsRef.current?.[conv.id] && conv.member_ids.length === 2 && conv.member_ids.includes(userId)) {
      await pinMembers(conv.id, conv.member_ids, { replace: true });
    }
    mergeConversations([conv]);
    await Promise.all([loadPeers(conv.member_ids, { force: true }), loadProfiles(conv.member_ids)]);
    return conv;
  }, [userId, device, pinMembers, mergeConversations, loadPeers, loadProfiles]);

  /** members: [{ username, user_id }] as found by exact lookup. Only these are pinned. */
  const startGroup = useCallback(async (members) => {
    const res = await callFn("conversations", await P.prepareCreateGroup({ userId, device, usernames: members.map((m) => m.username) }));
    startedHere.current.add(res.conversation.id);
    await pinMembers(res.conversation.id, [userId, ...members.map((m) => m.user_id)], { replace: true });
    mergeConversations([res.conversation]);
    await Promise.all([loadPeers(res.conversation.member_ids, { force: true }), loadProfiles(res.conversation.member_ids)]);
    return { conversation: res.conversation };
  }, [userId, device, pinMembers, mergeConversations, loadPeers, loadProfiles]);

  /** Needs a signature from this device. Only the people you named are pinned as known. */
  const addMembers = useCallback(async (conversation, usernames) => {
    const found = [];
    for (const u of usernames) found.push((await callFn("profile", { action: "find", username: u })).profile.user_id);
    const request = await P.signedRequest({ userId, device, action: "add_members", payload: { conversation_id: conversation.id, usernames } });
    const res = await callFn("conversations", request);
    await pinMembers(conversation.id, found);
    mergeConversations([res.conversation]);
    await Promise.all([loadPeers(res.conversation.member_ids, { force: true }), loadProfiles(res.conversation.member_ids)]);
    return res.conversation;
  }, [userId, device, pinMembers, mergeConversations, loadPeers, loadProfiles]);

  const leave = useCallback(async (conversation) => {
    await callFn("conversations", await P.signedRequest({ userId, device, action: "leave", payload: { conversation_id: conversation.id } }));
    setConversations((prev) => prev.filter((c) => c.id !== conversation.id));
  }, [userId, device]);

  const deleteMessage = useCallback(async (message) => {
    await callFn("messages", await P.signedRequest({ userId, device, action: "delete", payload: { message_id: message.id } }));
    mergeMessages([{ ...message, deleted: true, envelope: null, signature: null }]);
  }, [userId, device, mergeMessages]);

  /** The unique @username. Display names are chosen freely, so anyone can pick someone else's. */
  const handleOf = useCallback((id) => (profiles[id]?.username ? `@${profiles[id].username}` : ""), [profiles]);

  /** Only a group name whose signature checks out is shown; anything else falls back to who's in it. */
  const conversationName = useCallback((c) => {
    if (c.kind === "group") {
      const t = titles[c.id];
      if (t && t.status === "ok" && t.text) return t.text;
      const others = c.member_ids.filter((m) => m !== userId).map(nameOf);
      return others.length ? others.slice(0, 3).join(", ") + (others.length > 3 ? ` +${others.length - 3}` : "") : "Just you";
    }
    const other = c.member_ids.find((m) => m !== userId);
    return other ? nameOf(other) : "Conversation";
  }, [titles, userId, nameOf]);

  /** Every conversation as it reads now: edits applied, reactions gathered, disappeared messages gone. */
  const threads = useMemo(() => {
    const out = {};
    for (const [cid, list] of Object.entries(messages)) out[cid] = buildThread(list, opened, { userId, now });
    return out;
  }, [messages, opened, userId, now]);

  /** Search what this device has decrypted. The query never leaves it. */
  const searchMessages = useCallback((query) =>
    searchThreads(conversations.map((c) => ({ conversation: c, rows: threads[c.id] || [] })), query),
  [conversations, threads]);

  const value = useMemo(() => ({
    loaded,
    conversations,
    messages,
    threads,
    hasMore,
    opened,
    titles,
    profiles,
    alerts,
    updateAlerts,
    openConversation,
    closeConversation,
    loadOlder,
    loadHistory,
    searchMessages,
    markRead,
    isUnread,
    send,
    react,
    sendPoll,
    vote,
    editMessage,
    setTitle,
    setExpiry,
    setAdmin,
    removeMember,
    startDm,
    startGroup,
    addMembers,
    leave,
    deleteMessage,
    refreshConversation,
    nameOf,
    handleOf,
    conversationName,
    loadProfiles,
    newMembersOf,
    acknowledgeMembers,
    membershipProblem,
    addPollExtension,
    touchActivity,
  }), [loaded, conversations, messages, threads, hasMore, opened, titles, profiles, alerts, updateAlerts, openConversation, closeConversation, loadOlder, loadHistory, searchMessages, markRead, isUnread, send, react, sendPoll, vote, editMessage, setTitle, setExpiry, setAdmin, removeMember, startDm, startGroup, addMembers, leave, deleteMessage, refreshConversation, nameOf, handleOf, conversationName, loadProfiles, newMembersOf, acknowledgeMembers, membershipProblem, addPollExtension, touchActivity]);

  return <ChatContext.Provider value={value}>{children}</ChatContext.Provider>;
}
