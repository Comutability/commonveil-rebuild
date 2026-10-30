// Conversations and messages for the signed-in, set-up account: polling,
// decryption with signature checks, sending with automatic key refresh.
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, callFn } from "@/lib/api";
import { useSecure } from "./SecureContext.jsx";
import * as P from "./protocol.js";
import * as S from "./store.js";

const ChatContext = createContext(null);

export function useChat() {
  const ctx = useContext(ChatContext);
  if (!ctx) throw new Error("useChat must be used inside ChatProvider");
  return ctx;
}

const byCreated = (a, b) => String(a.created_date).localeCompare(String(b.created_date));
const RETRYABLE = new Set(["STALE_KEYS", "RECIPIENTS_CHANGED"]);

export function ChatProvider({ children }) {
  const { userId, device, keyring, peers, loadPeers, chainsFor, chainOf, devicesOf, ownMinCertVersion, refresh: refreshSecure } = useSecure();
  const [conversations, setConversations] = useState([]);
  const [loaded, setLoaded] = useState(false);
  const [profiles, setProfiles] = useState({});
  const [messages, setMessages] = useState({});
  const [hasMore, setHasMore] = useState({});
  const [opened, setOpened] = useState({});
  const [titles, setTitles] = useState({});
  const [readState, setReadState] = useState({});
  const [memberPins, setMemberPins] = useState(null);
  const memberPinsRef = useRef(null);
  // Groups started from this browser: their members were chosen here, so they're pinned as they are.
  const startedHere = useRef(new Set());
  const cursor = useRef(null);
  const polling = useRef(false);
  // Sender devices we've already re-fetched keys for, so an unknown device triggers one refresh, not a loop.
  const refetchedDevices = useRef(new Set());

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

  const mergeConversations = useCallback((list, { replace = false } = {}) => {
    setConversations((prev) => {
      const map = new Map(replace ? [] : prev.map((c) => [c.id, c]));
      for (const c of list) map.set(c.id, c);
      return [...map.values()].sort((a, b) =>
        String(b.last_message_at || b.created_date).localeCompare(String(a.last_message_at || a.created_date)),
      );
    });
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

  const loadProfiles = useCallback(async (ids) => {
    const missing = [...new Set(ids)].filter((id) => id && !profiles[id]);
    if (!missing.length) return;
    const { profiles: rows } = await callFn("profile", { action: "get_many", user_ids: missing.slice(0, 100) });
    setProfiles((prev) => {
      const next = { ...prev };
      for (const p of rows) next[p.user_id] = p;
      return next;
    });
  }, [profiles]);

  // Initial load.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const start = await callFn("messages", { action: "poll" });
      cursor.current = start.cursor;
      const { conversations: list } = await callFn("conversations", { action: "list" });
      const pins = await S.loadMemberPins(userId);
      if (cancelled) return;
      memberPinsRef.current = pins;
      setMemberPins(pins);
      mergeConversations(list, { replace: true });
      setReadState(await S.loadReadState(userId));
      setLoaded(true);
      const memberIds = list.flatMap((c) => c.member_ids);
      await Promise.all([loadPeers(memberIds), loadProfiles(memberIds)]);
    })().catch(() => setLoaded(true));
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId]);

  // Poll for changes: often while visible, rarely while hidden.
  useEffect(() => {
    let timer;
    const tick = async () => {
      if (!polling.current && cursor.current) {
        polling.current = true;
        try {
          let page;
          do {
            page = await callFn("messages", { action: "poll", since: cursor.current });
            cursor.current = page.cursor;
            if (page.conversations.length) {
              mergeConversations(page.conversations);
              const ids = page.conversations.flatMap((c) => c.member_ids);
              loadPeers(ids);
              loadProfiles(ids);
            }
            mergeMessages(page.messages);
            // Drop conversations we've left or been removed from.
            setConversations((prev) => prev.filter((c) => page.conversation_ids.includes(c.id)));
          } while (page.has_more);
        } catch {
          /* try again next tick */
        } finally {
          polling.current = false;
        }
      }
      timer = setTimeout(tick, document.visibilityState === "visible" ? 4000 : 20000);
    };
    timer = setTimeout(tick, 4000);
    return () => clearTimeout(timer);
  }, [mergeConversations, mergeMessages, loadPeers, loadProfiles]);

  // Decrypt anything new once the sender's keys are known.
  useEffect(() => {
    if (!keyring) return;
    let cancelled = false;
    const membersOf = new Map(conversations.map((c) => [c.id, new Set(c.member_ids)]));
    (async () => {
      const results = {};
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
          if (cancelled) return;
        }
      }
      if (!cancelled && Object.keys(results).length) setOpened((prev) => ({ ...prev, ...results }));
    })();
    return () => {
      cancelled = true;
    };
  }, [messages, conversations, keyring, peers, userId, chainOf, devicesOf, opened, knowsDevice, ownMinCertVersion]);

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

  const openConversation = useCallback(async (conversationId) => {
    const res = await callFn("messages", { action: "list", conversation_id: conversationId });
    mergeMessages(res.messages);
    setHasMore((prev) => ({ ...prev, [conversationId]: res.has_more }));
  }, [mergeMessages]);

  const loadOlder = useCallback(async (conversationId) => {
    const first = (messages[conversationId] || [])[0];
    if (!first) return;
    const res = await callFn("messages", { action: "list", conversation_id: conversationId, before: first.created_date });
    mergeMessages(res.messages);
    setHasMore((prev) => ({ ...prev, [conversationId]: res.has_more }));
  }, [messages, mergeMessages]);

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

  const refreshConversation = useCallback(async (conversationId) => {
    const { conversation } = await callFn("conversations", { action: "get", conversation_id: conversationId });
    mergeConversations([conversation]);
    await loadPeers(conversation.member_ids, { force: true });
    return conversation;
  }, [mergeConversations, loadPeers]);

  const send = useCallback(async (conversation, text) => {
    let conv = conversation;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      // Checked on every attempt: a refresh after a rejected send must not quietly add recipients.
      const problem = membershipProblem(conv);
      if (problem) throw new Error(problem);
      try {
        const body = await P.buildMessage({ userId, device, conversation: conv, chains: chainsFor(conv.member_ids), text, keyring });
        const res = await callFn("messages", body);
        mergeMessages([res.message]);
        mergeConversations([{ ...conv, last_message_at: res.message.created_date }]);
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
  }, [userId, device, keyring, chainsFor, mergeMessages, mergeConversations, refreshConversation, membershipProblem]);

  const setTitle = useCallback(async (conversation, title) => {
    const problem = membershipProblem(conversation);
    if (problem) throw new Error(problem);
    const body = await P.buildTitle({ userId, device, conversation, chains: chainsFor(conversation.member_ids), title, keyring });
    const res = await callFn("conversations", body);
    mergeConversations([res.conversation]);
    return res.conversation;
  }, [userId, device, keyring, chainsFor, mergeConversations, membershipProblem]);

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

  const nameOf = useCallback((id) => {
    if (id === userId) return "You";
    const p = profiles[id];
    return p ? p.display_name || p.username : "Member";
  }, [profiles, userId]);

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

  const value = useMemo(() => ({
    loaded,
    conversations,
    messages,
    hasMore,
    opened,
    titles,
    profiles,
    openConversation,
    loadOlder,
    markRead,
    isUnread,
    send,
    setTitle,
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
  }), [loaded, conversations, messages, hasMore, opened, titles, profiles, openConversation, loadOlder, markRead, isUnread, send, setTitle, startDm, startGroup, addMembers, leave, deleteMessage, refreshConversation, nameOf, handleOf, conversationName, loadProfiles, newMembersOf, acknowledgeMembers, membershipProblem]);

  return <ChatContext.Provider value={value}>{children}</ChatContext.Provider>;
}
