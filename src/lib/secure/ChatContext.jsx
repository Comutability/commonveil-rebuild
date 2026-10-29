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
  const { userId, device, keyring, peers, loadPeers, chainsFor, chainOf, devicesOf } = useSecure();
  const [conversations, setConversations] = useState([]);
  const [loaded, setLoaded] = useState(false);
  const [profiles, setProfiles] = useState({});
  const [messages, setMessages] = useState({});
  const [hasMore, setHasMore] = useState({});
  const [opened, setOpened] = useState({});
  const [titles, setTitles] = useState({});
  const [readState, setReadState] = useState({});
  const cursor = useRef(null);
  const polling = useRef(false);

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
      if (cancelled) return;
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
          const stillMember = membersOf.get(m.conversation_id)?.has(m.sender_id);
          const senderReady = m.sender_id === userId || peers[m.sender_id]?.ready !== undefined || !stillMember;
          if (!senderReady && !m.deleted) continue;
          const r = await P.openItem({ kind: "message", item: m, userId, keyring, senderChain, senderDevices: devicesOf(m.sender_id) });
          results[m.id] = { ...r, cacheKey };
          if (cancelled) return;
        }
      }
      if (!cancelled && Object.keys(results).length) setOpened((prev) => ({ ...prev, ...results }));
    })();
    return () => {
      cancelled = true;
    };
  }, [messages, conversations, keyring, peers, userId, chainOf, devicesOf, opened]);

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
        const r = await P.openItem({
          kind: "title",
          item: { ...c.title, conversation_id: c.id },
          userId,
          keyring,
          senderChain: chainOf(c.title.sender_id),
          senderDevices: devicesOf(c.title.sender_id),
        });
        results[c.id] = { ...r, key };
      }
      if (Object.keys(results).length) setTitles((prev) => ({ ...prev, ...results }));
    })();
  }, [conversations, keyring, peers, userId, chainOf, devicesOf, titles]);

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
      try {
        const body = await P.buildMessage({ userId, device, conversation: conv, chains: chainsFor(conv.member_ids), text });
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
  }, [userId, device, chainsFor, mergeMessages, mergeConversations, refreshConversation]);

  const setTitle = useCallback(async (conversation, title) => {
    const body = await P.buildTitle({ userId, device, conversation, chains: chainsFor(conversation.member_ids), title });
    const res = await callFn("conversations", body);
    mergeConversations([res.conversation]);
    return res.conversation;
  }, [userId, device, chainsFor, mergeConversations]);

  const startDm = useCallback(async (username) => {
    const res = await callFn("conversations", { action: "create_dm", username });
    mergeConversations([res.conversation]);
    await Promise.all([loadPeers(res.conversation.member_ids, { force: true }), loadProfiles(res.conversation.member_ids)]);
    return res.conversation;
  }, [mergeConversations, loadPeers, loadProfiles]);

  const startGroup = useCallback(async (usernames, title) => {
    const res = await callFn("conversations", { action: "create_group", usernames });
    mergeConversations([res.conversation]);
    await Promise.all([loadPeers(res.conversation.member_ids, { force: true }), loadProfiles(res.conversation.member_ids)]);
    return { conversation: res.conversation, title };
  }, [mergeConversations, loadPeers, loadProfiles]);

  const addMembers = useCallback(async (conversation, usernames) => {
    const res = await callFn("conversations", { action: "add_members", conversation_id: conversation.id, usernames });
    mergeConversations([res.conversation]);
    await Promise.all([loadPeers(res.conversation.member_ids, { force: true }), loadProfiles(res.conversation.member_ids)]);
    return res.conversation;
  }, [mergeConversations, loadPeers, loadProfiles]);

  const leave = useCallback(async (conversation) => {
    await callFn("conversations", { action: "leave", conversation_id: conversation.id });
    setConversations((prev) => prev.filter((c) => c.id !== conversation.id));
  }, []);

  const deleteMessage = useCallback(async (message) => {
    await callFn("messages", { action: "delete", message_id: message.id });
    mergeMessages([{ ...message, deleted: true, envelope: null, signature: null }]);
  }, [mergeMessages]);

  const nameOf = useCallback((id) => {
    if (id === userId) return "You";
    const p = profiles[id];
    return p ? p.display_name || p.username : "Member";
  }, [profiles, userId]);

  const conversationName = useCallback((c) => {
    if (c.kind === "group") {
      const t = titles[c.id];
      if (t && (t.status === "ok" || t.status === "unverified") && t.text) return t.text;
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
    conversationName,
    loadProfiles,
  }), [loaded, conversations, messages, hasMore, opened, titles, profiles, openConversation, loadOlder, markRead, isUnread, send, setTitle, startDm, startGroup, addMembers, leave, deleteMessage, refreshConversation, nameOf, conversationName, loadProfiles]);

  return <ChatContext.Provider value={value}>{children}</ChatContext.Provider>;
}
