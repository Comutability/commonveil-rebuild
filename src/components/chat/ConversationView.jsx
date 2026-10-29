import React, { useEffect, useLayoutEffect, useRef, useState } from "react";
import { AlertTriangle, ArrowLeft, Info, Lock, MoreHorizontal, SendHorizontal, ShieldCheck, ShieldQuestion, Trash2, UserPlus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { useChat } from "@/lib/secure/ChatContext";
import { useSecure } from "@/lib/secure/SecureContext";
import { MAX_MESSAGE_CHARS } from "@/lib/secure/protocol.js";
import { formatTime, Loading } from "@/components/site/bits";
import Avatar from "./Avatar";

function Bubble({ m, result, mine, showName, name, onDelete }) {
  const base = `max-w-[min(34rem,85%)] rounded-2xl px-3.5 py-2 text-[0.95rem] leading-relaxed ${mine ? "rounded-br-md bg-primary text-primary-foreground" : "rounded-bl-md bg-muted"}`;
  let body;
  if (!result) body = <span className="opacity-70">Decrypting…</span>;
  else if (result.status === "deleted") body = <span className="italic opacity-70">Message deleted</span>;
  else if (result.status === "locked") {
    body = (
      <span className="inline-flex items-center gap-1.5 italic opacity-80" title={result.message}>
        <Lock className="h-3.5 w-3.5" aria-hidden="true" /> Can't be read on this device
      </span>
    );
  } else body = <span className="whitespace-pre-wrap break-words">{result.text}</span>;

  return (
    <div className={`group flex flex-col ${mine ? "items-end" : "items-start"}`}>
      {showName && !mine && <span className="mb-1 ml-1 text-xs font-medium text-muted-foreground">{name}</span>}
      <div className={`flex items-center gap-1 ${mine ? "flex-row-reverse" : ""}`}>
        <div className={base}>{body}</div>
        {mine && result && result.status !== "deleted" && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button type="button" className="rounded-md p-1 text-muted-foreground opacity-0 transition-opacity hover:bg-muted focus:opacity-100 group-hover:opacity-100" aria-label="Message options">
                <MoreHorizontal className="h-4 w-4" />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onSelect={onDelete} className="text-destructive">
                <Trash2 className="mr-2 h-4 w-4" aria-hidden="true" /> Delete for everyone
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>
      <span className={`mt-1 flex items-center gap-1 text-[0.7rem] text-muted-foreground ${mine ? "mr-1" : "ml-1"}`}>
        {formatTime(m.created_date)}
        {result?.status === "unverified" && (
          <span className="inline-flex items-center gap-0.5 text-[hsl(var(--warning))]" title="The sender's signature couldn't be checked. Be cautious.">
            <ShieldQuestion className="h-3 w-3" aria-hidden="true" /> unverified
          </span>
        )}
      </span>
    </div>
  );
}

export default function ConversationView({ conversation, onBack, onInfo }) {
  const { messages, opened, hasMore, openConversation, loadOlder, markRead, send, deleteMessage, nameOf, conversationName, newMembersOf, acknowledgeMembers } = useChat();
  const { userId, peers, loadPeers } = useSecure();
  const list = messages[conversation.id] || [];
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState("");
  const [initialLoad, setInitialLoad] = useState(true);
  const scroller = useRef(null);
  const nearBottom = useRef(true);

  useEffect(() => {
    let cancelled = false;
    setInitialLoad(true);
    setError("");
    openConversation(conversation.id)
      .catch((err) => !cancelled && setError(err.message))
      .finally(() => !cancelled && setInitialLoad(false));
    return () => {
      cancelled = true;
    };
  }, [conversation.id, openConversation]);

  useEffect(() => {
    markRead(conversation.id);
  }, [conversation.id, list.length, markRead]);

  // Keep members' keys fresh while the conversation is open, so a key change shows up before you send.
  const memberKey = conversation.member_ids.join(",");
  useEffect(() => {
    const ids = memberKey.split(",");
    loadPeers(ids).catch(() => {});
    const t = setInterval(() => loadPeers(ids).catch(() => {}), 30_000);
    return () => clearInterval(t);
  }, [memberKey, loadPeers]);

  useLayoutEffect(() => {
    const el = scroller.current;
    if (el && nearBottom.current) el.scrollTop = el.scrollHeight;
  }, [list.length, opened]);

  const onScroll = () => {
    const el = scroller.current;
    if (el) nearBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 120;
  };

  const others = conversation.member_ids.filter((m) => m !== userId);
  const changed = others.filter((m) => peers[m]?.changed);
  const fresh = newMembersOf(conversation);
  const dmBroken = conversation.kind === "dm" && (conversation.member_ids.length !== 2 || !conversation.member_ids.includes(userId));
  const pausedReason = dmBroken
    ? "Sending is blocked for this conversation"
    : changed.length
      ? "Review the key change before sending"
      : fresh.length
        ? "Check who's new before sending"
        : null;
  const allVerified = others.length > 0 && others.every((m) => peers[m]?.verified);
  const other = conversation.kind === "dm" ? others[0] : null;

  const submit = async (e) => {
    e?.preventDefault();
    if (!text.trim() || sending) return;
    setSending(true);
    setError("");
    nearBottom.current = true;
    try {
      await send(conversation, text);
      setText("");
    } catch (err) {
      setError(err.message);
    } finally {
      setSending(false);
    }
  };

  return (
    <section className="flex h-full min-h-0 flex-col" aria-label={`Conversation: ${conversationName(conversation)}`}>
      <header className="flex items-center gap-3 border-b border-border px-3 py-2.5 sm:px-4">
        <Button variant="ghost" size="icon" className="md:hidden" onClick={onBack} aria-label="Back to conversations">
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <Avatar id={other} name={nameOf(other)} group={conversation.kind === "group"} size="h-9 w-9" />
        <div className="min-w-0 flex-1">
          <h2 className="truncate font-semibold">{conversationName(conversation)}</h2>
          <p className="flex items-center gap-1 text-xs text-muted-foreground">
            {allVerified ? (
              <><ShieldCheck className="h-3.5 w-3.5 text-primary" aria-hidden="true" /> Verified · end-to-end encrypted</>
            ) : (
              <><Lock className="h-3.5 w-3.5" aria-hidden="true" /> End-to-end encrypted{conversation.kind === "group" ? ` · ${conversation.member_ids.length} people` : ""}</>
            )}
          </p>
        </div>
        <Button variant="ghost" size="icon" onClick={onInfo} aria-label="Conversation details and safety numbers">
          <Info className="h-5 w-5" />
        </Button>
      </header>

      {changed.length > 0 && (
        <div className="flex items-start gap-3 border-b border-[hsl(var(--warning)/0.4)] bg-[hsl(var(--warning)/0.1)] px-4 py-3 text-sm">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[hsl(var(--warning))]" aria-hidden="true" />
          <p className="flex-1">
            {changed.map(nameOf).join(", ")} {changed.length === 1 ? "has" : "have"} new security keys. This happens when someone resets their
            account, but it could also mean someone is intercepting. Sending is paused until you review it.
          </p>
          <Button size="sm" variant="outline" onClick={onInfo}>Review</Button>
        </div>
      )}

      {fresh.length > 0 && !dmBroken && (
        <div className="flex items-start gap-3 border-b border-[hsl(var(--warning)/0.4)] bg-[hsl(var(--warning)/0.1)] px-4 py-3 text-sm">
          <UserPlus className="mt-0.5 h-4 w-4 shrink-0 text-[hsl(var(--warning))]" aria-hidden="true" />
          <p className="flex-1">
            New in this conversation: <strong>{fresh.map(nameOf).join(", ")}</strong>. Anything you send from now on can be read by them
            too. If you weren't expecting this, check with the group before sending.
          </p>
          <Button size="sm" variant="outline" onClick={() => acknowledgeMembers(conversation)}>OK, continue</Button>
        </div>
      )}

      {dmBroken && (
        <div className="flex items-start gap-3 border-b border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive" role="alert">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          <p className="flex-1">This direct message doesn't have exactly two people in it, which shouldn't happen. Sending is blocked to keep your messages private.</p>
        </div>
      )}

      <div ref={scroller} onScroll={onScroll} className="min-h-0 flex-1 space-y-3 overflow-y-auto px-3 py-4 sm:px-6" aria-live="polite">
        {hasMore[conversation.id] && (
          <div className="text-center">
            <Button variant="ghost" size="sm" onClick={() => { nearBottom.current = false; loadOlder(conversation.id); }}>Load earlier messages</Button>
          </div>
        )}
        {initialLoad && list.length === 0 ? (
          <Loading label="Loading messages" />
        ) : list.length === 0 ? (
          <div className="mx-auto max-w-sm py-12 text-center text-sm text-muted-foreground">
            <Lock className="mx-auto h-6 w-6 text-primary" aria-hidden="true" />
            <p className="mt-3">Messages here are end-to-end encrypted. Only the people in this conversation can read them.</p>
          </div>
        ) : (
          list.map((m, i) => (
            <Bubble
              key={m.id}
              m={m}
              result={opened[m.id]}
              mine={m.sender_id === userId}
              showName={conversation.kind === "group" && list[i - 1]?.sender_id !== m.sender_id}
              name={nameOf(m.sender_id)}
              onDelete={() => deleteMessage(m).catch((err) => setError(err.message))}
            />
          ))
        )}
      </div>

      <form onSubmit={submit} className="border-t border-border p-3 sm:p-4">
        {error && <p className="mb-2 text-sm text-destructive" role="alert">{error}</p>}
        <div className="flex items-end gap-2">
          <Textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
                e.preventDefault();
                submit();
              }
            }}
            rows={1}
            maxLength={MAX_MESSAGE_CHARS}
            placeholder={pausedReason || "Write a message"}
            disabled={Boolean(pausedReason)}
            className="max-h-40 min-h-[2.75rem] resize-none"
            aria-label="Message"
          />
          <Button type="submit" size="icon" className="h-11 w-11 shrink-0" disabled={!text.trim() || sending || Boolean(pausedReason)} aria-label="Send">
            <SendHorizontal className="h-5 w-5" />
          </Button>
        </div>
        {text.length > MAX_MESSAGE_CHARS - 300 && (
          <p className="mt-1 text-right text-xs text-muted-foreground">{MAX_MESSAGE_CHARS - text.length} characters left</p>
        )}
      </form>
    </section>
  );
}
