import React, { useEffect, useLayoutEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  Phone,
  PhoneIncoming,
  ArrowLeft,
  CornerUpLeft,
  Forward,
  Info,
  Lock,
  MoreHorizontal,
  Pencil,
  SendHorizontal,
  Smile,
  SmilePlus,
  ShieldCheck,
  ShieldQuestion,
  Timer,
  Trash2,
  UserPlus,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { useChat } from "@/lib/secure/ChatContext";
import { useSecure } from "@/lib/secure/SecureContext";
import { MAX_MESSAGE_CHARS } from "@/lib/secure/protocol.js";
import { QUICK_REACTIONS, emojiName } from "@/lib/emoji";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import EmojiPicker from "./EmojiPicker";
import PollCard from "./PollCard";
import ComposerPlus from "./ComposerPlus";
import CreatePollDialog from "./CreatePollDialog";
import RichText from "./RichText";
import AttachmentList from "./Attachments";
import StagedStrip from "./StagedStrip";
import VoiceRecorder from "./VoiceRecorder";
import ForwardDialog from "./ForwardDialog";
import { progressText, useStagedFiles } from "./useStagedFiles";
import { typingText, usePresence, usePresenceRoom } from "@/lib/secure/PresenceContext";
import { useVoice } from "@/lib/voice/VoiceContext";
import CallPanel from "@/components/voice/CallPanel";
import { fromB64 } from "@/lib/crypto/encoding";
import { hideAt, timerLabel } from "@/lib/secure/thread.js";
import { formatTime, Loading } from "@/components/site/bits";
import Avatar from "./Avatar";

const reactionName = emojiName;
const toMs = (value) => Date.parse(/Z$|[+-]\d{2}:\d{2}$/.test(String(value)) ? value : `${value}Z`);
const snippet = (text, max = 90) => {
  const flat = String(text || "").replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max)}…` : flat;
};

/** Why a decrypted message isn't vouched for, in a few words. */
function Caution({ result }) {
  if (result?.status === "unverified") {
    const removed = result.reason === "removed-device";
    return (
      <span
        className="inline-flex items-center gap-0.5 font-medium text-[hsl(var(--warning))]"
        title={removed
          ? "This was signed by a device that had already been removed from the sender's account. Don't trust it."
          : "The sender's signature couldn't be checked against keys you trust. Be cautious."}
      >
        <ShieldQuestion className="h-3 w-3" aria-hidden="true" /> {removed ? "sent from a removed device" : "unverified"}
      </span>
    );
  }
  if (result?.status === "ok" && result.removedDevice) {
    return <span title="Sent before this device was removed from the sender's account.">· from a device since removed</span>;
  }
  return null;
}

/** The message a reply answers, if it's here: a short quote you can jump to. */
function ReplyQuote({ replyTo, mine, nameOf, onJump }) {
  if (!replyTo) return null;
  const tone = mine ? "border-primary-foreground/50 text-primary-foreground/85" : "border-primary/50 text-muted-foreground";
  if (replyTo.missing) {
    return <span className={`mb-1 block border-l-2 pl-2 text-xs italic ${tone}`}>Replying to an earlier message</span>;
  }
  const target = replyTo.row;
  const gone = target.m.deleted || (target.result?.status !== "ok" && target.result?.status !== "unverified");
  return (
    <button type="button" onClick={() => onJump(target.m.id)} className={`mb-1 block w-full border-l-2 pl-2 text-left text-xs ${tone} hover:underline`}>
      <span className="font-medium">{nameOf(target.m.sender_id)}</span>{" "}
      {gone ? <span className="italic">message no longer available</span> : snippet(target.text)}
    </button>
  );
}

function Reactions({ reactions, mine, nameOf, onToggle, disabled }) {
  if (!reactions.length) return null;
  return (
    <div className={`mt-1 flex flex-wrap gap-1 ${mine ? "justify-end" : ""}`}>
      {reactions.map((r) => (
        <button
          key={r.emoji}
          type="button"
          disabled={disabled}
          onClick={() => onToggle(r.emoji, r.mine)}
          aria-pressed={r.mine}
          aria-label={`${reactionName(r.emoji)}, ${r.count}. ${r.mine ? "Remove yours" : "Add yours"}`}
          title={r.people.map(nameOf).join(", ")}
          className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs transition-colors ${r.mine ? "border-primary/60 bg-primary/10" : "border-border bg-background hover:bg-muted"}`}
        >
          <span aria-hidden="true">{r.emoji}</span>
          <span>{r.count}</span>
        </button>
      ))}
    </div>
  );
}

/** A call someone started here: join it with the key that came in the message. */
function CallCard({ row, mine, name, onJoin, inThisCall }) {
  const fresh = Date.now() - Date.parse(String(row.m.created_date).replace(/Z?$/, "Z")) < 12 * 3600_000;
  return (
    <div className="flex items-center gap-3 rounded-2xl border border-border bg-card px-3.5 py-2.5 text-foreground">
      <span className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/15 text-primary"><PhoneIncoming className="h-4 w-4" aria-hidden="true" /></span>
      <span className="text-sm">
        <span className="block font-medium">{mine ? "You started a call" : `${name} started a call`}</span>
        <span className="block text-xs text-muted-foreground">Encrypted end to end, device to device.</span>
      </span>
      {fresh && !inThisCall && <Button size="sm" onClick={onJoin}>Join</Button>}
      {inThisCall && <span className="text-xs font-medium text-primary">You're in it</span>}
    </div>
  );
}

function Bubble({ row, mine, showName, name, handle, nameOf, highlighted, canSend, onReply, onReact, onVote, onEdit, onDelete, onJump, onForward, onJoinCall, inCall }) {
  const [picker, setPicker] = useState(false);
  const { m, result } = row;
  const base = `max-w-[min(34rem,85%)] rounded-2xl px-3.5 py-2 text-[0.95rem] leading-relaxed ${mine ? "rounded-br-md bg-primary text-primary-foreground" : "rounded-bl-md bg-muted"} ${highlighted ? "ring-2 ring-[hsl(var(--warning))] ring-offset-2 ring-offset-background" : ""}`;
  const readable = result && (result.status === "ok" || result.status === "unverified");
  let body;
  if (!result) body = <span className="opacity-70">Decrypting…</span>;
  else if (result.status === "deleted") body = <span className="italic opacity-70">Message deleted</span>;
  else if (result.status === "locked") {
    body = (
      <span className="inline-flex items-center gap-1.5 italic opacity-80" title={result.message}>
        <Lock className="h-3.5 w-3.5" aria-hidden="true" /> Can't be read on this device
      </span>
    );
  } else {
    body = (
      <>
        <ReplyQuote replyTo={row.replyTo} mine={mine} nameOf={nameOf} onJump={onJump} />
        {result.content?.forwarded && <span className="mb-0.5 block text-xs italic opacity-80">Forwarded</span>}
        {row.poll ? (
          <div className="text-foreground">
            <PollCard poll={row.poll} nameOf={nameOf} disabled={!canSend} onVote={onVote} />
          </div>
        ) : row.text ? (
          <span className="whitespace-pre-wrap break-words"><RichText text={row.text} ctx={{}} /></span>
        ) : null}
      </>
    );
  }
  if (readable && result.content?.type === "call") {
    return (
      <div id={`msg-${m.id}`} className={`flex ${mine ? "justify-end" : "justify-start"}`}>
        <CallCard row={row} mine={mine} name={name} onJoin={onJoinCall} inThisCall={inCall === result.content.call_id} />
      </div>
    );
  }
  // A message that's only files shows them without a bubble around them.
  const filesOnly = readable && !row.poll && !row.text && !row.replyTo && !result.content?.forwarded && row.attachments.length > 0;
  const disappearsAt = hideAt(m, result);

  return (
    <div id={`msg-${m.id}`} className={`group flex flex-col ${mine ? "items-end" : "items-start"}`}>
      {showName && !mine && (
        <span className="mb-1 ml-1 text-xs font-medium text-muted-foreground">
          {name} {handle && <span className="font-normal opacity-80">{handle}</span>}
        </span>
      )}
      <div className={`flex max-w-full items-center gap-1 ${mine ? "flex-row-reverse" : ""}`}>
        <div className={`flex min-w-0 flex-col gap-1 ${mine ? "items-end" : "items-start"}`}>
          {!filesOnly && <div className={row.poll ? "max-w-[min(30rem,92%)]" : base}>{body}</div>}
          {readable && row.attachments.length > 0 && <div className="max-w-[min(26rem,85vw)]"><AttachmentList attachments={row.attachments} /></div>}
        </div>
        {readable && canSend && (
          <Popover open={picker} onOpenChange={setPicker}>
            <PopoverTrigger asChild>
              <button type="button" className="rounded-md p-1 text-muted-foreground opacity-60 transition-opacity hover:bg-muted focus:opacity-100 group-hover:opacity-100 sm:opacity-0" aria-label="Add a reaction">
                <SmilePlus className="h-4 w-4" aria-hidden="true" />
              </button>
            </PopoverTrigger>
            <PopoverContent align={mine ? "end" : "start"} className="w-auto p-0">
              <EmojiPicker
                label="Add a reaction"
                selected={row.reactions.filter((r) => r.mine).map((r) => r.emoji)}
                onPick={(emoji) => {
                  setPicker(false);
                  onReact(emoji, Boolean(row.reactions.find((r) => r.emoji === emoji)?.mine));
                }}
              />
            </PopoverContent>
          </Popover>
        )}
        {(readable || (mine && result?.status === "locked")) && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                className="rounded-md p-1 text-muted-foreground opacity-60 transition-opacity hover:bg-muted focus:opacity-100 group-hover:opacity-100 sm:opacity-0"
                aria-label="Message options"
              >
                <MoreHorizontal className="h-4 w-4" />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align={mine ? "end" : "start"}>
              {readable && (
                <>
                  <div className="flex gap-0.5 px-1 py-1" role="group" aria-label="React">
                    {QUICK_REACTIONS.map((emoji) => {
                      const already = row.reactions.find((r) => r.emoji === emoji)?.mine;
                      return (
                        <DropdownMenuItem
                          key={emoji}
                          disabled={!canSend}
                          onSelect={() => onReact(emoji, Boolean(already))}
                          className={`justify-center rounded-md px-1.5 text-lg ${already ? "bg-primary/10" : ""}`}
                          aria-label={`${already ? "Remove" : "React with"} ${reactionName(emoji)}`}
                        >
                          <span aria-hidden="true">{emoji}</span>
                        </DropdownMenuItem>
                      );
                    })}
                  </div>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem disabled={!canSend} onSelect={onReply}>
                    <CornerUpLeft className="mr-2 h-4 w-4" aria-hidden="true" /> Reply
                  </DropdownMenuItem>
                  {onForward && result.content?.type === "text" && (
                    <DropdownMenuItem onSelect={onForward}>
                      <Forward className="mr-2 h-4 w-4" aria-hidden="true" /> Forward
                    </DropdownMenuItem>
                  )}
                  {row.canEdit && (
                    <DropdownMenuItem disabled={!canSend} onSelect={onEdit}>
                      <Pencil className="mr-2 h-4 w-4" aria-hidden="true" /> Edit
                    </DropdownMenuItem>
                  )}
                </>
              )}
              {mine && (
                <DropdownMenuItem onSelect={onDelete} className="text-destructive">
                  <Trash2 className="mr-2 h-4 w-4" aria-hidden="true" /> Delete for everyone
                </DropdownMenuItem>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>
      <Reactions reactions={row.reactions} mine={mine} nameOf={nameOf} disabled={!canSend} onToggle={(emoji, already) => onReact(emoji, already)} />
      <span className={`mt-1 flex items-center gap-1 text-[0.7rem] text-muted-foreground ${mine ? "mr-1" : "ml-1"}`}>
        {formatTime(m.created_date)}
        {row.edited && <span title={row.editedAt ? `Edited ${formatTime(row.editedAt)}` : "Edited"}>· edited</span>}
        {disappearsAt && (
          <span className="inline-flex items-center" title={`Disappears ${new Date(disappearsAt).toLocaleString("en-GB")}`}>
            <Timer className="h-3 w-3" aria-hidden="true" />
            <span className="sr-only">Disappears {new Date(disappearsAt).toLocaleString("en-GB")}</span>
          </span>
        )}
        <Caution result={result} />
      </span>
    </div>
  );
}

/** A line in the conversation saying who last changed the timer. */
function TimerNote({ conversation, nameOf }) {
  const by = conversation.expiry_set_by;
  const seconds = conversation.expire_seconds;
  const who = by ? nameOf(by) : "Someone";
  return (
    <p className="mx-auto flex w-fit items-center gap-1.5 rounded-full bg-muted px-3 py-1 text-center text-xs text-muted-foreground">
      <Timer className="h-3.5 w-3.5" aria-hidden="true" />
      {seconds
        ? `${who} set messages to disappear after ${timerLabel(seconds).replace(/^1 /, "a ")}.`
        : `${who} turned off disappearing messages.`}
      <span>{formatTime(conversation.expiry_set_at)}</span>
    </p>
  );
}

export default function ConversationView({ conversation, onBack, onInfo }) {
  const {
    threads, messages, opened, hasMore, openConversation, closeConversation, loadOlder, markRead, send, react, sendPoll, vote, editMessage, deleteMessage,
    nameOf, handleOf, conversationName, newMembersOf, acknowledgeMembers,
  } = useChat();
  const { userId, peers, loadPeers } = useSecure();
  usePresenceRoom("c", conversation.id);
  const presence = usePresence();
  const typers = presence.typingIn("c", conversation.id).map(nameOf);
  const rows = threads[conversation.id] || [];
  const stored = messages[conversation.id] || [];
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState("");
  const [initialLoad, setInitialLoad] = useState(true);
  const [replyTo, setReplyTo] = useState(null);
  const [editing, setEditing] = useState(null);
  const [highlight, setHighlight] = useState(null);
  const scroller = useRef(null);
  const input = useRef(null);
  const nearBottom = useRef(true);

  useEffect(() => {
    let cancelled = false;
    setInitialLoad(true);
    setError("");
    setReplyTo(null);
    setEditing(null);
    setText("");
    openConversation(conversation.id)
      .catch((err) => !cancelled && setError(err.message))
      .finally(() => !cancelled && setInitialLoad(false));
    return () => {
      cancelled = true;
      closeConversation(conversation.id);
    };
  }, [conversation.id, openConversation, closeConversation]);

  useEffect(() => {
    markRead(conversation.id);
  }, [conversation.id, stored.length, markRead]);

  // Keep members' keys fresh while the conversation is open, so a key change shows up before you
  // send. loadPeers only asks again once its cached copy is a few minutes old.
  const memberKey = conversation.member_ids.join(",");
  useEffect(() => {
    const ids = memberKey.split(",");
    loadPeers(ids).catch(() => {});
    const t = setInterval(() => {
      if (document.visibilityState === "visible") loadPeers(ids).catch(() => {});
    }, 60_000);
    return () => clearInterval(t);
  }, [memberKey, loadPeers]);

  useLayoutEffect(() => {
    const el = scroller.current;
    if (el && nearBottom.current) el.scrollTop = el.scrollHeight;
  }, [rows.length, opened]);

  // If the message being answered or edited disappears, so does the bar.
  useEffect(() => {
    if (replyTo && !rows.some((r) => r.m.id === replyTo.m.id)) setReplyTo(null);
    if (editing && !rows.some((r) => r.m.id === editing.m.id && r.canEdit)) {
      setEditing(null);
      setText("");
    }
  }, [rows, replyTo, editing]);

  const onScroll = () => {
    const el = scroller.current;
    if (el) nearBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 120;
  };

  const jumpTo = (id) => {
    const el = document.getElementById(`msg-${id}`);
    if (!el) return;
    nearBottom.current = false;
    el.scrollIntoView({ block: "center", behavior: "smooth" });
    setHighlight(id);
    setTimeout(() => setHighlight((h) => (h === id ? null : h)), 1600);
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
  const timer = Number(conversation.expire_seconds) || 0;

  const startReply = (row) => {
    setEditing(null);
    setReplyTo(row);
    input.current?.focus();
  };
  const startEdit = (row) => {
    setReplyTo(null);
    setEditing(row);
    setText(row.text);
    input.current?.focus();
  };
  const cancelBars = () => {
    if (editing) setText("");
    setEditing(null);
    setReplyTo(null);
  };

  const voice = useVoice();
  const { startCall } = useChat();
  const [callError, setCallError] = useState("");
  const inThisCall = voice.room?.conversationId === conversation.id;
  const call = async () => {
    setCallError("");
    try {
      const { callId, key } = await startCall(conversation);
      await voice.joinCall(conversation.id, callId, key);
    } catch (err) {
      setCallError(err.message);
    }
  };
  const joinCallFrom = async (row) => {
    setCallError("");
    try {
      await voice.joinCall(conversation.id, row.result.content.call_id, fromB64(row.result.content.key));
    } catch (err) {
      setCallError(err.message);
    }
  };
  const staged = useStagedFiles();
  const [recording, setRecording] = useState(false);
  const [forwarding, setForwarding] = useState(null);
  const [dragging, setDragging] = useState(false);
  const canAttach = !editing && !pausedReason;
  const canSubmit = Boolean(text.trim() || (!editing && staged.items.length));

  const submit = async (e) => {
    e?.preventDefault();
    if (!canSubmit || sending) return;
    setSending(true);
    setError("");
    nearBottom.current = true;
    try {
      if (editing) {
        if (text !== editing.text) await editMessage(conversation, editing.m, text);
      } else {
        const files = staged.items.map(({ file, spoiler }) => ({ file, spoiler }));
        try {
          await send(conversation, text, { replyTo: replyTo?.m.msg_id || null, files, onProgress: staged.onProgress });
        } finally {
          staged.setProgress(null);
        }
        staged.clear();
      }
      setText("");
      setReplyTo(null);
      setEditing(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setSending(false);
    }
  };

  const [pollOpen, setPollOpen] = useState(false);
  const [emojiOpen, setEmojiOpen] = useState(false);
  const insertEmoji = (e) => {
    const el = input.current;
    const at = el ? el.selectionStart ?? text.length : text.length;
    setText((t) => `${t.slice(0, at)}${e}${t.slice(at)}`);
    setEmojiOpen(false);
    setTimeout(() => input.current?.focus(), 0);
  };
  const reactTo = (row, emoji, already) => {
    setError("");
    react(conversation, row.m, emoji, already).catch((err) => setError(err.message));
  };

  // Where the note about the timer goes: among the messages, at the time it was changed.
  const setAt = conversation.expiry_set_at ? toMs(conversation.expiry_set_at) : null;
  const noteIndex = setAt === null ? -1 : (() => {
    const i = rows.findIndex((r) => toMs(r.m.created_date) > setAt);
    return i === -1 ? rows.length : i;
  })();
  const timerNote = <TimerNote key="timer-note" conversation={conversation} nameOf={nameOf} />;

  return (
    <section className="flex h-full min-h-0 flex-col" aria-label={`Conversation: ${conversationName(conversation)}`}>
      <header className="flex items-center gap-3 border-b border-border px-3 py-2.5 sm:px-4">
        <Button variant="ghost" size="icon" className="md:hidden" onClick={onBack} aria-label="Back to conversations">
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <Avatar id={other} name={nameOf(other)} group={conversation.kind === "group"} size="h-9 w-9" />
        <div className="min-w-0 flex-1">
          <h2 className="truncate font-semibold">{conversationName(conversation)}</h2>
          <p className="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-muted-foreground">
            {allVerified ? (
              <span className="inline-flex items-center gap-1"><ShieldCheck className="h-3.5 w-3.5 text-primary" aria-hidden="true" /> Verified and end-to-end encrypted</span>
            ) : (
              <span className="inline-flex items-center gap-1"><Lock className="h-3.5 w-3.5" aria-hidden="true" /> End-to-end encrypted</span>
            )}
            {conversation.kind === "group" && <span>{conversation.member_ids.length} people</span>}
            {timer > 0 && (
              <span className="inline-flex items-center gap-1" title="New messages disappear after this long">
                <Timer className="h-3.5 w-3.5" aria-hidden="true" /> {timerLabel(timer)}
              </span>
            )}
          </p>
        </div>
        {voice.supported && !pausedReason && (
          <Button variant="ghost" size="icon" onClick={call} disabled={inThisCall} aria-label="Start a call">
            <Phone className="h-5 w-5" />
          </Button>
        )}
        <Button variant="ghost" size="icon" onClick={onInfo} aria-label="Conversation details and safety numbers">
          <Info className="h-5 w-5" />
        </Button>
      </header>

      {inThisCall && (
        <div className="flex max-h-[55%] flex-col items-center overflow-y-auto border-b border-border bg-[hsl(var(--rail)/0.5)] p-4">
          <CallPanel nameOf={nameOf} profileOf={() => null} />
        </div>
      )}
      {callError && <p className="border-b border-border px-4 py-2 text-sm text-destructive" role="alert">{callError}</p>}
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
            {fresh.length === others.length && conversation.kind === "group" ? (
              <>You're in a group you haven't checked yet, with <strong>{fresh.map((id) => `${nameOf(id)} ${handleOf(id)}`.trim()).join(", ")}</strong>. Make sure you know who these people are before you send anything.</>
            ) : (
              <>New in this conversation: <strong>{fresh.map((id) => `${nameOf(id)} ${handleOf(id)}`.trim()).join(", ")}</strong>. Anything you send from now on can be read by them too. If you weren't expecting this, check with the group before sending.</>
            )}
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
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                nearBottom.current = false;
                loadOlder(conversation.id).catch((err) => setError(err.message));
              }}
            >
              Load earlier messages
            </Button>
          </div>
        )}
        {initialLoad && rows.length === 0 ? (
          <Loading label="Loading messages" />
        ) : rows.length === 0 ? (
          <div className="mx-auto max-w-sm py-12 text-center text-sm text-muted-foreground">
            <Lock className="mx-auto h-6 w-6 text-primary" aria-hidden="true" />
            <p className="mt-3">Messages here are end-to-end encrypted. Only the people in this conversation can read them.</p>
            {conversation.expiry_set_at && <div className="mt-4">{timerNote}</div>}
          </div>
        ) : (
          rows.flatMap((row, i) => {
            const bubble = (
              <Bubble
                key={row.m.id}
                row={row}
                mine={row.m.sender_id === userId}
                showName={conversation.kind === "group" && rows[i - 1]?.m.sender_id !== row.m.sender_id}
                name={nameOf(row.m.sender_id)}
                handle={handleOf(row.m.sender_id)}
                nameOf={nameOf}
                highlighted={highlight === row.m.id}
                canSend={!pausedReason}
                onReply={() => startReply(row)}
                onReact={(emoji, already) => reactTo(row, emoji, already)}
                onVote={(choices) => vote(conversation, row.m, choices)}
                onEdit={() => startEdit(row)}
                onDelete={() => deleteMessage(row.m).catch((err) => setError(err.message))}
                onJump={jumpTo}
                onForward={() => setForwarding({ text: row.text, attachments: row.attachments })}
                onJoinCall={() => joinCallFrom(row)}
                inCall={voice.room?.conversationId === conversation.id ? voice.room.callId : null}
              />
            );
            return i === noteIndex ? [timerNote, bubble] : [bubble];
          }).concat(noteIndex === rows.length && rows.length > 0 ? [timerNote] : [])
        )}
      </div>

      <ForwardDialog text={forwarding?.text || ""} attachments={forwarding?.attachments || []} open={forwarding !== null} onOpenChange={(v) => !v && setForwarding(null)} />
      <VoiceRecorder open={recording} onOpenChange={setRecording} onSend={(file, seconds) => send(conversation, "", { files: [{ file, voice: true, duration: seconds }] })} />
      <form
        onSubmit={submit}
        className="relative border-t border-border p-3 sm:p-4"
        onDragOver={(e) => {
          if (!canAttach || ![...(e.dataTransfer?.types || [])].includes("Files")) return;
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={(e) => !e.currentTarget.contains(e.relatedTarget) && setDragging(false)}
        onDrop={(e) => {
          setDragging(false);
          if (canAttach && e.dataTransfer?.files?.length) {
            e.preventDefault();
            staged.add(e.dataTransfer.files);
          }
        }}
      >
        {dragging && (
          <div className="pointer-events-none absolute inset-2 z-30 flex items-center justify-center rounded-lg border-2 border-dashed border-primary bg-background/90 text-sm font-medium">
            Drop to attach. Files are encrypted before they leave this device.
          </div>
        )}
        {error && <p className="mb-2 text-sm text-destructive" role="alert">{error}</p>}
        {staged.notice && <p className="mb-2 text-sm text-destructive" role="alert">{staged.notice}</p>}
        {canAttach && <StagedStrip staged={staged} items={staged.items} busy={sending} className="mb-2" />}
        {(replyTo || editing) && (
          <div className="mb-2 flex items-start gap-2 rounded-lg border border-border bg-muted/50 px-3 py-2 text-sm">
            {editing ? <Pencil className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" /> : <CornerUpLeft className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" />}
            <p className="min-w-0 flex-1">
              <span className="font-medium">{editing ? "Editing your message" : `Replying to ${nameOf(replyTo.m.sender_id)}`}</span>
              {!editing && <span className="block truncate text-muted-foreground">{snippet(replyTo.text, 120)}</span>}
              {editing && <span className="block text-xs text-muted-foreground">Everyone will see that it was edited.</span>}
            </p>
            <button type="button" onClick={cancelBars} className="rounded-md p-0.5 text-muted-foreground hover:bg-muted" aria-label={editing ? "Cancel editing" : "Cancel reply"}>
              <X className="h-4 w-4" />
            </button>
          </div>
        )}
        <CreatePollDialog open={pollOpen} onOpenChange={setPollOpen} onCreate={(poll) => sendPoll(conversation, poll)} />
        <div className="flex items-end gap-2">
          {!editing && !pausedReason && <div className="pb-1.5"><ComposerPlus onPoll={() => setPollOpen(true)} onFiles={staged.add} onVoiceNote={() => setRecording(true)} /></div>}
          <Textarea
            ref={input}
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              if (e.target.value && !editing) presence.sendTyping("c", conversation.id);
            }}
            onPaste={(e) => {
              if (canAttach && e.clipboardData?.files?.length) {
                e.preventDefault();
                staged.add(e.clipboardData.files);
              }
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
                e.preventDefault();
                submit();
              } else if (e.key === "Escape" && (replyTo || editing)) {
                e.preventDefault();
                cancelBars();
              }
            }}
            rows={1}
            maxLength={MAX_MESSAGE_CHARS}
            placeholder={pausedReason || (editing ? "Edit your message" : "Write a message")}
            disabled={Boolean(pausedReason)}
            className="max-h-40 min-h-[2.75rem] resize-none"
            aria-label="Message"
          />
          {!editing && !pausedReason && (
            <Popover open={emojiOpen} onOpenChange={setEmojiOpen}>
              <PopoverTrigger asChild>
                <Button type="button" variant="ghost" size="icon" className="h-11 w-11 shrink-0" aria-label="Add an emoji">
                  <Smile className="h-5 w-5" aria-hidden="true" />
                </Button>
              </PopoverTrigger>
              <PopoverContent align="end" side="top" className="w-auto p-0">
                <EmojiPicker onPick={insertEmoji} label="Add an emoji" />
              </PopoverContent>
            </Popover>
          )}
          <Button type="submit" size="icon" className="h-11 w-11 shrink-0" disabled={!canSubmit || sending || Boolean(pausedReason)} aria-label={editing ? "Save edit" : "Send"}>
            <SendHorizontal className="h-5 w-5" />
          </Button>
        </div>
        {typingText(typers) && <p className="mt-1 text-xs text-muted-foreground" aria-live="polite">{typingText(typers)}</p>}
        {progressText(staged.progress) && <p className="mt-1 text-xs text-muted-foreground" role="status">{progressText(staged.progress)}</p>}
        {text.length > MAX_MESSAGE_CHARS - 300 && (
          <p className="mt-1 text-right text-xs text-muted-foreground">{MAX_MESSAGE_CHARS - text.length} characters left</p>
        )}
      </form>
    </section>
  );
}
