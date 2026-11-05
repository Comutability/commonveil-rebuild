import React, { Fragment, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { ArrowLeft, Loader2, Lock, LockOpen, MessagesSquare, Search, X } from "lucide-react";
import { NavButton } from "@/components/shell/Shell";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { useServers, viewKey } from "@/lib/secure/ServerContext";
import { useSecure } from "@/lib/secure/SecureContext";
import { useAppearance } from "@/lib/appearance";
import { P, channelPermissions, has } from "@/lib/secure/permissions";
import { automodReason } from "@/lib/secure/automod";
import { typingText, usePresence } from "@/lib/secure/PresenceContext";
import MessageRow, { DayDivider, newDay, sameRun, stamp } from "@/components/chat/MessageRow";
import Composer from "@/components/chat/Composer";
import ComposerPlus from "@/components/chat/ComposerPlus";
import CreatePollDialog from "@/components/chat/CreatePollDialog";
import ForwardDialog from "@/components/chat/ForwardDialog";
import VoiceRecorder from "@/components/chat/VoiceRecorder";
import { useStagedFiles } from "@/components/chat/useStagedFiles";
import ChannelHeader from "./ChannelHeader";
import MemberList from "./MemberList";
import MemberCard from "./MemberCard";
import { ChannelStart, RulesCard, WelcomeCard } from "./ChannelCards";
import { useServerText } from "./useServerText";

/** Unsent drafts, per channel and thread. In memory only: they're gone when the page closes. */
const drafts = new Map();

/** Why you can't post here right now, in words, or "". */
export function useSendBlock(serverId, channel, { kind = "message" } = {}) {
  const { servers, permsFor, keyState } = useServers();
  const e = servers[serverId];
  if (!e?.member || !channel) return "Loading…";
  const perms = permsFor(serverId, channel);
  const staff = has(perms, P.MANAGE_MESSAGES) || has(perms, P.MANAGE_SERVER);
  const need = kind === "post" ? P.CREATE_POSTS : P.SEND_MESSAGES;
  if (!has(perms, need)) {
    if (channel.kind === "announcement") return "Only staff post announcements. You can react.";
    if (channel.kind === "rules") return "Only staff can post here.";
    return "You can't post in this channel.";
  }
  if (e.member.timeout_until && Date.parse(e.member.timeout_until) > Date.now()) {
    return `You're timed out until ${new Date(e.member.timeout_until).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" })}.`;
  }
  if (!staff && e.server.settings?.rules_required && !e.member.rules_accepted_at) return "Accept the server's rules to post. They're at the top of this channel.";
  const minutes = e.server.settings?.min_member_minutes || 0;
  if (!staff && minutes && Date.now() - Date.parse(e.member.joined_at) < minutes * 60_000) return `New members can post ${minutes} minutes after joining.`;
  const keys = keyState(serverId, channel);
  if (keys === "waiting") return "Waiting for this channel's keys to reach this device…";
  if (keys === "setup") return "This channel's keys are being set up…";
  return "";
}

/** The newest page when a view opens, and read markers as you read. */
export function useChannelView(serverId, channel, opts = {}) {
  const { openView, setActiveChannel } = useServers();
  const [state, setState] = useState({ loading: true, error: "" });
  const key = channel ? viewKey(channel.id, opts) : "";
  useEffect(() => {
    if (!channel) return undefined;
    let alive = true;
    setState({ loading: true, error: "" });
    setActiveChannel(serverId, channel.id);
    openView(serverId, channel.id, opts)
      .then(() => alive && setState({ loading: false, error: "" }))
      .catch((err) => alive && setState({ loading: false, error: err.message }));
    return () => {
      alive = false;
      setActiveChannel(null, null);
    };
    // opts is a fresh object each render; the key captures what matters.
     
  }, [serverId, key, openView, setActiveChannel]);
  return state;
}

/**
 * A scrolling list of messages: runs grouped, days divided, earlier pages on request. Keeps to
 * the bottom while you're there, and marks the channel read as you reach it.
 */
export function MessagePane({ serverId, channel, threadId = "", rows, top = null, loading, error, onReply, onEdit, highlight, onAuthor, extraTop = null }) {
  const { userId } = useSecure();
  const { density } = useAppearance();
  const s = useServers();
  const { hasMore, loadOlder, markChannelRead, memberName, memberColor, profileOf, permsFor, react, deleteMessage, pinMessage, memberLists, servers, rolesOfMember, roleName, roleColor } = s;
  const { ctx } = useServerText(serverId, channel.id);
  const scroller = useRef(null);
  const nearBottom = useRef(true);
  const restore = useRef(null);
  const [olderBusy, setOlderBusy] = useState(false);
  const [actionError, setActionError] = useState("");
  const [forwarding, setForwarding] = useState(null);
  const location = useLocation();
  const navigate = useNavigate();
  const threadsHere = !threadId && channel.kind !== "forum";
  const key = viewKey(channel.id, threadId ? { threadId } : {});
  const more = hasMore[key];
  const perms = permsFor(serverId, channel);
  const e = servers[serverId];
  const myRoles = e?.member?.role_ids || [];
  const members = memberLists[serverId]?.members || [];
  const automod = s.automodOf(serverId);
  /** Why AutoMod hides a message, or null. Staff who can manage messages are exempt. */
  const hiddenBy = (row) => {
    if (!automod.enabled || row.m.sender_id === userId || !row.text) return null;
    const sender = members.find((mm) => mm.user_id === row.m.sender_id);
    if (sender && e?.roles && has(channelPermissions(e.server, e.roles, sender, channel), P.MANAGE_MESSAGES)) return null;
    return automodReason(automod, row.text, row.result?.content?.mentions);
  };

  useLayoutEffect(() => {
    const el = scroller.current;
    if (!el) return;
    if (restore.current !== null) {
      el.scrollTop = el.scrollHeight - restore.current;
      restore.current = null;
    } else if (nearBottom.current) {
      el.scrollTop = el.scrollHeight;
    }
  }, [rows.length, loading]);

  useEffect(() => {
    if (nearBottom.current && document.visibilityState === "visible") markChannelRead(channel.id);
  }, [rows.length, channel.id, markChannelRead]);

  // Opened from a saved message or the inbox: scroll to it once it's here.
  const jumpTo = location.state?.jumpTo;
  useEffect(() => {
    if (!jumpTo) return;
    const row = rows.find((r) => r.m.msg_id === jumpTo);
    if (!row) return;
    nearBottom.current = false;
    document.getElementById(`msg-${row.m.id}`)?.scrollIntoView({ block: "center" });
  }, [jumpTo, rows]);

  const onScroll = () => {
    const el = scroller.current;
    if (!el) return;
    nearBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 120;
    if (nearBottom.current) markChannelRead(channel.id);
  };

  const older = async () => {
    const el = scroller.current;
    setOlderBusy(true);
    try {
      restore.current = el ? el.scrollHeight - el.scrollTop : null;
      nearBottom.current = false;
      await loadOlder(serverId, channel.id, threadId ? { threadId } : {});
    } catch (err) {
      setActionError(err.message);
      restore.current = null;
    } finally {
      setOlderBusy(false);
    }
  };

  const tagFor = useCallback((uid) => {
    if (e?.server?.owner_id === uid) return <span className="rounded bg-primary/15 px-1 py-px text-[0.65rem] font-semibold text-primary">Owner</span>;
    const m = members.find((x) => x.user_id === uid) || (uid === userId ? e?.member : null);
    const top = m ? rolesOfMember(serverId, m).find((r) => r.hoist) : null;
    if (!top) return null;
    const color = roleColor(top);
    return (
      <span className="rounded px-1 py-px text-[0.65rem] font-semibold" style={{ color: color || undefined, backgroundColor: color ? `${color}22` : "hsl(var(--muted))" }}>
        {roleName(top)}
      </span>
    );
  }, [e, members, userId, rolesOfMember, roleColor, roleName, serverId]);

  const authorOf = (uid) => {
    const p = profileOf(serverId, uid);
    const m = members.find((x) => x.user_id === uid) || (uid === userId ? e?.member : null);
    return {
      name: memberName(serverId, uid),
      color: m ? memberColor(serverId, m) : "",
      emoji: p?.avatar_emoji,
      accent: p?.accent_color,
      tag: tagFor(uid),
      onClick: () => onAuthor(uid),
    };
  };

  const nameOf = (uid) => memberName(serverId, uid);
  const act = (fn) => fn().catch((err) => setActionError(err.message));

  return (
    <div ref={scroller} onScroll={onScroll} className="scroll-thin min-h-0 flex-1 overflow-y-auto pb-4" aria-live="polite">
      {more ? (
        <div className="py-3 text-center">
          <Button variant="ghost" size="sm" onClick={older} disabled={olderBusy}>{olderBusy ? "Loading…" : "Load earlier messages"}</Button>
        </div>
      ) : (
        !loading && top
      )}
      {extraTop}
      {loading && rows.length === 0 && (
        <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground" role="status"><Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Loading messages…</p>
      )}
      {error && <p className="px-4 py-3 text-sm text-destructive" role="alert">{error}</p>}
      {rows.map((row, i) => {
        const prev = rows[i - 1];
        const head = !sameRun(prev, row) || density === "compact";
        const mine = row.m.sender_id === userId;
        const mention = !mine && (() => {
          const mm = row.result?.content?.mentions;
          return Boolean(mm && (mm.everyone || mm.users?.includes(userId) || mm.roles?.some((r) => myRoles.includes(r))));
        })();
        return (
          <Fragment key={row.m.id}>
            {newDay(prev, row) && <DayDivider value={row.m.created_date} />}
            <MessageRow
              row={row}
              head={head}
              compact={density === "compact"}
              author={authorOf(row.m.sender_id)}
              highlighted={highlight === row.m.id}
              mention={mention}
              ctx={ctx}
              nameOf={nameOf}
              title={row.m.kind === "post" && row.result?.content?.title ? <h2 className="mb-1 text-xl font-semibold">{row.result.content.title}</h2> : null}
              can={{
                react: has(perms, P.ADD_REACTIONS),
                reply: has(perms, P.SEND_MESSAGES) && row.m.kind !== "post",
                edit: mine,
                pin: has(perms, P.MANAGE_MESSAGES),
                delete: mine || has(perms, P.MANAGE_MESSAGES),
              }}
              onReact={(emoji, already) => act(() => react(serverId, channel, row, emoji, already))}
              onVote={(choices) => s.vote(serverId, channel, row, choices)}
              onForward={row.result?.content?.type === "text" ? () => setForwarding({ text: row.text, attachments: row.result.content.attachments || [] }) : undefined}
              onSave={() => s.toggleSaved({ serverId, channelId: channel.id, threadId: row.m.thread_id || "", msgId: row.m.msg_id })}
              saved={s.isSaved(row.m.msg_id)}
              hiddenReason={hiddenBy(row)}
              onThread={threadsHere && row.m.kind === "message" && !row.m.deleted && (row.m.reply_count > 0 || has(perms, P.SEND_MESSAGES)) ? () => navigate(`/app/s/${serverId}/${channel.id}/${row.m.msg_id}`) : undefined}
              onReply={() => onReply?.(row)}
              onEdit={() => onEdit?.(row)}
              onDelete={() => act(() => deleteMessage(serverId, row))}
              onPin={() => act(() => pinMessage(serverId, row, !row.m.pinned))}
              onJump={(id) => document.getElementById(`msg-${id}`)?.scrollIntoView({ block: "center", behavior: "smooth" })}
            />
          </Fragment>
        );
      })}
      {actionError && (
        <p className="mx-4 mt-2 flex items-center justify-between gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive" role="alert">
          {actionError}
          <button type="button" onClick={() => setActionError("")} aria-label="Dismiss"><X className="h-4 w-4" aria-hidden="true" /></button>
        </p>
      )}
      <ForwardDialog text={forwarding?.text || ""} attachments={forwarding?.attachments || []} open={forwarding !== null} onOpenChange={(v) => !v && setForwarding(null)} />
    </div>
  );
}

/** The composer for a channel or a forum post's thread: mentions, replies, edits, and why you can't post if you can't. */
export function ChannelComposer({ serverId, channel, threadId = "", reply, setReply, editing, setEditing, placeholder }) {
  const { sendText, sendPoll, edit, channelName, memberName } = useServers();
  const presence = usePresence();
  const typers = presence.typingIn("s", serverId, channel.id, threadId).map((uid) => memberName(serverId, uid));
  const [pollOpen, setPollOpen] = useState(false);
  const [recording, setRecording] = useState(false);
  const [stickerOpen, setStickerOpen] = useState(false);
  const expressions = useServers().serverEmoji(serverId);
  const stickers = expressions.stickers;
  const staged = useStagedFiles();
  const { suggest, mentionsIn } = useServerText(serverId, channel.id);
  const block = useSendBlock(serverId, channel);
  const [text, setText] = useState("");
  const input = useRef(null);
  const draftKey = `${channel.id}:${threadId}`;

  useEffect(() => {
    setText(drafts.get(draftKey) || "");
  }, [draftKey]);

  useEffect(() => {
    if (editing) {
      setText(editing.text);
      input.current?.focus();
    }
  }, [editing]);

  useEffect(() => {
    if (reply) input.current?.focus();
  }, [reply]);

  const slow = channel.slowmode_seconds;
  const submit = async (value) => {
    if (editing) {
      if (value !== editing.text) await edit(serverId, channel, editing, value);
      setEditing(null);
    } else {
      const files = staged.items.map(({ file, spoiler }) => ({ file, spoiler }));
      try {
        await sendText(serverId, channel, value, { replyTo: reply?.m.msg_id || null, mentions: mentionsIn(value), threadId, files, onProgress: staged.onProgress });
      } finally {
        staged.setProgress(null);
      }
      staged.clear();
      setReply(null);
    }
    setText("");
    drafts.delete(draftKey);
  };

  return (
    <>
    <CreatePollDialog open={pollOpen} onOpenChange={setPollOpen} onCreate={(poll) => sendPoll(serverId, channel, poll, { threadId })} />
    <Dialog open={stickerOpen} onOpenChange={setStickerOpen}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Send a sticker</DialogTitle>
          <DialogDescription>This server's own stickers. Only members can see them.</DialogDescription>
        </DialogHeader>
        <div className="grid grid-cols-3 gap-2">
          {stickers.map((x) => (
            <button key={x.id} type="button" onClick={() => { setStickerOpen(false); sendText(serverId, channel, "", { threadId, sticker: x.id }).catch(() => {}); }} className="flex flex-col items-center gap-1 rounded-md p-2 hover:bg-muted" aria-label={`Send ${x.name}`}>
              <img src={x.img} alt="" className="h-24 w-24 object-contain" />
              <span className="truncate text-xs text-muted-foreground">{x.name}</span>
            </button>
          ))}
        </div>
      </DialogContent>
    </Dialog>
    <VoiceRecorder open={recording} onOpenChange={setRecording} onSend={(file, seconds) => sendText(serverId, channel, "", { threadId, files: [{ file, voice: true, duration: seconds }] })} />
    <Composer
      ref={input}
      tools={editing || block ? null : <ComposerPlus onPoll={() => setPollOpen(true)} onFiles={staged.add} onVoiceNote={() => setRecording(true)} onSticker={stickers.length ? () => setStickerOpen(true) : undefined} />}
      staged={block ? null : staged}
      customEmoji={expressions.emoji}
      value={text}
      onChange={(v) => {
        setText(v);
        if (v && !editing) presence.sendTyping("s", serverId, { channelId: channel.id, threadId, isPrivate: channel.private });
        if (v) drafts.set(draftKey, v);
        else drafts.delete(draftKey);
      }}
      onSubmit={submit}
      placeholder={placeholder || `Message #${channelName(channel)}`}
      disabledReason={editing ? "" : block}
      replyTo={reply ? { name: reply.authorName, text: reply.text } : null}
      editing={Boolean(editing)}
      onCancel={() => {
        if (editing) setText("");
        setEditing(null);
        setReply(null);
      }}
      suggest={suggest}
      hint={typingText(typers) || (slow ? `Slow mode is on: one message every ${slow >= 60 ? `${slow / 60} min` : `${slow} s`}.` : null)}
    />
    </>
  );
}

/** A thread off one message in a text channel: its replies, and a composer for them. */
export function ThreadView({ serverId, channel, threadId }) {
  const { threadOf, memberName, channelName, can, lockThread } = useServers();
  const view = useChannelView(serverId, channel, { threadId });
  const rows = useMemo(() => threadOf(channel.id, threadId), [threadOf, channel.id, threadId]);
  const root = rows.find((r) => r.m.msg_id === threadId && !r.m.thread_id);
  const [reply, setReply] = useState(null);
  const [editing, setEditing] = useState(null);
  const [card, setCard] = useState(null);
  const [lockError, setLockError] = useState("");
  const title = root?.text ? root.text.replace(/\s+/g, " ").slice(0, 60) : "Thread";
  const manage = can(serverId, P.MANAGE_THREADS, channel);
  const locked = Boolean(root?.m.thread_locked);
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <header className="flex h-12 shrink-0 items-center gap-2 border-b border-border/70 px-3 shadow-sm sm:px-4">
        <NavButton />
        <Link to={`/app/s/${serverId}/${channel.id}`} className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground" aria-label={`Back to #${channelName(channel)}`}>
          <ArrowLeft className="h-4 w-4" aria-hidden="true" />
        </Link>
        <MessagesSquare className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
        <span className="hidden text-sm text-muted-foreground sm:inline">#{channelName(channel)}</span>
        <span className="hidden text-muted-foreground sm:inline" aria-hidden="true">/</span>
        <h1 className="min-w-0 flex-1 truncate font-heading text-[1.05rem] font-semibold">{title}</h1>
        {manage && root && (
          <button type="button" onClick={() => lockThread(serverId, root, !locked).catch((err) => setLockError(err.message))} className="flex items-center gap-1 rounded-md px-2 py-1 text-sm text-muted-foreground hover:bg-muted hover:text-foreground">
            {locked ? <LockOpen className="h-4 w-4" aria-hidden="true" /> : <Lock className="h-4 w-4" aria-hidden="true" />} {locked ? "Unlock" : "Lock"}
          </button>
        )}
      </header>
      {lockError && <p className="px-4 py-2 text-sm text-destructive" role="alert">{lockError}</p>}
      <MessagePane
        serverId={serverId}
        channel={channel}
        threadId={threadId}
        rows={rows}
        loading={view.loading}
        error={view.error || (!view.loading && !root ? "This thread isn't here any more." : "")}
        onAuthor={setCard}
        onReply={(row) => {
          setEditing(null);
          setReply({ ...row, authorName: memberName(serverId, row.m.sender_id) });
        }}
        onEdit={(row) => {
          setReply(null);
          setEditing(row);
        }}
      />
      {root && (!locked || manage) && <ChannelComposer serverId={serverId} channel={channel} threadId={threadId} reply={reply} setReply={setReply} editing={editing} setEditing={setEditing} placeholder="Reply in this thread" />}
      {root && locked && !manage && <p className="px-4 pb-4 text-sm text-muted-foreground">This thread is locked. Only moderators can reply.</p>}
      <MemberCard serverId={serverId} userId={card} open={Boolean(card)} onOpenChange={(v) => !v && setCard(null)} />
    </div>
  );
}

function PinsDialog({ serverId, channel, open, onOpenChange, onJump }) {
  const { loadPins, threadOf, memberName } = useServers();
  const [ids, setIds] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    if (!open) return;
    setIds(null);
    loadPins(serverId, channel.id).then(setIds).catch((err) => setError(err.message));
  }, [open, serverId, channel.id, loadPins]);
  const pinned = ids ? threadOf(channel.id).filter((r) => ids.includes(r.m.id) && r.m.pinned) : [];
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[80dvh] max-w-lg overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Pinned messages</DialogTitle>
          <DialogDescription>Pinned by moderators. Decrypted on this device.</DialogDescription>
        </DialogHeader>
        {error && <p className="text-sm text-destructive">{error}</p>}
        {!ids && !error && <p className="text-sm text-muted-foreground">Loading…</p>}
        {ids && pinned.length === 0 && <p className="text-sm text-muted-foreground">Nothing's pinned here yet.</p>}
        <ul className="space-y-2">
          {pinned.map((r) => (
            <li key={r.m.id}>
              <button type="button" onClick={() => { onJump(r.m.id); onOpenChange(false); }} className="w-full rounded-lg border border-border p-3 text-left hover:bg-muted">
                <span className="flex items-baseline justify-between gap-2 text-sm">
                  <span className="font-semibold">{memberName(serverId, r.m.sender_id)}</span>
                  <span className="text-xs text-muted-foreground">{stamp(r.m.created_date)}</span>
                </span>
                <span className="mt-1 line-clamp-3 block whitespace-pre-wrap text-sm">{r.text || "Can't be read on this device"}</span>
              </button>
            </li>
          ))}
        </ul>
      </DialogContent>
    </Dialog>
  );
}

/** Search what this device has decrypted in one channel. The words never leave it. */
function SearchPanel({ serverId, channel, rows, onJump, onClose }) {
  const { memberName, hasMore, loadOlder } = useServers();
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const query = q.trim().toLowerCase();
  const hits = query.length < 2 ? [] : rows.filter((r) => r.text && r.text.toLowerCase().includes(query)).reverse().slice(0, 50);
  const more = hasMore[channel.id];
  return (
    <aside aria-label="Search" className="flex h-full w-full shrink-0 flex-col bg-panel sm:w-80">
      <div className="flex items-center gap-2 border-b border-border/70 p-3">
        <Search className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
        <input autoFocus value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search this channel" aria-label="Search this channel" className="min-w-0 flex-1 bg-transparent text-sm outline-none" />
        <button type="button" onClick={onClose} className="rounded p-1 text-muted-foreground hover:text-foreground" aria-label="Close search"><X className="h-4 w-4" aria-hidden="true" /></button>
      </div>
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto p-2">
        {query.length >= 2 && hits.length === 0 && <p className="p-2 text-sm text-muted-foreground">No messages here match.</p>}
        <ul className="space-y-1">
          {hits.map((r) => (
            <li key={r.m.id}>
              <button type="button" onClick={() => onJump(r.m.id)} className="w-full rounded-md p-2 text-left hover:bg-[hsl(var(--panel-hover))]">
                <span className="flex items-baseline justify-between gap-2 text-xs">
                  <span className="font-semibold">{memberName(serverId, r.m.sender_id)}</span>
                  <span className="text-muted-foreground">{stamp(r.m.created_date)}</span>
                </span>
                <span className="mt-0.5 line-clamp-2 block text-sm">{r.text}</span>
              </button>
            </li>
          ))}
        </ul>
        <div className="p-2 text-xs text-muted-foreground">
          <p>Searches only messages already decrypted on this device. Nothing you type here is sent anywhere.</p>
          {more && (
            <Button variant="outline" size="sm" className="mt-2" disabled={busy} onClick={async () => { setBusy(true); try { await loadOlder(serverId, channel.id); } finally { setBusy(false); } }}>
              {busy ? "Fetching…" : "Search earlier messages too"}
            </Button>
          )}
        </div>
      </div>
    </aside>
  );
}

/** A text, announcement or rules channel. */
export default function ChannelChat({ serverId, channel }) {
  const { threadOf, memberName } = useServers();
  const view = useChannelView(serverId, channel);
  const rows = useMemo(() => threadOf(channel.id), [threadOf, channel.id]);
  const [reply, setReply] = useState(null);
  const [editing, setEditing] = useState(null);
  const [membersOpen, setMembersOpen] = useState(() => typeof window !== "undefined" && window.innerWidth >= 1280);
  const [searchOpen, setSearchOpen] = useState(false);
  const [pinsOpen, setPinsOpen] = useState(false);
  const [card, setCard] = useState(null);
  const [highlight, setHighlight] = useState(null);

  useEffect(() => {
    setReply(null);
    setEditing(null);
    setSearchOpen(false);
  }, [channel.id]);

  const jump = (id) => {
    const el = document.getElementById(`msg-${id}`);
    if (!el) return;
    el.scrollIntoView({ block: "center", behavior: "smooth" });
    setHighlight(id);
    setTimeout(() => setHighlight((h) => (h === id ? null : h)), 1600);
  };

  const top = (
    <>
      {channel.template_key === "welcome" && <WelcomeCard serverId={serverId} />}
      {channel.kind === "rules" && <RulesCard serverId={serverId} />}
      <ChannelStart channel={channel} />
    </>
  );

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <ChannelHeader
        serverId={serverId}
        channel={channel}
        membersOpen={membersOpen}
        onToggleMembers={() => setMembersOpen((v) => !v)}
        onPins={() => setPinsOpen(true)}
        searchOpen={searchOpen}
        onToggleSearch={() => setSearchOpen((v) => !v)}
      />
      <div className="flex min-h-0 flex-1">
        <div className="flex min-w-0 flex-1 flex-col">
          <MessagePane
            serverId={serverId}
            channel={channel}
            rows={rows}
            top={top}
            loading={view.loading}
            error={view.error}
            highlight={highlight}
            onAuthor={setCard}
            onReply={(row) => {
              setEditing(null);
              setReply({ ...row, authorName: memberName(serverId, row.m.sender_id) });
            }}
            onEdit={(row) => {
              setReply(null);
              setEditing(row);
            }}
          />
          <ChannelComposer serverId={serverId} channel={channel} reply={reply} setReply={setReply} editing={editing} setEditing={setEditing} />
        </div>
        {searchOpen ? (
          <div className="fixed inset-0 z-30 flex justify-end bg-black/40 sm:static sm:z-auto sm:bg-transparent">
            <SearchPanel serverId={serverId} channel={channel} rows={rows} onJump={jump} onClose={() => setSearchOpen(false)} />
          </div>
        ) : (
          membersOpen && (
            <div className="fixed inset-y-0 right-0 z-30 flex shadow-2xl lg:static lg:z-auto lg:shadow-none">
              <button type="button" className="fixed inset-0 -z-10 bg-black/40 lg:hidden" onClick={() => setMembersOpen(false)} aria-label="Close member list" />
              <MemberList serverId={serverId} />
            </div>
          )
        )}
      </div>
      <PinsDialog serverId={serverId} channel={channel} open={pinsOpen} onOpenChange={setPinsOpen} onJump={jump} />
      <MemberCard serverId={serverId} userId={card} open={Boolean(card)} onOpenChange={(v) => !v && setCard(null)} />
    </div>
  );
}
