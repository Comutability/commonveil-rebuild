import React, { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowLeft, Loader2, MessageSquare, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ErrorNote } from "@/components/site/bits";
import { useServers, viewKey } from "@/lib/secure/ServerContext";
import { MAX_MESSAGE_CHARS } from "@/lib/secure/protocol.js";
import { MAX_POST_TITLE } from "@/lib/secure/serverProtocol.js";
import Avatar from "@/components/chat/Avatar";
import { stamp } from "@/components/chat/MessageRow";
import { NavButton } from "@/components/shell/Shell";
import ChannelHeader from "./ChannelHeader";
import MemberCard from "./MemberCard";
import { ChannelComposer, MessagePane, useChannelView, useSendBlock } from "./ChannelChat";
import { useServerText } from "./useServerText";

function NewPostDialog({ serverId, channel, open, onOpenChange, onPosted }) {
  const { sendPost } = useServers();
  const { mentionsIn } = useServerText(serverId, channel.id);
  const [title, setTitle] = useState("");
  const [text, setText] = useState("");
  const [state, setState] = useState({ busy: false, error: "" });
  useEffect(() => {
    if (open) setState({ busy: false, error: "" });
  }, [open]);
  const submit = async (e) => {
    e.preventDefault();
    setState({ busy: true, error: "" });
    try {
      const m = await sendPost(serverId, channel, title.trim(), text, { mentions: mentionsIn(text) });
      setTitle("");
      setText("");
      onOpenChange(false);
      onPosted(m);
    } catch (err) {
      setState({ busy: false, error: err.message });
    }
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <form onSubmit={submit} className="space-y-4">
          <DialogHeader>
            <DialogTitle>New post</DialogTitle>
            <DialogDescription>Its title and text are encrypted on this device, like everything else here.</DialogDescription>
          </DialogHeader>
          <div className="space-y-1.5">
            <Label htmlFor="post-title">Title</Label>
            <Input id="post-title" value={title} onChange={(e) => setTitle(e.target.value)} maxLength={MAX_POST_TITLE} required autoFocus />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="post-text">What's it about?</Label>
            <Textarea id="post-text" value={text} onChange={(e) => setText(e.target.value)} maxLength={MAX_MESSAGE_CHARS} rows={6} required />
          </div>
          <ErrorNote>{state.error}</ErrorNote>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button type="submit" disabled={state.busy || !title.trim() || !text.trim()}>{state.busy ? "Posting…" : "Post"}</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function PostList({ serverId, channel }) {
  const navigate = useNavigate();
  const { postsOf, memberName, profileOf, hasMore, loadOlder, channelTopic } = useServers();
  const view = useChannelView(serverId, channel, { posts: true });
  const posts = useMemo(() => postsOf(channel.id), [postsOf, channel.id]);
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState(false);
  const block = useSendBlock(serverId, channel, { kind: "post" });
  const more = hasMore[viewKey(channel.id, { posts: true })];

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <ChannelHeader serverId={serverId} channel={channel} />
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-3xl px-4 py-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="max-w-prose text-sm text-muted-foreground">{channelTopic(channel) || "Start a post for each topic. Replies go in its thread."}</p>
            <Button onClick={() => setCreating(true)} disabled={Boolean(block)} title={block || undefined}>
              <Plus className="mr-1.5 h-4 w-4" aria-hidden="true" /> New post
            </Button>
          </div>
          {block && <p className="mt-2 text-xs text-muted-foreground">{block}</p>}
          {view.loading && posts.length === 0 && (
            <p className="flex items-center gap-2 py-12 text-sm text-muted-foreground" role="status"><Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Loading posts…</p>
          )}
          {view.error && <ErrorNote>{view.error}</ErrorNote>}
          {!view.loading && posts.length === 0 && (
            <div className="mt-10 text-center">
              <MessageSquare className="mx-auto h-10 w-10 text-muted-foreground" aria-hidden="true" />
              <p className="mt-3 font-heading text-xl">No posts yet</p>
              <p className="mt-1 text-sm text-muted-foreground">Be the first to start one.</p>
            </div>
          )}
          <ul className="mt-5 space-y-2">
            {posts.map((row) => {
              const p = profileOf(serverId, row.m.sender_id);
              const title = row.result?.content?.title;
              return (
                <li key={row.m.id}>
                  <Link to={`/app/s/${serverId}/${channel.id}/${row.m.msg_id}`} className="block rounded-xl border border-border bg-card px-4 py-3 transition-colors hover:border-primary/40 hover:bg-[hsl(var(--chat-hover))]">
                    <p className="font-heading text-lg font-semibold leading-snug">{title || (row.result ? "Can't be read on this device" : "Decrypting…")}</p>
                    {row.text && <p className="mt-1 line-clamp-2 text-sm text-muted-foreground">{row.text}</p>}
                    <p className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
                      <span className="inline-flex items-center gap-1.5">
                        <Avatar id={row.m.sender_id} name={memberName(serverId, row.m.sender_id)} emoji={p?.avatar_emoji} image={p?.avatar_image} accent={p?.accent_color} size="h-5 w-5" className="text-[0.6rem]" />
                        {memberName(serverId, row.m.sender_id)}
                      </span>
                      <span className="inline-flex items-center gap-1"><MessageSquare className="h-3.5 w-3.5" aria-hidden="true" /> {row.m.reply_count} {row.m.reply_count === 1 ? "reply" : "replies"}</span>
                      <span>Active {stamp(row.m.last_reply_at || row.m.created_date)}</span>
                      {row.reactions.map((r) => <span key={r.emoji}>{r.emoji} {r.count}</span>)}
                    </p>
                  </Link>
                </li>
              );
            })}
          </ul>
          {more && (
            <div className="mt-4 text-center">
              <Button variant="ghost" size="sm" disabled={busy} onClick={async () => { setBusy(true); try { await loadOlder(serverId, channel.id, { posts: true }); } finally { setBusy(false); } }}>
                {busy ? "Loading…" : "Show older posts"}
              </Button>
            </div>
          )}
        </div>
      </div>
      <NewPostDialog serverId={serverId} channel={channel} open={creating} onOpenChange={setCreating} onPosted={(m) => navigate(`/app/s/${serverId}/${channel.id}/${m.msg_id}`)} />
    </div>
  );
}

function PostThread({ serverId, channel, postId }) {
  const { threadOf, memberName, channelName } = useServers();
  const view = useChannelView(serverId, channel, { threadId: postId });
  const rows = useMemo(() => threadOf(channel.id, postId), [threadOf, channel.id, postId]);
  const post = rows.find((r) => r.m.kind === "post");
  const [reply, setReply] = useState(null);
  const [editing, setEditing] = useState(null);
  const [card, setCard] = useState(null);
  const title = post?.result?.content?.title;
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <header className="flex h-12 shrink-0 items-center gap-2 border-b border-border/70 px-3 shadow-sm sm:px-4">
        <NavButton />
        <Link to={`/app/s/${serverId}/${channel.id}`} className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground" aria-label={`Back to #${channelName(channel)}`}>
          <ArrowLeft className="h-4 w-4" aria-hidden="true" />
        </Link>
        <span className="hidden text-sm text-muted-foreground sm:inline">#{channelName(channel)}</span>
        <span className="hidden text-muted-foreground sm:inline" aria-hidden="true">/</span>
        <h1 className="truncate font-heading text-[1.05rem] font-semibold">{title || "Post"}</h1>
      </header>
      <MessagePane
        serverId={serverId}
        channel={channel}
        threadId={postId}
        rows={rows}
        loading={view.loading}
        error={view.error || (!view.loading && !post ? "This post isn't here any more." : "")}
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
      {post && <ChannelComposer serverId={serverId} channel={channel} threadId={postId} reply={reply} setReply={setReply} editing={editing} setEditing={setEditing} placeholder={`Reply to ${title || "this post"}`} />}
      <MemberCard serverId={serverId} userId={card} open={Boolean(card)} onOpenChange={(v) => !v && setCard(null)} />
    </div>
  );
}

export default function ForumView({ serverId, channel, postId }) {
  return postId ? <PostThread serverId={serverId} channel={channel} postId={postId} /> : <PostList serverId={serverId} channel={channel} />;
}
