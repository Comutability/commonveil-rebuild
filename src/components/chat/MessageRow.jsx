import React from "react";
import { Bookmark, BookmarkCheck, Copy, CornerUpLeft, Forward, Hourglass, Lock, MoreHorizontal, Pencil, Pin, PinOff, ShieldQuestion, SmilePlus, Trash2 } from "lucide-react";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { QUICK_REACTIONS, emojiName } from "@/lib/emoji";
import Avatar from "./Avatar";
import RichText from "./RichText";
import EmojiPicker from "./EmojiPicker";
import PollCard from "./PollCard";
import AttachmentList from "./Attachments";

export const reactionName = emojiName;

const toDate = (value) => {
  if (!value) return null;
  const s = String(value);
  const d = new Date(/Z$|[+-]\d{2}:\d{2}$/.test(s) ? s : `${s}Z`);
  return Number.isNaN(d.getTime()) ? null : d;
};

export function clockTime(value) {
  const d = toDate(value);
  return d ? d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" }) : "";
}

/** "Today at 14:05", "Yesterday at 09:12", or the date. */
export function stamp(value) {
  const d = toDate(value);
  if (!d) return "";
  const today = new Date();
  const yesterday = new Date(today);
  yesterday.setDate(today.getDate() - 1);
  const time = d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
  if (d.toDateString() === today.toDateString()) return `Today at ${time}`;
  if (d.toDateString() === yesterday.toDateString()) return `Yesterday at ${time}`;
  return `${d.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: d.getFullYear() === today.getFullYear() ? undefined : "numeric" })}, ${time}`;
}

export function fullTime(value) {
  const d = toDate(value);
  return d ? d.toLocaleString("en-GB", { dateStyle: "full", timeStyle: "short" }) : "";
}

const snippet = (text, max = 100) => {
  const flat = String(text || "").replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max)}…` : flat;
};

/** Why a message can't be vouched for, in a few words. */
export function Caution({ result }) {
  if (result?.status === "unverified") {
    const removed = result.reason === "removed-device";
    return (
      <span
        className="inline-flex items-center gap-0.5 text-xs font-medium text-[hsl(var(--warning))]"
        title={removed
          ? "Signed by a device that had already been removed from the sender's account. Don't trust it."
          : "The sender's signature couldn't be checked against keys you trust. Be cautious."}
      >
        <ShieldQuestion className="h-3 w-3" aria-hidden="true" /> {removed ? "sent from a removed device" : "unverified"}
      </span>
    );
  }
  return null;
}

function ReplyQuote({ replyTo, nameOf, onJump }) {
  if (!replyTo) return null;
  if (replyTo.missing) {
    return <p className="mb-0.5 flex items-center gap-1 text-xs italic text-muted-foreground"><CornerUpLeft className="h-3 w-3" aria-hidden="true" /> Replying to an earlier message</p>;
  }
  const target = replyTo.row;
  const gone = target.m.deleted || (target.result?.status !== "ok" && target.result?.status !== "unverified");
  return (
    <button type="button" onClick={() => onJump?.(target.m.id)} className="mb-0.5 flex max-w-full items-center gap-1 text-left text-xs text-muted-foreground hover:text-foreground">
      <CornerUpLeft className="h-3 w-3 shrink-0" aria-hidden="true" />
      <span className="shrink-0 font-semibold">{nameOf(target.m.sender_id)}</span>
      <span className="truncate">{gone ? <em>message no longer available</em> : snippet(target.text)}</span>
    </button>
  );
}

function Reactions({ reactions, nameOf, onToggle, disabled }) {
  if (!reactions.length) return null;
  return (
    <div className="mt-1 flex flex-wrap gap-1">
      {reactions.map((r) => (
        <button
          key={r.emoji}
          type="button"
          disabled={disabled}
          onClick={() => onToggle(r.emoji, r.mine)}
          aria-pressed={r.mine}
          aria-label={`${reactionName(r.emoji)}, ${r.count}. ${r.mine ? "Remove yours" : "Add yours"}`}
          title={r.people.map(nameOf).join(", ")}
          className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-xs transition-colors ${r.mine ? "border-primary/60 bg-primary/10" : "border-transparent bg-muted hover:border-border"}`}
        >
          <span aria-hidden="true" className="text-sm">{r.emoji}</span>
          <span className="font-medium">{r.count}</span>
        </button>
      ))}
    </div>
  );
}

function Body({ row, ctx }) {
  const { result } = row;
  if (!result) return <span className="text-muted-foreground">Decrypting…</span>;
  if (result.status === "deleted") return <span className="italic text-muted-foreground">Message deleted</span>;
  if (result.status === "waiting") {
    return (
      <span className="inline-flex items-center gap-1.5 italic text-muted-foreground" title="Members' apps hand out keys. This one hasn't reached this device yet.">
        <Hourglass className="h-3.5 w-3.5" aria-hidden="true" /> Waiting for the key to this message
      </span>
    );
  }
  if (result.status === "before") return <span className="italic text-muted-foreground">Sent before you could read here</span>;
  if (result.status === "locked") {
    return (
      <span className="inline-flex items-center gap-1.5 italic text-muted-foreground" title={result.message || result.code}>
        <Lock className="h-3.5 w-3.5" aria-hidden="true" /> Can't be read on this device
      </span>
    );
  }
  if (row.poll) return null;
  return <RichText text={row.text} ctx={ctx} />;
}

/**
 * One message, the way chat apps lay them out: the first of a run shows who and when, the rest
 * just their text. Hovering (or focusing) shows what you can do with it.
 */
export default function MessageRow({
  row,
  head = true,
  compact = false,
  author,
  highlighted = false,
  mention = false,
  title = null,
  meta = null,
  ctx = {},
  nameOf,
  can = {},
  onReact,
  onReply,
  onEdit,
  onDelete,
  onPin,
  onJump,
  onVote,
  onForward,
  onSave,
  saved = false,
}) {
  const [picker, setPicker] = React.useState(false);
  const { m, result } = row;
  const readableNow = result && (result.status === "ok" || result.status === "unverified");
  const showTools = (readableNow && (can.react || can.reply || can.edit || can.pin || onForward || onSave)) || can.delete;
  const time = (
    <time dateTime={m.created_date} title={fullTime(m.created_date)} className="text-xs text-muted-foreground">
      {head && !compact ? stamp(m.created_date) : clockTime(m.created_date)}
    </time>
  );
  const nameButton = (
    <button type="button" onClick={author.onClick} className="truncate font-semibold hover:underline" style={author.color ? { color: author.color } : undefined}>
      {author.name}
    </button>
  );

  return (
    <div
      id={`msg-${m.id}`}
      className={`msg-row group relative flex gap-3 px-3 sm:px-4 ${head && !compact ? "mt-3 pt-1 pb-0.5" : "py-0.5"} ${mention ? "msg-mention" : ""} ${highlighted ? "bg-[hsl(var(--warning)/0.12)]" : ""} ${m.pinned ? "border-l-2 border-primary/60" : ""}`}
    >
      {compact ? (
        <span className="w-12 shrink-0 pt-0.5 text-right">{time}</span>
      ) : head ? (
        <button type="button" onClick={author.onClick} className="mt-0.5 h-10 w-10 shrink-0 rounded-full focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" aria-label={`${author.name}'s profile`}>
          <Avatar id={m.sender_id} name={author.name} emoji={author.emoji} accent={author.accent} />
        </button>
      ) : (
        <span className="w-10 shrink-0 pt-0.5 text-right text-[0.65rem] leading-5 text-muted-foreground opacity-0 group-hover:opacity-100" aria-hidden="true">
          {clockTime(m.created_date)}
        </span>
      )}
      <div className="min-w-0 flex-1">
        {(head || compact) && (
          <div className={`flex min-w-0 items-baseline gap-2 ${compact ? "float-left mr-2" : ""}`}>
            {nameButton}
            {author.tag}
            {!compact && time}
          </div>
        )}
        {readableNow && <ReplyQuote replyTo={row.replyTo} nameOf={nameOf} onJump={onJump} />}
        {readableNow && result.content?.forwarded && <p className="mb-0.5 flex items-center gap-1 text-xs italic text-muted-foreground"><Forward className="h-3 w-3" aria-hidden="true" /> Forwarded</p>}
        {title}
        <div className="whitespace-pre-wrap break-words text-[0.95rem] leading-relaxed">
          <Body row={row} ctx={ctx} />
          {row.edited && (
            <span className="ml-1 text-[0.7rem] text-muted-foreground" title={row.editedAt ? `Edited ${fullTime(row.editedAt)}` : "Edited"}>(edited)</span>
          )}
        </div>
        {(meta || result?.status === "unverified") && (
          <div className="mt-0.5 flex flex-wrap items-center gap-2">
            <Caution result={result} />
            {meta}
          </div>
        )}
        {row.poll && readableNow && <PollCard poll={row.poll} nameOf={nameOf} disabled={!can.react || !onVote} onVote={(choices) => onVote?.(choices)} />}
        <Reactions reactions={row.reactions} nameOf={nameOf} disabled={!can.react} onToggle={(emoji, already) => onReact?.(emoji, already)} />
      </div>

      {showTools && (
        <div className="absolute -top-3 right-3 z-10 flex items-center rounded-md border border-border bg-popover shadow-sm opacity-100 transition-opacity focus-within:opacity-100 group-hover:opacity-100 sm:opacity-0">
          {readableNow && can.react && QUICK_REACTIONS.slice(0, 3).map((emoji) => {
            const already = row.reactions.find((r) => r.emoji === emoji)?.mine;
            return (
              <button key={emoji} type="button" onClick={() => onReact(emoji, Boolean(already))} className="hidden h-8 w-8 items-center justify-center rounded-md hover:bg-muted sm:flex" aria-label={`${already ? "Remove" : "React with"} ${reactionName(emoji)}`}>
                <span aria-hidden="true">{emoji}</span>
              </button>
            );
          })}
          {readableNow && can.react && (
            <Popover open={picker} onOpenChange={setPicker}>
              <PopoverTrigger asChild>
                <button type="button" className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground" aria-label="Add a reaction">
                  <SmilePlus className="h-4 w-4" aria-hidden="true" />
                </button>
              </PopoverTrigger>
              <PopoverContent align="end" className="w-auto p-0">
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
          {readableNow && can.reply && (
            <button type="button" onClick={onReply} className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground" aria-label="Reply">
              <CornerUpLeft className="h-4 w-4" aria-hidden="true" />
            </button>
          )}
          {readableNow && can.edit && row.canEdit && (
            <button type="button" onClick={onEdit} className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground" aria-label="Edit">
              <Pencil className="h-4 w-4" aria-hidden="true" />
            </button>
          )}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button type="button" className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground" aria-label="More">
                <MoreHorizontal className="h-4 w-4" aria-hidden="true" />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              {readableNow && can.reply && <DropdownMenuItem onSelect={onReply}><CornerUpLeft className="mr-2 h-4 w-4" aria-hidden="true" /> Reply</DropdownMenuItem>}
              {readableNow && can.edit && row.canEdit && <DropdownMenuItem onSelect={onEdit}><Pencil className="mr-2 h-4 w-4" aria-hidden="true" /> Edit</DropdownMenuItem>}
              {readableNow && can.pin && (
                <DropdownMenuItem onSelect={onPin}>
                  {m.pinned ? <PinOff className="mr-2 h-4 w-4" aria-hidden="true" /> : <Pin className="mr-2 h-4 w-4" aria-hidden="true" />} {m.pinned ? "Unpin" : "Pin"}
                </DropdownMenuItem>
              )}
              {readableNow && onForward && <DropdownMenuItem onSelect={onForward}><Forward className="mr-2 h-4 w-4" aria-hidden="true" /> Forward</DropdownMenuItem>}
              {readableNow && onSave && (
                <DropdownMenuItem onSelect={onSave}>
                  {saved ? <BookmarkCheck className="mr-2 h-4 w-4" aria-hidden="true" /> : <Bookmark className="mr-2 h-4 w-4" aria-hidden="true" />} {saved ? "Remove from saved" : "Save for later"}
                </DropdownMenuItem>
              )}
              {readableNow && (
                <DropdownMenuItem onSelect={() => Promise.resolve(navigator.clipboard?.writeText(row.text)).catch(() => {})}><Copy className="mr-2 h-4 w-4" aria-hidden="true" /> Copy text</DropdownMenuItem>
              )}
              {can.delete && (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onSelect={onDelete} className="text-destructive"><Trash2 className="mr-2 h-4 w-4" aria-hidden="true" /> Delete for everyone</DropdownMenuItem>
                </>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      )}
    </div>
  );
}

/** A divider between days. */
export function DayDivider({ value }) {
  const d = toDate(value);
  if (!d) return null;
  return (
    <div className="relative my-4 flex items-center px-4" role="separator">
      <span className="h-px flex-1 bg-border" />
      <span className="px-2 text-xs font-medium text-muted-foreground">{d.toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long", year: "numeric" })}</span>
      <span className="h-px flex-1 bg-border" />
    </div>
  );
}

/** Whether two rows belong in one run: same sender, same day, within seven minutes. */
export function sameRun(prev, row) {
  if (!prev) return false;
  if (prev.m.sender_id !== row.m.sender_id) return false;
  const a = toDate(prev.m.created_date);
  const b = toDate(row.m.created_date);
  if (!a || !b || a.toDateString() !== b.toDateString()) return false;
  if (row.replyTo) return false;
  return b - a < 7 * 60_000;
}

export function newDay(prev, row) {
  const a = toDate(prev?.m.created_date);
  const b = toDate(row.m.created_date);
  return !a || !b || a.toDateString() !== b.toDateString();
}
