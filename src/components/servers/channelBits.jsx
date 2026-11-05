import React from "react";
import { BookOpen, Hash, Lock, Megaphone, MessagesSquare, Radio, Ticket, Volume2 } from "lucide-react";

export const KIND_LABELS = {
  text: "Text",
  announcement: "Announcements",
  rules: "Rules",
  forum: "Forum",
  voice: "Voice",
  stage: "Stage",
  tickets: "Support tickets",
  category: "Category",
};

const ICONS = { text: Hash, announcement: Megaphone, rules: BookOpen, forum: MessagesSquare, voice: Volume2, stage: Radio, tickets: Ticket };

/** A channel's icon, with a small lock when only some roles can see it. */
export function ChannelIcon({ kind, isPrivate = false, className = "h-5 w-5" }) {
  const Icon = ICONS[kind] || Hash;
  return (
    <span className="relative inline-flex shrink-0" aria-hidden="true">
      <Icon className={className} />
      {isPrivate && <Lock className="absolute -bottom-0.5 -right-1 h-2.5 w-2.5 rounded-sm bg-[hsl(var(--panel))]" strokeWidth={3} />}
    </span>
  );
}

/** Channels in the order the panel shows them: loose ones first, then each category with its own. */
export function arrange(channels, visible) {
  const byPos = (a, b) => a.position - b.position || String(a.id).localeCompare(String(b.id));
  const cats = channels.filter((c) => c.kind === "category").sort(byPos);
  const catIds = new Set(cats.map((c) => c.id));
  const loose = channels.filter((c) => c.kind !== "category" && (!c.parent_id || !catIds.has(c.parent_id)) && visible(c)).sort(byPos);
  const groups = cats
    .map((cat) => ({ cat, channels: channels.filter((c) => c.parent_id === cat.id && c.kind !== "category" && visible(c)).sort(byPos) }))
    .filter((g) => g.channels.length || visible(g.cat));
  return { loose, groups, flat: [...loose, ...groups.flatMap((g) => g.channels)] };
}

/** What a channel's history setting means for someone who joins later. */
export function historyNote(channel) {
  if (channel.private) return "Private channel: only people whose roles let them in hold its keys, and they can read all of it.";
  if (channel.history === "full") return "Full history: anyone who joins can read everything here.";
  return "From joining: people who join later read only what's sent after they arrive.";
}
