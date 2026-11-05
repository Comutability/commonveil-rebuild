import React, { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AtSign, Bookmark, Inbox as InboxIcon, X } from "lucide-react";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { useServers } from "@/lib/secure/ServerContext";
import { buildThread } from "@/lib/secure/thread";
import { useSecure } from "@/lib/secure/SecureContext";

const TABS = [
  { id: "mentions", label: "Mentions", icon: AtSign },
  { id: "unread", label: "Unread", icon: InboxIcon },
  { id: "saved", label: "Saved", icon: Bookmark },
];

/**
 * Your inbox, worked out on this device: channels where you were mentioned, channels with
 * anything new, and messages you saved for later (only where they are is saved, never their text).
 */
export default function Inbox({ className = "" }) {
  const navigate = useNavigate();
  const { userId } = useSecure();
  const { unread, servers, order, serverName, channelName, savedList, toggleSaved, rows, opened, markChannelRead, muted } = useServers();
  const [tab, setTab] = useState("mentions");
  const [open, setOpen] = useState(false);

  const channels = useMemo(() => {
    const out = [];
    for (const sid of order) {
      const e = servers[sid];
      for (const c of e?.channels || []) {
        const u = unread.channels[c.id];
        if (!u) continue;
        out.push({ sid, c, unread: u.unread && !muted(sid) && !muted(c.id), mentions: u.mentions });
      }
    }
    return out;
  }, [order, servers, unread, muted]);

  const mentionCount = channels.reduce((n, x) => n + x.mentions, 0);
  const list = tab === "mentions" ? channels.filter((x) => x.mentions > 0) : channels.filter((x) => x.unread);

  const savedRows = useMemo(() => savedList.map((s) => {
    const thread = rows[s.c] ? buildThread(rows[s.c], opened, { userId }) : [];
    const row = thread.find((r) => r.m.msg_id === s.m);
    return { ...s, text: row?.text || "", loaded: Boolean(row) };
  }), [savedList, rows, opened, userId]);

  const go = (sid, cid, extra = "", msgId = "") => {
    setOpen(false);
    navigate(`/app/s/${sid}/${cid}${extra}`, msgId ? { state: { jumpTo: msgId } } : undefined);
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          type="button"
          className={`relative flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted hover:text-foreground ${className}`}
          aria-label={mentionCount ? `Inbox, ${mentionCount} mentions` : "Inbox"}
          title="Inbox"
        >
          <InboxIcon className="h-4 w-4" aria-hidden="true" />
          {mentionCount > 0 && <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-[0.6rem] font-bold text-destructive-foreground" aria-hidden="true">{mentionCount > 99 ? "99+" : mentionCount}</span>}
        </button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-[min(24rem,calc(100vw-2rem))] p-0">
        <div className="flex items-center gap-1 border-b border-border px-2 py-2" role="tablist" aria-label="Inbox">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              aria-selected={tab === t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-1.5 rounded-md px-2.5 py-1 text-sm ${tab === t.id ? "bg-muted font-medium text-foreground" : "text-muted-foreground hover:text-foreground"}`}
            >
              <t.icon className="h-3.5 w-3.5" aria-hidden="true" /> {t.label}
            </button>
          ))}
        </div>
        <div className="scroll-thin max-h-96 overflow-y-auto p-2">
          {tab !== "saved" && (list.length === 0 ? (
            <p className="px-2 py-6 text-center text-sm text-muted-foreground">{tab === "mentions" ? "Nobody has mentioned you since you last looked." : "You're all caught up."}</p>
          ) : (
            <ul className="space-y-0.5">
              {list.map(({ sid, c, mentions }) => (
                <li key={c.id} className="flex items-center gap-2">
                  <button type="button" onClick={() => go(sid, c.id)} className="panel-item min-w-0 flex-1 text-left">
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-medium">#{channelName(c)}</span>
                      <span className="block truncate text-xs text-muted-foreground">{serverName(sid)}</span>
                    </span>
                    {mentions > 0 && <span className="rounded-full bg-destructive px-1.5 text-[0.65rem] font-bold text-destructive-foreground">{mentions}</span>}
                  </button>
                  {tab === "unread" && (
                    <button type="button" onClick={() => markChannelRead(c.id, new Date().toISOString())} className="rounded p-1 text-xs text-muted-foreground hover:bg-muted hover:text-foreground" aria-label={`Mark #${channelName(c)} as read`} title="Mark as read">
                      <X className="h-3.5 w-3.5" aria-hidden="true" />
                    </button>
                  )}
                </li>
              ))}
            </ul>
          ))}
          {tab === "saved" && (savedRows.length === 0 ? (
            <p className="px-2 py-6 text-center text-sm text-muted-foreground">Save a message from its menu to find it here. Only where it is gets saved, on this device.</p>
          ) : (
            <ul className="space-y-0.5">
              {savedRows.map((s) => {
                const c = servers[s.s]?.channels?.find((x) => x.id === s.c);
                return (
                  <li key={s.m} className="flex items-center gap-2">
                    <button type="button" onClick={() => go(s.s, s.c, s.t ? `/${s.t}` : "", s.m)} className="panel-item min-w-0 flex-1 text-left">
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm">{s.loaded ? s.text || "A message" : "Open to read it"}</span>
                        <span className="block truncate text-xs text-muted-foreground">{c ? `#${channelName(c)} in ${serverName(s.s)}` : "A channel you can't see now"}</span>
                      </span>
                    </button>
                    <button type="button" onClick={() => toggleSaved({ serverId: s.s, channelId: s.c, threadId: s.t, msgId: s.m })} className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground" aria-label="Remove from saved" title="Remove from saved">
                      <X className="h-3.5 w-3.5" aria-hidden="true" />
                    </button>
                  </li>
                );
              })}
            </ul>
          ))}
        </div>
      </PopoverContent>
    </Popover>
  );
}
