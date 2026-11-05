import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Hash, Keyboard, MessageCircle, Server, Volume2 } from "lucide-react";
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { useServers, MESSAGE_KINDS } from "@/lib/secure/ServerContext";
import { useChat } from "@/lib/secure/ChatContext";
import { P, has } from "@/lib/secure/permissions";

const SHORTCUTS = [
  ["Ctrl + K", "Find a server, channel or conversation"],
  ["Alt + ↑ / ↓", "Previous or next channel"],
  ["Alt + Shift + ↑ / ↓", "Previous or next channel with something new"],
  ["Ctrl + Alt + ↑ / ↓", "Previous or next server"],
  ["Shift + Esc", "Mark this server as read"],
  ["Enter / Shift + Enter", "Send / new line"],
  ["Esc", "Cancel a reply or an edit"],
  ["Ctrl + /", "Show these shortcuts"],
];

const isTyping = (el) => el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.isContentEditable);

/**
 * Ctrl+K to jump anywhere, plus keyboard shortcuts. Searching happens on this device, over
 * names it has already decrypted.
 */
export default function QuickSwitcher() {
  const navigate = useNavigate();
  const location = useLocation();
  const s = useServers();
  const chat = useChat();
  const [open, setOpen] = useState(false);
  const [help, setHelp] = useState(false);

  const here = useMemo(() => {
    const m = /^\/app\/s\/([^/]+)(?:\/([^/]+))?/.exec(location.pathname);
    return m ? { sid: m[1], cid: m[2] || "" } : null;
  }, [location.pathname]);

  const channelsOf = useCallback((sid) => {
    const e = s.servers[sid];
    if (!e?.channels) return [];
    return e.channels
      .filter((c) => c.kind !== "category" && has(s.permsFor(sid, c), P.VIEW_CHANNEL))
      .sort((a, b) => {
        const pa = e.channels.find((x) => x.id === a.parent_id)?.position ?? -1;
        const pb = e.channels.find((x) => x.id === b.parent_id)?.position ?? -1;
        return pa - pb || (a.position || 0) - (b.position || 0);
      });
  }, [s]);

  const step = useCallback((delta, onlyUnread) => {
    if (!here) return;
    const list = channelsOf(here.sid).filter((c) => !onlyUnread || (MESSAGE_KINDS.has(c.kind) && s.unread.channels[c.id]?.unread) || c.id === here.cid);
    if (!list.length) return;
    const i = Math.max(0, list.findIndex((c) => c.id === here.cid));
    const next = list[(i + delta + list.length) % list.length];
    if (next && next.id !== here.cid) navigate(`/app/s/${here.sid}/${next.id}`);
  }, [here, channelsOf, s.unread, navigate]);

  useEffect(() => {
    const onKey = (e) => {
      const mod = e.ctrlKey || e.metaKey;
      if (mod && !e.altKey && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((v) => !v);
      } else if (mod && e.key === "/") {
        e.preventDefault();
        setHelp(true);
      } else if (e.altKey && !mod && (e.key === "ArrowUp" || e.key === "ArrowDown")) {
        e.preventDefault();
        step(e.key === "ArrowUp" ? -1 : 1, e.shiftKey);
      } else if (e.altKey && mod && (e.key === "ArrowUp" || e.key === "ArrowDown")) {
        e.preventDefault();
        const ids = s.order;
        if (!ids.length) return;
        const i = here ? ids.indexOf(here.sid) : -1;
        const next = ids[(i + (e.key === "ArrowUp" ? -1 : 1) + ids.length) % ids.length];
        if (next) navigate(`/app/s/${next}`);
      } else if (e.shiftKey && e.key === "Escape" && here && !isTyping(document.activeElement)) {
        e.preventDefault();
        s.markServerRead(here.sid);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [step, s, here, navigate]);

  const go = (to) => {
    setOpen(false);
    navigate(to);
  };

  const conversations = chat.conversations || [];

  return (
    <>
      <CommandDialog open={open} onOpenChange={setOpen}>
        <CommandInput placeholder="Where to? Servers, channels, conversations" aria-label="Find a server, channel or conversation" />
        <CommandList>
          <CommandEmpty>Nothing with that name.</CommandEmpty>
          {conversations.length > 0 && (
            <CommandGroup heading="Direct messages">
              {conversations.slice(0, 50).map((c) => (
                <CommandItem key={c.id} value={`dm ${chat.conversationName(c)} ${c.id}`} onSelect={() => go(`/app/c/${c.id}`)}>
                  <MessageCircle className="mr-2 h-4 w-4 text-muted-foreground" aria-hidden="true" /> {chat.conversationName(c)}
                </CommandItem>
              ))}
            </CommandGroup>
          )}
          {s.order.map((sid) => (
            <CommandGroup key={sid} heading={s.serverName(sid)}>
              <CommandItem value={`server ${s.serverName(sid)} ${sid}`} onSelect={() => go(`/app/s/${sid}`)}>
                <Server className="mr-2 h-4 w-4 text-muted-foreground" aria-hidden="true" /> {s.serverName(sid)}
              </CommandItem>
              {channelsOf(sid).map((c) => (
                <CommandItem key={c.id} value={`${s.channelName(c)} ${s.serverName(sid)} ${c.id}`} onSelect={() => go(`/app/s/${sid}/${c.id}`)}>
                  {c.kind === "voice" ? <Volume2 className="mr-2 h-4 w-4 text-muted-foreground" aria-hidden="true" /> : <Hash className="mr-2 h-4 w-4 text-muted-foreground" aria-hidden="true" />}
                  {s.channelName(c)}
                  {s.unread.channels[c.id]?.mentions > 0 && <span className="ml-auto rounded-full bg-destructive px-1.5 text-[0.65rem] font-bold text-destructive-foreground">{s.unread.channels[c.id].mentions}</span>}
                </CommandItem>
              ))}
            </CommandGroup>
          ))}
          <CommandGroup heading="Help">
            <CommandItem value="keyboard shortcuts help" onSelect={() => { setOpen(false); setHelp(true); }}>
              <Keyboard className="mr-2 h-4 w-4 text-muted-foreground" aria-hidden="true" /> Keyboard shortcuts
            </CommandItem>
          </CommandGroup>
        </CommandList>
      </CommandDialog>
      <Dialog open={help} onOpenChange={setHelp}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Keyboard shortcuts</DialogTitle>
            <DialogDescription>On a Mac, use Cmd instead of Ctrl.</DialogDescription>
          </DialogHeader>
          <dl className="space-y-2 text-sm">
            {SHORTCUTS.map(([keys, what]) => (
              <div key={keys} className="flex items-baseline justify-between gap-4">
                <dt className="text-muted-foreground">{what}</dt>
                <dd><kbd className="rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-xs">{keys}</kbd></dd>
              </div>
            ))}
          </dl>
        </DialogContent>
      </Dialog>
    </>
  );
}
