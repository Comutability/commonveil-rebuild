import React, { useMemo, useState } from "react";
import { Forward, Hash, MessageCircle, Search } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { useServers, MESSAGE_KINDS } from "@/lib/secure/ServerContext";
import { useChat } from "@/lib/secure/ChatContext";
import { P, has } from "@/lib/secure/permissions";

/**
 * Forward a message's text somewhere else. It's encrypted again for the new place and marked
 * "Forwarded", without saying where it came from.
 */
export default function ForwardDialog({ text, open, onOpenChange }) {
  const s = useServers();
  const chat = useChat();
  const [query, setQuery] = useState("");
  const [state, setState] = useState({ busy: "", error: "", done: "" });

  const places = useMemo(() => {
    const out = [];
    for (const c of chat.conversations || []) out.push({ key: `c:${c.id}`, label: chat.conversationName(c), sub: "Direct message", kind: "dm", conversation: c });
    for (const sid of s.order) {
      for (const c of s.servers[sid]?.channels || []) {
        if (!MESSAGE_KINDS.has(c.kind) || c.kind === "forum") continue;
        const perms = s.permsFor(sid, c);
        if (!has(perms, P.VIEW_CHANNEL) || !has(perms, P.SEND_MESSAGES) || s.keyState(sid, c) !== "ready") continue;
        out.push({ key: `s:${c.id}`, label: `#${s.channelName(c)}`, sub: s.serverName(sid), kind: "channel", sid, channel: c });
      }
    }
    const q = query.trim().toLowerCase();
    return q ? out.filter((p) => `${p.label} ${p.sub}`.toLowerCase().includes(q)) : out;
  }, [chat, s, query]);

  const send = async (p) => {
    setState({ busy: p.key, error: "", done: "" });
    try {
      if (p.kind === "dm") await chat.sendPoll(p.conversation, { type: "text", text, forwarded: true });
      else await s.sendText(p.sid, p.channel, text, { forwarded: true });
      setState({ busy: "", error: "", done: p.key });
    } catch (err) {
      setState({ busy: "", error: err.message, done: "" });
    }
  };

  return (
    <Dialog open={open} onOpenChange={(v) => { onOpenChange(v); if (!v) setState({ busy: "", error: "", done: "" }); }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Forward</DialogTitle>
          <DialogDescription>It's encrypted again for wherever you send it, and marked as forwarded without saying where from.</DialogDescription>
        </DialogHeader>
        <blockquote className="max-h-24 overflow-hidden border-l-4 border-border pl-3 text-sm text-muted-foreground">{text}</blockquote>
        <label className="flex items-center gap-2 rounded-md border border-input px-3 py-2">
          <Search className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search conversations and channels" aria-label="Search conversations and channels" className="min-w-0 flex-1 bg-transparent text-sm outline-none" />
        </label>
        <ul className="scroll-thin max-h-72 space-y-0.5 overflow-y-auto">
          {places.length === 0 && <li className="py-4 text-center text-sm text-muted-foreground">Nowhere matches.</li>}
          {places.map((p) => (
            <li key={p.key} className="flex items-center gap-2 rounded-md px-2 py-1.5 hover:bg-muted">
              {p.kind === "dm" ? <MessageCircle className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" /> : <Hash className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />}
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm font-medium">{p.label}</span>
                <span className="block truncate text-xs text-muted-foreground">{p.sub}</span>
              </span>
              <Button size="sm" variant={state.done === p.key ? "outline" : "default"} disabled={Boolean(state.busy) || state.done === p.key} onClick={() => send(p)}>
                {state.busy === p.key ? "Sending…" : state.done === p.key ? "Sent" : <><Forward className="mr-1 h-3.5 w-3.5" aria-hidden="true" /> Send</>}
              </Button>
            </li>
          ))}
        </ul>
        {state.error && <p className="text-sm text-destructive" role="alert">{state.error}</p>}
      </DialogContent>
    </Dialog>
  );
}
