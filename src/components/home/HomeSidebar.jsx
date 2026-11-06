import React, { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { History, Plus, Search, Timer, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useChat } from "@/lib/secure/ChatContext";
import { useSecure } from "@/lib/secure/SecureContext";
import { formatTime, Loading } from "@/components/site/bits";
import Avatar from "@/components/chat/Avatar";

function previewOf(row) {
  if (!row?.result) return "Encrypted message";
  const { result } = row;
  if (result.status === "deleted") return "Message deleted";
  if (result.status === "locked") return "Can't be read on this device";
  if (result.status === "unverified") return `Unverified: ${row.text}`;
  return row.text;
}

/** Messages found on this device. The search never leaves it. */
function MessageResults({ query }) {
  const { searchMessages, loadHistory, conversationName, nameOf } = useChat();
  const [state, setState] = useState({ busy: false, done: false, error: "" });
  const hits = searchMessages(query).filter((h) => !h.conversation.server_id);
  const searchFurther = async () => {
    setState({ busy: true, done: false, error: "" });
    try {
      const more = await loadHistory({ pages: 3 });
      setState({ busy: false, done: !more, error: "" });
    } catch (err) {
      setState({ busy: false, done: false, error: err.message });
    }
  };
  return (
    <section aria-label="Messages found" className="mt-2 border-t border-border/60 pt-2">
      <h2 className="px-2 pb-1 pt-1 text-xs font-semibold text-muted-foreground">Messages</h2>
      {hits.length === 0 ? (
        <p className="px-2 py-1 text-sm text-muted-foreground">No messages here match.</p>
      ) : (
        <ul>
          {hits.map(({ conversation, row, snippet }) => (
            <li key={row.m.id}>
              <Link to={`/app/c/${conversation.id}`} className="panel-item flex-col !items-start !gap-0">
                <span className="flex w-full items-baseline justify-between gap-2 text-sm">
                  <span className="truncate font-medium text-foreground">{conversationName(conversation)}</span>
                  <span className="shrink-0 text-xs">{formatTime(row.m.created_date)}</span>
                </span>
                <span className="block w-full truncate text-xs">{nameOf(row.m.sender_id)}: {snippet}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
      <div className="px-2 py-2 text-xs text-muted-foreground">
        <p>Search looks only through messages already opened on this device. Nothing you type is sent anywhere.</p>
        {state.error && <p className="mt-1 text-destructive" role="alert">{state.error}</p>}
        {state.done ? (
          <p className="mt-1">That's everything there is.</p>
        ) : (
          <Button variant="outline" size="sm" className="mt-2" disabled={state.busy} onClick={searchFurther}>
            <History className="mr-1.5 h-4 w-4" aria-hidden="true" /> {state.busy ? "Fetching and decrypting…" : "Search older messages too"}
          </Button>
        )}
      </div>
    </section>
  );
}

/** Your direct messages and groups, most recent first. Support tickets live in their servers. */
export default function HomeSidebar({ activeId, onNew }) {
  const { conversations, conversationName, isUnread, threads, loaded, nameOf, profiles } = useChat();
  const { userId, peers } = useSecure();
  const [q, setQ] = useState("");
  const query = q.trim().toLowerCase();
  const mine = conversations.filter((c) => !c.server_id);
  const shown = mine.filter((c) => !query || conversationName(c).toLowerCase().includes(query));
  const lastRows = useMemo(() => {
    const out = {};
    for (const c of conversations) {
      const rows = threads[c.id] || [];
      out[c.id] = rows[rows.length - 1] || null;
    }
    return out;
  }, [conversations, threads]);

  return (
    <nav aria-label="Direct messages" className="flex h-full min-h-0 flex-col">
      <div className="flex h-12 shrink-0 items-center border-b border-border/70 px-2.5 shadow-sm">
        <div className="relative w-full">
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Find a conversation"
            aria-label="Find a conversation or message"
            className="h-8 w-full rounded-md bg-[hsl(var(--rail))] pl-7 pr-7 text-sm outline-none placeholder:text-muted-foreground focus:ring-2 focus:ring-ring/40"
          />
          {q && (
            <button type="button" onClick={() => setQ("")} className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded p-0.5 text-muted-foreground hover:text-foreground" aria-label="Clear search">
              <X className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          )}
        </div>
      </div>
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto px-2 pb-4 pt-3">
        <div className="flex items-center justify-between px-2 pb-1">
          <h2 className="text-xs font-semibold text-muted-foreground">Direct messages</h2>
          <button type="button" onClick={onNew} className="rounded p-0.5 text-muted-foreground hover:text-foreground" aria-label="New conversation" title="New conversation">
            <Plus className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>
        {!loaded ? (
          <Loading label="Loading conversations" />
        ) : shown.length === 0 ? (
          <div className="px-2 py-6 text-sm text-muted-foreground">
            {mine.length === 0 ? (
              <>
                <p className="font-medium text-foreground">No conversations yet</p>
                <p className="mt-1">Start one with someone's exact username. Nobody can browse a list of members to find you.</p>
                <Button size="sm" className="mt-3" onClick={onNew}><Plus className="mr-1 h-4 w-4" aria-hidden="true" /> New conversation</Button>
              </>
            ) : (
              "No conversation names match."
            )}
          </div>
        ) : (
          <ul className="space-y-0.5">
            {shown.map((c) => {
              const last = lastRows[c.id];
              const unread = isUnread(c);
              const other = c.member_ids.find((m) => m !== userId);
              const warn = c.member_ids.some((m) => m !== userId && peers[m]?.changed);
              const p = profiles[other];
              return (
                <li key={c.id}>
                  <Link to={`/app/c/${c.id}`} aria-current={activeId === c.id ? "page" : undefined} className={`panel-item !py-1.5 ${unread ? "!text-foreground" : ""}`}>
                    <Avatar id={other} name={nameOf(other)} group={c.kind === "group"} emoji={c.kind === "dm" ? p?.avatar_emoji : ""} image={c.kind === "dm" ? p?.avatar_image : ""} accent={c.kind === "dm" ? p?.accent_color : ""} size="h-8 w-8" />
                    <span className="min-w-0 flex-1">
                      <span className={`flex items-center gap-1 ${unread ? "font-semibold" : "font-medium"}`}>
                        <span className="truncate">{conversationName(c)}</span>
                        {c.expire_seconds > 0 && <Timer className="h-3 w-3 shrink-0" aria-label="Disappearing messages on" />}
                      </span>
                      <span className="block truncate text-xs">
                        {warn ? "Security keys changed" : last ? `${last.m.sender_id === userId ? "You: " : ""}${previewOf(last)}` : c.kind === "group" ? `${c.member_ids.length} people` : "Encrypted conversation"}
                      </span>
                    </span>
                    {unread && <span className="h-2 w-2 shrink-0 rounded-full bg-primary" aria-label="Unread" />}
                  </Link>
                </li>
              );
            })}
          </ul>
        )}
        {query.length >= 2 && <MessageResults query={query} />}
      </div>
    </nav>
  );
}
