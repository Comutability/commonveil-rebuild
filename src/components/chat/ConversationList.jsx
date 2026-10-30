import React, { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { History, Plus, Search, Timer } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useChat } from "@/lib/secure/ChatContext";
import { useSecure } from "@/lib/secure/SecureContext";
import { formatTime, Loading } from "@/components/site/bits";
import Avatar from "./Avatar";

function previewOf(row) {
  if (!row?.result) return "Encrypted message";
  const { result } = row;
  if (result.status === "deleted") return "Message deleted";
  if (result.status === "locked") return "Can't be read on this device";
  if (result.status === "unverified") return `⚠ Unverified: ${row.text}`;
  return row.text;
}

/** Messages found on this device. The search never leaves it. */
function MessageResults({ query }) {
  const { searchMessages, loadHistory, conversationName, nameOf } = useChat();
  const [state, setState] = useState({ busy: false, done: false, error: "" });
  const hits = searchMessages(query);
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
    <section aria-label="Messages found" className="border-t border-border pt-2">
      <h2 className="px-4 pb-1 pt-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Messages</h2>
      {hits.length === 0 ? (
        <p className="px-4 py-2 text-sm text-muted-foreground">No messages here match.</p>
      ) : (
        <ul>
          {hits.map(({ conversation, row, snippet }) => (
            <li key={row.m.id}>
              <Link to={`/app/c/${conversation.id}`} className="block px-4 py-2.5 transition-colors hover:bg-muted/60">
                <span className="flex items-baseline justify-between gap-2 text-sm">
                  <span className="truncate font-medium">{conversationName(conversation)}</span>
                  <span className="shrink-0 text-xs text-muted-foreground">{formatTime(row.m.created_date)}</span>
                </span>
                <span className="block truncate text-sm text-muted-foreground">{nameOf(row.m.sender_id)}: {snippet}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
      <div className="px-4 py-3 text-xs text-muted-foreground">
        <p>Search looks only through messages already opened on this device. Nothing you type here is sent anywhere.</p>
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

export default function ConversationList({ activeId, onNew }) {
  const { conversations, conversationName, isUnread, threads, loaded, nameOf } = useChat();
  const { userId, peers } = useSecure();
  const [q, setQ] = useState("");
  const query = q.trim().toLowerCase();
  const shown = conversations.filter((c) => !query || conversationName(c).toLowerCase().includes(query));
  const lastRows = useMemo(() => {
    const out = {};
    for (const c of conversations) {
      const rows = threads[c.id] || [];
      out[c.id] = rows[rows.length - 1] || null;
    }
    return out;
  }, [conversations, threads]);

  return (
    <aside className="flex h-full min-h-0 flex-col">
      <div className="flex items-center justify-between gap-2 px-4 pb-2 pt-4">
        <h1 className="text-2xl font-semibold">Messages</h1>
        <Button size="sm" onClick={onNew}>
          <Plus className="mr-1 h-4 w-4" aria-hidden="true" /> New
        </Button>
      </div>
      <div className="px-4 pb-3">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search conversations and messages" className="pl-9" aria-label="Search conversations and messages" />
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {!loaded ? (
          <Loading label="Loading conversations" />
        ) : (
          <>
            {shown.length === 0 ? (
              <div className="px-6 py-10 text-center text-sm text-muted-foreground">
                {conversations.length === 0 ? (
                  <>
                    <p className="font-heading text-lg text-foreground">No conversations yet</p>
                    <p className="mt-1">Start one with someone's exact username.</p>
                  </>
                ) : (
                  "No conversation names match."
                )}
              </div>
            ) : (
              <ul>
                {shown.map((c) => {
                  const last = lastRows[c.id];
                  const unread = isUnread(c);
                  const other = c.member_ids.find((m) => m !== userId);
                  const warn = c.member_ids.some((m) => m !== userId && peers[m]?.changed);
                  return (
                    <li key={c.id}>
                      <Link
                        to={`/app/c/${c.id}`}
                        aria-current={activeId === c.id ? "page" : undefined}
                        className={`flex items-center gap-3 px-4 py-3 transition-colors hover:bg-muted/60 ${activeId === c.id ? "bg-muted" : ""}`}
                      >
                        <Avatar id={other} name={nameOf(other)} group={c.kind === "group"} />
                        <span className="min-w-0 flex-1">
                          <span className="flex items-baseline justify-between gap-2">
                            <span className={`flex min-w-0 items-center gap-1 ${unread ? "font-semibold" : "font-medium"}`}>
                              <span className="truncate">{conversationName(c)}</span>
                              {c.expire_seconds > 0 && <Timer className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-label="Disappearing messages on" />}
                            </span>
                            <span className="shrink-0 text-xs text-muted-foreground">{formatTime(c.last_message_at)}</span>
                          </span>
                          <span className="flex items-center gap-2">
                            <span className={`truncate text-sm ${unread ? "text-foreground" : "text-muted-foreground"}`}>
                              {warn ? "⚠ Security keys changed" : last ? `${last.m.sender_id === userId ? "You: " : ""}${previewOf(last)}` : c.kind === "group" ? `${c.member_ids.length} people` : "Encrypted conversation"}
                            </span>
                            {unread && <span className="ml-auto h-2.5 w-2.5 shrink-0 rounded-full bg-primary" aria-label="Unread" />}
                          </span>
                        </span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            )}
            {query.length >= 2 && <MessageResults query={query} />}
          </>
        )}
      </div>
    </aside>
  );
}
