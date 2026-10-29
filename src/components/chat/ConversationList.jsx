import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Plus, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useChat } from "@/lib/secure/ChatContext";
import { useSecure } from "@/lib/secure/SecureContext";
import { formatTime, Loading } from "@/components/site/bits";
import Avatar from "./Avatar";

function previewOf(result) {
  if (!result) return "Encrypted message";
  if (result.status === "deleted") return "Message deleted";
  if (result.status === "locked") return "Can't be read on this device";
  return result.text;
}

export default function ConversationList({ activeId, onNew }) {
  const { conversations, conversationName, isUnread, messages, opened, loaded, nameOf } = useChat();
  const { userId, peers } = useSecure();
  const [q, setQ] = useState("");
  const query = q.trim().toLowerCase();
  const shown = conversations.filter((c) => !query || conversationName(c).toLowerCase().includes(query));

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
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search conversations" className="pl-9" aria-label="Search conversations" />
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {!loaded ? (
          <Loading label="Loading conversations" />
        ) : shown.length === 0 ? (
          <div className="px-6 py-10 text-center text-sm text-muted-foreground">
            {conversations.length === 0 ? (
              <>
                <p className="font-heading text-lg text-foreground">No conversations yet</p>
                <p className="mt-1">Start one with someone's exact username.</p>
              </>
            ) : (
              "Nothing matches that search."
            )}
          </div>
        ) : (
          <ul>
            {shown.map((c) => {
              const list = messages[c.id] || [];
              const last = list[list.length - 1];
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
                        <span className={`truncate ${unread ? "font-semibold" : "font-medium"}`}>{conversationName(c)}</span>
                        <span className="shrink-0 text-xs text-muted-foreground">{formatTime(c.last_message_at)}</span>
                      </span>
                      <span className="flex items-center gap-2">
                        <span className={`truncate text-sm ${unread ? "text-foreground" : "text-muted-foreground"}`}>
                          {warn ? "⚠ Security keys changed" : last ? `${last.sender_id === userId ? "You: " : ""}${previewOf(opened[last.id])}` : c.kind === "group" ? `${c.member_ids.length} people` : "Encrypted conversation"}
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
      </div>
    </aside>
  );
}
