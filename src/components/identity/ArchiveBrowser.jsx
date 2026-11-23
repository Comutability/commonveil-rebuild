import React, { useState } from "react";
import { formatDate } from "@/components/site/bits";

/** An archive brought from another site: conversations, read-only, kept in this browser. */
export default function ArchiveBrowser({ archive }) {
  const [openId, setOpenId] = useState(null);
  const conversations = archive?.data?.conversations || [];
  if (!conversations.length) return null;
  const active = conversations.find((_, i) => i === openId) || null;
  const label = (c) => c.name || (c.members || []).filter((m) => !m.you).map((m) => m.display_name || (m.username ? `@${m.username}` : "Someone")).join(", ") || "Conversation";

  return (
    <div className="grid gap-3 sm:grid-cols-[minmax(0,14rem)_minmax(0,1fr)]">
      <ul className="max-h-64 space-y-1 overflow-y-auto scroll-thin">
        {conversations.map((c, i) => (
          <li key={i}>
            <button
              type="button"
              onClick={() => setOpenId(i)}
              className="panel-item text-left"
              aria-current={openId === i ? "page" : undefined}
            >
              <span className="truncate">{label(c)}</span>
              <span className="ml-auto shrink-0 text-xs text-muted-foreground">{(c.messages || []).length}</span>
            </button>
          </li>
        ))}
      </ul>
      <div className="max-h-64 overflow-y-auto rounded-lg border border-border p-3 scroll-thin">
        {!active ? (
          <p className="text-sm text-muted-foreground">Pick a conversation to read it.</p>
        ) : (
          <>
            <p className="mb-2 text-sm font-medium">{label(active)}</p>
            <ul className="space-y-2">
              {(active.messages || []).map((m, i) => (
                <li key={i} className="text-sm">
                  <span className="font-medium">{m.from}</span>{" "}
                  <span className="text-xs text-muted-foreground">{formatDate(m.sent)}</span>
                  <p className="whitespace-pre-wrap">{m.text ?? <em className="text-muted-foreground">This message couldn't be read when the passport was made.</em>}</p>
                </li>
              ))}
            </ul>
          </>
        )}
      </div>
    </div>
  );
}