import React from "react";
import { EyeOff, FileText, X } from "lucide-react";
import { sizeLabel } from "@/lib/secure/attachments.js";

/** Files waiting to go with the next message: remove one, or mark it as a spoiler. */
export default function StagedStrip({ staged, items, busy = false, className = "" }) {
  if (!staged || !items?.length) return null;
  return (
    <ul className={`flex gap-2 overflow-x-auto ${className}`} aria-label="Files to send">
      {items.map((it) => (
        <li key={it.key} className="relative flex w-28 shrink-0 flex-col overflow-hidden rounded-md border border-border bg-background">
          <div className="flex h-20 items-center justify-center bg-muted">
            {it.preview ? <img src={it.preview} alt="" className={`h-full w-full object-cover ${it.spoiler ? "blur-md" : ""}`} /> : <FileText className="h-8 w-8 text-muted-foreground" aria-hidden="true" />}
          </div>
          <p className="truncate px-1.5 pt-1 text-xs font-medium" title={it.file.name}>{it.file.name}</p>
          <p className="px-1.5 pb-1 text-[0.7rem] text-muted-foreground">{sizeLabel(it.file.size)}{it.spoiler ? ", spoiler" : ""}</p>
          <div className="absolute right-1 top-1 flex gap-0.5">
            <button type="button" onClick={() => staged.toggleSpoiler(it.key)} disabled={busy} className={`rounded bg-background/90 p-0.5 hover:bg-muted ${it.spoiler ? "text-primary" : "text-muted-foreground"}`} aria-label={it.spoiler ? `Don't hide ${it.file.name}` : `Mark ${it.file.name} as a spoiler`} aria-pressed={it.spoiler}>
              <EyeOff className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
            <button type="button" onClick={() => staged.remove(it.key)} disabled={busy} className="rounded bg-background/90 p-0.5 text-muted-foreground hover:bg-muted" aria-label={`Remove ${it.file.name}`}>
              <X className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>
        </li>
      ))}
    </ul>
  );
}
