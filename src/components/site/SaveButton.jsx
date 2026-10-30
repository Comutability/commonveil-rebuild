import React from "react";
import { Bookmark, BookmarkCheck, CheckCircle2, Circle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useSaved } from "@/lib/site/saved.js";

/** Save a page on this browser. Nothing is sent anywhere. */
export function SaveButton({ kind, slug, title, className = "" }) {
  const { isSaved, toggleSaved } = useSaved();
  const saved = isSaved(kind, slug);
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      className={className}
      aria-pressed={saved}
      onClick={() => toggleSaved({ kind, slug, title })}
      title="Saved on this browser only"
    >
      {saved ? <BookmarkCheck className="mr-1.5 h-4 w-4 text-primary" aria-hidden="true" /> : <Bookmark className="mr-1.5 h-4 w-4" aria-hidden="true" />}
      {saved ? "Saved" : "Save"}
    </Button>
  );
}

/** Tick off a guide on this browser. Learning paths show how far along you are. */
export function DoneButton({ slug, className = "" }) {
  const { isDone, toggleDone } = useSaved();
  const done = isDone(slug);
  return (
    <Button type="button" variant={done ? "default" : "outline"} size="sm" className={className} aria-pressed={done} onClick={() => toggleDone(slug)}>
      {done ? <CheckCircle2 className="mr-1.5 h-4 w-4" aria-hidden="true" /> : <Circle className="mr-1.5 h-4 w-4" aria-hidden="true" />}
      {done ? "Done" : "Mark as done"}
    </Button>
  );
}
