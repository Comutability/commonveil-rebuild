import React from "react";
import { BarChart3, Mic, Paperclip, Plus } from "lucide-react";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

/** The + beside the message box: polls, files and voice messages. Only what's passed is offered. */
export default function ComposerPlus({ onPoll, onFile, onVoiceNote, disabled = false }) {
  if (!onPoll && !onFile && !onVoiceNote) return null;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          disabled={disabled}
          className="mb-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted text-muted-foreground transition-colors hover:bg-primary/15 hover:text-foreground disabled:opacity-50"
          aria-label="Add a poll, file or voice message"
        >
          <Plus className="h-4 w-4" aria-hidden="true" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" side="top" className="w-56">
        {onFile && <DropdownMenuItem onSelect={onFile}><Paperclip className="mr-2 h-4 w-4" aria-hidden="true" /> Upload a file</DropdownMenuItem>}
        {onVoiceNote && <DropdownMenuItem onSelect={onVoiceNote}><Mic className="mr-2 h-4 w-4" aria-hidden="true" /> Record a voice message</DropdownMenuItem>}
        {onPoll && <DropdownMenuItem onSelect={onPoll}><BarChart3 className="mr-2 h-4 w-4" aria-hidden="true" /> Create a poll</DropdownMenuItem>}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
