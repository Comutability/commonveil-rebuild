import React, { useRef } from "react";
import { BarChart3, Mic, Paperclip, Plus } from "lucide-react";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

/**
 * The + beside the message box: files, voice messages and polls. Only what's passed is offered.
 * onFiles(FileList) gets the files picked; nothing is read or sent until the message is.
 */
export default function ComposerPlus({ onPoll, onFiles, onVoiceNote, disabled = false }) {
  const picker = useRef(null);
  if (!onPoll && !onFiles && !onVoiceNote) return null;
  return (
    <>
      {onFiles && (
        <input
          ref={picker}
          type="file"
          multiple
          className="hidden"
          tabIndex={-1}
          aria-hidden="true"
          onChange={(e) => {
            if (e.target.files?.length) onFiles(e.target.files);
            e.target.value = "";
          }}
        />
      )}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            disabled={disabled}
            className="mb-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted text-muted-foreground transition-colors hover:bg-primary/15 hover:text-foreground disabled:opacity-50"
            aria-label="Add a file, voice message or poll"
          >
            <Plus className="h-4 w-4" aria-hidden="true" />
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" side="top" className="w-56">
          {onFiles && <DropdownMenuItem onSelect={() => setTimeout(() => picker.current?.click(), 0)}><Paperclip className="mr-2 h-4 w-4" aria-hidden="true" /> Upload a file</DropdownMenuItem>}
          {onVoiceNote && <DropdownMenuItem onSelect={onVoiceNote}><Mic className="mr-2 h-4 w-4" aria-hidden="true" /> Record a voice message</DropdownMenuItem>}
          {onPoll && <DropdownMenuItem onSelect={onPoll}><BarChart3 className="mr-2 h-4 w-4" aria-hidden="true" /> Create a poll</DropdownMenuItem>}
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  );
}
