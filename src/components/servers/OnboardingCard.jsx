import React from "react";
import { Check, ChevronRight, Flag } from "lucide-react";
import { Button } from "@/components/ui/button";
import ServerIcon from "@/components/shell/ServerIcon";

/**
 * The first thing someone sees in a server: its welcome, what it's about, and where to start.
 * Everything on it was decrypted on this device; nothing here is fetched from anywhere.
 * preview: shown in settings to the people writing it, so the actions are left out.
 */
export default function OnboardingCard({ look, welcome, steps = [], rulesRequired = false, onOpenStep, onOpenRules, onDone, doneLabel = "Start exploring", preview = false }) {
  return (
    <div className="overflow-hidden rounded-xl border border-border bg-card">
      <div
        className="h-20 w-full bg-cover bg-center"
        style={look?.banner_image ? { backgroundImage: `url(${look.banner_image})` } : { backgroundColor: look?.banner || "hsl(var(--accent))" }}
        aria-hidden="true"
      />
      <div className="px-5 pb-5">
        <div className="-mt-8 flex items-end gap-3">
          <ServerIcon look={look} size="h-16 w-16" rounded className="!text-2xl" />
          <p className="min-w-0 truncate pb-1.5 font-heading text-xl font-semibold">{look?.name || "This server"}</p>
        </div>
        {look?.traits?.length > 0 && (
          <ul className="mt-3 flex flex-wrap gap-1.5">
            {look.traits.map((t) => (
              <li key={t} className="rounded-full border border-border px-2.5 py-0.5 text-xs text-muted-foreground">{t}</li>
            ))}
          </ul>
        )}
        {welcome ? (
          <p className="mt-4 whitespace-pre-line text-sm leading-relaxed text-foreground">{welcome}</p>
        ) : (
          <p className="mt-4 text-sm text-muted-foreground">{look?.description || "Welcome in. Have a look around."}</p>
        )}

        {steps.length > 0 && (
          <ol className="mt-4 space-y-1.5">
            {steps.map((s) => {
              const inner = (
                <>
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-border text-muted-foreground">
                    <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
                  </span>
                  <span className="min-w-0 flex-1 truncate text-left text-sm">{s.label}</span>
                </>
              );
              return (
                <li key={`${s.channel_id}-${s.label}`}>
                  {preview ? (
                    <span className="flex items-center gap-2.5 rounded-lg border border-border px-3 py-2">{inner}</span>
                  ) : (
                    <button type="button" onClick={() => onOpenStep?.(s)} className="flex w-full items-center gap-2.5 rounded-lg border border-border px-3 py-2 hover:bg-[hsl(var(--chat-hover))]">
                      {inner}
                    </button>
                  )}
                </li>
              );
            })}
          </ol>
        )}

        {rulesRequired && (
          <div className="mt-4 flex items-start gap-2 rounded-lg border border-[hsl(var(--warning)/0.4)] bg-[hsl(var(--warning)/0.08)] p-3 text-sm">
            <Flag className="mt-0.5 h-4 w-4 shrink-0 text-[hsl(var(--warning))]" aria-hidden="true" />
            <span className="min-w-0 flex-1">
              This server asks everyone to accept its rules before posting.
              {!preview && onOpenRules && (
                <button type="button" onClick={onOpenRules} className="ml-1 font-medium text-primary underline underline-offset-2">Read them</button>
              )}
            </span>
          </div>
        )}

        {!preview && (
          <Button className="mt-5 w-full" onClick={onDone}>
            <Check className="mr-1.5 h-4 w-4" aria-hidden="true" /> {doneLabel}
          </Button>
        )}
      </div>
    </div>
  );
}