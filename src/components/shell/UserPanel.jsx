import React from "react";
import { Link } from "react-router-dom";
import { Lock, Settings } from "lucide-react";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { useSecure } from "@/lib/secure/SecureContext";
import Avatar from "@/components/chat/Avatar";
import VoiceStatus from "@/components/voice/VoiceStatus";

function IconButton({ label, children, to, onClick }) {
  const cls = "flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-[hsl(var(--panel-hover))] hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {to ? <Link to={to} className={cls} aria-label={label}>{children}</Link> : <button type="button" className={cls} onClick={onClick} aria-label={label}>{children}</button>}
      </TooltipTrigger>
      <TooltipContent side="top" className="bg-foreground text-background">{label}</TooltipContent>
    </Tooltip>
  );
}

/** Who you are, at the foot of the panel, with your settings a click away. */
export default function UserPanel() {
  const { me, userId, lockInfo, lockNow } = useSecure();
  const p = me?.profile;
  return (
    <TooltipProvider delayDuration={200}>
      <section aria-label="Your account" className="border-t border-border/60 bg-[hsl(var(--rail)/0.55)]">
        <VoiceStatus />
        <div className="flex items-center gap-2 px-2 py-2">
          <Link to="/app/settings/profile" className="flex min-w-0 flex-1 items-center gap-2 rounded-md px-1 py-1 hover-panel">
            <span className="sr-only">Your profile: </span>
            <Avatar id={userId} name={p?.display_name || p?.username} emoji={p?.avatar_emoji} image={p?.avatar_image} accent={p?.accent_color} size="h-8 w-8" />
            <span className="min-w-0 leading-tight">
              <span className="block truncate text-sm font-semibold">{p?.display_name || p?.username}</span>
              <span className="block truncate text-xs text-muted-foreground">@{p?.username}</span>
            </span>
          </Link>
          {lockInfo && (
            <IconButton label="Lock now" onClick={lockNow}>
              <Lock className="h-4 w-4" aria-hidden="true" />
            </IconButton>
          )}
          <IconButton label="Settings" to="/app/settings">
            <Settings className="h-4 w-4" aria-hidden="true" />
          </IconButton>
        </div>
      </section>
    </TooltipProvider>
  );
}
