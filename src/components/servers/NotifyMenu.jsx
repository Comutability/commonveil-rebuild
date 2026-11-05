import React from "react";
import { Bell, BellOff, BellRing } from "lucide-react";
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuLabel, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { useServers } from "@/lib/secure/ServerContext";

const LEVELS = [
  { id: "all", label: "All messages" },
  { id: "mentions", label: "Only @mentions" },
  { id: "none", label: "Nothing" },
];

/**
 * Notification setting for a channel (or, with no channel, a whole server). Kept on this
 * device; the service never knows what you chose.
 */
export default function NotifyMenu({ serverId, channel = null }) {
  const { notifyLevel, setNotifyLevel, effectiveLevel, muted, toggleMute } = useServers();
  const id = channel ? channel.id : serverId;
  const own = notifyLevel(id);
  const now = channel ? effectiveLevel(serverId, channel.id) : own || effectiveLevel(serverId, "");
  const isMuted = muted(id);
  const Icon = isMuted || now === "none" ? BellOff : now === "mentions" ? Bell : BellRing;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button type="button" className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted hover:text-foreground" aria-label="Notification settings" title="Notification settings">
          <Icon className="h-4 w-4" aria-hidden="true" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel>{channel ? "Notify me about this channel" : "Notify me about this server"}</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={own || "default"} onValueChange={(v) => setNotifyLevel(id, v === "default" ? null : v)}>
          {channel && <DropdownMenuRadioItem value="default">Same as the server</DropdownMenuRadioItem>}
          {LEVELS.map((l) => <DropdownMenuRadioItem key={l.id} value={l.id}>{l.label}</DropdownMenuRadioItem>)}
        </DropdownMenuRadioGroup>
        <DropdownMenuSeparator />
        <DropdownMenuCheckboxItem checked={isMuted} onCheckedChange={() => toggleMute(id)}>{channel ? "Mute channel" : "Mute server"}</DropdownMenuCheckboxItem>
        <p className="px-2 pb-1.5 pt-1 text-xs text-muted-foreground">Alerts show only if you've turned them on in Settings. This choice stays on this device.</p>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
