import React from "react";
import { Link } from "react-router-dom";
import { Headphones, HeadphoneOff, Mic, MicOff, PhoneOff, ShieldCheck } from "lucide-react";
import { useVoice } from "@/lib/voice/VoiceContext";
import { useServers } from "@/lib/secure/ServerContext";

/** While you're in a call: where, and the controls to mute, deafen or hang up. */
export default function VoiceStatus() {
  const { room, leave, muted, deafened, toggleMute, toggleDeafen, participants } = useVoice();
  const { serverName, channelName, servers } = useServers();
  if (!room) return null;
  const channel = servers[room.serverId]?.channels?.find((c) => c.id === room.channelId);
  const btn = "flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-[hsl(var(--panel-hover))] hover:text-foreground";
  return (
    <div className="border-b border-border/60 px-2 py-2">
      <div className="flex items-center gap-2">
        <div className="min-w-0 flex-1">
          <p className={`flex items-center gap-1 text-sm font-semibold ${room.status === "connected" ? "text-primary" : "text-[hsl(var(--warning))]"}`}>
            <ShieldCheck className="h-4 w-4" aria-hidden="true" />
            {room.status === "connected" ? "Voice connected" : "Connecting…"}
          </p>
          <Link to={`/app/s/${room.serverId}/${room.channelId}`} className="block truncate text-xs text-muted-foreground hover:underline">
            {channelName(channel)} in {serverName(room.serverId)}, {participants.length} {participants.length === 1 ? "person" : "people"}
          </Link>
        </div>
        <button type="button" className={btn} onClick={leave} aria-label="Leave the call">
          <PhoneOff className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>
      <div className="mt-1 flex gap-1">
        <button type="button" className={btn} onClick={toggleMute} aria-pressed={muted} aria-label={muted ? "Unmute" : "Mute"}>
          {muted ? <MicOff className="h-4 w-4 text-destructive" aria-hidden="true" /> : <Mic className="h-4 w-4" aria-hidden="true" />}
        </button>
        <button type="button" className={btn} onClick={toggleDeafen} aria-pressed={deafened} aria-label={deafened ? "Undeafen" : "Deafen"}>
          {deafened ? <HeadphoneOff className="h-4 w-4 text-destructive" aria-hidden="true" /> : <Headphones className="h-4 w-4" aria-hidden="true" />}
        </button>
      </div>
    </div>
  );
}
