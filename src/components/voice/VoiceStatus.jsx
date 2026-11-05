import React from "react";
import { Link } from "react-router-dom";
import { Headphones, HeadphoneOff, Mic, MicOff, PhoneOff, ShieldCheck } from "lucide-react";
import { useVoice } from "@/lib/voice/VoiceContext";
import { useServers } from "@/lib/secure/ServerContext";
import { useChat } from "@/lib/secure/ChatContext";

/** While you're in a call: where, and the controls to mute, deafen or hang up. */
export default function VoiceStatus() {
  const { room, leave, muted, deafened, toggleMute, toggleDeafen, participants } = useVoice();
  const { serverName, channelName, servers } = useServers();
  const { conversationName, conversations } = useChat();
  if (!room) return null;
  const channel = room.serverId ? servers[room.serverId]?.channels?.find((c) => c.id === room.channelId) : null;
  const conv = room.conversationId ? (conversations || []).find((c) => c.id === room.conversationId) : null;
  const where = room.serverId ? `${channelName(channel)} in ${serverName(room.serverId)}` : conv ? conversationName(conv) : "Call";
  const to = room.serverId ? `/app/s/${room.serverId}/${room.channelId}` : `/app/dm/${room.conversationId}`;
  const btn = "flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-[hsl(var(--panel-hover))] hover:text-foreground";
  return (
    <div className="border-b border-border/60 px-2 py-2">
      <div className="flex items-center gap-2">
        <div className="min-w-0 flex-1">
          <p className={`flex items-center gap-1 text-sm font-semibold ${room.status === "connected" ? "text-primary" : "text-[hsl(var(--warning))]"}`}>
            <ShieldCheck className="h-4 w-4" aria-hidden="true" />
            {room.status === "connected" ? (room.serverId ? "Voice connected" : "Call connected") : "Connecting…"}
          </p>
          <Link to={to} className="block truncate text-xs text-muted-foreground hover:underline">
            {where}, {participants.length} {participants.length === 1 ? "person" : "people"}
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
