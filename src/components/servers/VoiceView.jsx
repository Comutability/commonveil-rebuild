import React, { useState } from "react";
import { Headphones, HeadphoneOff, Mic, MicOff, PhoneOff, ShieldCheck, Volume2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ErrorNote } from "@/components/site/bits";
import { useServers } from "@/lib/secure/ServerContext";
import { useVoice } from "@/lib/voice/VoiceContext";
import { P } from "@/lib/secure/permissions";
import Avatar from "@/components/chat/Avatar";
import ChannelHeader from "./ChannelHeader";

const STATE_LABEL = {
  checking: "Checking their keys…",
  connecting: "Connecting…",
  unverified: "Couldn't verify, not connected",
  failed: "Can't connect",
};

/** A voice channel: who's talking, and joining in. Audio goes straight between people's devices. */
export default function VoiceView({ serverId, channel }) {
  const { channelName, can, memberName, profileOf } = useServers();
  const voice = useVoice();
  const [state, setState] = useState({ busy: false, error: "" });
  const here = voice.room?.serverId === serverId && voice.room?.channelId === channel.id;
  const allowed = can(serverId, P.CONNECT, channel);

  const join = async () => {
    setState({ busy: true, error: "" });
    try {
      await voice.join(serverId, channel);
      setState({ busy: false, error: "" });
    } catch (err) {
      setState({ busy: false, error: err.message });
    }
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <ChannelHeader serverId={serverId} channel={channel} />
      <div className="scroll-thin flex min-h-0 flex-1 flex-col items-center justify-center overflow-y-auto bg-[hsl(var(--rail)/0.5)] p-6">
        {here ? (
          <>
            <ul className="grid w-full max-w-3xl grid-cols-[repeat(auto-fill,minmax(10rem,1fr))] gap-3" aria-label="In this call">
              {voice.participants.map((p) => {
                const prof = profileOf(serverId, p.userId);
                return (
                  <li key={p.userId} className={`flex flex-col items-center gap-2 rounded-xl border bg-card px-4 py-6 transition-shadow ${p.speaking ? "border-primary ring-2 ring-primary/50" : "border-border"}`}>
                    <Avatar id={p.userId} name={memberName(serverId, p.userId)} emoji={prof?.avatar_emoji} accent={prof?.accent_color} size="h-16 w-16" className="text-xl" />
                    <span className="max-w-full truncate text-sm font-medium">{memberName(serverId, p.userId)}{p.self ? " (you)" : ""}</span>
                    <span className="flex items-center gap-1 text-xs text-muted-foreground">
                      {p.muted && <MicOff className="h-3.5 w-3.5" aria-label="Muted" />}
                      {p.deafened && <HeadphoneOff className="h-3.5 w-3.5" aria-label="Deafened" />}
                      {!p.self && p.state && p.state !== "connected" && <span>{STATE_LABEL[p.state] || "Can't connect"}</span>}
                    </span>
                  </li>
                );
              })}
            </ul>
            <div className="mt-8 flex items-center gap-2">
              <Button variant="outline" size="icon" className="h-11 w-11 rounded-full" onClick={voice.toggleMute} aria-pressed={voice.muted} aria-label={voice.muted ? "Unmute" : "Mute"}>
                {voice.muted ? <MicOff className="h-5 w-5 text-destructive" aria-hidden="true" /> : <Mic className="h-5 w-5" aria-hidden="true" />}
              </Button>
              <Button variant="outline" size="icon" className="h-11 w-11 rounded-full" onClick={voice.toggleDeafen} aria-pressed={voice.deafened} aria-label={voice.deafened ? "Undeafen" : "Deafen"}>
                {voice.deafened ? <HeadphoneOff className="h-5 w-5 text-destructive" aria-hidden="true" /> : <Headphones className="h-5 w-5" aria-hidden="true" />}
              </Button>
              <Button variant="destructive" size="icon" className="h-11 w-11 rounded-full" onClick={voice.leave} aria-label="Leave the call">
                <PhoneOff className="h-5 w-5" aria-hidden="true" />
              </Button>
            </div>
            {voice.error && <div className="mt-4"><ErrorNote>{voice.error}</ErrorNote></div>}
          </>
        ) : (
          <div className="max-w-md text-center">
            <span className="mx-auto flex h-20 w-20 items-center justify-center rounded-full bg-card text-muted-foreground">
              <Volume2 className="h-10 w-10" aria-hidden="true" />
            </span>
            <h2 className="mt-4 text-2xl font-semibold">{channelName(channel)}</h2>
            <p className="mt-2 text-sm text-muted-foreground">
              Audio goes directly between the people in the call, encrypted end to end. Commonveil only helps you find each other, and never hears anything.
            </p>
            <p className="mt-2 flex items-start justify-center gap-1.5 text-xs text-muted-foreground">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
              Connecting directly means the people in the call can see your device's network address, as with any peer-to-peer call.
            </p>
            <p className="mt-2 flex items-start justify-center gap-1.5 text-xs text-muted-foreground">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
              Each audio frame is also encrypted with this channel's post-quantum protected keys, and your app checks every device's keys before connecting.
            </p>
            <ErrorNote>{state.error || voice.error}</ErrorNote>
            {!voice.supported && <p className="mt-3 text-sm text-muted-foreground">This browser can't join encrypted calls. A recent Firefox, Safari, Chrome or Edge can.</p>}
            <Button className="mt-5" onClick={join} disabled={!allowed || state.busy || !voice.supported}>
              {!allowed ? "You can't join this channel" : state.busy ? "Joining…" : voice.room ? "Switch to this call" : "Join voice"}
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
