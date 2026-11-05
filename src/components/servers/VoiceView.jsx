import React, { useState } from "react";
import { Radio, ShieldCheck, Volume2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ErrorNote } from "@/components/site/bits";
import { useServers } from "@/lib/secure/ServerContext";
import { useVoice } from "@/lib/voice/VoiceContext";
import { P } from "@/lib/secure/permissions";
import CallPanel from "@/components/voice/CallPanel";
import ChannelHeader from "./ChannelHeader";

/** A voice or stage channel: who's talking, and joining in. Audio goes straight between people's devices. */
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
          <CallPanel nameOf={(uid) => memberName(serverId, uid)} profileOf={(uid) => profileOf(serverId, uid)} />
        ) : (
          <div className="max-w-md text-center">
            <span className="mx-auto flex h-20 w-20 items-center justify-center rounded-full bg-card text-muted-foreground">
              {channel.kind === "stage" ? <Radio className="h-10 w-10" aria-hidden="true" /> : <Volume2 className="h-10 w-10" aria-hidden="true" />}
            </span>
            <h2 className="mt-4 text-2xl font-semibold">{channelName(channel)}</h2>
            <p className="mt-2 text-sm text-muted-foreground">
              {channel.kind === "stage" ? "A stage: moderators speak and bring people up; everyone else listens and can ask to speak. " : ""}Audio goes directly between the people in the call, encrypted end to end. Commonveil only helps you find each other, and never hears anything.
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
              {!allowed ? "You can't join this channel" : state.busy ? "Joining…" : voice.room ? "Switch to this call" : channel.kind === "stage" ? "Join the stage" : "Join voice"}
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
