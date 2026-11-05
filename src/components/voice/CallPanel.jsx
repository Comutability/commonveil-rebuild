import React, { useEffect, useRef } from "react";
import { Hand, Headphones, HeadphoneOff, Mic, MicOff, MonitorOff, MonitorUp, PhoneOff, Video, VideoOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ErrorNote } from "@/components/site/bits";
import { useVoice } from "@/lib/voice/VoiceContext";
import Avatar from "@/components/chat/Avatar";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

const STATE_LABEL = {
  checking: "Checking their keys…",
  connecting: "Connecting…",
  unverified: "Couldn't verify, not connected",
  failed: "Can't connect",
};

/** A camera or shared screen. Sound plays separately, so the video element stays muted. */
function VideoTile({ stream, mirrored = false, label }) {
  const ref = useRef(null);
  useEffect(() => {
    if (ref.current) ref.current.srcObject = stream;
  }, [stream]);
  return <video ref={ref} autoPlay playsInline muted aria-label={label} className={`aspect-video w-full rounded-lg bg-black object-contain ${mirrored ? "-scale-x-100" : ""}`} />;
}

function Tile({ p, nameOf, profileOf, small = false, voice }) {
  const prof = profileOf(p.userId);
  const name = nameOf(p.userId);
  const body = (
    <>
      {p.stream ? (
        <VideoTile stream={p.stream} mirrored={p.self && p.video === "camera"} label={`${name}'s ${p.video === "screen" ? "screen" : "camera"}`} />
      ) : (
        <span className="relative">
          <Avatar id={p.userId} name={name} emoji={prof?.avatar_emoji} accent={prof?.accent_color} size={small ? "h-10 w-10" : "h-16 w-16"} className={small ? "" : "text-xl"} />
          {p.hand && <Hand className="absolute -right-1 -top-1 h-5 w-5 rounded-full bg-card p-0.5 text-[hsl(var(--warning))]" aria-label="Asking to speak" />}
        </span>
      )}
      <span className="max-w-full truncate text-sm font-medium">{name}{p.self ? " (you)" : ""}</span>
      <span className="flex items-center gap-1 text-xs text-muted-foreground">
        {p.canSpeak && p.muted && <MicOff className="h-3.5 w-3.5" aria-label="Muted" />}
        {p.deafened && <HeadphoneOff className="h-3.5 w-3.5" aria-label="Deafened" />}
        {!p.self && p.state && p.state !== "connected" && <span>{STATE_LABEL[p.state] || "Can't connect"}</span>}
      </span>
    </>
  );
  const cls = `flex flex-col items-center gap-2 rounded-xl border bg-card transition-shadow ${p.stream ? "col-span-full p-2 sm:col-span-2" : small ? "px-2 py-3" : "px-4 py-6"} ${p.speaking ? "border-primary ring-2 ring-primary/50" : "border-border"}`;
  if (!voice.stage || !voice.canModerate || p.self) return <li className={cls}>{body}</li>;
  return (
    <li className={cls}>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button type="button" className="flex w-full flex-col items-center gap-2 rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" aria-label={`Stage options for ${name}`}>{body}</button>
        </DropdownMenuTrigger>
        <DropdownMenuContent>
          {p.canSpeak ? (
            <>
              <DropdownMenuItem onSelect={() => voice.mutePeer(p.userId)}>Mute</DropdownMenuItem>
              <DropdownMenuItem onSelect={() => voice.setSpeaker(p.userId, false)}>Move to the audience</DropdownMenuItem>
            </>
          ) : (
            <DropdownMenuItem onSelect={() => voice.setSpeaker(p.userId, true)}>Invite to speak</DropdownMenuItem>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
    </li>
  );
}

/** The call you're in: who's there and the controls. On a stage, speakers and audience apart. */
export default function CallPanel({ nameOf, profileOf }) {
  const voice = useVoice();
  const me = voice.participants.find((p) => p.self);
  const speakers = voice.stage ? voice.participants.filter((p) => p.canSpeak) : voice.participants;
  const audience = voice.stage ? voice.participants.filter((p) => !p.canSpeak) : [];
  const round = "h-11 w-11 rounded-full";
  return (
    <>
      {voice.stage && <h3 className="mb-2 self-start text-sm font-semibold text-muted-foreground">Speakers</h3>}
      <ul className="grid w-full max-w-3xl grid-cols-[repeat(auto-fill,minmax(10rem,1fr))] gap-3" aria-label={voice.stage ? "Speakers" : "In this call"}>
        {speakers.map((p) => <Tile key={`${p.userId}-${p.self ? "me" : p.state}`} p={p} nameOf={nameOf} profileOf={profileOf} voice={voice} />)}
      </ul>
      {voice.stage && (
        <>
          <h3 className="mb-2 mt-6 self-start text-sm font-semibold text-muted-foreground">Audience, {audience.length}</h3>
          <ul className="grid w-full max-w-3xl grid-cols-[repeat(auto-fill,minmax(6.5rem,1fr))] gap-2" aria-label="Audience">
            {audience.map((p) => <Tile key={`${p.userId}-${p.self ? "me" : p.state}`} p={p} nameOf={nameOf} profileOf={profileOf} small voice={voice} />)}
          </ul>
        </>
      )}
      <div className="mt-8 flex flex-wrap items-center justify-center gap-2">
        {voice.canSpeak ? (
          <>
            <Button variant="outline" size="icon" className={round} onClick={voice.toggleMute} aria-pressed={voice.muted} aria-label={voice.muted ? "Unmute" : "Mute"}>
              {voice.muted ? <MicOff className="h-5 w-5 text-destructive" aria-hidden="true" /> : <Mic className="h-5 w-5" aria-hidden="true" />}
            </Button>
            <Button variant="outline" size="icon" className={round} onClick={voice.toggleCamera} aria-pressed={voice.video === "camera"} aria-label={voice.video === "camera" ? "Turn camera off" : "Turn camera on"}>
              {voice.video === "camera" ? <VideoOff className="h-5 w-5" aria-hidden="true" /> : <Video className="h-5 w-5" aria-hidden="true" />}
            </Button>
            {voice.canShareScreen && (
              <Button variant="outline" size="icon" className={round} onClick={voice.toggleScreen} aria-pressed={voice.video === "screen"} aria-label={voice.video === "screen" ? "Stop sharing your screen" : "Share your screen"}>
                {voice.video === "screen" ? <MonitorOff className="h-5 w-5" aria-hidden="true" /> : <MonitorUp className="h-5 w-5" aria-hidden="true" />}
              </Button>
            )}
            {voice.stage && !voice.canModerate && (
              <Button variant="outline" className="rounded-full" onClick={() => voice.setSpeaker(me?.userId, false)} disabled>Speaking</Button>
            )}
          </>
        ) : (
          <Button variant={me?.hand ? "default" : "outline"} className="rounded-full" onClick={() => voice.raiseHand(!me?.hand)} aria-pressed={Boolean(me?.hand)}>
            <Hand className="mr-1.5 h-4 w-4" aria-hidden="true" /> {me?.hand ? "Asked to speak" : "Ask to speak"}
          </Button>
        )}
        <Button variant="outline" size="icon" className={round} onClick={voice.toggleDeafen} aria-pressed={voice.deafened} aria-label={voice.deafened ? "Undeafen" : "Deafen"}>
          {voice.deafened ? <HeadphoneOff className="h-5 w-5 text-destructive" aria-hidden="true" /> : <Headphones className="h-5 w-5" aria-hidden="true" />}
        </Button>
        <Button variant="destructive" size="icon" className={round} onClick={voice.leave} aria-label="Leave the call">
          <PhoneOff className="h-5 w-5" aria-hidden="true" />
        </Button>
      </div>
      {voice.error && <div className="mt-4"><ErrorNote>{voice.error}</ErrorNote></div>}
    </>
  );
}
