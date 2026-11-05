import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Hourglass, Pin, Search, Settings, ShieldCheck, Users } from "lucide-react";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { useServers } from "@/lib/secure/ServerContext";
import { useSecure } from "@/lib/secure/SecureContext";
import { P } from "@/lib/secure/permissions";
import { NavButton } from "@/components/shell/Shell";
import { ChannelIcon, historyNote } from "./channelBits";
import NotifyMenu from "./NotifyMenu";
import Inbox from "@/components/shell/Inbox";

function HeaderButton({ label, active = false, onClick, children }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      aria-pressed={active}
      title={label}
      className={`flex h-8 w-8 items-center justify-center rounded-md transition-colors hover:bg-muted ${active ? "text-foreground" : "text-muted-foreground hover:text-foreground"}`}
    >
      {children}
    </button>
  );
}

/** The seal: whether this device holds the channel's keys, and what that protects. */
export function Seal({ serverId, channel }) {
  const { keyState } = useServers();
  const { chain } = useSecure();
  const state = keyState(serverId, channel);
  const pq = Boolean(chain?.latest?.kem_pub);
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          className={`hidden items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium sm:inline-flex ${state === "ready" ? "border-primary/40 text-primary" : "border-[hsl(var(--warning)/0.5)] text-[hsl(var(--warning))]"}`}
        >
          {state === "ready" ? <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" /> : <Hourglass className="h-3.5 w-3.5" aria-hidden="true" />}
          {state === "ready" ? "Encrypted" : state === "waiting" ? "Waiting for keys" : "Setting up keys"}
        </button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 space-y-2 text-sm">
        <p className="font-heading text-base font-semibold">How this channel is protected</p>
        <p>Messages are encrypted on members' devices with keys the server's members hold. Commonveil stores only ciphertext and can't read it.</p>
        <p className="text-muted-foreground">{historyNote(channel)}</p>
        <p className="text-muted-foreground">
          {pq
            ? "Your copies of the keys are sealed with a post-quantum key exchange (ML-KEM-768 together with P-256), and messages use 256-bit AES."
            : "Your account's keys are being upgraded to post-quantum. Messages use 256-bit AES."}
        </p>
        {state !== "ready" && (
          <p className="text-[hsl(var(--warning))]">
            {state === "waiting"
              ? "This device is waiting for its copy of the keys. Members' apps hand them out, usually as soon as someone who can is online."
              : "Nobody has made this channel's keys yet. That happens automatically the first time someone who can opens it."}
          </p>
        )}
      </PopoverContent>
    </Popover>
  );
}

export default function ChannelHeader({ serverId, channel, membersOpen, onToggleMembers, onPins, searchOpen, onToggleSearch, title }) {
  const navigate = useNavigate();
  const { channelName, channelTopic, can } = useServers();
  const [expanded, setExpanded] = useState(false);
  const topic = channelTopic(channel);
  return (
    <header className="flex h-12 shrink-0 items-center gap-2 border-b border-border/70 px-3 shadow-sm sm:px-4">
      <NavButton />
      <ChannelIcon kind={channel.kind} isPrivate={channel.private} className="h-5 w-5 text-muted-foreground" />
      <h1 className="truncate font-heading text-[1.05rem] font-semibold">{title || channelName(channel)}</h1>
      {topic && (
        <>
          <span className="hidden h-5 w-px bg-border md:block" aria-hidden="true" />
          <button type="button" onClick={() => setExpanded((v) => !v)} className={`hidden min-w-0 flex-1 text-left text-sm text-muted-foreground md:block ${expanded ? "whitespace-normal" : "truncate"}`} title={topic}>
            {topic}
          </button>
        </>
      )}
      {!topic && <span className="flex-1" />}
      <div className="ml-auto flex shrink-0 items-center gap-0.5">
        <Seal serverId={serverId} channel={channel} />
        {channel.kind !== "voice" && <NotifyMenu serverId={serverId} channel={channel} />}
        {onPins && (
          <HeaderButton label="Pinned messages" onClick={onPins}>
            <Pin className="h-4 w-4" aria-hidden="true" />
          </HeaderButton>
        )}
        {onToggleSearch && (
          <HeaderButton label="Search this channel" active={searchOpen} onClick={onToggleSearch}>
            <Search className="h-4 w-4" aria-hidden="true" />
          </HeaderButton>
        )}
        {onToggleMembers && (
          <HeaderButton label={membersOpen ? "Hide member list" : "Show member list"} active={membersOpen} onClick={onToggleMembers}>
            <Users className="h-4 w-4" aria-hidden="true" />
          </HeaderButton>
        )}
        <Inbox />
        {can(serverId, P.MANAGE_CHANNELS) && (
          <HeaderButton label="Channel settings" onClick={() => navigate(`/app/s/${serverId}/settings/channel/${channel.id}`)}>
            <Settings className="h-4 w-4" aria-hidden="true" />
          </HeaderButton>
        )}
      </div>
    </header>
  );
}
