import React, { useEffect } from "react";
import { Navigate, useNavigate, useParams } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import Shell, { NavButton } from "@/components/shell/Shell";
import ChannelSidebar from "@/components/servers/ChannelSidebar";
import ChannelChat, { ThreadView } from "@/components/servers/ChannelChat";
import { usePresenceRoom } from "@/lib/secure/PresenceContext";
import ForumView from "@/components/servers/ForumView";
import TicketsView from "@/components/servers/TicketsView";
import VoiceView from "@/components/servers/VoiceView";
import ServerOnboarding from "@/components/servers/ServerOnboarding";
import { arrange } from "@/components/servers/channelBits";
import { MESSAGE_KINDS, useServers } from "@/lib/secure/ServerContext";
import { P, has } from "@/lib/secure/permissions";

function Centered({ children }) {
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <header className="flex h-12 shrink-0 items-center border-b border-border/70 px-3 md:hidden"><NavButton /></header>
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center text-muted-foreground">{children}</div>
    </div>
  );
}

/** A server: its channels on the left, the open channel in the middle. */
export default function ServerView() {
  const { serverId, channelId, threadId } = useParams();
  usePresenceRoom("s", serverId);
  const navigate = useNavigate();
  const { servers, loaded, prefs, permsFor, loadState } = useServers();
  const e = servers[serverId];
  const ready = e?.status === "ready" && e.channels;
  const visible = (c) => has(permsFor(serverId, c), P.VIEW_CHANNEL);
  const channel = ready && channelId ? e.channels.find((c) => c.id === channelId && c.kind !== "category" && visible(c)) : null;

  // Load a server that's listed but not yet loaded (just joined, say).
  useEffect(() => {
    if (e && !e.roles && e.status === "listed") loadState(serverId).catch(() => {});
  }, [e, serverId, loadState]);

  if (!loaded) {
    return (
      <Shell panel={null} mainOpen>
        <Centered><Loader2 className="h-5 w-5 animate-spin" aria-hidden="true" /> Loading servers…</Centered>
      </Shell>
    );
  }
  if (!e) {
    return (
      <Shell panel={null} mainOpen>
        <Centered>
          <p className="font-heading text-xl text-foreground">You're not in that server</p>
          <p className="text-sm">It may have been deleted, or you may have left it.</p>
          <Button variant="outline" onClick={() => navigate("/app")}>Go home</Button>
        </Centered>
      </Shell>
    );
  }
  // No channel chosen: where you were last, else the first one you can read.
  if (ready && !channel) {
    const { flat } = arrange(e.channels, visible);
    const last = prefs.last?.[serverId];
    const target = flat.find((c) => c.id === last) || flat.find((c) => c.template_key === "welcome") || flat.find((c) => MESSAGE_KINDS.has(c.kind)) || flat[0];
    if (target && target.id !== channelId) return <Navigate to={`/app/s/${serverId}/${target.id}`} replace />;
  }

  let main;
  if (!ready) main = <Centered><Loader2 className="h-5 w-5 animate-spin" aria-hidden="true" /> {e.status === "error" ? "Couldn't load this server. Trying again shortly." : "Opening the server…"}</Centered>;
  else if (!channel) main = <Centered><p className="font-heading text-xl text-foreground">No channels you can see</p><p className="text-sm">Ask an admin to give you access.</p></Centered>;
  else if (channel.kind === "forum") main = <ForumView key={channel.id} serverId={serverId} channel={channel} postId={threadId} />;
  else if (channel.kind === "tickets") main = <TicketsView key={channel.id} serverId={serverId} channel={channel} ticketId={threadId} />;
  else if (channel.kind === "voice" || channel.kind === "stage") main = <VoiceView key={channel.id} serverId={serverId} channel={channel} />;
  else if (threadId) main = <ThreadView key={`${channel.id}:${threadId}`} serverId={serverId} channel={channel} threadId={threadId} />;
  else main = <ChannelChat key={channel.id} serverId={serverId} channel={channel} />;

  return (
    <Shell panel={<ChannelSidebar serverId={serverId} activeChannelId={channel?.id} />} mainOpen={Boolean(channelId)}>
      {main}
      <ServerOnboarding serverId={serverId} />
    </Shell>
  );
}