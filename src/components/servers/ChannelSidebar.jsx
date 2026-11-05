import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  BellOff,
  Check,
  ChevronDown,
  ChevronRight,
  FolderPlus,
  Hourglass,
  Link2,
  Loader2,
  LogOut,
  Pencil,
  Plus,
  Settings,
  ShieldCheck,
  UserCog,
} from "lucide-react";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { useServers } from "@/lib/secure/ServerContext";
import { useVoice } from "@/lib/voice/VoiceContext";
import { P, has } from "@/lib/secure/permissions";
import Avatar from "@/components/chat/Avatar";
import { ChannelIcon, arrange } from "./channelBits";
import InviteDialog from "./InviteDialog";
import CreateChannelDialog from "./CreateChannelDialog";
import ConfirmDialog from "@/components/app/ConfirmDialog";
import NicknameDialog from "./NicknameDialog";

const MANAGE_ANY = P.MANAGE_SERVER | P.MANAGE_ROLES | P.MANAGE_CHANNELS | P.KICK_MEMBERS | P.BAN_MEMBERS | P.VIEW_AUDIT_LOG | P.MANAGE_INVITES | P.MANAGE_KEYS;

function ChannelLink({ sid, channel, active, onSettings, onInvite }) {
  const { channelName, unread, muted, can, memberName, profileOf } = useServers();
  const { room, participants } = useVoice();
  const u = unread.channels[channel.id] || { unread: false, mentions: 0 };
  const isMuted = muted(channel.id);
  const bold = u.unread && !isMuted && !active;
  const inCall = room?.channelId === channel.id ? participants : [];
  return (
    <li>
      <div className="group relative">
        {bold && <span className="absolute -left-2 top-1/2 h-2 w-1 -translate-y-1/2 rounded-r-full bg-foreground" aria-hidden="true" />}
        <Link
          to={`/app/s/${sid}/${channel.id}`}
          aria-current={active ? "page" : undefined}
          className={`panel-item pr-14 ${bold ? "font-semibold !text-foreground" : ""} ${isMuted && !active ? "opacity-55" : ""}`}
        >
          <ChannelIcon kind={channel.kind} isPrivate={channel.private} className="h-[1.1rem] w-[1.1rem] opacity-80" />
          <span className="truncate">{channelName(channel)}</span>
          {u.mentions > 0 && (
            <span className="ml-auto flex h-4 min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-[0.65rem] font-bold text-destructive-foreground" aria-label={`${u.mentions} mentions`}>
              {u.mentions}
            </span>
          )}
        </Link>
        <span className="absolute right-1 top-1/2 flex -translate-y-1/2 items-center gap-0.5 opacity-0 transition-opacity focus-within:opacity-100 group-hover:opacity-100">
          {can(sid, P.CREATE_INVITES) && (
            <button type="button" onClick={onInvite} className="rounded p-1 text-muted-foreground hover:text-foreground" aria-label={`Invite people to ${channelName(channel)}`}>
              <Link2 className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          )}
          {can(sid, P.MANAGE_CHANNELS) && (
            <button type="button" onClick={onSettings} className="rounded p-1 text-muted-foreground hover:text-foreground" aria-label={`Settings for ${channelName(channel)}`}>
              <Settings className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          )}
        </span>
      </div>
      {inCall.length > 0 && (
        <ul className="mb-1 ml-7 space-y-0.5" aria-label={`In ${channelName(channel)}`}>
          {inCall.map((p) => {
            const prof = profileOf(sid, p.userId);
            return (
              <li key={p.userId} className="flex items-center gap-2 py-0.5 text-sm text-muted-foreground">
                <span className={`rounded-full ${p.speaking ? "ring-2 ring-primary" : ""}`}>
                  <Avatar id={p.userId} name={memberName(sid, p.userId)} emoji={prof?.avatar_emoji} accent={prof?.accent_color} size="h-6 w-6" />
                </span>
                <span className="truncate">{memberName(sid, p.userId)}</span>
              </li>
            );
          })}
        </ul>
      )}
    </li>
  );
}

/** A server's side panel: its name and menu, the state of its keys, and its channels by category. */
export default function ChannelSidebar({ serverId, activeChannelId }) {
  const navigate = useNavigate();
  const s = useServers();
  const { servers, serverLook, can, permsFor, prefs, toggleCollapsed, toggleMute, muted, markServerRead, leaveServer } = s;
  const e = servers[serverId];
  const look = serverLook(serverId);
  const [invite, setInvite] = useState(null);
  const [creating, setCreating] = useState(null);
  const [leaving, setLeaving] = useState(false);
  const [nick, setNick] = useState(false);

  if (!e) return null;
  const ready = e.status === "ready" && e.channels;
  const visible = (c) => has(permsFor(serverId, c), P.VIEW_CHANNEL);
  const { loose, groups } = ready ? arrange(e.channels, visible) : { loose: [], groups: [] };
  const isOwner = e.server?.owner_id && e.server.owner_id === e.member?.user_id;
  const manages = (permsFor(serverId) & MANAGE_ANY) !== 0;
  const waiting = e.member?.key_status === "pending";
  const settingsFor = (c) => navigate(`/app/s/${serverId}/settings/channel/${c.id}`);

  return (
    <nav aria-label={`${look.name} channels`} className="flex h-full min-h-0 flex-col">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button type="button" className="flex h-12 shrink-0 items-center gap-2 border-b border-border/70 px-4 text-left shadow-sm transition-colors hover-panel focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring">
            <span className="min-w-0 flex-1 truncate font-heading text-[1.05rem] font-semibold">{look.name}</span>
            <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-56">
          {can(serverId, P.CREATE_INVITES) && <DropdownMenuItem onSelect={() => setInvite({ channelId: "" })}><Link2 className="mr-2 h-4 w-4" aria-hidden="true" /> Invite people</DropdownMenuItem>}
          {manages && <DropdownMenuItem onSelect={() => navigate(`/app/s/${serverId}/settings`)}><Settings className="mr-2 h-4 w-4" aria-hidden="true" /> Server settings</DropdownMenuItem>}
          {can(serverId, P.MANAGE_CHANNELS) && (
            <>
              <DropdownMenuItem onSelect={() => setCreating({ kind: "text", parentId: "" })}><Plus className="mr-2 h-4 w-4" aria-hidden="true" /> Create channel</DropdownMenuItem>
              <DropdownMenuItem onSelect={() => setCreating({ kind: "category", parentId: "" })}><FolderPlus className="mr-2 h-4 w-4" aria-hidden="true" /> Create category</DropdownMenuItem>
            </>
          )}
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => navigate(`/app/s/${serverId}/settings/privacy`)}><ShieldCheck className="mr-2 h-4 w-4" aria-hidden="true" /> Privacy settings</DropdownMenuItem>
          {can(serverId, P.CHANGE_NICKNAME) && <DropdownMenuItem onSelect={() => setNick(true)}><UserCog className="mr-2 h-4 w-4" aria-hidden="true" /> Edit server nickname</DropdownMenuItem>}
          <DropdownMenuItem onSelect={() => toggleMute(serverId)}><BellOff className="mr-2 h-4 w-4" aria-hidden="true" /> {muted(serverId) ? "Unmute server" : "Mute server"}</DropdownMenuItem>
          <DropdownMenuItem onSelect={() => markServerRead(serverId)}><Check className="mr-2 h-4 w-4" aria-hidden="true" /> Mark as read</DropdownMenuItem>
          {!isOwner && !e.server?.is_default && (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuItem className="text-destructive" onSelect={() => setLeaving(true)}><LogOut className="mr-2 h-4 w-4" aria-hidden="true" /> Leave server</DropdownMenuItem>
            </>
          )}
        </DropdownMenuContent>
      </DropdownMenu>

      {ready && waiting && (
        <p className="flex items-start gap-2 border-b border-border/60 bg-[hsl(var(--warning)/0.08)] px-4 py-2 text-xs text-muted-foreground" role="status">
          <Hourglass className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[hsl(var(--warning))]" aria-hidden="true" />
          <span>
            {e.server?.key_handout === "staff"
              ? "Waiting for keys. Here only staff hand them out, from their own devices, so other members can't see who joins. It can take a while if no staff are online."
              : "Waiting for keys. Members' apps hand them out, so it can take a little while if nobody is online."}
          </span>
        </p>
      )}

      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto px-2 pb-4 pt-3">
        {!ready ? (
          <div className="flex items-center gap-2 px-2 py-4 text-sm text-muted-foreground" role="status">
            <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> {e.status === "error" ? "Couldn't load this server. Trying again shortly." : "Loading channels…"}
          </div>
        ) : (
          <>
            {loose.length > 0 && (
              <ul className="mb-3 space-y-0.5">
                {loose.map((c) => (
                  <ChannelLink key={c.id} sid={serverId} channel={c} active={c.id === activeChannelId} onSettings={() => settingsFor(c)} onInvite={() => setInvite({ channelId: c.id })} />
                ))}
              </ul>
            )}
            {groups.map(({ cat, channels }) => {
              const collapsed = Boolean(prefs.collapsed?.[cat.id]);
              const shown = collapsed ? channels.filter((c) => c.id === activeChannelId) : channels;
              return (
                <section key={cat.id} className="mb-3" aria-label={s.channelName(cat)}>
                  <div className="group flex items-center pr-1">
                    <button
                      type="button"
                      onClick={() => toggleCollapsed(cat.id)}
                      aria-expanded={!collapsed}
                      className="flex min-w-0 flex-1 items-center gap-0.5 rounded px-0.5 py-1 text-[0.8rem] font-semibold text-muted-foreground hover:text-foreground"
                    >
                      {collapsed ? <ChevronRight className="h-3 w-3 shrink-0" aria-hidden="true" /> : <ChevronDown className="h-3 w-3 shrink-0" aria-hidden="true" />}
                      <span className="truncate">{s.channelName(cat)}</span>
                    </button>
                    {can(serverId, P.MANAGE_CHANNELS) && (
                      <>
                        <button type="button" onClick={() => settingsFor(cat)} className="rounded p-0.5 text-muted-foreground opacity-0 hover:text-foreground focus:opacity-100 group-hover:opacity-100" aria-label={`Edit ${s.channelName(cat)}`}>
                          <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                        </button>
                        <button type="button" onClick={() => setCreating({ kind: "text", parentId: cat.id })} className="rounded p-0.5 text-muted-foreground hover:text-foreground" aria-label={`Create a channel in ${s.channelName(cat)}`}>
                          <Plus className="h-4 w-4" aria-hidden="true" />
                        </button>
                      </>
                    )}
                  </div>
                  <ul className="space-y-0.5">
                    {shown.map((c) => (
                      <ChannelLink key={c.id} sid={serverId} channel={c} active={c.id === activeChannelId} onSettings={() => settingsFor(c)} onInvite={() => setInvite({ channelId: c.id })} />
                    ))}
                  </ul>
                </section>
              );
            })}
          </>
        )}
      </div>

      <InviteDialog serverId={invite ? serverId : null} channelId={invite?.channelId || ""} open={Boolean(invite)} onOpenChange={(v) => !v && setInvite(null)} />
      <CreateChannelDialog serverId={serverId} open={Boolean(creating)} initial={creating} onOpenChange={(v) => !v && setCreating(null)} onCreated={(c) => c.kind !== "category" && navigate(`/app/s/${serverId}/${c.id}`)} />
      <NicknameDialog serverId={serverId} open={nick} onOpenChange={setNick} />
      <ConfirmDialog
        open={leaving}
        onOpenChange={setLeaving}
        title={`Leave ${look.name}?`}
        confirmLabel="Leave server"
        busyLabel="Leaving…"
        onConfirm={async () => {
          await leaveServer(serverId);
          navigate("/app");
        }}
      >
        <p>Your copies of its keys are deleted from your account. To come back, you'll need a new invite (unless it's open to anyone).</p>
      </ConfirmDialog>
    </nav>
  );
}
