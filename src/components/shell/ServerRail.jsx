import React, { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { ArrowDown, ArrowUp, BellOff, Check, Compass, Folder, FolderMinus, FolderPlus, Link2, LogOut, Plus, Settings, ShieldCheck } from "lucide-react";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { ContextMenu, ContextMenuContent, ContextMenuItem, ContextMenuSeparator, ContextMenuSub, ContextMenuSubContent, ContextMenuSubTrigger, ContextMenuTrigger } from "@/components/ui/context-menu";
import { LogoMark } from "@/components/site/Logo";
import { useServers } from "@/lib/secure/ServerContext";
import { useChat } from "@/lib/secure/ChatContext";
import { P } from "@/lib/secure/permissions";
import ServerIcon from "./ServerIcon";
import CreateServerDialog from "@/components/servers/CreateServerDialog";
import InviteDialog from "@/components/servers/InviteDialog";
import ConfirmDialog from "@/components/app/ConfirmDialog";

function Badge({ count }) {
  if (!count) return null;
  return (
    <span aria-hidden="true" className="absolute -bottom-0.5 -right-0.5 flex h-5 min-w-5 items-center justify-center rounded-full bg-destructive px-1 text-[0.7rem] font-bold text-destructive-foreground ring-[3px] ring-[hsl(var(--rail))]">
      {count > 99 ? "99+" : count}
    </span>
  );
}

/** The left-hand pill: tall for where you are, a dot for unread. */
function Pill({ active, unread }) {
  if (!active && !unread) return null;
  return <span className={`absolute -left-3 top-1/2 w-1 -translate-y-1/2 rounded-r-full bg-foreground transition-all ${active ? "h-10" : "h-2"}`} aria-hidden="true" />;
}

function RailButton({ label, children, to, onClick, active, unread = false, mentions = 0 }) {
  const name = mentions ? `${label}, ${mentions} ${mentions === 1 ? "mention" : "mentions"}` : label;
  const inner = (
    <>
      <span className="sr-only">{name}</span>
      <Pill active={active} unread={unread} />
      {children}
      <Badge count={mentions} />
    </>
  );
  const cls = "relative flex rounded-full focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {to ? (
          <Link to={to} className={cls} aria-current={active ? "page" : undefined}>{inner}</Link>
        ) : (
          <button type="button" onClick={onClick} className={cls}>{inner}</button>
        )}
      </TooltipTrigger>
      <TooltipContent side="right" className="bg-foreground text-sm font-medium text-background">{label}</TooltipContent>
    </Tooltip>
  );
}

function ServerItem({ sid, active, onInvite, onLeave, folderId = null }) {
  const navigate = useNavigate();
  const { serverLook, unread, prefs, muted, toggleMute, markServerRead, moveServer, can, servers, folders, moveToFolder } = useServers();
  const look = serverLook(sid);
  const u = unread.servers[sid] || { unread: false, mentions: 0 };
  const last = prefs.last?.[sid];
  const entry = servers[sid];
  const isOwner = entry?.server?.owner_id && entry.server.owner_id === entry.member?.user_id;
  return (
    <li>
      <ContextMenu>
        <ContextMenuTrigger asChild>
          <div>
            <RailButton label={look.name} to={`/app/s/${sid}${last ? `/${last}` : ""}`} active={active} unread={u.unread} mentions={u.mentions}>
              <ServerIcon look={look} active={active} />
            </RailButton>
          </div>
        </ContextMenuTrigger>
        <ContextMenuContent className="w-56">
          <ContextMenuItem onSelect={() => markServerRead(sid)}><Check className="mr-2 h-4 w-4" aria-hidden="true" /> Mark as read</ContextMenuItem>
          <ContextMenuItem onSelect={() => toggleMute(sid)}><BellOff className="mr-2 h-4 w-4" aria-hidden="true" /> {muted(sid) ? "Unmute server" : "Mute server"}</ContextMenuItem>
          <ContextMenuSeparator />
          {can(sid, P.CREATE_INVITES) && <ContextMenuItem onSelect={() => onInvite(sid)}><Link2 className="mr-2 h-4 w-4" aria-hidden="true" /> Invite people</ContextMenuItem>}
          <ContextMenuItem onSelect={() => navigate(`/app/s/${sid}/settings/privacy`)}><ShieldCheck className="mr-2 h-4 w-4" aria-hidden="true" /> Privacy settings</ContextMenuItem>
          <ContextMenuItem onSelect={() => navigate(`/app/s/${sid}/settings`)}><Settings className="mr-2 h-4 w-4" aria-hidden="true" /> Server settings</ContextMenuItem>
          <ContextMenuSeparator />
          <ContextMenuSub>
            <ContextMenuSubTrigger><Folder className="mr-2 h-4 w-4" aria-hidden="true" /> Add to folder</ContextMenuSubTrigger>
            <ContextMenuSubContent className="w-48">
              {folders.filter((f) => f.id !== folderId).map((f) => (
                <ContextMenuItem key={f.id} onSelect={() => moveToFolder(sid, f.id)}><Folder className="mr-2 h-4 w-4" aria-hidden="true" /> {f.name}</ContextMenuItem>
              ))}
              <ContextMenuItem onSelect={() => moveToFolder(sid, "new", "New folder")}><FolderPlus className="mr-2 h-4 w-4" aria-hidden="true" /> New folder</ContextMenuItem>
            </ContextMenuSubContent>
          </ContextMenuSub>
          {folderId && <ContextMenuItem onSelect={() => moveToFolder(sid, null)}><FolderMinus className="mr-2 h-4 w-4" aria-hidden="true" /> Take out of folder</ContextMenuItem>}
          <ContextMenuItem onSelect={() => moveServer(sid, -1)}><ArrowUp className="mr-2 h-4 w-4" aria-hidden="true" /> Move up</ContextMenuItem>
          <ContextMenuItem onSelect={() => moveServer(sid, 1)}><ArrowDown className="mr-2 h-4 w-4" aria-hidden="true" /> Move down</ContextMenuItem>
          {!isOwner && !entry?.server?.is_default && (
            <>
              <ContextMenuSeparator />
              <ContextMenuItem className="text-destructive" onSelect={() => onLeave(sid)}>
                <LogOut className="mr-2 h-4 w-4" aria-hidden="true" /> Leave server
              </ContextMenuItem>
            </>
          )}
        </ContextMenuContent>
      </ContextMenu>
    </li>
  );
}

/** A folder of servers: a little grid of their icons, opening to show them. Only on this device. */
function FolderItem({ folder, activeServer, onInvite, onLeave }) {
  const { serverLook, unread, prefs, toggleCollapsed, renameFolder } = useServers();
  const open = !prefs.collapsed?.[folder.id];
  const mentions = folder.servers.reduce((n, sid) => n + (unread.servers[sid]?.mentions || 0), 0);
  const anyUnread = folder.servers.some((sid) => unread.servers[sid]?.unread);
  const holdsActive = folder.servers.includes(activeServer);
  return (
    <li className={`flex flex-col items-center gap-2 rounded-[1.6rem] ${open ? "bg-panel/70 pb-2" : ""}`}>
      <ContextMenu>
        <ContextMenuTrigger asChild>
          <div>
            <RailButton label={`${folder.name}, ${folder.servers.length} servers`} onClick={() => toggleCollapsed(folder.id)} active={!open && holdsActive} unread={!open && anyUnread} mentions={open ? 0 : mentions}>
              <span className="server-icon grid grid-cols-2 gap-0.5 bg-panel p-1.5" aria-hidden="true">
                {open ? <Folder className="col-span-2 m-auto h-6 w-6 text-primary" /> : folder.servers.slice(0, 4).map((sid) => (
                  <span key={sid} className="flex items-center justify-center overflow-hidden rounded-full text-[0.5rem]" style={{ background: serverLook(sid).color || undefined }}>
                    {(serverLook(sid).icon || serverLook(sid).name || "?").slice(0, 2)}
                  </span>
                ))}
              </span>
            </RailButton>
          </div>
        </ContextMenuTrigger>
        <ContextMenuContent className="w-48">
          <ContextMenuItem onSelect={() => {
            const name = window.prompt("Folder name", folder.name);
            if (name !== null) renameFolder(folder.id, name);
          }}>Rename folder</ContextMenuItem>
        </ContextMenuContent>
      </ContextMenu>
      {open && (
        <ul className="flex flex-col items-center gap-2" aria-label={folder.name}>
          {folder.servers.map((sid) => (
            <ServerItem key={sid} sid={sid} active={activeServer === sid} onInvite={onInvite} onLeave={onLeave} folderId={folder.id} />
          ))}
        </ul>
      )}
    </li>
  );
}

/** Home (direct messages), your servers, and ways to add one. */
export default function ServerRail() {
  const location = useLocation();
  const navigate = useNavigate();
  const { order, loaded, serverLook, leaveServer, folders } = useServers();
  const { conversations, isUnread } = useChat();
  const [creating, setCreating] = useState(false);
  const [inviteFor, setInviteFor] = useState(null);
  const [leaving, setLeaving] = useState(null);
  const path = location.pathname;
  const atHome = path === "/app" || path.startsWith("/app/c/");
  const activeServer = path.startsWith("/app/s/") ? path.split("/")[3] : null;
  const dmUnread = conversations.filter((c) => !c.server_id && isUnread(c)).length;

  return (
    <TooltipProvider delayDuration={150}>
      <nav aria-label="Servers" className="scroll-thin flex h-full w-[4.5rem] shrink-0 flex-col items-center gap-2 overflow-y-auto bg-rail py-3">
        <RailButton label="Direct messages" to="/app" active={atHome} mentions={dmUnread}>
          <span className="server-icon bg-panel" data-active={atHome ? "true" : "false"}>
            <LogoMark className="h-12 w-12 text-primary-foreground" />
          </span>
        </RailButton>
        <span className="h-0.5 w-8 rounded-full bg-border" aria-hidden="true" />
        <ul className="flex flex-col items-center gap-2" aria-label="Your servers">
          {order.map((sid) => {
            const folder = folders.find((f) => f.servers.includes(sid));
            if (!folder) return <ServerItem key={sid} sid={sid} active={activeServer === sid} onInvite={setInviteFor} onLeave={setLeaving} />;
            // A folder sits where its first server would.
            if (order.find((id) => folder.servers.includes(id)) !== sid) return null;
            return <FolderItem key={folder.id} folder={folder} activeServer={activeServer} onInvite={setInviteFor} onLeave={setLeaving} />;
          })}
          {!loaded && <li className="h-12 w-12 animate-pulse rounded-full bg-panel" aria-label="Loading servers" />}
        </ul>
        <RailButton label="Add a server" onClick={() => setCreating(true)}>
          <span className="server-icon bg-panel text-primary hover:bg-primary hover:text-primary-foreground">
            <Plus className="h-6 w-6" aria-hidden="true" />
          </span>
        </RailButton>
        <RailButton label="Discover servers" to="/app/discover" active={path === "/app/discover"}>
          <span className="server-icon bg-panel text-primary hover:bg-primary hover:text-primary-foreground" data-active={path === "/app/discover" ? "true" : "false"}>
            <Compass className="h-6 w-6" aria-hidden="true" />
          </span>
        </RailButton>
      </nav>
      <CreateServerDialog open={creating} onOpenChange={setCreating} />
      <InviteDialog serverId={inviteFor} open={Boolean(inviteFor)} onOpenChange={(v) => !v && setInviteFor(null)} />
      <ConfirmDialog
        open={Boolean(leaving)}
        onOpenChange={(v) => !v && setLeaving(null)}
        title={leaving ? `Leave ${serverLook(leaving).name}?` : "Leave server?"}
        confirmLabel="Leave server"
        busyLabel="Leaving…"
        onConfirm={async () => {
          await leaveServer(leaving);
          if (activeServer === leaving) navigate("/app");
        }}
      >
        <p>Your copies of its keys are deleted from your account. To come back, you'll need a new invite (unless it's open to anyone).</p>
        <p>Messages you sent stay unless you delete them first.</p>
      </ConfirmDialog>
    </TooltipProvider>
  );
}
