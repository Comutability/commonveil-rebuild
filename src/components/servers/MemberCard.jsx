import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AlertTriangle, Ban, Clock, Loader2, MessageSquare, ShieldCheck, UserCog, UserMinus } from "lucide-react";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { NativeSelect } from "@/components/ui/native-select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ErrorNote } from "@/components/site/bits";
import { useServers } from "@/lib/secure/ServerContext";
import { useSecure } from "@/lib/secure/SecureContext";
import { useChat } from "@/lib/secure/ChatContext";
import { P } from "@/lib/secure/permissions";
import Avatar, { ACCENT_HUES } from "@/components/chat/Avatar";
import NicknameDialog from "./NicknameDialog";
import ConfirmDialog from "@/components/app/ConfirmDialog";

const TIMEOUTS = [
  [5, "5 minutes"],
  [60, "1 hour"],
  [1440, "1 day"],
  [10_080, "1 week"],
];
const DELETE_HISTORY = [
  [0, "Don't delete any"],
  [3600, "The last hour"],
  [86_400, "The last day"],
  [604_800, "The last week"],
];

function monthOf(value) {
  if (!value) return "";
  const d = new Date(`${String(value).slice(0, 7)}-01T00:00:00Z`);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleDateString("en-GB", { month: "long", year: "numeric" });
}

/**
 * Someone's profile as this server sees it: what they chose to share, their roles here, and
 * (for moderators) what can be done about them. Opening it asks the server for nothing that
 * other members couldn't see in their messages anyway.
 */
export default function MemberCard({ serverId, userId: targetId, open, onOpenChange }) {
  const navigate = useNavigate();
  const { userId, peers, acceptKeyChange } = useSecure();
  const { startDm } = useChat();
  const s = useServers();
  const { servers, memberCard, memberName, nickOf, roleName, roleColor, rolesOfMember, can, myTop, act, banMember, loadMembers } = s;
  const e = servers[serverId];
  const [card, setCard] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const [timeout, setTimeoutValue] = useState(60);
  const [nickOpen, setNickOpen] = useState(false);
  const [confirm, setConfirm] = useState(null);
  const [banHistory, setBanHistory] = useState(0);
  const [banReason, setBanReason] = useState("");

  useEffect(() => {
    if (!open || !targetId) return;
    setCard(null);
    setError("");
    memberCard(serverId, targetId).then(setCard).catch((err) => setError(err.message));
  }, [open, serverId, targetId, memberCard]);

  if (!e || !targetId) return null;
  const profile = card?.profile;
  const member = card?.member;
  const self = targetId === userId;
  const isOwner = e.server.owner_id === targetId;
  const myRank = myTop(serverId);
  const theirRoles = member ? rolesOfMember(serverId, member) : [];
  const theirRank = isOwner ? Number.MAX_SAFE_INTEGER : theirRoles[0]?.position || 0;
  const above = !self && myRank > theirRank;
  const assignable = e.roles.filter((r) => !r.is_everyone && r.position < myRank).sort((a, b) => b.position - a.position);
  const peer = peers[targetId];
  const timedOut = member?.timeout_until && Date.parse(member.timeout_until) > Date.now();
  const accent = profile?.accent_color;
  const bannerHue = ACCENT_HUES[accent];

  const run = async (label, fn) => {
    setBusy(label);
    setError("");
    try {
      await fn();
      setCard(await memberCard(serverId, targetId).catch(() => card));
      loadMembers(serverId, { force: true }).catch(() => {});
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  };

  const toggleRole = (roleId, on) => run("roles", () => act(serverId, "set_member_roles", { user_id: targetId, role_ids: on ? [...new Set([...(member.role_ids || []), roleId])] : (member.role_ids || []).filter((r) => r !== roleId) }));

  const message = async () => {
    setBusy("dm");
    setError("");
    try {
      const conv = await startDm(profile.username);
      onOpenChange(false);
      navigate(`/app/c/${conv.id}`);
    } catch (err) {
      setError(err.message);
      setBusy("");
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90dvh] max-w-sm overflow-hidden overflow-y-auto p-0">
        <div className="h-16" style={{ background: bannerHue !== undefined ? `hsl(${bannerHue} 45% 45% / 0.45)` : "hsl(var(--primary) / 0.25)" }} aria-hidden="true" />
        <div className="-mt-9 px-5 pb-5">
          <div className="flex items-end justify-between">
            <span className="rounded-full ring-[5px] ring-[hsl(var(--popover))]">
              <Avatar id={targetId} name={profile?.display_name || profile?.username} emoji={profile?.avatar_emoji} accent={accent} size="h-16 w-16" className="text-xl" />
            </span>
            {!self && profile && (
              <Button size="sm" variant="outline" disabled={busy === "dm"} onClick={message}>
                <MessageSquare className="mr-1.5 h-4 w-4" aria-hidden="true" /> Message
              </Button>
            )}
          </div>
          {!card && !error ? (
            <p className="mt-6 flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Loading…</p>
          ) : (
            <>
              <DialogTitle className="mt-3 text-xl">{memberName(serverId, targetId)}</DialogTitle>
              <p className="text-sm text-muted-foreground">
                @{profile?.username}
                {profile?.pronouns ? `, ${profile.pronouns}` : ""}
              </p>
              {nickOf(serverId, targetId) && profile?.display_name && <p className="text-xs text-muted-foreground">Display name: {profile.display_name}</p>}

              {peer?.changed && (
                <div className="mt-3 rounded-lg border border-[hsl(var(--warning)/0.4)] bg-[hsl(var(--warning)/0.1)] p-3 text-sm">
                  <p className="flex items-center gap-1.5 font-medium"><AlertTriangle className="h-4 w-4 text-[hsl(var(--warning))]" aria-hidden="true" /> Their security keys changed</p>
                  <p className="mt-1 text-muted-foreground">This happens when someone resets their account. Until you accept it, their new messages show as unverified.</p>
                  <Button size="sm" variant="outline" className="mt-2" onClick={() => acceptKeyChange(targetId)}>Accept the new keys</Button>
                </div>
              )}
              {peer?.verified && <p className="mt-2 flex items-center gap-1 text-xs text-primary"><ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" /> You've verified their safety number</p>}

              {profile?.bio && (
                <section className="mt-4">
                  <h3 className="text-xs font-semibold text-muted-foreground">About</h3>
                  <p className="mt-1 whitespace-pre-wrap text-sm">{profile.bio}</p>
                </section>
              )}
              <section className="mt-4">
                <h3 className="text-xs font-semibold text-muted-foreground">In this server</h3>
                <p className="mt-1 text-sm">{isOwner ? "Owner. " : ""}Joined {monthOf(member?.joined_at)}{timedOut ? `. Timed out until ${new Date(member.timeout_until).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" })}` : ""}</p>
                {theirRoles.length > 0 && (
                  <ul className="mt-2 flex flex-wrap gap-1.5">
                    {theirRoles.map((r) => (
                      <li key={r.id} className="inline-flex items-center gap-1.5 rounded-md bg-muted px-2 py-0.5 text-xs">
                        <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: roleColor(r) || "hsl(var(--muted-foreground))" }} aria-hidden="true" />
                        {roleName(r)}
                      </li>
                    ))}
                  </ul>
                )}
              </section>
              {!profile?.bio && !profile?.pronouns && !self && (
                <p className="mt-3 text-xs text-muted-foreground">Only what they chose to share is shown here.</p>
              )}

              {(above || self) && (can(serverId, P.MANAGE_ROLES) || can(serverId, P.MANAGE_NICKNAMES) || can(serverId, P.TIMEOUT_MEMBERS) || can(serverId, P.KICK_MEMBERS) || can(serverId, P.BAN_MEMBERS)) && (
                <section className="mt-5 space-y-3 border-t border-border pt-4">
                  <h3 className="text-xs font-semibold text-muted-foreground">Moderation</h3>
                  {can(serverId, P.MANAGE_ROLES) && assignable.length > 0 && member && (
                    <fieldset disabled={busy === "roles"} className="space-y-1.5">
                      <legend className="mb-1 text-sm font-medium">Roles</legend>
                      {assignable.map((r) => (
                        <label key={r.id} className="flex items-center gap-2 text-sm">
                          <Checkbox checked={(member.role_ids || []).includes(r.id)} onCheckedChange={(v) => toggleRole(r.id, Boolean(v))} />
                          <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: roleColor(r) || "hsl(var(--muted-foreground))" }} aria-hidden="true" />
                          {roleName(r)}
                        </label>
                      ))}
                    </fieldset>
                  )}
                  {!self && (
                    <div className="flex flex-wrap gap-2">
                      {can(serverId, P.MANAGE_NICKNAMES) && (
                        <Button size="sm" variant="outline" onClick={() => setNickOpen(true)}><UserCog className="mr-1.5 h-4 w-4" aria-hidden="true" /> Nickname</Button>
                      )}
                      {can(serverId, P.KICK_MEMBERS) && (
                        <Button size="sm" variant="outline" onClick={() => setConfirm("kick")}><UserMinus className="mr-1.5 h-4 w-4" aria-hidden="true" /> Kick</Button>
                      )}
                      {can(serverId, P.BAN_MEMBERS) && (
                        <Button size="sm" variant="outline" className="text-destructive" onClick={() => setConfirm("ban")}><Ban className="mr-1.5 h-4 w-4" aria-hidden="true" /> Ban</Button>
                      )}
                    </div>
                  )}
                  {!self && can(serverId, P.TIMEOUT_MEMBERS) && (
                    <div className="flex items-end gap-2">
                      {timedOut ? (
                        <Button size="sm" variant="outline" disabled={busy === "timeout"} onClick={() => run("timeout", () => act(serverId, "timeout_member", { user_id: targetId, minutes: 0 }, { reload: false }))}>
                          <Clock className="mr-1.5 h-4 w-4" aria-hidden="true" /> End time-out
                        </Button>
                      ) : (
                        <>
                          <div className="flex-1 space-y-1">
                            <Label htmlFor="timeout-len" className="text-xs">Time out for</Label>
                            <NativeSelect id="timeout-len" value={String(timeout)} onChange={(ev) => setTimeoutValue(Number(ev.target.value))}>
                              {TIMEOUTS.map(([v, l]) => <option key={v} value={String(v)}>{l}</option>)}
                            </NativeSelect>
                          </div>
                          <Button size="sm" variant="outline" disabled={busy === "timeout"} onClick={() => run("timeout", () => act(serverId, "timeout_member", { user_id: targetId, minutes: timeout }, { reload: false }))}>
                            <Clock className="mr-1.5 h-4 w-4" aria-hidden="true" /> Time out
                          </Button>
                        </>
                      )}
                    </div>
                  )}
                </section>
              )}
              <ErrorNote>{error}</ErrorNote>
            </>
          )}
        </div>
        <NicknameDialog serverId={serverId} targetId={targetId} open={nickOpen} onOpenChange={setNickOpen} />
        <ConfirmDialog
          open={confirm === "kick"}
          onOpenChange={(v) => !v && setConfirm(null)}
          title={`Kick ${memberName(serverId, targetId)}?`}
          confirmLabel="Kick"
          onConfirm={async () => {
            await act(serverId, "kick_member", { user_id: targetId });
            loadMembers(serverId, { force: true }).catch(() => {});
            onOpenChange(false);
          }}
        >
          <p>They're removed from the server and their copies of its keys are deleted. They can come back with an invite.</p>
        </ConfirmDialog>
        <ConfirmDialog
          open={confirm === "ban"}
          onOpenChange={(v) => !v && setConfirm(null)}
          title={`Ban ${memberName(serverId, targetId)}?`}
          confirmLabel="Ban"
          onConfirm={async () => {
            await banMember(serverId, targetId, { deleteSeconds: banHistory, reason: banReason });
            onOpenChange(false);
          }}
        >
          <p>They're removed and can't come back. The server's keys are renewed, so they can't read anything sent from now on.</p>
          <div className="space-y-1.5 pt-2 text-foreground">
            <Label htmlFor="ban-history">Delete their messages from</Label>
            <NativeSelect id="ban-history" value={String(banHistory)} onChange={(ev) => setBanHistory(Number(ev.target.value))}>
              {DELETE_HISTORY.map(([v, l]) => <option key={v} value={String(v)}>{l}</option>)}
            </NativeSelect>
          </div>
          <div className="space-y-1.5 text-foreground">
            <Label htmlFor="ban-reason">Reason (encrypted, seen by moderators)</Label>
            <Input id="ban-reason" value={banReason} onChange={(ev) => setBanReason(ev.target.value)} maxLength={500} />
          </div>
        </ConfirmDialog>
      </DialogContent>
    </Dialog>
  );
}

