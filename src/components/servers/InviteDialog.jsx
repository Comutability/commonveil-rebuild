import React, { useEffect, useState } from "react";
import { Check, Copy, Lock } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { ErrorNote } from "@/components/site/bits";
import { useServers } from "@/lib/secure/ServerContext";
import { P } from "@/lib/secure/permissions";

export const INVITE_AGES = [
  [1800, "30 minutes"],
  [3600, "1 hour"],
  [21_600, "6 hours"],
  [43_200, "12 hours"],
  [86_400, "1 day"],
  [604_800, "7 days"],
  [0, "Never"],
];
export const INVITE_USES = [
  [0, "No limit"],
  [1, "1 use"],
  [5, "5 uses"],
  [10, "10 uses"],
  [25, "25 uses"],
  [50, "50 uses"],
  [100, "100 uses"],
];

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export default function InviteDialog({ serverId, open, onOpenChange, channelId = "" }) {
  const { serverLook, servers, can, createInvite } = useServers();
  const [maxAge, setMaxAge] = useState(604_800);
  const [maxUses, setMaxUses] = useState(0);
  const [invite, setInvite] = useState(null);
  const [copied, setCopied] = useState(false);
  const [state, setState] = useState({ busy: false, error: "" });

  useEffect(() => {
    if (open) {
      setInvite(null);
      setCopied(false);
      setState({ busy: false, error: "" });
    }
  }, [open, serverId]);

  if (!serverId) return null;
  const look = serverLook(serverId);
  const paused = servers[serverId]?.server?.settings?.invites_paused;
  const allowed = can(serverId, P.CREATE_INVITES);

  const make = async () => {
    setState({ busy: true, error: "" });
    try {
      setInvite(await createInvite(serverId, { maxAge, maxUses, channelId }));
      setState({ busy: false, error: "" });
    } catch (err) {
      setState({ busy: false, error: err.message });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Invite people to {look.name}</DialogTitle>
          <DialogDescription>Anyone with the link can join while it's valid. Send it only to people you mean to invite.</DialogDescription>
        </DialogHeader>
        {!allowed ? (
          <p className="text-sm text-muted-foreground">You don't have permission to make invites here. Ask a moderator.</p>
        ) : paused ? (
          <p className="text-sm text-muted-foreground">Invites are paused in this server. Its admins can turn them back on in the server's safety settings.</p>
        ) : invite ? (
          <div className="space-y-3">
            <Label htmlFor="invite-link">Your invite link</Label>
            <div className="flex gap-2">
              <Input id="invite-link" value={invite.url} readOnly onFocus={(e) => e.target.select()} className="font-mono text-xs" />
              <Button
                type="button"
                onClick={async () => setCopied(await copyText(invite.url))}
                aria-label="Copy link"
              >
                {copied ? <Check className="h-4 w-4" aria-hidden="true" /> : <Copy className="h-4 w-4" aria-hidden="true" />}
                <span className="ml-1.5">{copied ? "Copied" : "Copy"}</span>
              </Button>
            </div>
            <p className="text-sm text-muted-foreground">
              {invite.expires_at ? `Expires ${new Date(invite.expires_at).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" })}` : "Doesn't expire"}
              {invite.max_uses ? `, after ${invite.max_uses} ${invite.max_uses === 1 ? "use" : "uses"} at most.` : "."}
            </p>
            <p className="flex items-start gap-2 rounded-lg bg-muted px-3 py-2 text-xs text-muted-foreground">
              <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
              The part of the link after # is a key that only the link carries. Browsers never send it to Commonveil, so the server's name in the preview stays readable only to people who have the link.
            </p>
            <Button variant="ghost" size="sm" onClick={() => setInvite(null)}>Make a different link</Button>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="invite-age">Expire after</Label>
                <NativeSelect id="invite-age" value={String(maxAge)} onChange={(e) => setMaxAge(Number(e.target.value))}>
                  {INVITE_AGES.map(([v, label]) => <option key={v} value={String(v)}>{label}</option>)}
                </NativeSelect>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="invite-uses">Max uses</Label>
                <NativeSelect id="invite-uses" value={String(maxUses)} onChange={(e) => setMaxUses(Number(e.target.value))}>
                  {INVITE_USES.map(([v, label]) => <option key={v} value={String(v)}>{label}</option>)}
                </NativeSelect>
              </div>
            </div>
            <ErrorNote>{state.error}</ErrorNote>
            <Button onClick={make} disabled={state.busy} className="w-full">{state.busy ? "Making link…" : "Make invite link"}</Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
