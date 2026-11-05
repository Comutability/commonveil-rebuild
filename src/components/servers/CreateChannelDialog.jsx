import React, { useEffect, useState } from "react";
import { Lock } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { NativeSelect } from "@/components/ui/native-select";
import { ErrorNote } from "@/components/site/bits";
import { useServers } from "@/lib/secure/ServerContext";
import { P } from "@/lib/secure/permissions";
import { cleanChannelName } from "@/lib/secure/serverTemplates";
import { ChannelIcon, KIND_LABELS } from "./channelBits";

const KINDS = [
  ["text", "Send messages, images of thought, and ideas."],
  ["announcement", "Staff post, everyone reads and reacts."],
  ["forum", "Each topic gets its own post and thread."],
  ["voice", "Talk together, peer to peer and encrypted."],
  ["tickets", "Members open private tickets with your support team."],
  ["rules", "Your server's rules, read-only for members."],
];

export default function CreateChannelDialog({ serverId, open, onOpenChange, initial, onCreated }) {
  const { servers, createChannel, channelName, roleName } = useServers();
  const e = servers[serverId];
  const [kind, setKind] = useState("text");
  const [name, setName] = useState("");
  const [topic, setTopic] = useState("");
  const [parentId, setParentId] = useState("");
  const [isPrivate, setPrivate] = useState(false);
  const [roles, setRoles] = useState([]);
  const [history, setHistory] = useState("joined");
  const [state, setState] = useState({ busy: false, error: "" });

  useEffect(() => {
    if (!open) return;
    setKind(initial?.kind || "text");
    setName("");
    setTopic("");
    setParentId(initial?.parentId || "");
    setPrivate(false);
    setRoles([]);
    setHistory(e?.server?.settings?.default_history || "joined");
    setState({ busy: false, error: "" });
  }, [open, initial, e?.server?.settings?.default_history]);

  if (!e?.channels) return null;
  const isCategory = kind === "category";
  const cats = e.channels.filter((c) => c.kind === "category").sort((a, b) => a.position - b.position);
  const everyone = e.roles.find((r) => r.is_everyone);
  const otherRoles = e.roles.filter((r) => !r.is_everyone).sort((a, b) => b.position - a.position);
  const cleaned = cleanChannelName(name, kind);

  const submit = async (ev) => {
    ev.preventDefault();
    if (!cleaned) return;
    setState({ busy: true, error: "" });
    try {
      const overwrites = isPrivate && everyone
        ? [{ role_id: everyone.id, allow: 0, deny: P.VIEW_CHANNEL }, ...roles.map((rid) => ({ role_id: rid, allow: P.VIEW_CHANNEL, deny: 0 }))]
        : kind === "announcement" || kind === "rules"
          ? everyone ? [{ role_id: everyone.id, allow: 0, deny: P.SEND_MESSAGES | P.CREATE_POSTS }] : []
          : [];
      const channel = await createChannel(serverId, {
        kind,
        name: cleaned,
        topic: isCategory ? "" : topic.trim(),
        parentId: isCategory ? "" : parentId,
        overwrites,
        history: isCategory || kind === "voice" ? undefined : history,
      });
      onOpenChange(false);
      onCreated?.(channel);
    } catch (err) {
      setState({ busy: false, error: err.message });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90dvh] max-w-lg overflow-y-auto">
        <form onSubmit={submit} className="space-y-5">
          <DialogHeader>
            <DialogTitle>{isCategory ? "Create a category" : "Create a channel"}</DialogTitle>
            <DialogDescription>
              {isCategory ? "Categories group channels in the side panel." : "Its name and topic are encrypted: only members who can see the channel can read them."}
            </DialogDescription>
          </DialogHeader>

          {!isCategory && (
            <fieldset className="space-y-2">
              <legend className="mb-2 text-sm font-medium">Channel type</legend>
              {KINDS.map(([k, text]) => (
                <label key={k} className={`flex cursor-pointer items-center gap-3 rounded-lg border px-3 py-2.5 transition-colors ${kind === k ? "border-primary bg-primary/5" : "border-border hover:bg-muted"}`}>
                  <input type="radio" name="kind" value={k} checked={kind === k} onChange={() => setKind(k)} className="sr-only" />
                  <ChannelIcon kind={k} className="h-5 w-5 text-muted-foreground" />
                  <span className="min-w-0">
                    <span className="block text-sm font-medium">{KIND_LABELS[k]}</span>
                    <span className="block text-xs text-muted-foreground">{text}</span>
                  </span>
                </label>
              ))}
            </fieldset>
          )}

          <div className="space-y-1.5">
            <Label htmlFor="channel-name">{isCategory ? "Category name" : "Channel name"}</Label>
            <Input id="channel-name" value={name} onChange={(ev) => setName(ev.target.value)} maxLength={100} placeholder={isCategory ? "New category" : kind === "voice" ? "Hangout" : "new-channel"} required autoFocus />
            {!isCategory && kind !== "voice" && name && cleaned !== name && <p className="text-xs text-muted-foreground">It'll be called #{cleaned}</p>}
          </div>

          {!isCategory && (
            <>
              <div className="space-y-1.5">
                <Label htmlFor="channel-topic">Topic (optional)</Label>
                <Input id="channel-topic" value={topic} onChange={(ev) => setTopic(ev.target.value)} maxLength={300} placeholder="What it's for" />
              </div>
              {cats.length > 0 && (
                <div className="space-y-1.5">
                  <Label htmlFor="channel-parent">Category</Label>
                  <NativeSelect id="channel-parent" value={parentId} onChange={(ev) => setParentId(ev.target.value)}>
                    <option value="">No category</option>
                    {cats.map((c) => <option key={c.id} value={c.id}>{channelName(c)}</option>)}
                  </NativeSelect>
                </div>
              )}
            </>
          )}

          <div className="space-y-3 rounded-lg border border-border p-3">
            <label className="flex items-start gap-3">
              <Checkbox checked={isPrivate} onCheckedChange={(v) => setPrivate(Boolean(v))} className="mt-0.5" />
              <span>
                <span className="flex items-center gap-1.5 text-sm font-medium"><Lock className="h-3.5 w-3.5" aria-hidden="true" /> Private {isCategory ? "category" : "channel"}</span>
                <span className="block text-xs text-muted-foreground">
                  Only the roles you choose (and admins) can see it. It gets its own keys, so nobody else can read it even with the server's.
                </span>
              </span>
            </label>
            {isPrivate && (
              <div className="ml-7 space-y-1.5">
                {otherRoles.length === 0 ? (
                  <p className="text-xs text-muted-foreground">There are no roles yet besides @everyone, so only admins will see it. Make roles in Server settings.</p>
                ) : (
                  otherRoles.map((r) => (
                    <label key={r.id} className="flex items-center gap-2 text-sm">
                      <Checkbox checked={roles.includes(r.id)} onCheckedChange={(v) => setRoles((prev) => (v ? [...prev, r.id] : prev.filter((x) => x !== r.id)))} />
                      {roleName(r)}
                    </label>
                  ))
                )}
              </div>
            )}
          </div>

          {!isCategory && kind !== "voice" && !isPrivate && (
            <div className="space-y-1.5">
              <Label htmlFor="channel-history">People who join later can read</Label>
              <NativeSelect id="channel-history" value={history} onChange={(ev) => setHistory(ev.target.value)}>
                <option value="joined">Only what's sent after they join</option>
                <option value="full">Everything, from the start</option>
              </NativeSelect>
              <p className="text-xs text-muted-foreground">
                "After they join" uses keys that move on every hour, and newcomers only get keys from their hour onwards. Their app can't read what came before, whatever the server shows them.
              </p>
            </div>
          )}

          <ErrorNote>{state.error}</ErrorNote>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={state.busy}>Cancel</Button>
            <Button type="submit" disabled={state.busy || !cleaned}>{state.busy ? "Creating…" : isCategory ? "Create category" : "Create channel"}</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
