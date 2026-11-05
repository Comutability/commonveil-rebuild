import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Check, Minus, Trash2, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { ErrorNote } from "@/components/site/bits";
import { useServers } from "@/lib/secure/ServerContext";
import { P } from "@/lib/secure/permissions";
import { cleanChannelName } from "@/lib/secure/serverTemplates";
import { timerLabel } from "@/lib/secure/thread.js";
import ConfirmDialog from "@/components/app/ConfirmDialog";
import { ChannelIcon, KIND_LABELS, historyNote } from "@/components/servers/channelBits";
import { ChoiceList, SettingsGroup, SettingsTitle } from "./SettingsLayout";

const SLOWMODE = [0, 5, 10, 30, 60, 300, 900, 3600];
const EXPIRY = [0, 3600, 86_400, 604_800, 2_419_200];
const slowLabel = (s) => (!s ? "Off" : s < 60 ? `${s} seconds` : s < 3600 ? `${s / 60} minutes` : "1 hour");

/** Permissions that can be set per channel. */
const CHANNEL_PERMS = [
  [P.VIEW_CHANNEL, "View channel", "See it and read what's in it."],
  [P.SEND_MESSAGES, "Send messages", "Post here (and reply in forum posts)."],
  [P.CREATE_POSTS, "Create forum posts", "Start new posts, in forums."],
  [P.ADD_REACTIONS, "Add reactions", "React to messages."],
  [P.READ_HISTORY, "Read message history", "Page back to messages from before they arrived, where history allows."],
  [P.MENTION_EVERYONE, "Mention @everyone", "Notify everyone here at once."],
  [P.MANAGE_MESSAGES, "Manage messages", "Delete anyone's messages and pin them."],
  [P.CONNECT, "Connect", "Join, in voice channels."],
  [P.SPEAK, "Speak", "Talk, in voice channels."],
  [P.MANAGE_TICKETS, "Handle tickets", "Receive tickets opened here."],
];

function Tri({ value, onChange, label }) {
  const opts = [
    ["deny", X, "Deny", "text-destructive"],
    ["inherit", Minus, "Use the role's setting", "text-muted-foreground"],
    ["allow", Check, "Allow", "text-primary"],
  ];
  return (
    <div role="radiogroup" aria-label={label} className="flex overflow-hidden rounded-md border border-border">
      {opts.map(([v, Icon, title, tone]) => (
        <button key={v} type="button" role="radio" aria-checked={value === v} title={title} aria-label={title} onClick={() => onChange(v)} className={`flex h-7 w-8 items-center justify-center ${value === v ? `bg-muted ${tone}` : "text-muted-foreground/50 hover:bg-muted/60"}`}>
          <Icon className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      ))}
    </div>
  );
}

function Overwrites({ serverId, channel }) {
  const { servers, roleName, updateChannel } = useServers();
  const e = servers[serverId];
  const roles = [...(e?.roles || [])].sort((a, b) => b.position - a.position);
  const [rows, setRows] = useState(channel.overwrites);
  const [roleId, setRoleId] = useState(roles.find((r) => r.is_everyone)?.id || "");
  const [state, setState] = useState({ busy: false, msg: "", error: "" });
  useEffect(() => setRows(channel.overwrites), [channel.overwrites]);
  const row = rows.find((o) => o.role_id === roleId) || { role_id: roleId, allow: 0, deny: 0 };
  const valueOf = (bit) => ((row.allow & bit) ? "allow" : (row.deny & bit) ? "deny" : "inherit");
  const setBit = (bit, v) => {
    const next = { ...row, allow: v === "allow" ? row.allow | bit : row.allow & ~bit, deny: v === "deny" ? row.deny | bit : row.deny & ~bit };
    setRows((prev) => [...prev.filter((o) => o.role_id !== roleId), next].filter((o) => o.allow || o.deny));
  };
  const dirty = JSON.stringify([...rows].sort((a, b) => a.role_id.localeCompare(b.role_id))) !== JSON.stringify([...channel.overwrites].sort((a, b) => a.role_id.localeCompare(b.role_id)));
  const save = async () => {
    setState({ busy: true, msg: "", error: "" });
    try {
      await updateChannel(serverId, channel, { overwrites: rows });
      setState({ busy: false, msg: "Saved. Anyone who lost access no longer gets this channel's new keys.", error: "" });
    } catch (err) {
      setState({ busy: false, msg: "", error: err.message });
    }
  };
  return (
    <SettingsGroup title="Permissions" description="Change what a role can do in this channel. Denying @everyone the View permission makes the channel private, with its own keys.">
      <div className="space-y-1.5">
        <Label htmlFor="ow-role">Role</Label>
        <NativeSelect id="ow-role" value={roleId} onChange={(ev) => setRoleId(ev.target.value)} className="max-w-xs">
          {roles.map((r) => <option key={r.id} value={r.id}>{roleName(r)}{rows.some((o) => o.role_id === r.id) ? " (changed here)" : ""}</option>)}
        </NativeSelect>
      </div>
      <ul className="mt-4 divide-y divide-border">
        {CHANNEL_PERMS.map(([bit, label, help]) => (
          <li key={bit} className="flex items-center justify-between gap-4 py-2.5">
            <span className="text-sm"><span className="block font-medium">{label}</span><span className="block text-xs text-muted-foreground">{help}</span></span>
            <Tri value={valueOf(bit)} onChange={(v) => setBit(bit, v)} label={label} />
          </li>
        ))}
      </ul>
      <ErrorNote>{state.error}</ErrorNote>
      <div className="mt-3 flex items-center gap-3">
        <Button onClick={save} disabled={!dirty || state.busy}>{state.busy ? "Saving…" : "Save permissions"}</Button>
        {state.msg && !dirty && <span className="text-sm text-primary">{state.msg}</span>}
      </div>
    </SettingsGroup>
  );
}

export default function ChannelSettings({ serverId, channelId }) {
  const navigate = useNavigate();
  const { servers, channelName, channelTopic, updateChannel, act, can } = useServers();
  const e = servers[serverId];
  const channel = e?.channels?.find((c) => c.id === channelId);
  const [name, setName] = useState("");
  const [topic, setTopic] = useState("");
  const [parentId, setParentId] = useState("");
  const [state, setState] = useState({ busy: false, msg: "", error: "" });
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    if (!channel) return;
    setName(channelName(channel));
    setTopic(channelTopic(channel));
    setParentId(channel.parent_id || "");
    // Only when another channel is opened.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [channelId, Boolean(channel)]);

  if (!channel) return <p className="text-sm text-muted-foreground">That channel isn't here any more.</p>;
  if (!can(serverId, P.MANAGE_CHANNELS)) return <p className="text-sm text-muted-foreground">You don't have permission to change channels.</p>;
  const isCategory = channel.kind === "category";
  const cats = e.channels.filter((c) => c.kind === "category");
  const run = async (fn, msg = "Saved.") => {
    setState({ busy: true, msg: "", error: "" });
    try {
      await fn();
      setState({ busy: false, msg, error: "" });
    } catch (err) {
      setState({ busy: false, msg: "", error: err.message });
    }
  };
  const cleaned = cleanChannelName(name, channel.kind);
  const textual = ["text", "announcement", "rules", "forum"].includes(channel.kind);

  return (
    <>
      <SettingsTitle intro={isCategory ? "A category groups channels in the side panel." : `${KIND_LABELS[channel.kind]} channel. Its name and topic are encrypted.`}>
        <span className="flex items-center gap-2"><ChannelIcon kind={channel.kind} isPrivate={channel.private} className="h-6 w-6 text-muted-foreground" /> {channelName(channel)}</span>
      </SettingsTitle>
      <SettingsGroup title="Overview">
        <form
          className="space-y-4"
          onSubmit={(ev) => {
            ev.preventDefault();
            const changes = {};
            if (cleaned && (cleaned !== channelName(channel) || topic !== channelTopic(channel))) Object.assign(changes, { name: cleaned, topic: topic.trim() });
            if (!isCategory && parentId !== (channel.parent_id || "")) changes.parent_id = parentId;
            if (Object.keys(changes).length) run(() => updateChannel(serverId, channel, changes));
          }}
        >
          <div className="space-y-1.5">
            <Label htmlFor="ch-name">Name</Label>
            <Input id="ch-name" value={name} onChange={(ev) => setName(ev.target.value)} maxLength={100} />
          </div>
          {!isCategory && (
            <div className="space-y-1.5">
              <Label htmlFor="ch-topic">Topic</Label>
              <Input id="ch-topic" value={topic} onChange={(ev) => setTopic(ev.target.value)} maxLength={300} />
            </div>
          )}
          {!isCategory && cats.length > 0 && (
            <div className="space-y-1.5">
              <Label htmlFor="ch-parent">Category</Label>
              <NativeSelect id="ch-parent" value={parentId} onChange={(ev) => setParentId(ev.target.value)} className="max-w-xs">
                <option value="">No category</option>
                {cats.map((c) => <option key={c.id} value={c.id}>{channelName(c)}</option>)}
              </NativeSelect>
            </div>
          )}
          <Button type="submit" disabled={state.busy}>{state.busy ? "Saving…" : "Save"}</Button>
        </form>
      </SettingsGroup>

      {textual && !channel.private && (
        <SettingsGroup title="History for people who join later" description={historyNote(channel)}>
          <ChoiceList
            name="history"
            value={channel.history}
            disabled={state.busy}
            onChange={(v) => run(() => updateChannel(serverId, channel, { history: v }), "Saved. It applies to messages sent from now on.")}
            options={[
              { value: "joined", label: "Only what's sent after they join", help: "Uses keys that move on every hour; newcomers get keys from their hour onwards." },
              { value: "full", label: "Everything, from the start", help: "Anyone who joins can read the whole channel." },
            ]}
          />
          <p className="mt-2 text-xs text-muted-foreground">Changing this affects new messages. Messages already sent keep the keys they were sent with.</p>
        </SettingsGroup>
      )}

      {textual && (
        <SettingsGroup title="Messages">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="ch-slow">Slow mode</Label>
              <NativeSelect id="ch-slow" value={String(channel.slowmode_seconds)} disabled={state.busy} onChange={(ev) => run(() => updateChannel(serverId, channel, { slowmode_seconds: Number(ev.target.value) }))}>
                {SLOWMODE.map((s) => <option key={s} value={String(s)}>{slowLabel(s)}</option>)}
              </NativeSelect>
              <p className="text-xs text-muted-foreground">How long members wait between messages. Staff aren't limited.</p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="ch-expire">Disappearing messages</Label>
              <NativeSelect id="ch-expire" value={String(channel.expire_seconds)} disabled={state.busy} onChange={(ev) => run(() => updateChannel(serverId, channel, { expire_seconds: Number(ev.target.value) }))}>
                {EXPIRY.map((s) => <option key={s} value={String(s)}>{s ? `After ${timerLabel(s) === "1 day" ? "a day" : timerLabel(s) === "Off" ? "an hour" : timerLabel(s).replace(/^1 /, "a ")}` : "Off"}</option>)}
              </NativeSelect>
              <p className="text-xs text-muted-foreground">New messages are deleted from the server this long after they're sent.</p>
            </div>
          </div>
          <label className="mt-4 flex items-center justify-between gap-4">
            <span className="text-sm"><span className="block font-medium">Sensitive content</span><span className="block text-xs text-muted-foreground">Members are warned before the channel opens.</span></span>
            <Switch checked={channel.sensitive} disabled={state.busy} onCheckedChange={(v) => run(() => updateChannel(serverId, channel, { sensitive: v }))} />
          </label>
        </SettingsGroup>
      )}

      <Overwrites serverId={serverId} channel={channel} />

      <ErrorNote>{state.error}</ErrorNote>
      {state.msg && <p className="text-sm text-primary">{state.msg}</p>}

      <SettingsGroup title={`Delete this ${isCategory ? "category" : "channel"}`}>
        <Button variant="outline" className="text-destructive" onClick={() => setDeleting(true)}><Trash2 className="mr-1.5 h-4 w-4" aria-hidden="true" /> Delete {isCategory ? "category" : "channel"}</Button>
      </SettingsGroup>
      <ConfirmDialog
        open={deleting}
        onOpenChange={setDeleting}
        title={`Delete ${channelName(channel)}?`}
        confirmLabel="Delete"
        onConfirm={async () => {
          await act(serverId, "delete_channel", { channel_id: channel.id });
          navigate(`/app/s/${serverId}`, { replace: true });
        }}
      >
        {isCategory ? <p>Its channels stay, outside any category.</p> : <p>Everything in it is deleted for everyone, and can't be brought back.</p>}
      </ConfirmDialog>
    </>
  );
}
