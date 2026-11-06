import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Navigate, useNavigate, useParams } from "react-router-dom";
import {
  Ban,
  BookOpen,
  Compass,
  Eye,
  Hash,
  KeyRound,
  Link2,
  ListChecks,
  LogOut,
  Rocket,
  Shield,
  ShieldAlert,
  Flag,
  Smile,
  Sparkles,
  Trash2,
  Users,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { ErrorNote } from "@/components/site/bits";
import { callFn } from "@/lib/api";
import { useServers } from "@/lib/secure/ServerContext";
import { useSecure } from "@/lib/secure/SecureContext";
import { P } from "@/lib/secure/permissions";
import { stamp } from "@/components/chat/MessageRow";
import Avatar from "@/components/chat/Avatar";
import ServerIcon from "@/components/shell/ServerIcon";
import { ColorPicker } from "@/components/servers/CreateServerDialog";
import InviteDialog from "@/components/servers/InviteDialog";
import MemberCard from "@/components/servers/MemberCard";
import NicknameDialog from "@/components/servers/NicknameDialog";
import ConfirmDialog from "@/components/app/ConfirmDialog";
import SettingsLayout, { ChoiceList, SettingsGroup, SettingsTitle, useCloseSettings } from "@/components/settings/SettingsLayout";
import RolesSettings from "@/components/settings/RolesSettings";
import ChannelSettings from "@/components/settings/ChannelSettings";
import { ALL_TAGS, tagLabel } from "./Discover";
import { EMOJI_LIMITS, EMOJI_NAME_RE, imageForSet, nameFromFile, newEmojiId } from "@/lib/customEmoji";
import { MENTION_LIMITS } from "@/lib/secure/automod";
import { CaseLog, ModerationRules, ReportsQueue } from "@/components/settings/ModerationSettings";
import OnboardingSettings from "@/components/settings/OnboardingSettings";

function useRun() {
  const [state, setState] = useState({ busy: false, msg: "", error: "" });
  const run = useCallback(async (fn, msg = "Saved.") => {
    setState({ busy: true, msg: "", error: "" });
    try {
      await fn();
      setState({ busy: false, msg, error: "" });
    } catch (err) {
      setState({ busy: false, msg: "", error: err.message });
    }
  }, []);
  return [state, run];
}

function Status({ state }) {
  return (
    <>
      <ErrorNote>{state.error}</ErrorNote>
      {state.msg && <p className="mt-2 text-sm text-primary">{state.msg}</p>}
    </>
  );
}

function ToggleRow({ label, help, checked, onChange, disabled }) {
  return (
    <label className="flex items-center justify-between gap-4 py-2">
      <span className="text-sm"><span className="block font-medium">{label}</span>{help && <span className="block text-xs text-muted-foreground">{help}</span>}</span>
      <Switch checked={checked} disabled={disabled} onCheckedChange={onChange} />
    </label>
  );
}

// ---------- overview ----------

function Overview({ sid }) {
  const { serverLook, setServerProfile, servers } = useServers();
  const look = serverLook(sid);
  const details = { name: look.name, description: look.description, icon: look.icon, color: look.color, banner: look.banner, traits: look.traits || [] };
  const [form, setFormState] = useState(details);
  // Until someone edits the form, follow the server's details (they may still be decrypting).
  const edited = useRef(false);
  const setForm = useCallback((fn) => {
    edited.current = true;
    setFormState(fn);
  }, []);
  useEffect(() => {
    if (!edited.current) setFormState({ name: look.name, description: look.description, icon: look.icon, color: look.color, banner: look.banner, traits: look.traits || [] });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [look.name, look.description, look.icon, look.color, look.banner, (look.traits || []).join("|")]);
  const setTrait = (i, value) => setForm((f) => {
    const traits = [0, 1, 2, 3, 4].map((j) => (j === i ? value.slice(0, 24) : f.traits[j] || ""));
    return { ...f, traits };
  });
  const [state, run] = useRun();
  const isDefault = servers[sid]?.server?.is_default;
  return (
    <>
      <SettingsTitle intro="The name, description, icon, banner and traits members see. They're encrypted with the server's keys: Commonveil can't read them." help="create-a-server">Overview</SettingsTitle>
      <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); run(() => setServerProfile(sid, form)); }}>
        <div className="flex items-center gap-5">
          <ServerIcon look={form} size="h-20 w-20" rounded className="!text-2xl" />
          <div className="min-w-0 flex-1 space-y-1.5">
            <Label htmlFor="ov-icon">Icon</Label>
            <Input id="ov-icon" value={form.icon} onChange={(e) => setForm((f) => ({ ...f, icon: e.target.value.slice(0, 8) }))} placeholder="An emoji, or up to two letters" className="max-w-xs" />
            <p className="text-xs text-muted-foreground">Icons are text, so showing one never fetches an image.</p>
          </div>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="ov-name">Server name</Label>
          <Input id="ov-name" value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} maxLength={100} required />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="ov-desc">Description</Label>
          <Textarea id="ov-desc" value={form.description} onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))} maxLength={500} rows={3} />
        </div>
        <div className="space-y-1.5">
          <Label>Colour</Label>
          <ColorPicker value={form.color} onChange={(c) => setForm((f) => ({ ...f, color: c }))} />
          <p className="text-xs text-muted-foreground">Tints the server's icon.</p>
        </div>
        <div className="space-y-1.5">
          <Label>Banner</Label>
          <ColorPicker label="Banner colour" value={form.banner} onChange={(c) => setForm((f) => ({ ...f, banner: c }))} />
          <div className="flex items-center gap-2">
            <span className="h-7 w-16 rounded-md border border-border" style={{ backgroundColor: form.banner || "transparent" }} aria-hidden="true" />
            <Button type="button" variant="ghost" size="sm" onClick={() => setForm((f) => ({ ...f, banner: "" }))}>No banner</Button>
          </div>
        </div>
        <fieldset className="space-y-1.5">
          <legend className="text-sm font-medium">Traits</legend>
          <p className="text-xs text-muted-foreground">Up to five short words about this place, shown on the welcome new members see. They're encrypted like the name.</p>
          <div className="grid gap-2 sm:grid-cols-3">
            {[0, 1, 2, 3, 4].map((i) => (
              <Input key={i} value={form.traits[i] || ""} maxLength={24} aria-label={`Trait ${i + 1}`} placeholder={["Cozy", "Late nights", "Learning", "Making things", "Quiet"][i]} onChange={(ev) => setTrait(i, ev.target.value)} />
            ))}
          </div>
        </fieldset>
        {isDefault && <p className="text-xs text-muted-foreground">The community server's public card, shown in Discover, is set separately under Discovery.</p>}
        <Button type="submit" disabled={state.busy || !form.name.trim()}>{state.busy ? "Encrypting and saving…" : "Save changes"}</Button>
        <Status state={state} />
      </form>
    </>
  );
}

// ---------- community: rules ----------

function Community({ sid }) {
  const { serverRules, setServerRules, servers, updateSettings } = useServers();
  const e = servers[sid];
  const current = serverRules(sid);
  const [rules, setRules] = useState(current.rules.length ? current.rules : [""]);
  const [intro, setIntro] = useState(current.intro);
  const [state, run] = useRun();
  return (
    <>
      <SettingsTitle intro="Rules show in the rules channel. They're encrypted like everything else members write." help="moderation">Rules and screening</SettingsTitle>
      <SettingsGroup title="Ask new members to accept the rules" description="Until they do, they can read but not post. Staff aren't affected.">
        <ToggleRow label="Rules screening" checked={Boolean(e.server.settings.rules_required)} disabled={state.busy} onChange={(v) => run(() => updateSettings(sid, { rules_required: v }))} />
      </SettingsGroup>
      <SettingsGroup title="Rules">
        <div className="space-y-1.5">
          <Label htmlFor="rules-intro">Introduction</Label>
          <Textarea id="rules-intro" value={intro} onChange={(ev) => setIntro(ev.target.value)} maxLength={1000} rows={2} />
        </div>
        <ol className="mt-4 space-y-2">
          {rules.map((r, i) => (
            <li key={i} className="flex items-start gap-2">
              <span className="mt-2 w-6 text-right font-heading font-semibold text-primary">{i + 1}.</span>
              <Textarea value={r} onChange={(ev) => setRules((rs) => rs.map((x, j) => (j === i ? ev.target.value : x)))} maxLength={500} rows={2} aria-label={`Rule ${i + 1}`} />
              <Button type="button" variant="ghost" size="icon" onClick={() => setRules((rs) => rs.filter((_, j) => j !== i))} aria-label={`Remove rule ${i + 1}`}><Trash2 className="h-4 w-4" aria-hidden="true" /></Button>
            </li>
          ))}
        </ol>
        <div className="mt-3 flex flex-wrap gap-2">
          <Button type="button" variant="outline" size="sm" disabled={rules.length >= 25} onClick={() => setRules((rs) => [...rs, ""])}>Add a rule</Button>
          <Button type="button" size="sm" disabled={state.busy} onClick={() => run(() => setServerRules(sid, rules.map((r) => r.trim()).filter(Boolean), intro.trim()))}>
            {state.busy ? "Saving…" : "Save rules"}
          </Button>
          {current.custom && <Button type="button" variant="ghost" size="sm" disabled={state.busy} onClick={() => run(() => setServerRules(sid, null), "Back to the template's rules.")}>Use the template's rules</Button>}
        </div>
      </SettingsGroup>
      <Status state={state} />
    </>
  );
}

// ---------- discovery ----------

function Discovery({ sid }) {
  const { servers, updateSettings, serverLook } = useServers();
  const e = servers[sid];
  const s = e.server;
  const isDefault = s.is_default;
  const pub = s.public || { name: "", description: "", tags: [], icon: "", color: "" };
  const look = serverLook(sid);
  const [form, setForm] = useState({ name: pub.name || look.name, description: pub.description || "", tags: pub.tags || [], icon: pub.icon || look.icon, color: pub.color || look.color });
  const [state, run] = useRun();
  const listed = isDefault || s.discoverable;
  const toggleTag = (t) => setForm((f) => ({ ...f, tags: f.tags.includes(t) ? f.tags.filter((x) => x !== t) : f.tags.length >= 5 ? f.tags : [...f.tags, t] }));
  return (
    <>
      <SettingsTitle intro="Off unless you turn it on. Listing a server publishes a public card about it. Everything inside stays encrypted." help="create-a-server">Discovery</SettingsTitle>
      <div className="mb-6 flex items-start gap-3 rounded-lg border border-[hsl(var(--warning)/0.4)] bg-[hsl(var(--warning)/0.08)] p-4 text-sm">
        <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-[hsl(var(--warning))]" aria-hidden="true" />
        <p>The public card (name, description, tags, icon and colour) is stored unencrypted, so that people who aren't members can find the server. Don't put anything on it you wouldn't put on a public notice board. Member counts are shown rounded.</p>
      </div>
      {!isDefault && (
        <SettingsGroup>
          <ToggleRow label="List this server in Discover" checked={Boolean(s.discoverable)} disabled={state.busy} onChange={(v) => run(() => updateSettings(sid, v ? { discoverable: true, public: form } : { discoverable: false }), v ? "Listed." : "Unlisted. Its public card was deleted.")} />
          <ToggleRow label="Anyone who finds it can join" help="Off: people still need an invite, even when it's listed." checked={s.join_mode === "open"} disabled={state.busy} onChange={(v) => run(() => updateSettings(sid, { join_mode: v ? "open" : "invite" }))} />
        </SettingsGroup>
      )}
      {(listed || !isDefault) && (
        <SettingsGroup title="Public card">
          <form className="space-y-4" onSubmit={(ev) => { ev.preventDefault(); run(() => updateSettings(sid, { public: form })); }}>
            <div className="flex items-center gap-4">
              <ServerIcon look={form} size="h-14 w-14" rounded />
              <div className="min-w-0 flex-1 space-y-1.5">
                <Label htmlFor="pub-icon">Icon</Label>
                <Input id="pub-icon" value={form.icon} onChange={(ev) => setForm((f) => ({ ...f, icon: ev.target.value.slice(0, 8) }))} className="max-w-xs" />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="pub-name">Public name</Label>
              <Input id="pub-name" value={form.name} onChange={(ev) => setForm((f) => ({ ...f, name: ev.target.value }))} maxLength={60} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="pub-desc">Public description</Label>
              <Textarea id="pub-desc" value={form.description} onChange={(ev) => setForm((f) => ({ ...f, description: ev.target.value }))} maxLength={300} rows={3} />
            </div>
            <div className="space-y-1.5">
              <Label>Colour</Label>
              <ColorPicker value={form.color} onChange={(c) => setForm((f) => ({ ...f, color: c }))} />
            </div>
            <fieldset>
              <legend className="text-sm font-medium">Tags (up to 5)</legend>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {ALL_TAGS.map((t) => (
                  <button key={t} type="button" aria-pressed={form.tags.includes(t)} onClick={() => toggleTag(t)} className={`rounded-full border px-2.5 py-0.5 text-xs ${form.tags.includes(t) ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:bg-muted"}`}>
                    {tagLabel(t)}
                  </button>
                ))}
              </div>
            </fieldset>
            <Button type="submit" disabled={state.busy || (listed && !form.name.trim())}>{state.busy ? "Saving…" : listed ? "Save public card" : "Save, for when it's listed"}</Button>
          </form>
        </SettingsGroup>
      )}
      <Status state={state} />
    </>
  );
}

// ---------- safety ----------

function Safety({ sid }) {
  const { servers, updateSettings } = useServers();
  const st = servers[sid].server.settings;
  const [state, run] = useRun();
  const set = (changes) => run(() => updateSettings(sid, changes));
  return (
    <>
      <SettingsTitle intro="Ways to slow down spam and raids. The server enforces them; staff aren't affected." help="moderation">Safety</SettingsTitle>
      <SettingsGroup title="New accounts and newcomers">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="sf-acct">Accounts must be at least</Label>
            <NativeSelect id="sf-acct" value={String(st.min_account_minutes)} disabled={state.busy} onChange={(ev) => set({ min_account_minutes: Number(ev.target.value) })}>
              {[[0, "Any age"], [5, "5 minutes old"], [10, "10 minutes old"], [60, "1 hour old"], [1440, "1 day old"]].map(([v, l]) => <option key={v} value={String(v)}>{l}</option>)}
            </NativeSelect>
            <p className="text-xs text-muted-foreground">Before they can post.</p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="sf-member">Newcomers wait</Label>
            <NativeSelect id="sf-member" value={String(st.min_member_minutes)} disabled={state.busy} onChange={(ev) => set({ min_member_minutes: Number(ev.target.value) })}>
              {[[0, "No wait"], [10, "10 minutes"], [60, "1 hour"]].map(([v, l]) => <option key={v} value={String(v)}>{l}</option>)}
            </NativeSelect>
            <p className="text-xs text-muted-foreground">After joining, before they can post.</p>
          </div>
        </div>
      </SettingsGroup>
      <SettingsGroup title="Lockdown" description="For when something's going wrong. Both can be undone at any time.">
        <ToggleRow label="Pause invites" help="Existing links stop working until you turn this off." checked={st.invites_paused} disabled={state.busy} onChange={(v) => set({ invites_paused: v })} />
        <ToggleRow label="Pause joining" help="Nobody new can join, by invite or from Discover." checked={st.joins_paused} disabled={state.busy} onChange={(v) => set({ joins_paused: v })} />
      </SettingsGroup>
      <Status state={state} />
      <ModerationRules sid={sid} />
      <AutoMod sid={sid} />
    </>
  );
}

// ---------- emoji and stickers ----------

function ExpressionSet({ sid, kind }) {
  const { serverEmoji, setServerSet } = useServers();
  const [state, run] = useRun();
  const picker = useRef(null);
  const set = serverEmoji(sid)[kind];
  const max = kind === "stickers" ? EMOJI_LIMITS.stickers : EMOJI_LIMITS.emoji;
  const save = (items, msg) => run(() => setServerSet(sid, kind, items.length ? { items } : null), msg);
  const add = async (files) => {
    const room = max - set.length;
    const picked = [...files].slice(0, Math.max(0, room));
    if (!picked.length) return;
    await run(async () => {
      const made = [];
      for (const f of picked) made.push({ id: newEmojiId(), name: uniqueName(nameFromFile(f.name), [...set, ...made]), img: await imageForSet(f, kind) });
      await setServerSet(sid, kind, { items: [...set, ...made] });
    }, picked.length === 1 ? "Added." : `Added ${picked.length}.`);
  };
  const rename = (id, name) => {
    const clean = name.toLowerCase().replace(/[^a-z0-9_]+/g, "_").slice(0, 32);
    if (!EMOJI_NAME_RE.test(clean) || set.some((x) => x.id !== id && x.name === clean)) return;
    save(set.map((x) => (x.id === id ? { ...x, name: clean } : x)), "Renamed.");
  };
  return (
    <SettingsGroup
      title={kind === "stickers" ? `Stickers (${set.length} of ${max})` : `Emoji (${set.length} of ${max})`}
      description={kind === "stickers" ? "Pictures members can send on their own. Up to 160 pixels square." : "Members use them in messages as :name: and as reactions. Up to 64 pixels square."}
    >
      <input ref={picker} type="file" accept="image/png,image/jpeg,image/webp,image/gif" multiple className="hidden" aria-hidden="true" tabIndex={-1} onChange={(ev) => { add(ev.target.files || []); ev.target.value = ""; }} />
      <Button type="button" size="sm" disabled={state.busy || set.length >= max} onClick={() => picker.current?.click()}>
        {kind === "stickers" ? "Upload stickers" : "Upload emoji"}
      </Button>
      {set.length > 0 && (
        <ul className="mt-3 divide-y divide-border rounded-md border border-border">
          {set.map((x) => (
            <li key={x.id} className="flex items-center gap-3 px-3 py-2">
              <img src={x.img} alt="" className={kind === "stickers" ? "h-14 w-14" : "h-8 w-8"} />
              <span className="text-muted-foreground" aria-hidden="true">:</span>
              <Input defaultValue={x.name} aria-label={`Name for ${x.name}`} className="h-8 max-w-[14rem]" disabled={state.busy} onBlur={(ev) => ev.target.value !== x.name && rename(x.id, ev.target.value)} />
              <span className="text-muted-foreground" aria-hidden="true">:</span>
              <button type="button" disabled={state.busy} onClick={() => save(set.filter((y) => y.id !== x.id), "Removed.")} className="ml-auto rounded p-1.5 text-muted-foreground hover:bg-muted hover:text-destructive" aria-label={`Remove ${x.name}`}>
                <Trash2 className="h-4 w-4" aria-hidden="true" />
              </button>
            </li>
          ))}
        </ul>
      )}
      <Status state={state} />
    </SettingsGroup>
  );
}

function uniqueName(base, taken) {
  let name = base;
  for (let i = 2; taken.some((x) => x.name === name); i += 1) name = `${base.slice(0, 29)}_${i}`;
  return name;
}

function Expressions({ sid }) {
  return (
    <>
      <SettingsTitle intro="Pictures are shrunk on your device and encrypted with the server's key, so only members can see them, or their names." help="channels">Emoji and stickers</SettingsTitle>
      <ExpressionSet sid={sid} kind="emoji" />
      <ExpressionSet sid={sid} kind="stickers" />
    </>
  );
}

// ---------- AutoMod ----------

function AutoMod({ sid }) {
  const { automodOf, setServerSet } = useServers();
  const rules = automodOf(sid);
  const [state, run] = useRun();
  const [words, setWords] = useState(rules.words.join("\n"));
  useEffect(() => setWords(rules.words.join("\n")), [rules.words.join("\n")]);  
  const save = (changes, msg = "Saved.") => run(() => setServerSet(sid, "automod", { ...rules, ...changes }), msg);
  return (
    <SettingsGroup
      title="AutoMod"
      description="Messages are encrypted, so the service can't filter them. These rules are encrypted too, and members' apps apply them: the sender's app won't send a message that breaks them, and everyone else's hides one that does. People who can manage messages are exempt."
    >
      <ToggleRow label="Use AutoMod" checked={rules.enabled} disabled={state.busy} onChange={(v) => save({ enabled: v })} />
      <ToggleRow label="Block links" help="Web addresses in messages." checked={rules.block_links} disabled={state.busy || !rules.enabled} onChange={(v) => save({ block_links: v })} />
      <ToggleRow label="Block invites to other servers" checked={rules.block_invites} disabled={state.busy || !rules.enabled} onChange={(v) => save({ block_invites: v })} />
      <div className="space-y-1.5 py-2">
        <Label htmlFor="am-mentions">Most people or roles one message can mention</Label>
        <NativeSelect id="am-mentions" value={String(rules.mention_limit)} disabled={state.busy || !rules.enabled} onChange={(ev) => save({ mention_limit: Number(ev.target.value) })}>
          {MENTION_LIMITS.map((n) => <option key={n} value={String(n)}>{n === 0 ? "No limit" : n}</option>)}
        </NativeSelect>
      </div>
      <div className="space-y-1.5 py-2">
        <Label htmlFor="am-words">Blocked words</Label>
        <Textarea id="am-words" rows={5} value={words} disabled={state.busy || !rules.enabled} onChange={(ev) => setWords(ev.target.value)} placeholder={"One per line. Use * for any letters, like spam*"} />
        <Button type="button" size="sm" variant="outline" disabled={state.busy || !rules.enabled} onClick={() => save({ words: words.split(/\n|,/).map((w) => w.trim()).filter(Boolean) })}>Save words</Button>
      </div>
      <Status state={state} />
    </SettingsGroup>
  );
}

function CasesPage({ sid }) {
  return (
    <>
      <SettingsTitle intro="Warnings, notes, and every timeout, kick, ban and purge, by people or by the server's own rules." help="moderation">Cases</SettingsTitle>
      <CaseLog sid={sid} />
    </>
  );
}

// ---------- privacy and encryption ----------

function KeyStatus({ sid }) {
  const { servers, channelName, renewKeys, can } = useServers();
  const e = servers[sid];
  const [state, run] = useRun();
  const [confirm, setConfirm] = useState(false);
  const label = (c) => (c.kind === "h" ? "Full-history channels and server details" : c.kind === "l" ? "Channels that start from joining" : `#${channelName(e.channels.find((x) => x.id === c.channel_id)) || "private channel"}`);
  return (
    <SettingsGroup title="Encryption keys" description="Each set of keys has generations. A new generation is started when someone who held the keys loses access, so they can't read what's sent next.">
      <ul className="divide-y divide-border text-sm">
        {e.chains.map((c) => {
          const gens = e.generations.filter((g) => g.chain_id === c.chain_id);
          const latest = gens.reduce((a, g) => (!a || g.generation > a.generation ? g : a), null);
          return (
            <li key={c.chain_id} className="flex items-center justify-between gap-3 py-2">
              <span>{label(c)}</span>
              <span className="text-xs text-muted-foreground">
                {latest ? `Generation ${latest.generation + 1}, since ${stamp(latest.started_at)}` : "Not set up yet"}
                {c.rotation_needed && <span className="ml-2 font-medium text-[hsl(var(--warning))]">renewal due</span>}
              </span>
            </li>
          );
        })}
      </ul>
      {can(sid, P.MANAGE_KEYS) && (
        <div className="mt-3">
          <Button variant="outline" disabled={state.busy} onClick={() => setConfirm(true)}><KeyRound className="mr-1.5 h-4 w-4" aria-hidden="true" /> Renew all keys now</Button>
          <p className="mt-1 text-xs text-muted-foreground">Renewals due after a ban happen automatically whenever someone who can is online.</p>
        </div>
      )}
      <Status state={state} />
      <ConfirmDialog open={confirm} onOpenChange={setConfirm} title="Renew all keys?" confirmLabel="Renew keys" destructive={false} onConfirm={() => run(() => renewKeys(sid), "Renewed. Members get the new keys as their apps hand them out.")}>
        <p>Your device makes new keys for everything you can read here. Members' apps then hand them on. Until someone's app has its copy, they can't read new messages.</p>
      </ConfirmDialog>
    </SettingsGroup>
  );
}

function Privacy({ sid }) {
  const { servers, updateSettings, act, can, muted, toggleMute } = useServers();
  const e = servers[sid];
  const st = e.server.settings;
  const [state, run] = useRun();
  const [nick, setNick] = useState(false);
  const manage = can(sid, P.MANAGE_SERVER);
  const set = (changes) => run(() => updateSettings(sid, changes));
  return (
    <>
      <SettingsTitle intro="Your own choices here, and (for admins) how much the server shares about its members." help="create-a-server">Privacy</SettingsTitle>
      <SettingsGroup title="You, in this server">
        <ToggleRow
          label="List me in the member list"
          help={st.member_list === "opt_in" ? "Off: other members only see you when you post. Staff are always listed." : "This server doesn't list ordinary members, whatever you choose."}
          checked={Boolean(e.member.listed)}
          disabled={state.busy || st.member_list !== "opt_in"}
          onChange={(v) => run(() => act(sid, "set_listed", { listed: v }))}
        />
        <ToggleRow label="Mute this server" help="No unread marks from it. Remembered on this device only." checked={muted(sid)} onChange={() => toggleMute(sid)} />
        {can(sid, P.CHANGE_NICKNAME) && <Button variant="outline" size="sm" className="mt-2" onClick={() => setNick(true)}>Change my nickname here</Button>}
      </SettingsGroup>
      {manage && (
        <>
          <SettingsGroup title="Member list" description="Staff are always listed, so people can tell who's who. This decides who else is.">
            <ChoiceList
              name="ml"
              value={st.member_list}
              disabled={state.busy}
              onChange={(v) => set({ member_list: v })}
              options={[
                { value: "opt_in", label: "Members choose", help: "Each member decides whether to be listed. Nobody is by default." },
                { value: "staff_only", label: "Staff only", help: "Only staff are listed." },
                { value: "count_only", label: "Just a count", help: "Only the number of members, and staff." },
              ]}
            />
          </SettingsGroup>
          <SettingsGroup title="New channels start with">
            <ChoiceList
              name="dh"
              value={st.default_history}
              disabled={state.busy}
              onChange={(v) => set({ default_history: v })}
              options={[
                { value: "joined", label: "History from joining", help: "Newcomers read only what's sent after they arrive." },
                { value: "full", label: "Full history", help: "Newcomers can read everything." },
              ]}
            />
          </SettingsGroup>
          <SettingsGroup title="Who hands out keys" description="When someone joins, a member's app seals the server's keys to them. Whoever does that learns who's waiting for keys.">
            <ChoiceList
              name="kh"
              value={st.key_handout}
              disabled={state.busy}
              onChange={(v) => set({ key_handout: v })}
              options={[
                { value: "members", label: "Any member's app", help: "Newcomers get keys quickly. Members' apps learn the account ids of people joining." },
                { value: "staff", label: "Only staff with Manage encryption", help: "Ordinary members never learn who joins. Newcomers wait until a staff member's app is online." },
              ]}
            />
          </SettingsGroup>
          <SettingsGroup title="Other settings">
            <ToggleRow label="Members can message each other" help="When on, people who only share this server can start direct messages, if their own settings allow." checked={st.allow_member_dms} disabled={state.busy} onChange={(v) => set({ allow_member_dms: v })} />
            <div className="mt-3 max-w-xs space-y-1.5">
              <Label htmlFor="audit-keep">Keep the audit log for</Label>
              <NativeSelect id="audit-keep" value={String(st.audit_retention_days)} disabled={state.busy} onChange={(ev) => set({ audit_retention_days: Number(ev.target.value) })}>
                {[30, 90, 180].map((d) => <option key={d} value={String(d)}>{d} days</option>)}
              </NativeSelect>
              <p className="text-xs text-muted-foreground">Applies to new entries. The log never holds message content.</p>
            </div>
          </SettingsGroup>
        </>
      )}
      <KeyStatus sid={sid} />
      <Status state={state} />
      <NicknameDialog serverId={sid} open={nick} onOpenChange={setNick} />
    </>
  );
}

// ---------- members, invites, bans, audit log ----------

function Members({ sid }) {
  const { loadMembers, memberLists, memberName, profileOf, rolesOfMember, roleName, servers } = useServers();
  const [card, setCard] = useState(null);
  const [q, setQ] = useState("");
  const list = memberLists[sid];
  useEffect(() => {
    loadMembers(sid, { force: true }).catch(() => {});
  }, [sid, loadMembers]);
  const shown = (list?.members || []).filter((m) => !q.trim() || memberName(sid, m.user_id).toLowerCase().includes(q.trim().toLowerCase()) || profileOf(sid, m.user_id)?.username?.toLowerCase().includes(q.trim().toLowerCase()));
  return (
    <>
      <SettingsTitle intro="Staff, and members who chose to be listed. Moderators don't get a list of everyone: to act on someone who isn't listed, open their profile from one of their messages.">Members</SettingsTitle>
      {list && <p className="mb-3 text-sm text-muted-foreground">{list.count} members in all, {list.members.length} listed.</p>}
      <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by name" aria-label="Filter members" className="mb-4 max-w-sm" />
      <ul className="divide-y divide-border">
        {shown.map((m) => {
          const p = profileOf(sid, m.user_id);
          return (
            <li key={m.user_id}>
              <button type="button" onClick={() => setCard(m.user_id)} className="flex w-full items-center gap-3 py-2.5 text-left hover:bg-[hsl(var(--chat-hover))]">
                <Avatar id={m.user_id} name={memberName(sid, m.user_id)} emoji={p?.avatar_emoji} image={p?.avatar_image} accent={p?.accent_color} size="h-9 w-9" />
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium">{memberName(sid, m.user_id)}</span>
                  <span className="block truncate text-xs text-muted-foreground">@{p?.username}{servers[sid].server.owner_id === m.user_id ? ", owner" : ""}</span>
                </span>
                <span className="hidden max-w-[40%] truncate text-xs text-muted-foreground sm:block">{rolesOfMember(sid, m).map(roleName).join(", ")}</span>
              </button>
            </li>
          );
        })}
      </ul>
      <MemberCard serverId={sid} userId={card} open={Boolean(card)} onOpenChange={(v) => !v && setCard(null)} />
    </>
  );
}

const AGE_LABEL = (i) => (i.expires_at ? `Expires ${stamp(i.expires_at)}` : "Doesn't expire");

function Invites({ sid }) {
  const { listInvites, revokeInvite, memberName } = useServers();
  const [invites, setInvites] = useState(null);
  const [error, setError] = useState("");
  const [making, setMaking] = useState(false);
  const load = useCallback(() => listInvites(sid).then(setInvites).catch((err) => setError(err.message)), [listInvites, sid]);
  useEffect(() => {
    load();
  }, [load]);
  return (
    <>
      <SettingsTitle intro="Links that let people join. The part after # in a link is never sent to Commonveil, so links can't be rebuilt from this list: copy a link when you make it." help="create-a-server">Invites</SettingsTitle>
      <Button onClick={() => setMaking(true)} className="mb-4"><Link2 className="mr-1.5 h-4 w-4" aria-hidden="true" /> Make an invite link</Button>
      <ErrorNote>{error}</ErrorNote>
      {!invites && !error && <p className="text-sm text-muted-foreground">Loading…</p>}
      {invites && invites.length === 0 && <p className="text-sm text-muted-foreground">No active invites.</p>}
      <ul className="divide-y divide-border">
        {(invites || []).map((i) => (
          <li key={i.code} className="flex flex-wrap items-center gap-3 py-3 text-sm">
            <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{i.code}</code>
            <span className="text-muted-foreground">by {memberName(sid, i.creator_id)}</span>
            <span className="text-muted-foreground">
              {i.max_uses ? `${i.uses} of ${i.max_uses} uses` : `${i.uses} ${i.uses === 1 ? "use" : "uses"}`}
            </span>
            <span className="text-muted-foreground">{AGE_LABEL(i)}</span>
            <Button size="sm" variant="ghost" className="ml-auto text-destructive" onClick={async () => { try { await revokeInvite(sid, i.code); load(); } catch (err) { setError(err.message); } }}>Revoke</Button>
          </li>
        ))}
      </ul>
      <InviteDialog serverId={sid} open={making} onOpenChange={(v) => { setMaking(v); if (!v) load(); }} />
    </>
  );
}

function Bans({ sid }) {
  const { act, openBanReason, memberName } = useServers();
  const [data, setData] = useState(null);
  const [reasons, setReasons] = useState({});
  const [error, setError] = useState("");
  const opener = useRef(openBanReason);
  opener.current = openBanReason;
  useEffect(() => {
    let alive = true;
    callFn("servers", { action: "bans", server_id: sid })
      .then(async (res) => {
        if (!alive) return;
        setData(res);
        const out = {};
        for (const b of res.bans) if (b.reason) out[b.user_id] = await opener.current(sid, b.reason).catch(() => "");
        if (alive) setReasons(out);
      })
      .catch((err) => alive && setError(err.message));
    return () => {
      alive = false;
    };
  }, [sid]);
  const nameOf = (uid) => data?.profiles.find((p) => p.user_id === uid)?.username || "someone";
  return (
    <>
      <SettingsTitle intro="People who can't come back. Ban reasons are encrypted: only members with the server's keys can read them." help="moderation">Bans</SettingsTitle>
      <ErrorNote>{error}</ErrorNote>
      {!data && !error && <p className="text-sm text-muted-foreground">Loading…</p>}
      {data && data.bans.length === 0 && <p className="text-sm text-muted-foreground">Nobody's banned.</p>}
      <ul className="divide-y divide-border">
        {(data?.bans || []).map((b) => (
          <li key={b.user_id} className="flex flex-wrap items-start gap-3 py-3 text-sm">
            <span className="min-w-0 flex-1">
              <span className="block font-medium">@{nameOf(b.user_id)}</span>
              <span className="block text-xs text-muted-foreground">Banned by {memberName(sid, b.banned_by)} {stamp(b.created_date)}</span>
              {reasons[b.user_id] && <span className="mt-1 block text-muted-foreground">{reasons[b.user_id]}</span>}
            </span>
            <Button size="sm" variant="outline" onClick={async () => {
              try {
                await act(sid, "unban_member", { user_id: b.user_id }, { reload: false });
                setData((d) => ({ ...d, bans: d.bans.filter((x) => x.user_id !== b.user_id) }));
              } catch (err) {
                setError(err.message);
              }
            }}>Unban</Button>
          </li>
        ))}
      </ul>
    </>
  );
}

const ACTIONS = {
  server_create: "created the server",
  keys_renewed: "renewed encryption keys",
  member_kick: "kicked",
  member_ban: "banned",
  member_unban: "unbanned",
  member_timeout: "timed out",
  member_timeout_end: "ended the time-out of",
  member_roles: "changed the roles of",
  nickname_change: "changed the nickname of",
  role_create: "created a role",
  role_update: "changed a role",
  role_delete: "deleted a role",
  roles_reorder: "reordered roles",
  channel_create: "created a channel",
  channel_update: "changed a channel",
  channel_delete: "deleted a channel",
  channels_reorder: "reordered channels",
  server_profile: "changed the server's name or icon",
  server_rules: "changed the rules",
  server_onboarding: "changed the welcome new members see",
  server_emoji: "changed the emoji",
  server_stickers: "changed the stickers",
  server_automod: "changed AutoMod",
  member_warn: "warned",
  report_sent: "reported",
  report_resolved: "closed a report about",
  report_dismissed: "dismissed a report about",
  report_escalated: "sent a report to Commonveil about",
  case_pardon: "pardoned a warning for",
  messages_purge: "deleted recent messages from",
  mod_policy: "changed the moderation rules",
  raid_lockdown: "paused joining (raid protection)",
  staff_quarantine: "took away roles (staff limits) from",
  thread_lock: "locked a thread",
  thread_unlock: "unlocked a thread",
  event_create: "scheduled an event",
  event_update: "changed an event",
  event_cancel: "cancelled an event",
  server_settings: "changed settings",
  ownership_transfer: "handed ownership to",
  invite_create: "made an invite",
  invite_revoke: "revoked an invite",
  message_delete: "deleted a message from",
  message_pin: "pinned a message",
  message_unpin: "unpinned a message",
  ticket_close: "closed a ticket",
  ticket_reopen: "reopened a ticket",
};

function AuditLog({ sid }) {
  const { servers, channelName, roleName } = useServers();
  const e = servers[sid];
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    callFn("servers", { action: "audit_log", server_id: sid }).then(setData).catch((err) => setError(err.message));
  }, [sid]);
  const userOf = (uid) => data?.profiles.find((p) => p.user_id === uid)?.username;
  const target = (a) => {
    if (a.target_kind === "member") return userOf(a.target_id) ? `@${userOf(a.target_id)}` : "a former member";
    if (a.target_kind === "channel") {
      const c = e.channels.find((x) => x.id === a.target_id);
      return c ? `#${channelName(c)}` : "";
    }
    if (a.target_kind === "role") {
      const r = e.roles.find((x) => x.id === a.target_id);
      return r ? roleName(r) : "";
    }
    return "";
  };
  return (
    <>
      <SettingsTitle intro={`Who changed what. Entries are kept for ${data?.retention_days || e.server.settings.audit_retention_days} days, and never include anything anyone wrote.`} help="moderation">Audit log</SettingsTitle>
      <ErrorNote>{error}</ErrorNote>
      {!data && !error && <p className="text-sm text-muted-foreground">Loading…</p>}
      {data && data.entries.length === 0 && <p className="text-sm text-muted-foreground">Nothing yet.</p>}
      <ol className="divide-y divide-border">
        {(data?.entries || []).map((a) => (
          <li key={a.id} className="py-2.5 text-sm">
            <span className="font-medium">{userOf(a.actor_id) ? `@${userOf(a.actor_id)}` : "Someone"}</span> {ACTIONS[a.action] || a.action} <span className="font-medium">{target(a)}</span>
            {a.detail && <span className="text-muted-foreground"> ({a.detail})</span>}
            <span className="block text-xs text-muted-foreground">{stamp(a.at)}</span>
          </li>
        ))}
      </ol>
    </>
  );
}

// ---------- ownership, leaving, deleting ----------

function DangerZone({ sid }) {
  const navigate = useNavigate();
  const { userId } = useSecure();
  const { servers, serverLook, loadMembers, memberLists, memberName, act, deleteServer, leaveServer } = useServers();
  const e = servers[sid];
  const owner = e.server.owner_id === userId;
  const look = serverLook(sid);
  const [heir, setHeir] = useState("");
  const [typed, setTyped] = useState("");
  const [confirm, setConfirm] = useState(null);
  useEffect(() => {
    if (owner) loadMembers(sid).catch(() => {});
  }, [owner, sid, loadMembers]);
  const candidates = (memberLists[sid]?.members || []).filter((m) => m.user_id !== userId);
  return (
    <>
      <SettingsTitle>{owner ? "Ownership" : "Leave"}</SettingsTitle>
      {owner ? (
        <>
          <SettingsGroup title="Hand the server on" description="The new owner can do everything, including deleting the server. You stay as a member.">
            <div className="flex flex-wrap items-end gap-2">
              <div className="min-w-[12rem] flex-1 space-y-1.5">
                <Label htmlFor="heir">New owner</Label>
                <NativeSelect id="heir" value={heir} onChange={(ev) => setHeir(ev.target.value)}>
                  <option value="">Choose a listed member</option>
                  {candidates.map((m) => <option key={m.user_id} value={m.user_id}>{memberName(sid, m.user_id)}</option>)}
                </NativeSelect>
              </div>
              <Button variant="outline" disabled={!heir} onClick={() => setConfirm("transfer")}>Transfer ownership</Button>
            </div>
          </SettingsGroup>
          {!e.server.is_default && (
            <SettingsGroup title="Delete the server" description="Every channel, message, role and invite is deleted for everyone. It can't be undone.">
              <div className="max-w-sm space-y-1.5">
                <Label htmlFor="del-name">Type the server's name to confirm</Label>
                <Input id="del-name" value={typed} onChange={(ev) => setTyped(ev.target.value)} placeholder={look.name} />
              </div>
              <Button variant="destructive" className="mt-3" disabled={typed.trim() !== look.name.trim()} onClick={() => setConfirm("delete")}><Trash2 className="mr-1.5 h-4 w-4" aria-hidden="true" /> Delete server</Button>
            </SettingsGroup>
          )}
        </>
      ) : (
        <SettingsGroup description={e.server.is_default ? "You can leave the community server, and come back from Discover." : "Your copies of its keys are deleted. You'll need a new invite to come back."}>
          <Button variant="outline" className="text-destructive" onClick={() => setConfirm("leave")}><LogOut className="mr-1.5 h-4 w-4" aria-hidden="true" /> Leave {look.name}</Button>
        </SettingsGroup>
      )}
      <ConfirmDialog open={confirm === "transfer"} onOpenChange={(v) => !v && setConfirm(null)} title={`Make ${heir ? memberName(sid, heir) : "them"} the owner?`} confirmLabel="Transfer" onConfirm={() => act(sid, "transfer_ownership", { user_id: heir })}>
        <p>You can't undo this yourself: only the new owner can hand it back.</p>
      </ConfirmDialog>
      <ConfirmDialog open={confirm === "delete"} onOpenChange={(v) => !v && setConfirm(null)} title={`Delete ${look.name}?`} confirmLabel="Delete forever" busyLabel="Deleting…" onConfirm={async () => { await deleteServer(sid); navigate("/app", { replace: true }); }}>
        <p>Everything in it is deleted for everyone.</p>
      </ConfirmDialog>
      <ConfirmDialog open={confirm === "leave"} onOpenChange={(v) => !v && setConfirm(null)} title={`Leave ${look.name}?`} confirmLabel="Leave server" onConfirm={async () => { await leaveServer(sid); navigate("/app", { replace: true }); }}>
        <p>Messages you sent stay unless you delete them first.</p>
      </ConfirmDialog>
    </>
  );
}

// ---------- the page ----------

export default function ServerSettings() {
  const { serverId, section, channelId } = useParams();
  const { userId } = useSecure();
  const { servers, loaded, loadState, can, serverLook, channelName } = useServers();
  const close = useCloseSettings(`/app/s/${serverId}`);
  const e = servers[serverId];

  // Opened directly (a reload or a link): load the server like the server view does.
  useEffect(() => {
    if (e && !e.roles && e.status === "listed") loadState(serverId).catch(() => {});
  }, [e, serverId, loadState]);
  const perms = useMemo(() => ({
    server: can(serverId, P.MANAGE_SERVER),
    expressions: can(serverId, P.MANAGE_EXPRESSIONS),
    roles: can(serverId, P.MANAGE_ROLES),
    channels: can(serverId, P.MANAGE_CHANNELS),
    invites: can(serverId, P.CREATE_INVITES) || can(serverId, P.MANAGE_INVITES),
    bans: can(serverId, P.BAN_MEMBERS),
    audit: can(serverId, P.VIEW_AUDIT_LOG),
    mod: can(serverId, P.KICK_MEMBERS) || can(serverId, P.BAN_MEMBERS) || can(serverId, P.TIMEOUT_MEMBERS) || can(serverId, P.MANAGE_ROLES),
    reports: can(serverId, P.KICK_MEMBERS) || can(serverId, P.BAN_MEMBERS) || can(serverId, P.TIMEOUT_MEMBERS) || can(serverId, P.MANAGE_MESSAGES),
  }), [can, serverId]);

  if (!loaded || (e && !e.roles)) {
    return (
      <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
        {e?.status === "error" ? "Couldn't load this server. Trying again shortly." : "Loading…"}
      </div>
    );
  }
  if (!e) return <Navigate to="/app" replace />;

  const sections = {
    overview: perms.server && Overview,
    roles: perms.roles && RolesSettings,
    members: perms.mod && Members,
    invites: perms.invites && Invites,
    expressions: perms.expressions && Expressions,
    community: perms.server && Community,
    onboarding: perms.server && OnboardingSettings,
    discovery: perms.server && Discovery,
    safety: perms.server && Safety,
    privacy: Privacy,
    bans: perms.bans && Bans,
    reports: perms.reports && ReportsQueue,
    cases: perms.reports && CasesPage,
    audit: perms.audit && AuditLog,
    leave: DangerZone,
  };
  const owner = e.server.owner_id === userId;
  const first = Object.keys(sections).find((k) => sections[k]);
  if (!section && !channelId) return <Navigate to={`/app/s/${serverId}/settings/${first}`} replace />;
  if (section && section !== "channel" && !sections[section]) return <Navigate to={`/app/s/${serverId}/settings/privacy`} replace />;
  const active = channelId ? `channel-${channelId}` : section;
  const Current = channelId ? null : sections[section];
  const channel = channelId ? e.channels.find((c) => c.id === channelId) : null;

  const groups = [
    {
      label: serverLook(serverId).name,
      items: [
        sections.overview && { id: "overview", label: "Overview", icon: Sparkles },
        sections.roles && { id: "roles", label: "Roles", icon: Shield },
        sections.invites && { id: "invites", label: "Invites", icon: Link2 },
        sections.expressions && { id: "expressions", label: "Emoji and stickers", icon: Smile },
        { id: "privacy", label: "Privacy and encryption", icon: Eye },
      ].filter(Boolean),
    },
    perms.server && {
      label: "Community",
      items: [
        { id: "onboarding", label: "Onboarding", icon: Rocket },
        { id: "community", label: "Rules and screening", icon: BookOpen },
        { id: "discovery", label: "Discovery", icon: Compass },
        { id: "safety", label: "Safety", icon: ShieldAlert },
      ],
    },
    (perms.mod || perms.bans || perms.audit || perms.reports) && {
      label: "Moderation",
      items: [
        sections.reports && { id: "reports", label: "Reports", icon: Flag },
        sections.cases && { id: "cases", label: "Cases", icon: ListChecks },
        sections.members && { id: "members", label: "Members", icon: Users },
        sections.bans && { id: "bans", label: "Bans", icon: Ban },
        sections.audit && { id: "audit", label: "Audit log", icon: ListChecks },
      ].filter(Boolean),
    },
    channel && { label: "Channel", items: [{ id: `channel-${channel.id}`, label: channelName(channel), icon: Hash, to: `/app/s/${serverId}/settings/channel/${channel.id}` }] },
    { label: "", items: [{ id: "leave", label: owner ? "Ownership" : "Leave server", icon: owner ? KeyRound : LogOut, tone: owner ? undefined : "danger" }] },
  ].filter(Boolean);

  return (
    <SettingsLayout groups={groups} active={active} base={`/app/s/${serverId}/settings`} title={serverLook(serverId).name} onClose={close}>
      {channelId ? <ChannelSettings serverId={serverId} channelId={channelId} /> : Current ? <Current sid={serverId} serverId={serverId} /> : null}
    </SettingsLayout>
  );
}