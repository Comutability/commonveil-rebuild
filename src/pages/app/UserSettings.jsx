import React, { useEffect, useState } from "react";
import { Link, Navigate, useParams } from "react-router-dom";
import { Bell, ClipboardCheck, CloudOff, Database, Download, Eye, Fingerprint, KeyRound, LogOut, Palette, Shield, ShieldCheck, UserRound } from "lucide-react";
import SignInSettings from "./SignInSettings";
import OfflineSettings from "./OfflineSettings";
import PrivacyReport from "./PrivacyReport";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { ErrorNote } from "@/components/site/bits";
import { useAuth } from "@/lib/AuthContext";
import { usePresence } from "@/lib/secure/PresenceContext";
import { useSecure } from "@/lib/secure/SecureContext";
import { setAppearance, TEXT_SIZES, useAppearance } from "@/lib/appearance";
import Avatar, { ACCENT_HUES } from "@/components/chat/Avatar";
import PictureInput from "@/components/app/PictureInput";
import { handleOf, useSiteInfo } from "@/lib/site/siteInfo";
import SettingsLayout, { ChoiceList, SettingsGroup, SettingsTitle, useCloseSettings } from "@/components/settings/SettingsLayout";
import { InstallSection, PushSection } from "@/components/app/PushAndInstall";
import {
  AlertsSection,
  QuietSection,
  AutoDeleteSection,
  BlockedSection,
  DataSection,
  DeleteSection,
  DevicesSection,
  LockSection, ProtocolSection,
  RecoverySection,
  SignOutSection,
} from "./Settings";

const ACCENTS = ["", ...Object.keys(ACCENT_HUES)];
const EMOJI_RE = /^\p{Extended_Pictographic}(‍\p{Extended_Pictographic}|️|[\u{1f3fb}-\u{1f3ff}])*$/u;

function useSaver() {
  const [state, setState] = useState({ busy: false, msg: "", error: "" });
  const run = async (fn, msg = "Saved.") => {
    setState({ busy: true, msg: "", error: "" });
    try {
      await fn();
      setState({ busy: false, msg, error: "" });
    } catch (err) {
      setState({ busy: false, msg: "", error: err.message });
    }
  };
  return [state, run];
}

function ProfileCard({ userId, p }) {
  const hue = ACCENT_HUES[p.accent_color];
  return (
    <div className="overflow-hidden rounded-xl border border-border bg-card">
      <div className="h-16" style={{ background: hue !== undefined ? `hsl(${hue} 45% 45% / 0.45)` : "hsl(var(--primary) / 0.25)" }} aria-hidden="true" />
      <div className="-mt-8 px-4 pb-4">
        <span className="inline-block rounded-full ring-4 ring-[hsl(var(--card))]">
          <Avatar id={userId} name={p.display_name || p.username} emoji={p.avatar_emoji} image={p.avatar_image} accent={p.accent_color} size="h-16 w-16" className="text-xl" />
        </span>
        <p className="mt-2 text-lg font-semibold">{p.display_name || p.username}</p>
        <p className="text-sm text-muted-foreground">@{p.username}{p.pronouns ? `, ${p.pronouns}` : ""}</p>
        {p.bio && <p className="mt-3 whitespace-pre-wrap text-sm">{p.bio}</p>}
      </div>
    </div>
  );
}

function ProfileSettings() {
  const { me, userId, updateProfile } = useSecure();
  const p = me?.profile || {};
  const handle = handleOf(p.username, useSiteInfo());
  const [form, setForm] = useState({ display_name: p.display_name || "", pronouns: p.pronouns || "", bio: p.bio || "", avatar_emoji: p.avatar_emoji || "", avatar_image: p.avatar_image || "", accent_color: p.accent_color || "" });
  const [state, run] = useSaver();
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target ? e.target.value : e }));
  const emojiOk = !form.avatar_emoji || EMOJI_RE.test(form.avatar_emoji.trim());
  return (
    <>
      <SettingsTitle intro="Your profile is plain text the service can read, like a name on a letter. Choose how much to share and who sees it in Privacy and safety." help="profile-and-appearance">My profile</SettingsTitle>
      <div className="grid gap-8 lg:grid-cols-[1fr_16rem]">
        <form
          className="space-y-5"
          onSubmit={(e) => {
            e.preventDefault();
            run(() => updateProfile({ ...form, avatar_emoji: form.avatar_emoji.trim() }));
          }}
        >
          <div>
            <p className="text-sm text-muted-foreground">Username</p>
            <p className="font-medium">@{p.username}</p>
            <p className="text-xs text-muted-foreground">Usernames can't be changed. People find you only by typing it exactly.</p>
          </div>
          {handle && (
            <div>
              <p className="text-sm text-muted-foreground">Your address</p>
              <p className="break-all font-mono text-sm font-medium">@{handle}</p>
              <p className="text-xs text-muted-foreground">People on other Commonveil sites can message you at this address. Opened in a browser, it shows your profile.</p>
            </div>
          )}
          <div className="space-y-1.5">
            <Label htmlFor="pf-name">Display name</Label>
            <Input id="pf-name" value={form.display_name} onChange={set("display_name")} maxLength={50} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="pf-pronouns">Pronouns</Label>
            <Input id="pf-pronouns" value={form.pronouns} onChange={set("pronouns")} maxLength={30} placeholder="Optional" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="pf-bio">About me</Label>
            <Textarea id="pf-bio" value={form.bio} onChange={set("bio")} maxLength={280} rows={3} placeholder="Optional" />
          </div>
          <div className="space-y-1.5">
            <Label>Profile picture</Label>
            <PictureInput value={form.avatar_image} onChange={(v) => setForm((f) => ({ ...f, avatar_image: v }))} disabled={state.busy} />
            <p className="text-xs text-muted-foreground">Made small on this device and kept with your profile, so showing it never makes anyone's device fetch an image. Like the rest of your profile, it isn't end-to-end encrypted: choose who sees it in Privacy and safety.</p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="pf-emoji">Avatar emoji</Label>
            <Input id="pf-emoji" value={form.avatar_emoji} onChange={set("avatar_emoji")} maxLength={16} placeholder="One emoji, or leave empty for your initials" className="max-w-xs" />
            {!emojiOk && <p className="text-xs text-destructive">Use a single emoji.</p>}
            <p className="text-xs text-muted-foreground">Shown when you have no picture.</p>
          </div>
          <div className="space-y-1.5">
            <Label>Profile colour</Label>
            <div role="radiogroup" aria-label="Profile colour" className="flex flex-wrap gap-2">
              {ACCENTS.map((a) => (
                <button
                  key={a || "auto"}
                  type="button"
                  role="radio"
                  aria-checked={form.accent_color === a}
                  aria-label={a || "Automatic"}
                  onClick={() => setForm((f) => ({ ...f, accent_color: a }))}
                  className={`h-8 w-8 rounded-full border ring-offset-2 ring-offset-background ${form.accent_color === a ? "ring-2 ring-foreground" : ""}`}
                  style={{ background: a ? `hsl(${ACCENT_HUES[a]} 50% 50%)` : "conic-gradient(hsl(172 50% 50%), hsl(234 50% 55%), hsl(350 50% 55%), hsl(38 70% 50%), hsl(172 50% 50%))" }}
                />
              ))}
            </div>
          </div>
          <ErrorNote>{state.error}</ErrorNote>
          <div className="flex items-center gap-3">
            <Button type="submit" disabled={state.busy || !emojiOk}>{state.busy ? "Saving…" : "Save changes"}</Button>
            {state.msg && <span className="text-sm text-primary">{state.msg}</span>}
          </div>
        </form>
        <div>
          <p className="mb-2 text-xs font-semibold text-muted-foreground">Preview</p>
          <ProfileCard userId={userId} p={{ ...p, ...form }} />
        </div>
      </div>
    </>
  );
}

function PresenceGroup() {
  const { settings, setSettings } = usePresence();
  return (
    <SettingsGroup title="Online status and typing" description="Off unless you turn them on, and mutual: you see other people's only while you share yours. They pass through a live room that writes nothing down, and only for the server or conversation you have open. Typing is never shared in private channels. This choice is kept on this device.">
      <label className="flex items-start gap-3">
        <Checkbox checked={settings.presence} onCheckedChange={(v) => setSettings({ presence: Boolean(v) })} className="mt-0.5" />
        <span>
          <span className="block text-sm font-medium">Show when I'm online</span>
          <span className="block text-xs text-muted-foreground">People in the same server or conversation see a dot by your name while you have it open, even in servers where you aren't listed as a member.</span>
        </span>
      </label>
      <label className="mt-3 flex items-start gap-3">
        <Checkbox checked={settings.typing} disabled={!settings.presence} onCheckedChange={(v) => setSettings({ typing: Boolean(v) })} className="mt-0.5" />
        <span>
          <span className="block text-sm font-medium">Show when I'm typing</span>
          <span className="block text-xs text-muted-foreground">Others see "typing…" while you write, before you send anything.</span>
        </span>
      </label>
    </SettingsGroup>
  );
}

function PrivacySettings() {
  const { me, updateProfile } = useSecure();
  const privacy = me?.privacy || { profile_visibility: "shared", dm_policy: "anyone", default_listed: false };
  const [state, run] = useSaver();
  const change = (changes) => run(() => updateProfile(changes));
  return (
    <>
      <SettingsTitle intro="Commonveil has no member directory, and online status is off unless you turn it on. These choices decide the little that others can learn about you." help="privacy-settings">Privacy and safety</SettingsTitle>
      <SettingsGroup title="Who can start a conversation with you" description="People you already have a conversation with can always keep writing to you.">
        <ChoiceList
          name="dm"
          value={privacy.dm_policy}
          disabled={state.busy}
          onChange={(v) => change({ dm_policy: v })}
          options={[
            { value: "anyone", label: "Anyone who knows my username", help: "They have to type it exactly: nobody can browse for you." },
            { value: "servers", label: "Only people I share a server with", help: "Servers can turn this off for their members." },
            { value: "nobody", label: "Nobody new", help: "Only existing conversations, and people you start one with." },
          ]}
        />
      </SettingsGroup>
      <SettingsGroup title="Who can see your profile" description="Your username is always visible to people you talk with. This covers your display name, pronouns, avatar and about me.">
        <ChoiceList
          name="vis"
          value={privacy.profile_visibility}
          disabled={state.busy}
          onChange={(v) => change({ profile_visibility: v })}
          options={[
            { value: "shared", label: "People I share a conversation or server with" },
            { value: "conversations", label: "Only people I have a conversation with", help: "In servers, others see just your username." },
            { value: "nobody", label: "Nobody", help: "Everyone sees just your username." },
          ]}
        />
      </SettingsGroup>
      <PresenceGroup />
      <SettingsGroup title="Member lists" description="Servers list their staff. Everyone else chooses, server by server, whether to appear. This is your starting choice for servers you join.">
        <label className="flex items-start gap-3">
          <Checkbox checked={privacy.default_listed} disabled={state.busy} onCheckedChange={(v) => change({ default_listed: Boolean(v) })} className="mt-0.5" />
          <span>
            <span className="block text-sm font-medium">List me in member lists of servers I join</span>
            <span className="block text-xs text-muted-foreground">Off: other members only see you when you post. You can change it in each server's privacy settings.</span>
          </span>
        </label>
      </SettingsGroup>
      <ErrorNote>{state.error}</ErrorNote>
      {state.msg && <p className="text-sm text-primary">{state.msg}</p>}
      <div className="mt-6"><BlockedSection /></div>
    </>
  );
}

function KeySettings() {
  const { chain, status } = useSecure();
  const pq = Boolean(chain?.latest?.kem_pub);
  const devices = (status?.devices || []).filter((d) => d.status === "active");
  return (
    <>
      <SettingsTitle intro="Your keys live on your devices. Commonveil stores only public keys, and an encrypted backup that only your recovery phrase opens." help="devices-and-recovery">Devices and keys</SettingsTitle>
      <div className={`mb-6 flex items-start gap-3 rounded-xl border p-4 ${pq ? "border-primary/40 bg-primary/5" : "border-[hsl(var(--warning)/0.4)] bg-[hsl(var(--warning)/0.08)]"}`}>
        <ShieldCheck className={`mt-0.5 h-5 w-5 shrink-0 ${pq ? "text-primary" : "text-[hsl(var(--warning))]"}`} aria-hidden="true" />
        <div className="text-sm">
          <p className="font-medium">{pq ? "Post-quantum protection is on" : "Upgrading to post-quantum keys"}</p>
          <p className="mt-1 text-muted-foreground">
            {pq
              ? `Messages to you, and your copies of server keys, are sealed with ML-KEM-768 together with P-256, so recordings made today stay private even against a future quantum computer. ${devices.length} ${devices.length === 1 ? "device holds" : "devices hold"} your keys.`
              : "This happens automatically on one of your devices. Until then, your messages use the classic key exchange (P-256)."}
          </p>
        </div>
      </div>
      <div className="space-y-5">
        <DevicesSection />
        <RecoverySection />
        <LockSection />
        <ProtocolSection />
      </div>
    </>
  );
}

function AppearanceSettings() {
  const a = useAppearance();
  const swatch = (theme) => (
    <span className={`flex h-14 w-full overflow-hidden rounded-md border ${theme === "dark" ? "border-[hsl(222_15%_19%)]" : "border-[hsl(40_16%_84%)]"}`} aria-hidden="true">
      <span className="w-3" style={{ background: theme === "dark" ? "hsl(222 30% 4%)" : "hsl(40 18% 86%)" }} />
      <span className="w-6" style={{ background: theme === "dark" ? "hsl(222 25% 7.5%)" : "hsl(41 27% 93%)" }} />
      <span className="flex flex-1 flex-col justify-center gap-1 px-2" style={{ background: theme === "dark" ? "hsl(222 22% 9.5%)" : "hsl(42 33% 97.5%)" }}>
        <span className="h-1.5 w-3/4 rounded-full" style={{ background: theme === "dark" ? "hsl(40 26% 91% / 0.6)" : "hsl(222 24% 12% / 0.5)" }} />
        <span className="h-1.5 w-1/2 rounded-full" style={{ background: theme === "dark" ? "hsl(164 52% 52%)" : "hsl(170 62% 26%)" }} />
      </span>
    </span>
  );
  return (
    <>
      <SettingsTitle intro="Saved in this browser only." help="profile-and-appearance">Appearance</SettingsTitle>
      <SettingsGroup title="Theme">
        <div role="radiogroup" aria-label="Theme" className="grid max-w-lg grid-cols-3 gap-3">
          {[["system", "Match my system"], ["light", "Paper"], ["dark", "Ink"]].map(([value, label]) => (
            <button key={value} type="button" role="radio" aria-checked={a.theme === value} onClick={() => setAppearance({ theme: value })} className={`rounded-lg border p-2 text-left text-sm transition-colors ${a.theme === value ? "border-primary ring-2 ring-primary/30" : "border-border hover:bg-muted"}`}>
              {value === "system" ? (
                <span className="flex h-14 overflow-hidden rounded-md" aria-hidden="true">
                  <span className="flex-1">{swatch("light")}</span>
                  <span className="flex-1">{swatch("dark")}</span>
                </span>
              ) : (
                swatch(value)
              )}
              <span className="mt-1.5 block font-medium">{label}</span>
            </button>
          ))}
        </div>
      </SettingsGroup>
      <SettingsGroup title="Message display">
        <ChoiceList
          name="density"
          value={a.density}
          onChange={(v) => setAppearance({ density: v })}
          options={[
            { value: "cozy", label: "Cozy", help: "Avatars and names at the start of each run of messages." },
            { value: "compact", label: "Compact", help: "One line per message, with the time and name in front." },
          ]}
        />
      </SettingsGroup>
      <SettingsGroup title="Text size">
        <div role="radiogroup" aria-label="Text size" className="flex flex-wrap gap-2">
          {TEXT_SIZES.map((size) => (
            <button key={size} type="button" role="radio" aria-checked={a.textSize === size} onClick={() => setAppearance({ textSize: size })} className={`rounded-md border px-3 py-1.5 text-sm ${a.textSize === size ? "border-primary bg-primary/10 font-medium" : "border-border hover:bg-muted"}`}>
              {size === 100 ? "Default" : `${size}%`}
            </button>
          ))}
        </div>
      </SettingsGroup>
      <SettingsGroup title="Motion">
        <label className="flex items-start gap-3">
          <Checkbox checked={a.reduceMotion} onCheckedChange={(v) => setAppearance({ reduceMotion: Boolean(v) })} className="mt-0.5" />
          <span className="text-sm">Reduce motion<span className="block text-xs text-muted-foreground">Turns off animations, whatever your system says.</span></span>
        </label>
      </SettingsGroup>
    </>
  );
}

function NotificationSettings() {
  return (
    <>
      <SettingsTitle intro="Notifications never say who a message is from or what it says, unless you choose to see the sender while Commonveil is open." help="notifications">Notifications</SettingsTitle>
      <PushSection />
      <div className="mt-5"><AlertsSection /></div>
      <div className="mt-5"><QuietSection /></div>
      <p className="mt-4 text-sm text-muted-foreground">To quiet a server or a channel, right-click it (or use its menu) and choose Mute. Muting is remembered on this device only.</p>
    </>
  );
}

function AppSettings() {
  return (
    <>
      <SettingsTitle intro="Commonveil is a web app you can install, with its own window and icon." help="install-the-app">The app</SettingsTitle>
      <InstallSection />
    </>
  );
}

function DataSettings() {
  return (
    <>
      <SettingsTitle help="your-data">Data and account</SettingsTitle>
      <div className="space-y-5">
        <DataSection />
        <AutoDeleteSection />
        <SignOutSection />
        <DeleteSection />
      </div>
    </>
  );
}

const SECTIONS = {
  profile: ProfileSettings,
  privacy: PrivacySettings,
  "privacy-report": PrivacyReport,
  keys: KeySettings,
  appearance: AppearanceSettings,
  notifications: NotificationSettings,
  app: AppSettings,
  data: DataSettings,
  offline: OfflineSettings,
  "sign-in": SignInSettings,
};

export default function UserSettings() {
  const { section } = useParams();
  const { isAdmin, signOut } = useSecure();
  const { user } = useAuth();
  const close = useCloseSettings("/app");
  const [wide, setWide] = useState(() => typeof window !== "undefined" && window.innerWidth >= 768);
  useEffect(() => {
    const onResize = () => setWide(window.innerWidth >= 768);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);
  if (section && !SECTIONS[section]) return <Navigate to="/app/settings" replace />;
  // On a wide screen there's always a section open.
  if (!section && wide) return <Navigate to="/app/settings/profile" replace />;
  const Current = section ? SECTIONS[section] : null;
  const groups = [
    {
      label: "Your account",
      items: [
        { id: "profile", label: "My profile", icon: UserRound },
        { id: "privacy", label: "Privacy and safety", icon: Eye },
        { id: "privacy-report", label: "Privacy report", icon: ClipboardCheck },
        { id: "sign-in", label: "Sign-in and recovery", icon: Fingerprint },
        { id: "keys", label: "Devices and keys", icon: KeyRound },
        { id: "data", label: "Data and account", icon: Database },
      ],
    },
    {
      label: "This app",
      items: [
        { id: "appearance", label: "Appearance", icon: Palette },
        { id: "notifications", label: "Notifications", icon: Bell },
        { id: "offline", label: "Offline mode", icon: CloudOff },
        { id: "app", label: "Install the app", icon: Download },
      ],
    },
  ];
  if (isAdmin) groups.push({ label: "Staff", items: [{ id: "admin", label: user?.site_owner ? "Site owner" : "Site admin", icon: Shield, to: "/admin" }] });
  return (
    <SettingsLayout
      groups={groups}
      active={section}
      base="/app/settings"
      title="Settings"
      onClose={close}
      footer={
        <div className="border-t border-border/60 pt-4">
          <button type="button" onClick={() => signOut()} className="panel-item">
            <LogOut className="h-4 w-4" aria-hidden="true" /> Sign out
          </button>
          <Link to="/help" className="panel-item">Help Centre</Link>
          <Link to="/" className="panel-item">Commonveil website</Link>
        </div>
      }
    >
      {Current && <Current />}
    </SettingsLayout>
  );
}