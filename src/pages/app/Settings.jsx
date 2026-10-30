import React, { useEffect, useRef, useState } from "react";
import { AlertTriangle, Bell, CalendarClock, Download, KeyRound, Laptop, Lock, LogOut, ShieldCheck, Smartphone, Trash2, UserRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { NativeSelect } from "@/components/ui/native-select";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog";
import { ErrorNote, Pill, formatDate } from "@/components/site/bits";
import { PhraseCheckpoint } from "@/components/app/Phrase";
import { DeleteAccountForm } from "@/components/app/DeleteAccount";
import { callFn } from "@/lib/api";
import { useAuth } from "@/lib/AuthContext";
import { useSecure } from "@/lib/secure/SecureContext";
import { useChat } from "@/lib/secure/ChatContext";
import { askNotificationPermission, notificationPermission, notificationsSupported } from "@/lib/secure/alerts.js";
import { buildExport, downloadJson } from "@/lib/secure/exportData.js";
import { IDLE_CHOICES, MIN_PASSCODE_CHARS } from "@/lib/crypto/lock.js";
import { groupDigits, linkCode, safetyFingerprint } from "@/lib/crypto/identity.js";

function Section({ icon: Icon, title, children, description }) {
  return (
    <section className="card-cv p-5 sm:p-6">
      <div className="flex items-center gap-2">
        <Icon className="h-5 w-5 text-primary" aria-hidden="true" />
        <h2 className="text-xl font-semibold">{title}</h2>
      </div>
      {description && <p className="mt-1 text-sm text-muted-foreground">{description}</p>}
      <div className="mt-5">{children}</div>
    </section>
  );
}

function ProfileSection() {
  const { me, updateProfile } = useSecure();
  const [displayName, setDisplayName] = useState(me?.profile?.display_name || "");
  const [bio, setBio] = useState(me?.profile?.bio || "");
  const [state, setState] = useState({ busy: false, msg: "", error: "" });
  const save = async (e) => {
    e.preventDefault();
    setState({ busy: true, msg: "", error: "" });
    try {
      await updateProfile({ display_name: displayName, bio });
      setState({ busy: false, msg: "Saved.", error: "" });
    } catch (err) {
      setState({ busy: false, msg: "", error: err.message });
    }
  };
  return (
    <Section icon={UserRound} title="Profile" description="Visible to people who look up your exact username or share a conversation with you.">
      <form onSubmit={save} className="space-y-4">
        <div>
          <p className="text-sm text-muted-foreground">Username</p>
          <p className="font-medium">@{me?.profile?.username}</p>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="dn">Display name</Label>
          <Input id="dn" value={displayName} onChange={(e) => setDisplayName(e.target.value)} maxLength={50} />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="bio">About you</Label>
          <Textarea id="bio" value={bio} onChange={(e) => setBio(e.target.value)} maxLength={280} rows={3} />
        </div>
        <ErrorNote>{state.error}</ErrorNote>
        <div className="flex items-center gap-3">
          <Button type="submit" disabled={state.busy}>{state.busy ? "Saving…" : "Save"}</Button>
          {state.msg && <span className="text-sm text-primary">{state.msg}</span>}
        </div>
      </form>
    </Section>
  );
}

/**
 * A browser asking to join. Its code covers its keys and your account's key history, so it
 * only matches the new screen if nobody swapped either. Ticking the box freezes exactly the
 * keys you compared, and approval uses those, whatever the server shows afterwards.
 */
function PendingDevice({ d }) {
  const { userId, chainDigest, approveDevice, denyDevice } = useSecure();
  const [compared, setCompared] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const code = chainDigest ? linkCode({ userId, deviceId: d.device_id, signPub: d.sign_pub, boxPub: d.box_pub, accountDigest: chainDigest }) : null;
  const match = Boolean(compared);
  const act = async (fn) => {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  };
  return (
    <li className="rounded-lg border-2 border-primary/50 bg-accent/30 p-4">
      <p className="font-semibold">{d.label} wants to join</p>
      <p className="mt-1 text-sm text-muted-foreground">Only approve if this code is exactly the one on the new device's screen.</p>
      <p className="mono mt-3 rounded-lg bg-card px-3 py-3 text-center text-xl tracking-wider">{code ? groupDigits(code, 4) : "…"}</p>
      <label className="mt-3 flex items-center gap-2 text-sm">
        <Checkbox
          checked={match}
          disabled={!code}
          onCheckedChange={(v) => setCompared(v ? { device_id: d.device_id, sign_pub: d.sign_pub, box_pub: d.box_pub, label: d.label } : null)}
        />{" "}
        The codes match, and this is my device
      </label>
      <ErrorNote>{error}</ErrorNote>
      <div className="mt-3 flex gap-2">
        <Button size="sm" disabled={!match || busy} onClick={() => act(() => approveDevice(compared))}>{busy ? "Working…" : "Approve"}</Button>
        <Button size="sm" variant="outline" disabled={busy} onClick={() => act(() => denyDevice(d.device_id))}>Deny</Button>
      </div>
    </li>
  );
}

function DevicesSection() {
  const { status, chain, device, removeDevice, refresh } = useSecure();
  const [target, setTarget] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [showHistory, setShowHistory] = useState(false);

  // A new device asking to join shows up here without a reload. Only while the page is in view:
  // every check is a handful of queries against the app's per-minute allowance.
  useEffect(() => {
    const t = setInterval(() => {
      if (document.visibilityState === "visible") refresh({ silent: true });
    }, 20_000);
    return () => clearInterval(t);
  }, [refresh]);

  const devices = status?.devices || [];
  const pending = devices.filter((d) => d.status === "pending");
  const active = devices.filter((d) => d.status === "active");
  const history = devices.filter((d) => d.status === "revoked" || d.status === "expired");

  const confirmRemove = async () => {
    setBusy(true);
    setError("");
    try {
      await removeDevice(target.device_id);
      setTarget(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Section icon={Laptop} title="Devices" description="Every device here holds your keys. Remove any you don't recognise; your keys are rotated so it can't read anything new.">
      {/* Keyed by the keys too: if they change, the box has to be ticked again. */}
      {pending.length > 0 && <ul className="mb-5 space-y-3">{pending.map((d) => <PendingDevice key={`${d.device_id}:${d.sign_pub}:${d.box_pub}`} d={d} />)}</ul>}
      <ul className="divide-y divide-border">
        {active.map((d) => {
          const mine = d.device_id === device?.device_id;
          // Certificates are renewed at every key change; one left behind belongs to a device that was removed then.
          const stale = chain && d.cert_key_version !== chain.latest.version;
          return (
            <li key={d.device_id} className="flex items-center gap-3 py-3">
              {/Android|iOS/.test(d.label) ? <Smartphone className="h-5 w-5 text-muted-foreground" aria-hidden="true" /> : <Laptop className="h-5 w-5 text-muted-foreground" aria-hidden="true" />}
              <div className="min-w-0 flex-1">
                <p className="font-medium">
                  {d.label} {mine && <Pill tone="accent">This browser</Pill>} {stale && !mine && <Pill tone="warn">Not certified for your current keys</Pill>}
                </p>
                <p className="text-xs text-muted-foreground">
                  Added {formatDate(d.approved_at || d.created_date)}
                  {d.last_seen_at && !mine ? ` · last seen ${formatDate(d.last_seen_at)}` : ""}
                  {d.keys_waiting ? " · waiting to pick up new keys" : ""}
                  {stale && !mine ? " · it won't be sent new keys; remove it and set it up again" : ""}
                </p>
              </div>
              <Button size="sm" variant="ghost" className="text-destructive" onClick={() => setTarget(d)}>Remove</Button>
            </li>
          );
        })}
      </ul>
      {history.length > 0 && (
        <div className="mt-3">
          <button type="button" className="text-sm text-muted-foreground underline-offset-2 hover:underline" onClick={() => setShowHistory((v) => !v)} aria-expanded={showHistory}>
            {showHistory ? "Hide" : "Show"} removed devices ({history.length})
          </button>
          {showHistory && (
            <ul className="mt-2 space-y-1 text-sm text-muted-foreground">
              {history.map((d) => <li key={d.device_id}>{d.label} · {d.revoked_reason || d.status} {formatDate(d.revoked_at || d.created_date)}</li>)}
            </ul>
          )}
        </div>
      )}
      <ErrorNote>{error}</ErrorNote>
      <AlertDialog open={Boolean(target)} onOpenChange={(v) => !v && setTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove {target?.label}?</AlertDialogTitle>
            <AlertDialogDescription>
              {target?.device_id === device?.device_id
                ? "This browser's keys will be deleted and you'll be signed out of encryption here. You can set it up again later."
                : "It won't be able to send messages, and your keys will be rotated so it can't read anything new. Messages it already has stay on it."}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={(e) => { e.preventDefault(); confirmRemove(); }} disabled={busy} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
              {busy ? "Removing…" : "Remove"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Section>
  );
}

function RecoverySection() {
  const { beginPhraseChange, finishPhraseChange, cancelPending, userId, chainDigest } = useSecure();
  const [phrase, setPhrase] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);
  const fingerprint = chainDigest ? groupDigits(safetyFingerprint(userId, chainDigest), 5) : "";

  if (phrase) {
    return (
      <Section icon={KeyRound} title="Your new recovery phrase">
        <PhraseCheckpoint
          phrase={phrase}
          confirmLabel="Replace my old phrase"
          busy={busy}
          error={error}
          onConfirmed={async () => {
            setBusy(true);
            setError("");
            try {
              await finishPhraseChange();
              setPhrase(null);
              setDone(true);
            } catch (err) {
              setError(err.message);
            } finally {
              setBusy(false);
            }
          }}
        />
        <Button variant="ghost" className="mt-3" onClick={() => { cancelPending(); setPhrase(null); }} disabled={busy}>Cancel</Button>
      </Section>
    );
  }

  return (
    <Section icon={KeyRound} title="Recovery phrase" description="Your 24 words unlock an encrypted backup of your keys. We don't have a copy.">
      <div className="space-y-4 text-sm">
        <p className="text-muted-foreground">
          If you think someone has seen your phrase, make a new one. The old phrase stops working immediately, and your keys are rotated.
        </p>
        {done && <p className="flex items-center gap-1.5 text-primary"><ShieldCheck className="h-4 w-4" aria-hidden="true" /> Done. Your old phrase no longer opens anything.</p>}
        <ErrorNote>{error}</ErrorNote>
        <Button
          variant="outline"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            setError("");
            setDone(false);
            try {
              setPhrase(await beginPhraseChange());
            } catch (err) {
              setError(err.message);
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "Preparing…" : "Make a new recovery phrase"}
        </Button>
        {fingerprint && (
          <div className="border-t border-border pt-4">
            <p className="text-muted-foreground">Your key fingerprint (half of every safety number you share):</p>
            <p className="mono mt-1 text-sm">{fingerprint}</p>
          </div>
        )}
      </div>
    </Section>
  );
}

function Toggle({ id, checked, onChange, disabled, children, hint }) {
  return (
    <div className="flex items-start gap-3">
      <Checkbox id={id} checked={checked} disabled={disabled} onCheckedChange={(v) => onChange(Boolean(v))} className="mt-0.5" />
      <div>
        <Label htmlFor={id} className="font-normal">{children}</Label>
        {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
      </div>
    </div>
  );
}

/** Notifications and an unread count, on this browser only. */
function AlertsSection() {
  const { alerts, updateAlerts } = useChat();
  const [permission, setPermission] = useState(notificationPermission());
  const [error, setError] = useState("");
  const supported = notificationsSupported();
  const change = async (changes) => {
    setError("");
    try {
      if (changes.notify) {
        const p = await askNotificationPermission();
        setPermission(p);
        if (p !== "granted") {
          setError(p === "denied" ? "Your browser is blocking notifications for this site. Allow them in the browser's site settings first." : "Notifications weren't allowed.");
          return;
        }
      }
      await updateAlerts(changes);
    } catch (err) {
      setError(err.message);
    }
  };
  return (
    <Section icon={Bell} title="Alerts on this browser" description="Off unless you turn them on. They're set for this browser only and never sent anywhere.">
      <div className="space-y-4 text-sm">
        <Toggle
          id="alert-notify"
          checked={alerts.notify && permission === "granted"}
          disabled={!supported}
          onChange={(v) => change({ notify: v })}
          hint={supported
            ? "Shown while Commonveil is open in a tab, when you're not already looking at that conversation. A notification says \"New message\" and never what it says. There are no push notifications: nothing is sent to your browser's maker or anyone else."
            : "This browser doesn't support notifications from web pages."}
        >
          Notify me of new messages
        </Toggle>
        <Toggle
          id="alert-sender"
          checked={alerts.showSender}
          disabled={!alerts.notify}
          onChange={(v) => change({ showSender: v })}
          hint="Notifications can show on a locked screen, so this is off unless you want it."
        >
          Say who it's from
        </Toggle>
        <Toggle id="alert-title" checked={alerts.titleCount} onChange={(v) => change({ titleCount: v })} hint={'For example "(2) Commonveil", so you can see it from another tab.'}>
          Show the number of unread conversations in the tab's title
        </Toggle>
        <ErrorNote>{error}</ErrorNote>
      </div>
    </Section>
  );
}

/** A passcode that encrypts this browser's keys, and locks after a while without use. */
function LockSection() {
  const { lockInfo, setPasscode, setLockIdle, removePasscode, lockNow } = useSecure();
  const [editing, setEditing] = useState(false);
  const [first, setFirst] = useState("");
  const [second, setSecond] = useState("");
  const [idle, setIdle] = useState(lockInfo?.idle_minutes || 15);
  const [state, setState] = useState({ busy: false, msg: "", error: "" });
  const run = async (fn, msg) => {
    setState({ busy: true, msg: "", error: "" });
    try {
      await fn();
      setState({ busy: false, msg, error: "" });
    } catch (err) {
      setState({ busy: false, msg: "", error: err.message });
    }
  };
  const save = (e) => {
    e.preventDefault();
    if (first !== second) {
      setState({ busy: false, msg: "", error: "The two passcodes don't match." });
      return;
    }
    run(async () => {
      await setPasscode(first, idle);
      setFirst("");
      setSecond("");
      setEditing(false);
    }, lockInfo ? "Passcode changed." : "This browser is now locked with your passcode.");
  };
  return (
    <Section icon={Lock} title="Passcode lock" description="Encrypts this browser's copy of your keys with a passcode, and locks after a while without use.">
      <div className="space-y-4 text-sm">
        <p className="text-muted-foreground">
          While it's locked, your keys aren't in memory and your conversations aren't shown. It's for this browser only: set one on each
          device you want locked. There's no way to recover a forgotten passcode; you'd set this browser up again from another device or
          with your recovery phrase. Someone who copies this browser's files can still try guesses, so a longer passcode is stronger.
        </p>
        {lockInfo && !editing && (
          <div className="space-y-3">
            <p className="flex items-center gap-1.5 text-primary"><ShieldCheck className="h-4 w-4" aria-hidden="true" /> On.</p>
            <div className="max-w-xs space-y-1.5">
              <Label htmlFor="lock-idle">Lock after</Label>
              <NativeSelect
                id="lock-idle"
                value={String(lockInfo.idle_minutes)}
                disabled={state.busy}
                onChange={(e) => {
                  const minutes = Number(e.target.value);
                  setIdle(minutes);
                  run(() => setLockIdle(minutes), "Saved.");
                }}
              >
                {IDLE_CHOICES.map((m) => <option key={m} value={String(m)}>{m === 60 ? "1 hour" : `${m} minutes`} without use</option>)}
              </NativeSelect>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" onClick={lockNow}>Lock now</Button>
              <Button variant="outline" onClick={() => { setEditing(true); setState({ busy: false, msg: "", error: "" }); }}>Change passcode</Button>
              <Button variant="ghost" className="text-destructive" disabled={state.busy} onClick={() => run(removePasscode, "The lock is off. Your keys are stored on this browser without it.")}>
                Turn off
              </Button>
            </div>
          </div>
        )}
        {(!lockInfo || editing) && (
          <form onSubmit={save} className="max-w-sm space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="passcode-new">{lockInfo ? "New passcode" : "Passcode"}</Label>
              <Input id="passcode-new" type="password" autoComplete="new-password" value={first} onChange={(e) => setFirst(e.target.value)} />
              <p className="text-xs text-muted-foreground">At least {MIN_PASSCODE_CHARS} characters. A few unrelated words make a strong one.</p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="passcode-again">Type it again</Label>
              <Input id="passcode-again" type="password" autoComplete="new-password" value={second} onChange={(e) => setSecond(e.target.value)} />
            </div>
            {!lockInfo && (
              <div className="space-y-1.5">
                <Label htmlFor="lock-idle-new">Lock after</Label>
                <NativeSelect id="lock-idle-new" value={String(idle)} onChange={(e) => setIdle(Number(e.target.value))}>
                  {IDLE_CHOICES.map((m) => <option key={m} value={String(m)}>{m === 60 ? "1 hour" : `${m} minutes`} without use</option>)}
                </NativeSelect>
              </div>
            )}
            <div className="flex gap-2">
              <Button type="submit" disabled={state.busy || first.length < MIN_PASSCODE_CHARS || !second}>{state.busy ? "Encrypting…" : lockInfo ? "Change passcode" : "Turn on"}</Button>
              {editing && <Button type="button" variant="ghost" onClick={() => { setEditing(false); setFirst(""); setSecond(""); }}>Cancel</Button>}
            </div>
          </form>
        )}
        <ErrorNote>{state.error}</ErrorNote>
        {state.msg && <p className="text-primary">{state.msg}</p>}
      </div>
    </Section>
  );
}

/** A copy of everything the service holds about you, decrypted here and saved as a file. */
function DataSection() {
  const secure = useSecure();
  const { user } = useAuth();
  const [state, setState] = useState({ busy: false, progress: "", error: "", done: false });
  // If the page goes away (say it locks) before the file is ready, it isn't saved.
  const alive = useRef(true);
  useEffect(() => () => {
    alive.current = false;
  }, []);
  const start = async () => {
    setState({ busy: true, progress: "Starting", error: "", done: false });
    try {
      const data = await buildExport(secure, { email: user?.email || null, onProgress: (progress) => alive.current && setState((s) => ({ ...s, progress })) });
      if (!alive.current) return;
      downloadJson(data, `commonveil-data-${new Date().toISOString().slice(0, 10)}.json`);
      setState({ busy: false, progress: "", error: "", done: true });
    } catch (err) {
      if (alive.current) setState({ busy: false, progress: "", error: err.message, done: false });
    }
  };
  return (
    <Section icon={Download} title="Download your data" description="Everything Commonveil holds about your account, in one file.">
      <div className="space-y-3 text-sm">
        <p className="text-muted-foreground">
          Your profile, devices, conversations and every message you can read, decrypted here in your browser and saved as a JSON file.
          Nothing is sent anywhere to make it, and your keys aren't in it. The file holds your messages in readable form, so keep it
          somewhere safe.
        </p>
        <ErrorNote>{state.error}</ErrorNote>
        {state.done && <p className="text-primary">Done. Check your downloads.</p>}
        <Button variant="outline" disabled={state.busy} onClick={start}>
          <Download className="mr-2 h-4 w-4" aria-hidden="true" /> {state.busy ? `Working: ${state.progress}…` : "Download my data"}
        </Button>
      </div>
    </Section>
  );
}

/** Opt in to having the account deleted after a stretch without use. */
function AutoDeleteSection() {
  const { me, setAutoDelete, isAdmin } = useSecure();
  const current = me?.auto_delete || { days: 0 };
  const [state, setState] = useState({ busy: false, msg: "", error: "" });
  if (isAdmin) return null;
  const change = async (days) => {
    setState({ busy: true, msg: "", error: "" });
    try {
      await setAutoDelete(days);
      setState({ busy: false, msg: days ? "Saved." : "Off. The day you last used Commonveil is no longer kept.", error: "" });
    } catch (err) {
      setState({ busy: false, msg: "", error: err.message });
    }
  };
  return (
    <Section icon={CalendarClock} title="Delete my account if I stop using it" description="Off unless you turn it on.">
      <div className="space-y-3 text-sm">
        <div className="max-w-xs space-y-1.5">
          <Label htmlFor="auto-delete">Delete my account after</Label>
          <NativeSelect id="auto-delete" value={String(current.days || 0)} disabled={state.busy} onChange={(e) => change(Number(e.target.value))}>
            <option value="0">Never (off)</option>
            <option value="183">6 months without use</option>
            <option value="365">1 year without use</option>
          </NativeSelect>
        </div>
        <p className="text-muted-foreground">
          While this is on, the server keeps the date (not the time) you last opened Commonveil, and nothing else about your use. A week
          before the deletion, your sign-in email address is sent a warning; opening Commonveil before then keeps your account. Deletion
          removes everything, exactly as if you'd deleted the account yourself. Turning this off forgets the date.
        </p>
        {current.days > 0 && current.last_active_on && <p>Last used: {formatDate(current.last_active_on)}.</p>}
        <ErrorNote>{state.error}</ErrorNote>
        {state.msg && <p className="text-primary">{state.msg}</p>}
      </div>
    </Section>
  );
}

function BlockedSection() {
  const [blocked, setBlocked] = useState(null);
  const load = () => callFn("safety", { action: "list_blocks" }).then((r) => setBlocked(r.blocked)).catch(() => setBlocked([]));
  useEffect(() => {
    load();
  }, []);
  return (
    <Section icon={AlertTriangle} title="Blocked people">
      {!blocked ? <p className="text-sm text-muted-foreground">Loading…</p> : blocked.length === 0 ? (
        <p className="text-sm text-muted-foreground">You haven't blocked anyone.</p>
      ) : (
        <ul className="divide-y divide-border">
          {blocked.map((p) => (
            <li key={p.user_id} className="flex items-center justify-between py-2">
              <span>{p.display_name || p.username} <span className="text-sm text-muted-foreground">@{p.username}</span></span>
              <Button size="sm" variant="ghost" onClick={async () => { await callFn("safety", { action: "unblock", user_id: p.user_id }); load(); }}>Unblock</Button>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

function SignOutSection() {
  const { signOut } = useSecure();
  const [busy, setBusy] = useState(false);
  return (
    <Section icon={LogOut} title="Sign out">
      <div className="space-y-3 text-sm">
        <p className="text-muted-foreground">
          Signing out keeps this browser's keys so you can sign back in quickly. On a shared or borrowed computer, remove this device as you
          sign out.
        </p>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" disabled={busy} onClick={() => { setBusy(true); signOut(); }}>Sign out</Button>
          <Button variant="destructive" disabled={busy} onClick={async () => { setBusy(true); await signOut({ removeThisDevice: true }); }}>
            Sign out and remove this device
          </Button>
        </div>
      </div>
    </Section>
  );
}

function DeleteSection() {
  const { isAdmin } = useSecure();
  return (
    <Section icon={Trash2} title="Delete your account">
      {isAdmin ? (
        <p className="text-sm text-muted-foreground">Staff accounts can't be deleted here. The app owner removes staff access in Base44.</p>
      ) : (
        <DeleteAccountForm />
      )}
    </Section>
  );
}

export default function Settings() {
  return (
    <div className="mx-auto w-full max-w-3xl space-y-5 overflow-y-auto px-4 py-8">
      <h1 className="text-3xl font-semibold">Settings</h1>
      <DevicesSection />
      <ProfileSection />
      <RecoverySection />
      <LockSection />
      <AlertsSection />
      <BlockedSection />
      <DataSection />
      <SignOutSection />
      <AutoDeleteSection />
      <DeleteSection />
    </div>
  );
}
