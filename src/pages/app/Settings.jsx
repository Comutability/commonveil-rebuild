import React, { useEffect, useState } from "react";
import { AlertTriangle, KeyRound, Laptop, LogOut, ShieldCheck, Smartphone, UserRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog";
import { ErrorNote, Pill, formatDate } from "@/components/site/bits";
import { PhraseCheckpoint } from "@/components/app/Phrase";
import { callFn } from "@/lib/api";
import { useSecure } from "@/lib/secure/SecureContext";
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

function PendingDevice({ d }) {
  const { userId, approveDevice, denyDevice } = useSecure();
  const [match, setMatch] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const code = linkCode({ userId, deviceId: d.device_id, signPub: d.sign_pub, boxPub: d.box_pub });
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
      <p className="mono mt-3 rounded-lg bg-card px-3 py-3 text-center text-xl tracking-wider">{groupDigits(code, 4)}</p>
      <label className="mt-3 flex items-center gap-2 text-sm">
        <Checkbox checked={match} onCheckedChange={(v) => setMatch(Boolean(v))} /> The codes match, and this is my device
      </label>
      <ErrorNote>{error}</ErrorNote>
      <div className="mt-3 flex gap-2">
        <Button size="sm" disabled={!match || busy} onClick={() => act(() => approveDevice(d))}>{busy ? "Working…" : "Approve"}</Button>
        <Button size="sm" variant="outline" disabled={busy} onClick={() => act(() => denyDevice(d.device_id))}>Deny</Button>
      </div>
    </li>
  );
}

function DevicesSection() {
  const { status, device, removeDevice, refresh } = useSecure();
  const [target, setTarget] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [showHistory, setShowHistory] = useState(false);

  useEffect(() => {
    const t = setInterval(() => refresh(), 15000);
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
      {pending.length > 0 && <ul className="mb-5 space-y-3">{pending.map((d) => <PendingDevice key={d.device_id} d={d} />)}</ul>}
      <ul className="divide-y divide-border">
        {active.map((d) => {
          const mine = d.device_id === device?.device_id;
          return (
            <li key={d.device_id} className="flex items-center gap-3 py-3">
              {/Android|iOS/.test(d.label) ? <Smartphone className="h-5 w-5 text-muted-foreground" aria-hidden="true" /> : <Laptop className="h-5 w-5 text-muted-foreground" aria-hidden="true" />}
              <div className="min-w-0 flex-1">
                <p className="font-medium">{d.label} {mine && <Pill tone="accent">This browser</Pill>}</p>
                <p className="text-xs text-muted-foreground">
                  Added {formatDate(d.approved_at || d.created_date)}
                  {d.last_seen_at && !mine ? ` · last seen ${formatDate(d.last_seen_at)}` : ""}
                  {d.keys_waiting ? " · waiting to pick up new keys" : ""}
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
  const { beginPhraseChange, finishPhraseChange, cancelPending, userId, chain } = useSecure();
  const [phrase, setPhrase] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);
  const fingerprint = chain ? groupDigits(safetyFingerprint(userId, chain.latest.sign_pub), 5) : "";

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

export default function Settings() {
  return (
    <div className="mx-auto w-full max-w-3xl space-y-5 overflow-y-auto px-4 py-8">
      <h1 className="text-3xl font-semibold">Settings</h1>
      <DevicesSection />
      <ProfileSection />
      <RecoverySection />
      <BlockedSection />
      <SignOutSection />
    </div>
  );
}
