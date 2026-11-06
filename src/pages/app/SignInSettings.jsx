import React, { useCallback, useEffect, useState } from "react";
import { Copy, Fingerprint, KeyRound, Laptop, Loader2, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { ErrorNote, formatDate } from "@/components/site/bits";
import { SettingsGroup, SettingsTitle } from "@/components/settings/SettingsLayout";
import { useSecure } from "@/lib/secure/SecureContext";
import { addPasskey, answerApproval, forgetDevice, identityAction, identityStatus, passkeysSupported, pendingApprovals, setOwnerKey } from "@/lib/identity/client";
import { clearSession } from "@/lib/identity/session";
import { looksLikePrivateKey, phraseFromPrivateKey, privateKeyFromPhrase } from "@/lib/crypto/owner";

const HOW = { registration: "when you made your account", password: "with your password", passkey: "with a passkey", key: "with your recovery phrase or private key", device: "from another device", email: "with an email code", session: "already signed in" };

/** How you sign in on a self-hosted site, and how you'd get back in (docs/IDENTITY.md). */
export default function SignInSettings() {
  const { me } = useSecure();
  const [state, setState] = useState(null);
  const [approvals, setApprovals] = useState([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [s, a] = await Promise.all([identityStatus(), pendingApprovals()]);
      setState(s);
      setApprovals(a.approvals || []);
      setError("");
    } catch (err) {
      setError(err.message);
    }
  }, []);
  useEffect(() => {
    refresh();
  }, [refresh]);

  const run = async (key, fn) => {
    setBusy(key);
    setError("");
    try {
      await fn();
      await refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  };

  if (!state) return error ? <ErrorNote>{error}</ErrorNote> : <p className="text-sm text-muted-foreground">Loading…</p>;

  return (
    <>
      <SettingsTitle intro="Your username and password sign you in. Passkeys make it quicker, and your recovery phrase is how you get back in." help="sign-in-and-recovery">
        Sign-in and recovery
      </SettingsTitle>
      <ErrorNote>{error}</ErrorNote>

      {state.email_retiring && (
        <div className="mb-6 rounded-xl border border-primary/40 bg-primary/5 p-4 text-sm" role="status">
          <p className="font-medium">Email sign-in is going away soon</p>
          <p className="mt-1 text-muted-foreground">
            You signed in with <span className="font-medium text-foreground">{state.email}</span>. From now on your account signs in with your username, <span className="font-medium text-foreground">@{me?.profile?.username}</span>, and a password. To get back in, you'll use your recovery phrase, and optionally a passkey or another signed-in device. Set a password and confirm your phrase below, then remove your email.
          </p>
          <Button className="mt-3" size="sm" variant="outline" disabled={!state.owner || !state.has_password || Boolean(busy)} onClick={() => run("email", () => identityAction("remove_email"))}>
            Remove my email now
          </Button>
          {(!state.owner || !state.has_password) && <p className="mt-2 text-xs text-muted-foreground">{!state.has_password ? "Set a password first." : "Confirm your recovery phrase first."}</p>}
        </div>
      )}

      {approvals.length > 0 && (
        <SettingsGroup title="Waiting for your approval" description="Someone signed in with your password on a new device. Approve it only if it's you and the code matches what that device shows.">
          <ul className="space-y-2">
            {approvals.map((a) => (
              <li key={a.id} className="flex flex-wrap items-center gap-3 rounded-lg border p-3 text-sm">
                <div className="min-w-0 flex-1">
                  <p className="font-medium">{a.device_name}</p>
                  <p className="font-mono text-lg tracking-widest">{a.code.slice(0, 3)} {a.code.slice(3)}</p>
                </div>
                <Button size="sm" disabled={Boolean(busy)} onClick={() => run(`ap:${a.id}`, () => answerApproval(a.id, true))}>Approve</Button>
                <Button size="sm" variant="outline" disabled={Boolean(busy)} onClick={() => run(`ap:${a.id}`, () => answerApproval(a.id, false))}>It wasn't me</Button>
              </li>
            ))}
          </ul>
        </SettingsGroup>
      )}

      <SettingsGroup title="Passkeys" description="Sign in without typing your password, and confirm new devices. A passkey on this device stays here; one in a password manager follows you to your other devices.">
        {state.passkeys.length === 0 ? (
          <p className="text-sm text-muted-foreground">No passkeys yet.</p>
        ) : (
          <ul className="divide-y rounded-lg border">
            {state.passkeys.map((p) => (
              <li key={p.id} className="flex items-center gap-3 p-3 text-sm">
                <Fingerprint className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
                <div className="min-w-0 flex-1">
                  <p className="font-medium">{p.name}</p>
                  <p className="text-xs text-muted-foreground">{p.synced ? "Synced by a password manager or account" : "This device only"}. Added {formatDate(p.created_at)}{p.last_used ? `, last used ${formatDate(p.last_used)}` : ""}</p>
                </div>
                <Button size="sm" variant="ghost" aria-label={`Remove ${p.name}`} disabled={Boolean(busy)} onClick={() => run(`pk:${p.id}`, () => identityAction("remove_passkey", { id: p.id }))}>
                  <Trash2 className="h-4 w-4" />
                </Button>
              </li>
            ))}
          </ul>
        )}
        {passkeysSupported() ? (
          <div className="mt-3 flex flex-wrap gap-2">
            <Button size="sm" disabled={Boolean(busy)} onClick={() => run("add-device", () => addPasskey("device"))}>
              {busy === "add-device" && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}Add a passkey on this device
            </Button>
            <Button size="sm" variant="outline" disabled={Boolean(busy)} onClick={() => run("add-synced", () => addPasskey("synced"))}>
              {busy === "add-synced" && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}Add one to a password manager
            </Button>
          </div>
        ) : (
          <p className="mt-3 text-sm text-muted-foreground">This browser doesn't support passkeys.</p>
        )}
      </SettingsGroup>

      <RecoverySection owner={state.owner} ownerSetAt={state.owner_set_at} onSaved={refresh} />

      <SettingsGroup title="Signed-in devices" description="Every browser that has signed in to your account. Disconnect one and it's signed out, and has to be confirmed again to come back.">
        <ul className="divide-y rounded-lg border">
          {state.devices.map((d) => (
            <li key={d.id} className="flex flex-wrap items-center gap-3 p-3 text-sm">
              <Laptop className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
              <div className="min-w-0 flex-1">
                <p className="font-medium">{d.name}{d.current && <span className="ml-2 text-xs font-normal text-primary">This device</span>}</p>
                <p className="text-xs text-muted-foreground">Added {formatDate(d.created_at)} {HOW[d.confirmed_by] || ""}. Last active {formatDate(d.last_seen)}.</p>
              </div>
              <Button
                size="sm"
                variant="outline"
                disabled={Boolean(busy)}
                onClick={() =>
                  run(`dev:${d.id}`, async () => {
                    const r = await identityAction("disconnect_device", { id: d.id });
                    if (r.signed_out) {
                      forgetDevice();
                      clearSession();
                      window.location.href = "/login";
                    }
                  })
                }
              >
                {d.current ? "Disconnect and sign out" : "Disconnect"}
              </Button>
            </li>
          ))}
        </ul>
        <p className="mt-2 text-xs text-muted-foreground">These are sign-ins. The devices that hold your encryption keys are under Devices and keys.</p>
      </SettingsGroup>

      <PasswordSection hasPassword={state.has_password} username={me?.profile?.username} onSaved={refresh} />
    </>
  );
}

function RecoverySection({ owner, ownerSetAt, onSaved }) {
  const [secret, setSecret] = useState("");
  const [shown, setShown] = useState("");
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  const confirm = async () => {
    setBusy(true);
    setError("");
    setNote("");
    try {
      await setOwnerKey(secret);
      setSecret("");
      setNote("Saved. You can use this phrase or private key to confirm new devices and get back in.");
      await onSaved();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const convert = () => {
    setError("");
    try {
      setShown(looksLikePrivateKey(secret) ? phraseFromPrivateKey(secret) : privateKeyFromPhrase(secret));
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <SettingsGroup
      title="Recovery phrase and private key"
      description="Your 24-word recovery phrase and your private key are the same secret written two ways: keep whichever is easier to store safely. Either one proves the account is yours. This site only ever sees a signature made with it."
    >
      <p className="mb-3 flex items-center gap-2 text-sm">
        <KeyRound className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
        {owner ? `Set up${ownerSetAt ? ` ${formatDate(ownerSetAt)}` : ""}. You can get back in with it.` : "Not confirmed yet. Enter your recovery phrase so you can always get back in."}
      </p>
      <div className="space-y-1.5">
        <Label htmlFor="owner-secret">Recovery phrase or private key</Label>
        <Textarea id="owner-secret" rows={3} value={secret} onChange={(e) => { setSecret(e.target.value); setShown(""); }} autoComplete="off" autoCapitalize="none" spellCheck={false} className="font-mono text-sm" />
      </div>
      <ErrorNote>{error}</ErrorNote>
      {note && <p className="mt-2 text-sm text-primary" role="status">{note}</p>}
      <div className="mt-3 flex flex-wrap gap-2">
        <Button size="sm" disabled={busy || !secret.trim()} onClick={confirm}>{owner ? "Use this one instead" : "Confirm it's mine"}</Button>
        <Button size="sm" variant="outline" disabled={!secret.trim()} onClick={convert}>{looksLikePrivateKey(secret) ? "Show it as a phrase" : "Show it as a private key"}</Button>
      </div>
      {shown && (
        <div className="mt-3 rounded-lg border bg-muted/40 p-3">
          <p className="break-all font-mono text-sm">{shown}</p>
          <Button size="sm" variant="ghost" className="mt-2" onClick={() => navigator.clipboard?.writeText(shown).catch(() => {})}>
            <Copy className="mr-1 h-4 w-4" aria-hidden="true" /> Copy
          </Button>
          <p className="mt-1 text-xs text-muted-foreground">Keep it offline, like on paper or in a password manager. Anyone with it can take over your account.</p>
        </div>
      )}
      <p className="mt-3 text-xs text-muted-foreground">To make a new phrase, go to Devices and keys. The new one is used here automatically.</p>
    </SettingsGroup>
  );
}

function PasswordSection({ hasPassword, username, onSaved }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <SettingsGroup title="Password" description={hasPassword ? undefined : `Your account doesn't have a password yet. Set one to sign in as @${username || "you"}.`}>
      <form
        className="max-w-sm space-y-3"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError("");
          setMsg("");
          try {
            if (hasPassword) await identityAction("change_password", { password: current, new_password: next });
            else await identityAction("set_password", { new_password: next });
            setCurrent("");
            setNext("");
            setMsg(hasPassword ? "Password changed." : "Password set. You can sign in with your username now.");
            await onSaved?.();
          } catch (err) {
            setError(err.message);
          } finally {
            setBusy(false);
          }
        }}
      >
        {hasPassword && (
          <div className="space-y-1.5">
            <Label htmlFor="pw-current">Current password</Label>
            <Input id="pw-current" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
          </div>
        )}
        <div className="space-y-1.5">
          <Label htmlFor="pw-new">New password</Label>
          <Input id="pw-new" type="password" autoComplete="new-password" minLength={10} value={next} onChange={(e) => setNext(e.target.value)} required />
        </div>
        <ErrorNote>{error}</ErrorNote>
        {msg && <p className="text-sm text-primary" role="status">{msg}</p>}
        <Button type="submit" size="sm" disabled={busy}>{hasPassword ? "Change password" : "Set password"}</Button>
      </form>
    </SettingsGroup>
  );
}
