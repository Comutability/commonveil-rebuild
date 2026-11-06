import React, { useEffect, useRef, useState } from "react";
import { Fingerprint, KeyRound, Loader2, Mail, MonitorSmartphone } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { confirmByEmail, confirmFromDevice, confirmWithKey, confirmWithPasskey, passkeysSupported } from "@/lib/identity/client";

const LABELS = {
  passkey: { icon: Fingerprint, label: "Passkey" },
  device: { icon: MonitorSmartphone, label: "Another device" },
  key: { icon: KeyRound, label: "Recovery phrase or private key" },
  email: { icon: Mail, label: "Email code" },
};

/**
 * Confirm a browser the site hasn't seen before, after the password was right. `verify` is what
 * the sign-in answered ({ id, methods, code, challenge, host }). Calls onDone once signed in.
 */
export default function ConfirmDevice({ verify, onDone, onCancel }) {
  const methods = verify.methods.filter((m) => m !== "passkey" || passkeysSupported());
  const [method, setMethod] = useState(methods[0]);
  const [secret, setSecret] = useState("");
  const [code, setCode] = useState("");
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const done = useRef(false);

  const finish = (r) => {
    if (r?.access_token && !done.current) {
      done.current = true;
      onDone();
    }
  };

  // Approval from another device: ask every few seconds until it's approved or turned down.
  useEffect(() => {
    if (method !== "device") return undefined;
    let live = true;
    const tick = async () => {
      try {
        const r = await confirmFromDevice(verify);
        if (live) finish(r);
      } catch (err) {
        if (live) setError(err.message);
        live = false;
      }
    };
    const t = setInterval(tick, 3000);
    tick();
    return () => {
      live = false;
      clearInterval(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [method, verify]);

  const run = async (fn) => {
    setBusy(true);
    setError("");
    try {
      finish(await fn());
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-5">
      <p className="text-sm text-muted-foreground">
        This browser hasn't signed in to your account before. Confirm it's you, and it won't be asked again. You can disconnect it later in Settings.
      </p>

      {methods.length > 1 && (
        <div role="tablist" aria-label="How to confirm" className="grid gap-2 sm:grid-cols-2">
          {methods.map((m) => {
            const { icon: Icon, label } = LABELS[m];
            return (
              <button
                key={m}
                type="button"
                role="tab"
                aria-selected={method === m}
                onClick={() => {
                  setMethod(m);
                  setError("");
                }}
                className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-left text-sm transition-colors ${method === m ? "border-primary bg-primary/10 text-foreground" : "border-border text-muted-foreground hover:bg-muted"}`}
              >
                <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
                {label}
              </button>
            );
          })}
        </div>
      )}

      {error && <div className="rounded-lg bg-destructive/10 p-3 text-sm text-destructive" role="alert">{error}</div>}

      {method === "passkey" && (
        <Button className="h-12 w-full" disabled={busy} onClick={() => run(() => confirmWithPasskey(verify))}>
          {busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Fingerprint className="mr-2 h-4 w-4" aria-hidden="true" />}
          Use a passkey
        </Button>
      )}

      {method === "device" && (
        <div className="space-y-3 rounded-lg border p-4">
          <p className="text-sm">On a device where you're already signed in, open Commonveil and approve this sign-in. Check it shows this code:</p>
          <p className="text-center font-mono text-3xl tracking-[0.3em]" aria-label={`Code ${verify.code.split("").join(" ")}`}>{verify.code.slice(0, 3)} {verify.code.slice(3)}</p>
          <p className="flex items-center gap-2 text-xs text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> Waiting for approval…</p>
        </div>
      )}

      {method === "key" && (
        <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); run(() => confirmWithKey(verify, secret)); }}>
          <div className="space-y-1.5">
            <Label htmlFor="confirm-secret">Your 24-word recovery phrase, or your private key</Label>
            <Textarea id="confirm-secret" value={secret} onChange={(e) => setSecret(e.target.value)} rows={3} autoComplete="off" autoCapitalize="none" spellCheck={false} className="font-mono text-sm" />
            <p className="text-xs text-muted-foreground">It stays in this browser. Only a signature made with it is sent.</p>
          </div>
          <Button type="submit" className="h-12 w-full" disabled={busy || !secret.trim()}>{busy ? "Checking…" : "Confirm"}</Button>
        </form>
      )}

      {method === "email" && (
        <div className="space-y-3">
          {!sent ? (
            <Button className="h-12 w-full" disabled={busy} onClick={() => run(async () => { await confirmByEmail(verify); setSent(true); })}>Email me a code</Button>
          ) : (
            <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); run(() => confirmByEmail(verify, code)); }}>
              <Label htmlFor="confirm-code">The 6-digit code from your email</Label>
              <Input id="confirm-code" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" className="h-12 text-center font-mono text-lg tracking-widest" />
              <Button type="submit" className="h-12 w-full" disabled={busy || code.length < 6}>Confirm</Button>
            </form>
          )}
          <p className="text-xs text-muted-foreground">Email sign-in is going away. Once you're in, set up a passkey and keep your recovery phrase.</p>
        </div>
      )}

      <button type="button" onClick={onCancel} className="text-sm text-muted-foreground hover:underline">Use a different account</button>
    </div>
  );
}
