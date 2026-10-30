import React, { useEffect, useRef, useState } from "react";
import { Lock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ErrorNote } from "@/components/site/bits";
import { useSecure } from "@/lib/secure/SecureContext";

/** After a few wrong tries, wait a little longer before each next one. */
const waitAfter = (failures) => (failures < 3 ? 0 : Math.min(60, 2 ** (failures - 2)) * 1000);

export default function LockScreen() {
  const { unlock, forgetLockedBrowser } = useSecure();
  const [passcode, setPasscode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [failures, setFailures] = useState(0);
  const [blockedUntil, setBlockedUntil] = useState(0);
  const [, setTick] = useState(0);
  const [forgot, setForgot] = useState(false);
  const [confirmWord, setConfirmWord] = useState("");
  const input = useRef(null);

  useEffect(() => {
    input.current?.focus();
  }, []);

  useEffect(() => {
    if (!blockedUntil) return undefined;
    const t = setInterval(() => {
      setTick((n) => n + 1);
      if (Date.now() >= blockedUntil) setBlockedUntil(0);
    }, 500);
    return () => clearInterval(t);
  }, [blockedUntil]);

  const waiting = blockedUntil > Date.now() ? Math.ceil((blockedUntil - Date.now()) / 1000) : 0;

  const submit = async (e) => {
    e.preventDefault();
    if (!passcode || busy || waiting) return;
    setBusy(true);
    setError("");
    try {
      await unlock(passcode);
    } catch (err) {
      const next = failures + 1;
      setFailures(next);
      setBlockedUntil(Date.now() + waitAfter(next));
      setError(err?.code === "WRONG_PASSCODE" ? "That passcode isn't right." : err?.message || "Couldn't unlock.");
      setPasscode("");
      setBusy(false);
      input.current?.focus();
    }
  };

  return (
    <div className="mx-auto w-full max-w-md px-4 py-16">
      <div className="card-cv p-6 sm:p-8">
        <Lock className="h-8 w-8 text-primary" aria-hidden="true" />
        <h1 className="mt-4 text-2xl font-semibold">Commonveil is locked</h1>
        <p className="mt-2 text-sm text-muted-foreground">Your keys on this browser are encrypted with your passcode. Enter it to open your messages.</p>
        <form onSubmit={submit} className="mt-6 space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="passcode">Passcode</Label>
            <Input
              id="passcode"
              ref={input}
              type="password"
              autoComplete="current-password"
              value={passcode}
              onChange={(e) => setPasscode(e.target.value)}
              disabled={busy}
            />
          </div>
          <ErrorNote>{error}</ErrorNote>
          {waiting > 0 && <p className="text-sm text-muted-foreground">Try again in {waiting} second{waiting === 1 ? "" : "s"}.</p>}
          <Button type="submit" className="w-full" disabled={!passcode || busy || waiting > 0}>{busy ? "Unlocking…" : "Unlock"}</Button>
        </form>

        <div className="mt-6 border-t border-border pt-4 text-sm">
          {!forgot ? (
            <button type="button" className="text-muted-foreground underline-offset-2 hover:underline" onClick={() => setForgot(true)}>
              Forgot your passcode?
            </button>
          ) : (
            <div className="space-y-3">
              <p>
                There's no way to recover a passcode: we never had it. You can remove this browser from your account and wipe its keys, then
                set it up again by linking it from another of your devices or with your recovery phrase. Your account and messages stay
                as they are on your other devices.
              </p>
              <div className="space-y-1.5">
                <Label htmlFor="confirm-forget">Type REMOVE to confirm</Label>
                <Input id="confirm-forget" value={confirmWord} onChange={(e) => setConfirmWord(e.target.value)} autoComplete="off" />
              </div>
              <div className="flex flex-wrap gap-2">
                <Button
                  variant="destructive"
                  disabled={confirmWord !== "REMOVE" || busy}
                  onClick={async () => {
                    setBusy(true);
                    setError("");
                    try {
                      await forgetLockedBrowser();
                    } catch (err) {
                      setError(err.message);
                      setBusy(false);
                    }
                  }}
                >
                  Remove this browser
                </Button>
                <Button variant="ghost" onClick={() => { setForgot(false); setConfirmWord(""); }}>Cancel</Button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
