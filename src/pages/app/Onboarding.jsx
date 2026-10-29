import React, { useState } from "react";
import { AtSign, KeyRound, Laptop, Loader2, LifeBuoy, ShieldAlert, Smartphone } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { ErrorNote } from "@/components/site/bits";
import { PhraseCheckpoint } from "@/components/app/Phrase";
import { useSecure } from "@/lib/secure/SecureContext";
import { groupDigits } from "@/lib/crypto/identity.js";
import { isKnownWord, phraseWords } from "@/lib/crypto/recovery.js";

function Panel({ icon: Icon, eyebrow, title, children }) {
  return (
    <div className="mx-auto max-w-2xl px-4 py-12">
      <div className="card-cv p-6 sm:p-8">
        <div className="flex items-center gap-3">
          <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-accent text-accent-foreground">
            <Icon className="h-5 w-5" aria-hidden="true" />
          </span>
          {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        </div>
        <h1 className="mt-4 text-3xl font-semibold">{title}</h1>
        <div className="mt-6">{children}</div>
      </div>
    </div>
  );
}

const USERNAME_RE = /^[A-Za-z0-9_]{3,20}$/;

export function Welcome() {
  const { claimUsername } = useSecure();
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const valid = USERNAME_RE.test(username.trim());

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await claimUsername(username.trim(), displayName.trim());
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  };

  return (
    <Panel icon={AtSign} eyebrow="Step 1 of 2" title="Choose your username">
      <form onSubmit={submit} className="space-y-5">
        <p className="text-muted-foreground">
          People reach you by typing your exact username. There's no directory, so nobody can browse for you. You can't change it later.
        </p>
        <div className="space-y-1.5">
          <Label htmlFor="username">Username</Label>
          <div className="relative">
            <span className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground">@</span>
            <Input id="username" value={username} onChange={(e) => setUsername(e.target.value)} className="pl-7" autoComplete="off" autoCapitalize="none" spellCheck={false} maxLength={20} required aria-describedby="username-help" />
          </div>
          <p id="username-help" className="text-xs text-muted-foreground">3-20 letters, numbers or underscores.</p>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="display">Display name <span className="font-normal text-muted-foreground">(optional)</span></Label>
          <Input id="display" value={displayName} onChange={(e) => setDisplayName(e.target.value)} maxLength={50} />
        </div>
        <ErrorNote>{error}</ErrorNote>
        <Button type="submit" disabled={!valid || busy}>{busy ? "Saving…" : "Continue"}</Button>
      </form>
    </Panel>
  );
}

export function SetupKeys() {
  const { beginCreateAccount, finishCreateAccount, cancelPending, refresh } = useSecure();
  const [phrase, setPhrase] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const begin = async () => {
    setBusy(true);
    setError("");
    try {
      setPhrase(await beginCreateAccount());
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const finish = async () => {
    setBusy(true);
    setError("");
    try {
      await finishCreateAccount();
    } catch (err) {
      if (err.code === "ALREADY_INITIALISED") {
        cancelPending();
        await refresh();
        return;
      }
      setError(err.message);
      setBusy(false);
    }
  };

  return (
    <Panel icon={KeyRound} eyebrow="Step 2 of 2" title={phrase ? "Your recovery phrase" : "Set up encryption"}>
      {!phrase ? (
        <div className="space-y-5">
          <p className="text-muted-foreground">
            Your keys are created here, in this browser. Then you'll get a 24-word recovery phrase. It's the only way back in if you lose
            every device, so you'll need pen and paper.
          </p>
          <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
            <li>Your private keys never leave your devices.</li>
            <li>To use Commonveil on another device later, you'll approve it from this one, or use the phrase.</li>
          </ul>
          <ErrorNote>{error}</ErrorNote>
          <Button onClick={begin} disabled={busy}>
            {busy ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Creating keys…</> : "Create my keys"}
          </Button>
        </div>
      ) : (
        <PhraseCheckpoint phrase={phrase} onConfirmed={finish} confirmLabel="Finish setup" busy={busy} error={error} />
      )}
    </Panel>
  );
}

export function AddDevice() {
  const { phase, startLinking, cancelLinking, myLinkCode, recoverWithPhrase, notice, clearNotice } = useSecure();
  const [mode, setMode] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [phrase, setPhrase] = useState("");

  if (phase === "awaiting-approval" && mode !== "phrase") {
    return (
      <Panel icon={Smartphone} eyebrow="Add this device" title="Approve this device from another one">
        <div className="space-y-5">
          <p className="text-muted-foreground">
            On a device where you're already set up, open <strong>Settings → Devices</strong>. You'll see this browser waiting. Approve it
            only if the code there matches this one exactly.
          </p>
          <p className="mono rounded-xl border border-border bg-muted/50 px-4 py-5 text-center text-2xl tracking-wider sm:text-3xl" aria-label="Device link code">
            {myLinkCode ? groupDigits(myLinkCode, 4) : "…"}
          </p>
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Waiting for approval. This request expires after 15 minutes.
          </p>
          <div className="flex flex-wrap gap-3">
            <Button variant="outline" onClick={() => setMode("phrase")}>Use my recovery phrase instead</Button>
            <Button variant="ghost" onClick={cancelLinking}>Cancel</Button>
          </div>
        </div>
      </Panel>
    );
  }

  const link = async () => {
    setBusy(true);
    setError("");
    try {
      await startLinking();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const recover = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await recoverWithPhrase(phrase);
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  };

  const words = phraseWords(phrase);
  const unknown = words.filter((w) => !isKnownWord(w));

  return (
    <Panel icon={Laptop} eyebrow="New device" title="Set up encryption on this device">
      {notice && (
        <div className="mb-5 rounded-lg border border-border bg-muted p-3 text-sm">
          {notice} <button type="button" className="ml-1 underline" onClick={clearNotice}>Dismiss</button>
        </div>
      )}
      {mode !== "phrase" && mode !== "reset" && (
        <div className="space-y-4">
          <p className="text-muted-foreground">Your account already has encryption keys. Bring them to this browser one of two ways.</p>
          <button type="button" onClick={link} disabled={busy} className="card-cv flex w-full items-start gap-4 p-5 text-left transition-colors hover:bg-muted/50">
            <Smartphone className="mt-0.5 h-6 w-6 text-primary" aria-hidden="true" />
            <span>
              <span className="block font-semibold">Approve it from another device</span>
              <span className="mt-1 block text-sm text-muted-foreground">Recommended. You'll compare a code on both screens.</span>
            </span>
          </button>
          <button type="button" onClick={() => setMode("phrase")} className="card-cv flex w-full items-start gap-4 p-5 text-left transition-colors hover:bg-muted/50">
            <KeyRound className="mt-0.5 h-6 w-6 text-primary" aria-hidden="true" />
            <span>
              <span className="block font-semibold">Use your 24-word recovery phrase</span>
              <span className="mt-1 block text-sm text-muted-foreground">For when you don't have another device to hand.</span>
            </span>
          </button>
          <ErrorNote>{error}</ErrorNote>
          <button type="button" onClick={() => setMode("reset")} className="flex items-center gap-2 pt-2 text-sm text-muted-foreground underline-offset-2 hover:underline">
            <LifeBuoy className="h-4 w-4" aria-hidden="true" /> I've lost every device and my phrase
          </button>
        </div>
      )}

      {mode === "phrase" && (
        <form onSubmit={recover} className="space-y-4">
          <Label htmlFor="phrase">Recovery phrase</Label>
          <Textarea
            id="phrase"
            rows={5}
            className="mono"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            value={phrase}
            onChange={(e) => setPhrase(e.target.value)}
            placeholder="word1 word2 word3 …"
          />
          <p className="text-sm text-muted-foreground">
            {words.length} of 24 words
            {unknown.length > 0 && <span className="text-destructive"> · not in the word list: {unknown.slice(0, 3).join(", ")}</span>}
          </p>
          <ErrorNote>{error}</ErrorNote>
          <div className="flex gap-3">
            <Button type="submit" disabled={busy || words.length !== 24 || unknown.length > 0}>{busy ? "Unlocking…" : "Unlock my keys"}</Button>
            <Button type="button" variant="ghost" onClick={() => setMode(null)}>Back</Button>
          </div>
        </form>
      )}

      {mode === "reset" && <ResetAccount onBack={() => setMode(null)} />}
    </Panel>
  );
}

function ResetAccount({ onBack }) {
  const { beginReset, finishReset } = useSecure();
  const [typed, setTyped] = useState("");
  const [phrase, setPhrase] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  if (phrase) {
    const finish = async () => {
      setBusy(true);
      setError("");
      try {
        await finishReset();
      } catch (err) {
        setError(err.message);
        setBusy(false);
      }
    };
    return <PhraseCheckpoint phrase={phrase} onConfirmed={finish} confirmLabel="Reset and finish" busy={busy} error={error} />;
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-3 rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm">
        <ShieldAlert className="h-5 w-5 shrink-0 text-destructive" aria-hidden="true" />
        <div className="space-y-2">
          <p className="font-semibold">This starts a new encryption identity.</p>
          <ul className="list-disc space-y-1 pl-5">
            <li>Every message sent to you before now becomes permanently unreadable.</li>
            <li>All your other devices are removed.</li>
            <li>The people you talk to will see a warning that your keys changed.</li>
          </ul>
        </div>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="confirm-reset">Type RESET to continue</Label>
        <Input id="confirm-reset" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
      </div>
      <ErrorNote>{error}</ErrorNote>
      <div className="flex gap-3">
        <Button
          variant="destructive"
          disabled={typed !== "RESET" || busy}
          onClick={async () => {
            setBusy(true);
            setError("");
            try {
              setPhrase(await beginReset());
            } catch (err) {
              setError(err.message);
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "Preparing…" : "Reset my encryption"}
        </Button>
        <Button variant="ghost" onClick={onBack}>Back</Button>
      </div>
    </div>
  );
}

export function AwaitingKeys() {
  const { startOver } = useSecure();
  const [busy, setBusy] = useState(false);
  return (
    <Panel icon={Loader2} eyebrow="Almost there" title="Waiting for your latest keys">
      <div className="space-y-4 text-muted-foreground">
        <p>
          This device is approved, but your keys changed since. Your other devices send the update automatically the next time one of them
          opens Commonveil.
        </p>
        <p>If that's not possible, remove this device and set it up again with your recovery phrase.</p>
        <Button
          variant="outline"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            await startOver();
            setBusy(false);
          }}
        >
          {busy ? "Working…" : "Set this device up again"}
        </Button>
      </div>
    </Panel>
  );
}
