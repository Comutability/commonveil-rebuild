import React, { useCallback, useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { Fingerprint, ShieldAlert, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { answerApproval, identityAction, identityStatus, pendingApprovals } from "@/lib/identity/client";
import { useConfirmItsYou } from "./ConfirmItsYou";

const DISMISS_KEY = "commonveil_identity_prompt";

function dismissed(kind) {
  try {
    return window.sessionStorage.getItem(DISMISS_KEY) === kind || window.localStorage.getItem(`${DISMISS_KEY}:${kind}`) === "1";
  } catch {
    return false;
  }
}

function dismiss(kind, forever) {
  try {
    if (forever) window.localStorage.setItem(`${DISMISS_KEY}:${kind}`, "1");
    else window.sessionStorage.setItem(DISMISS_KEY, kind);
  } catch {
    // Storage refused: it's shown again next time.
  }
}

/**
 * At the top of the app on a self-hosted site: sign-ins waiting for this device's approval, and
 * the nudges Commonveil Identity needs (email going away, confirm your phrase, add a passkey).
 */
export default function IdentityPrompts() {
  const [status, setStatus] = useState(null);
  const [approvals, setApprovals] = useState([]);
  const [approveError, setApproveError] = useState("");
  const { confirm, dialog } = useConfirmItsYou();
  const [hidden, setHidden] = useState(false);
  const { pathname } = useLocation();
  const onSettings = pathname.startsWith("/app/settings/sign-in");

  const poll = useCallback(async () => {
    try {
      setApprovals((await pendingApprovals()).approvals || []);
    } catch {
      // Offline, or signed out: nothing to show.
    }
  }, []);

  useEffect(() => {
    poll();
    const t = setInterval(() => {
      if (document.visibilityState === "visible") poll();
    }, 10_000);
    return () => clearInterval(t);
  }, [poll]);

  // What's set up changes in settings; check again on the way out.
  useEffect(() => {
    if (!onSettings) identityStatus().then(setStatus).catch(() => {});
  }, [onSettings]);

  if (approvals.length) {
    const a = approvals[0];
    return (
      <div role="alertdialog" aria-labelledby="approve-title" className="border-b border-amber-500/40 bg-amber-500/10">
        <div className="mx-auto flex max-w-5xl flex-wrap items-center gap-3 px-4 py-2 text-sm">
          <ShieldAlert className="h-4 w-4 text-amber-600" aria-hidden="true" />
          <p id="approve-title" className="min-w-0 flex-1">
            <span className="font-medium">{a.device_name}</span> is signing in to your account and shows the code <span className="font-mono font-semibold tracking-wider">{a.code.slice(0, 3)} {a.code.slice(3)}</span>. Is that you?
          </p>
          <Button size="sm" onClick={() => { setApproveError(""); confirm((o) => answerApproval(a.id, true, o)).catch((e) => setApproveError(e.message)).finally(poll); }}>Yes, approve</Button>
          <Button size="sm" variant="outline" onClick={() => answerApproval(a.id, false).finally(poll)}>No</Button>
          {approveError && <p className="w-full text-xs text-destructive" role="alert">{approveError}</p>}
        </div>
        {dialog}
      </div>
    );
  }

  // Accounts from before the 16+ rule confirm it once. Not dismissible.
  if (status && !status.age_confirmed) return <AgeCheck onConfirmed={() => setStatus({ ...status, age_confirmed: true })} />;

  if (!status || hidden || onSettings) return null;
  const kind = status.email_retiring ? "email" : !status.has_password ? "password" : !status.owner ? "owner" : !status.passkeys.length ? "passkey" : null;
  if (!kind || dismissed(kind)) return null;
  const text = {
    email: "Email sign-in is going away soon. Set a password for your username, confirm your recovery phrase, and add a passkey, then you won't need your email.",
    password: "Set a password, so you can sign in with your username.",
    owner: "Confirm your recovery phrase, so you can always get back into your account.",
    passkey: "Add a passkey to sign in without typing your password.",
  }[kind];
  return (
    <div role="status" className="border-b border-[hsl(var(--primary)/0.3)] bg-[hsl(var(--primary)/0.08)]">
      <div className="mx-auto flex max-w-5xl flex-wrap items-center gap-3 px-4 py-2 text-sm">
        <Fingerprint className="h-4 w-4 text-primary" aria-hidden="true" />
        <p className="min-w-0 flex-1">{text}</p>
        <Button size="sm" variant="outline" asChild>
          <Link to="/app/settings/sign-in">Set it up</Link>
        </Button>
        <button
          type="button"
          className="rounded p-1 text-muted-foreground hover:bg-muted"
          aria-label="Not now"
          onClick={() => {
            dismiss(kind, kind === "passkey");
            setHidden(true);
          }}
        >
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

function AgeCheck({ onConfirmed }) {
  const [busy, setBusy] = useState(false);
  const [under, setUnder] = useState(false);
  const [error, setError] = useState("");
  return (
    <div role="alertdialog" aria-labelledby="age-title" className="border-b border-amber-500/40 bg-amber-500/10">
      <div className="mx-auto flex max-w-5xl flex-wrap items-center gap-3 px-4 py-2 text-sm">
        <ShieldAlert className="h-4 w-4 text-amber-600" aria-hidden="true" />
        {under ? (
          <p className="min-w-0 flex-1">
            Commonveil is for people 16 and over, so this account needs to be closed. You can delete it in{" "}
            <Link to="/app/settings/data" className="font-medium underline">Settings → Data and account</Link>, and you're welcome back when you're 16.
          </p>
        ) : (
          <>
            <p id="age-title" className="min-w-0 flex-1">
              Commonveil is for people 16 and over. Please confirm you're 16 or older to keep using it. <Link to="/terms" className="underline">Terms of Use</Link>
            </p>
            {error && <span className="text-destructive">{error}</span>}
            <Button
              size="sm"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                try {
                  await identityAction("confirm_age", { age_confirmed: true });
                  onConfirmed();
                } catch (err) {
                  setError(err.message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              I'm 16 or older
            </Button>
            <Button size="sm" variant="outline" onClick={() => setUnder(true)}>I'm not</Button>
          </>
        )}
      </div>
    </div>
  );
}
