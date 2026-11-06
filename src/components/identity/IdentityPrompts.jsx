import React, { useCallback, useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { Fingerprint, ShieldAlert, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SELF_HOSTED } from "@/api/base44Client";
import { answerApproval, identityStatus, pendingApprovals } from "@/lib/identity/client";

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
    if (!SELF_HOSTED) return undefined;
    poll();
    const t = setInterval(() => {
      if (document.visibilityState === "visible") poll();
    }, 10_000);
    return () => clearInterval(t);
  }, [poll]);

  // What's set up changes in settings; check again on the way out.
  useEffect(() => {
    if (SELF_HOSTED && !onSettings) identityStatus().then(setStatus).catch(() => {});
  }, [onSettings]);

  if (!SELF_HOSTED) return null;

  if (approvals.length) {
    const a = approvals[0];
    return (
      <div role="alertdialog" aria-labelledby="approve-title" className="border-b border-amber-500/40 bg-amber-500/10">
        <div className="mx-auto flex max-w-5xl flex-wrap items-center gap-3 px-4 py-2 text-sm">
          <ShieldAlert className="h-4 w-4 text-amber-600" aria-hidden="true" />
          <p id="approve-title" className="min-w-0 flex-1">
            <span className="font-medium">{a.device_name}</span> is signing in to your account and shows the code <span className="font-mono font-semibold tracking-wider">{a.code.slice(0, 3)} {a.code.slice(3)}</span>. Is that you?
          </p>
          <Button size="sm" onClick={() => answerApproval(a.id, true).finally(poll)}>Yes, approve</Button>
          <Button size="sm" variant="outline" onClick={() => answerApproval(a.id, false).finally(poll)}>No</Button>
        </div>
      </div>
    );
  }

  if (!status || hidden || onSettings) return null;
  const kind = status.email_retiring ? "email" : !status.owner ? "owner" : !status.passkeys.length ? "passkey" : null;
  if (!kind || dismissed(kind)) return null;
  const text = {
    email: "Email sign-in is going away soon. You'll sign in with your username and password, and keep your recovery phrase to get back in. Set up a passkey now.",
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
