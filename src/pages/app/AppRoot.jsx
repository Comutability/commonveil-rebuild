import React, { useState } from "react";
import { Link, NavLink, Outlet } from "react-router-dom";
import { AlertTriangle, Lock, MessagesSquare, Settings, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SecureProvider, useSecure } from "@/lib/secure/SecureContext";
import { ChatProvider } from "@/lib/secure/ChatContext";
import { LogoMark } from "@/components/site/Logo";
import { FullScreenLoading } from "@/components/site/bits";
import LockScreen from "@/components/app/LockScreen";
import { AddDevice, AwaitingKeys, BrowserRemoved, ResetWaiting, SetupKeys, Welcome, formatWhen } from "./Onboarding";

/** Shown on every screen while someone's asked to reset this account: any of its devices can stop it. */
function ResetRequested() {
  const { waitingReset, cancelReset } = useSecure();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  if (!waitingReset) return null;
  return (
    <div className="border-b border-destructive/30 bg-destructive/10 px-3 py-3 text-sm sm:px-4" role="alert">
      <div className="mx-auto flex w-full max-w-7xl flex-wrap items-start gap-3">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" aria-hidden="true" />
        <div className="min-w-0 flex-1 space-y-1">
          <p className="font-semibold">Someone asked to reset your encryption keys</p>
          <p>
            The request came from &ldquo;{waitingReset.device_label}&rdquo; on {formatWhen(waitingReset.requested_at)}. If it goes ahead on{" "}
            {formatWhen(waitingReset.effective_at)}, all your devices are removed and your contacts see new keys. If it wasn't you, cancel it
            and change your password.
          </p>
          {error && <p className="text-destructive">{error}</p>}
        </div>
        <Button
          size="sm"
          variant="destructive"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            setError("");
            try {
              await cancelReset();
            } catch (err) {
              setError(err.message);
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "Cancelling…" : "Cancel the reset"}
        </Button>
      </div>
    </div>
  );
}

const tabClass = ({ isActive }) =>
  `inline-flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors ${isActive ? "bg-muted text-foreground" : "text-muted-foreground hover:bg-muted/60 hover:text-foreground"}`;

function Frame({ children, showNav }) {
  const { me, isAdmin, lockInfo, lockNow } = useSecure();
  return (
    <div className="flex min-h-[100dvh] flex-col">
      <header className="border-b border-border bg-background">
        <div className="mx-auto flex h-14 w-full max-w-7xl items-center justify-between gap-3 px-3 sm:px-4">
          <Link to={showNav ? "/app" : "/"} className="flex items-center gap-2">
            <LogoMark className="h-7 w-7 text-primary-foreground" />
            <span className="hidden font-heading text-lg font-semibold sm:inline">Commonveil</span>
          </Link>
          {showNav && (
            <nav className="flex items-center gap-1" aria-label="App">
              <NavLink to="/app" end className={tabClass}><MessagesSquare className="h-4 w-4" aria-hidden="true" /><span className="hidden sm:inline">Messages</span></NavLink>
              <NavLink to="/app/settings" className={tabClass}><Settings className="h-4 w-4" aria-hidden="true" /><span className="hidden sm:inline">Settings</span></NavLink>
              {isAdmin && <NavLink to="/admin" className={tabClass}><Shield className="h-4 w-4" aria-hidden="true" /><span className="hidden sm:inline">Admin</span></NavLink>}
            </nav>
          )}
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            {showNav && lockInfo && (
              <Button variant="ghost" size="sm" onClick={lockNow} aria-label="Lock now" title="Lock now">
                <Lock className="h-4 w-4" aria-hidden="true" /><span className="ml-1 hidden sm:inline">Lock</span>
              </Button>
            )}
            {me?.profile && <span className="hidden md:inline">@{me.profile.username}</span>}
            <Link to="/" className="hover:text-foreground">Site</Link>
          </div>
        </div>
      </header>
      {showNav && <ResetRequested />}
      <div className="flex min-h-0 flex-1 flex-col">{children}</div>
    </div>
  );
}

function Gate() {
  const { phase, error, refresh } = useSecure();
  if (phase === "loading") return <FullScreenLoading label="Checking your keys" />;
  if (phase === "locked") return <Frame><LockScreen /></Frame>;
  if (phase === "error") {
    return (
      <Frame>
        <div className="mx-auto max-w-lg px-4 py-16 text-center">
          <AlertTriangle className="mx-auto h-8 w-8 text-destructive" aria-hidden="true" />
          <h1 className="mt-4 text-2xl font-semibold">Something isn't right</h1>
          <p className="mt-2 text-muted-foreground">{error}</p>
          <Button className="mt-6" onClick={refresh}>Try again</Button>
        </div>
      </Frame>
    );
  }
  if (phase === "needs-username") return <Frame><Welcome /></Frame>;
  if (phase === "needs-keys") return <Frame><SetupKeys /></Frame>;
  if (phase === "needs-device" || phase === "awaiting-approval") return <Frame><AddDevice /></Frame>;
  if (phase === "awaiting-keys") return <Frame><AwaitingKeys /></Frame>;
  if (phase === "removed") return <Frame><BrowserRemoved /></Frame>;
  if (phase === "reset-waiting") return <Frame><ResetWaiting /></Frame>;
  return (
    <ChatProvider>
      <Frame showNav>
        <Outlet />
      </Frame>
    </ChatProvider>
  );
}

export default function AppRoot() {
  return (
    <SecureProvider>
      <Gate />
    </SecureProvider>
  );
}
