import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Fingerprint, Loader2, Lock, LogIn, Mail, ShieldCheck, UserRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import AuthLayout from "@/components/AuthLayout";
import ConfirmDevice from "@/components/identity/ConfirmDevice";
import { base44, SELF_HOSTED } from "@/api/base44Client";
import { leavePlatformSession, linkPlatform, login, loginWithPasskey, passkeysSupported } from "@/lib/identity/client";
import { safeReturnTo } from "@/lib/authReturnTo";

const Error_ = ({ children }) => (children ? <div className="mb-4 rounded-lg bg-destructive/10 p-3 text-sm text-destructive" role="alert">{children}</div> : null);

/**
 * Signing in (docs/IDENTITY.md): a passkey, or a username and password. On commonveil.online,
 * accounts made with an email before usernames can come in with it, once, and are then moved over.
 */
export default function IdentityLogin() {
  const [mode, setMode] = useState("username");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [email, setEmail] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState("");
  const [verify, setVerify] = useState(null);
  const [viaEmail, setViaEmail] = useState(false);
  const returnTo = safeReturnTo() === "/" ? "/app" : safeReturnTo();
  // After an email sign-in, Base44's own session is ended too, so only Commonveil's remains.
  const go = () => (viaEmail ? leavePlatformSession(returnTo) : (window.location.href = returnTo));

  const run = async (what, fn) => {
    setError("");
    setLoading(what);
    try {
      await fn();
    } catch (err) {
      setError(err?.message || "That didn't work. Try again.");
    } finally {
      setLoading("");
    }
  };

  const withPassword = (e) => {
    e.preventDefault();
    run("password", async () => {
      const r = await login({ username: username.trim().replace(/^@/, ""), password });
      if (r.verify) setVerify(r.verify);
      else go();
    });
  };

  const withEmail = (e) => {
    e.preventDefault();
    run("email", async () => {
      await base44.auth.loginViaEmailPassword(email.trim(), password);
      setViaEmail(true);
      const r = await linkPlatform();
      if (r.verify) setVerify(r.verify);
      else leavePlatformSession(returnTo);
    });
  };

  if (verify) {
    return (
      <AuthLayout icon={ShieldCheck} title="Confirm it's you" subtitle="One more step on a new device.">
        <ConfirmDevice verify={verify} onDone={go} onCancel={() => { setVerify(null); setPassword(""); }} />
      </AuthLayout>
    );
  }

  if (mode === "email") {
    return (
      <AuthLayout
        icon={Mail}
        title="Sign in with your email"
        subtitle="For accounts made with an email, before usernames."
        footer={<button type="button" className="hover:underline" onClick={() => { setMode("username"); setError(""); }}>Back to signing in with a username</button>}
      >
        <Error_>{error}</Error_>
        <form onSubmit={withEmail} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <Input id="email" type="email" autoComplete="email" autoFocus value={email} onChange={(e) => setEmail(e.target.value)} className="h-12" required />
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label htmlFor="email-password">Password</Label>
              <Link to="/forgot-password?email=1" className="text-xs text-primary hover:underline">Forgot it?</Link>
            </div>
            <Input id="email-password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} className="h-12" required />
          </div>
          <Button type="submit" className="h-12 w-full font-medium" disabled={Boolean(loading)}>
            {loading === "email" ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Signing in…</> : "Sign in"}
          </Button>
        </form>
        <p className="mt-6 text-xs text-muted-foreground">
          Email sign-in is going away. Once you're in, you'll be asked to set a password for your username and confirm your recovery phrase. After that you won't need your email.
        </p>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout
      icon={LogIn}
      title="Sign in"
      subtitle="Your messages stay encrypted on your devices."
      footer={
        <>
          New here?{" "}
          <Link to={"/register" + (returnTo !== "/app" ? "?returnTo=" + encodeURIComponent(returnTo) : "")} className="font-medium text-primary hover:underline">Create an account</Link>
          {" · "}
          <Link to="/" className="hover:underline">Back to the site</Link>
        </>
      }
    >
      <Error_>{error}</Error_>
      {passkeysSupported() && (
        <>
          <Button type="button" className="h-12 w-full font-medium" onClick={() => run("passkey", async () => { await loginWithPasskey(); go(); })} disabled={Boolean(loading)}>
            {loading === "passkey" ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Fingerprint className="mr-2 h-4 w-4" aria-hidden="true" />}
            Sign in with a passkey
          </Button>
          <div className="my-5 flex items-center gap-3 text-xs text-muted-foreground" aria-hidden="true">
            <span className="h-px flex-1 bg-border" />or with your password<span className="h-px flex-1 bg-border" />
          </div>
        </>
      )}
      <form onSubmit={withPassword} className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="username">Username</Label>
          <div className="relative">
            <UserRound className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input id="username" autoComplete="username webauthn" autoCapitalize="none" spellCheck={false} value={username} onChange={(e) => setUsername(e.target.value)} className="h-12 pl-10" required />
          </div>
        </div>
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <Label htmlFor="password">Password</Label>
            <Link to="/forgot-password" className="text-xs text-primary hover:underline">Can't sign in?</Link>
          </div>
          <div className="relative">
            <Lock className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input id="password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} className="h-12 pl-10" required />
          </div>
        </div>
        <Button type="submit" variant={passkeysSupported() ? "outline" : "default"} className="h-12 w-full font-medium" disabled={Boolean(loading)}>
          {loading === "password" ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Signing in…</> : "Sign in"}
        </Button>
      </form>
      {!SELF_HOSTED && (
        <p className="mt-6 text-sm text-muted-foreground">
          Made your account with an email?{" "}
          <button type="button" className="font-medium text-primary hover:underline" onClick={() => { setMode("email"); setError(""); }}>Sign in with your email</button>
        </p>
      )}
    </AuthLayout>
  );
}
