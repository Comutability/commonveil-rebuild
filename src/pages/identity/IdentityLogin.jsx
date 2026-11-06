import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Fingerprint, Loader2, Lock, LogIn, ShieldCheck, UserRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import AuthLayout from "@/components/AuthLayout";
import ConfirmDevice from "@/components/identity/ConfirmDevice";
import { login, loginWithPasskey, passkeysSupported } from "@/lib/identity/client";
import { safeReturnTo } from "@/lib/authReturnTo";

/** Sign-in on a self-hosted site: a passkey, or a username and password (docs/IDENTITY.md). */
export default function IdentityLogin() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState("");
  const [verify, setVerify] = useState(null);
  const returnTo = safeReturnTo() === "/" ? "/app" : safeReturnTo();
  const go = () => {
    window.location.href = returnTo;
  };

  const withPassword = async (e) => {
    e.preventDefault();
    setError("");
    setLoading("password");
    try {
      const r = await login({ username: username.trim().replace(/^@/, ""), password });
      if (r.verify) setVerify(r.verify);
      else go();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading("");
    }
  };

  const withPasskey = async () => {
    setError("");
    setLoading("passkey");
    try {
      await loginWithPasskey();
      go();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading("");
    }
  };

  if (verify) {
    return (
      <AuthLayout icon={ShieldCheck} title="Confirm it's you" subtitle="One more step on a new device.">
        <ConfirmDevice verify={verify} onDone={go} onCancel={() => { setVerify(null); setPassword(""); }} />
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
          <Link to={"/register" + (returnTo !== "/" ? "?returnTo=" + encodeURIComponent(returnTo) : "")} className="font-medium text-primary hover:underline">Create an account</Link>
          {" · "}
          <Link to="/" className="hover:underline">Back to the site</Link>
        </>
      }
    >
      {error && <div className="mb-4 rounded-lg bg-destructive/10 p-3 text-sm text-destructive" role="alert">{error}</div>}
      {passkeysSupported() && (
        <>
          <Button type="button" className="h-12 w-full font-medium" onClick={withPasskey} disabled={Boolean(loading)}>
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
            <Input id="username" autoComplete="username webauthn" autoCapitalize="none" spellCheck={false} value={username} onChange={(e) => setUsername(e.target.value)} className="h-12 pl-10" required aria-describedby="username-help" />
          </div>
          <p id="username-help" className="text-xs text-muted-foreground">Made your account with an email? You can still use it here, for now.</p>
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
    </AuthLayout>
  );
}
