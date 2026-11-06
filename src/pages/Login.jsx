import React, { useState } from "react";
import { Link } from "react-router-dom";
import { base44, SELF_HOSTED } from "@/api/base44Client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Loader2, Lock, LogIn, Mail } from "lucide-react";
import AuthLayout from "@/components/AuthLayout";
import { safeReturnTo } from "@/lib/authReturnTo";
import IdentityLogin from "@/pages/identity/IdentityLogin";

function EmailLogin() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const returnTo = safeReturnTo();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await base44.auth.loginViaEmailPassword(email, password);
      window.location.href = returnTo;
    } catch (err) {
      setError(err?.message || "That email and password don't match.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout
      icon={LogIn}
      title="Sign in"
      subtitle="Your messages stay encrypted on your devices."
      footer={
        <>
          New here?{" "}
          <Link to={"/register" + (returnTo !== "/" ? "?returnTo=" + encodeURIComponent(returnTo) : "")} className="font-medium text-primary hover:underline">
            Create an account
          </Link>
          {" · "}
          <Link to="/" className="hover:underline">Back to the site</Link>
        </>
      }
    >
      {error && <div className="mb-4 rounded-lg bg-destructive/10 p-3 text-sm text-destructive" role="alert">{error}</div>}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="email">Email</Label>
          <div className="relative">
            <Mail className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input id="email" type="email" autoComplete="email" autoFocus value={email} onChange={(e) => setEmail(e.target.value)} className="h-12 pl-10" required />
          </div>
        </div>
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <Label htmlFor="password">Password</Label>
            <Link to="/forgot-password" className="text-xs text-primary hover:underline">Forgot password?</Link>
          </div>
          <div className="relative">
            <Lock className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input id="password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} className="h-12 pl-10" required />
          </div>
        </div>
        <Button type="submit" className="h-12 w-full font-medium" disabled={loading}>
          {loading ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Signing in…</> : "Sign in"}
        </Button>
      </form>
      <p className="mt-6 text-xs text-muted-foreground">
        Your password signs you in. It isn't your encryption key: on a new device you'll also approve it from another device or enter your
        recovery phrase.
      </p>
    </AuthLayout>
  );
}

/** Self-hosted sites use Commonveil Identity (usernames and passkeys); Base44 signs in by email. */
export default function Login() {
  return SELF_HOSTED ? <IdentityLogin /> : <EmailLogin />;
}
