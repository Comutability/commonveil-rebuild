import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Loader2, Lock, UserPlus, UserRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import AuthLayout from "@/components/AuthLayout";
import { register } from "@/lib/identity/client";
import { safeReturnTo } from "@/lib/authReturnTo";

/** A new account on a self-hosted site: a username and a password. No email. */
export default function IdentityRegister() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [over16, setOver16] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const returnTo = safeReturnTo() === "/" ? "/app" : safeReturnTo();

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    const name = username.trim().replace(/^@/, "");
    if (!/^[A-Za-z0-9_]{3,20}$/.test(name)) return setError("Usernames are 3 to 20 letters, numbers or underscores.");
    if (password.length < 10) return setError("Use at least 10 characters. A few random words works well.");
    if (password !== confirm) return setError("The passwords don't match.");
    if (!over16) return setError("Commonveil is for people 16 and over. Confirm you're 16 or older to create an account.");
    setLoading(true);
    try {
      await register({ username: name, password, ageConfirmed: over16 });
      window.location.href = returnTo;
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
    return undefined;
  };

  return (
    <AuthLayout
      icon={UserPlus}
      title="Create your account"
      subtitle="No email needed. Next you'll set up encryption and get your recovery phrase."
      footer={
        <>
          Already have an account?{" "}
          <Link to={"/login" + (returnTo !== "/" ? "?returnTo=" + encodeURIComponent(returnTo) : "")} className="font-medium text-primary hover:underline">Sign in</Link>
        </>
      }
    >
      {error && <div className="mb-4 rounded-lg bg-destructive/10 p-3 text-sm text-destructive" role="alert">{error}</div>}
      <form onSubmit={submit} className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="username">Username</Label>
          <div className="relative">
            <UserRound className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input id="username" autoComplete="username" autoCapitalize="none" spellCheck={false} autoFocus maxLength={20} value={username} onChange={(e) => setUsername(e.target.value)} className="h-12 pl-10" required aria-describedby="username-help" />
          </div>
          <p id="username-help" className="text-xs text-muted-foreground">It's how people reach you, and it can't be changed. There's no directory: people need to know it exactly.</p>
        </div>
        <div className="space-y-2">
          <Label htmlFor="password">Password</Label>
          <div className="relative">
            <Lock className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input id="password" type="password" autoComplete="new-password" minLength={10} value={password} onChange={(e) => setPassword(e.target.value)} className="h-12 pl-10" required />
          </div>
        </div>
        <div className="space-y-2">
          <Label htmlFor="confirm">Confirm password</Label>
          <div className="relative">
            <Lock className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input id="confirm" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} className="h-12 pl-10" required />
          </div>
        </div>
        <div className="flex items-start gap-3 rounded-lg border border-border p-3">
          <Checkbox id="over16" checked={over16} onCheckedChange={(v) => setOver16(v === true)} aria-describedby="over16-help" className="mt-0.5" />
          <div className="space-y-1">
            <Label htmlFor="over16" className="font-medium">I'm 16 or older</Label>
            <p id="over16-help" className="text-xs text-muted-foreground">
              Commonveil is for people 16 and over. If we find out an account belongs to someone younger, it's closed. Nothing about your age is stored, only that you ticked this.
            </p>
          </div>
        </div>
        <p className="text-xs text-muted-foreground">
          By creating an account you agree to the <Link to="/terms" className="text-primary hover:underline">Terms of Use</Link>. <Link to="/privacy" className="text-primary hover:underline">Privacy</Link> says exactly what's kept.
        </p>
        <Button type="submit" className="h-12 w-full font-medium" disabled={loading}>
          {loading ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Creating account…</> : "Create account"}
        </Button>
      </form>
      <p className="mt-6 text-xs text-muted-foreground">
        Without an email, your recovery phrase is how you get back in if you forget your password. You'll write it down in the next step, and can add a passkey after.
      </p>
    </AuthLayout>
  );
}
