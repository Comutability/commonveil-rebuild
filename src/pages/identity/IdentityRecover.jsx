import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Fingerprint, KeyRound, LifeBuoy, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import AuthLayout from "@/components/AuthLayout";
import { SELF_HOSTED } from "@/api/base44Client";
import { passkeysSupported, recover } from "@/lib/identity/client";

/**
 * Getting back into an account on a self-hosted site: prove it's yours with your recovery phrase,
 * private key or a passkey, and choose a new password. Nobody else can do it for you, not even
 * the site's admin.
 */
export default function IdentityRecover() {
  const [username, setUsername] = useState("");
  const [method, setMethod] = useState("key");
  const [secret, setSecret] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    if (password.length < 10) return setError("Use at least 10 characters for your new password.");
    if (password !== confirm) return setError("The passwords don't match.");
    setLoading(true);
    try {
      await recover({ username: username.trim().replace(/^@/, ""), method, phraseOrKey: secret, newPassword: password });
      window.location.href = "/app";
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
    return undefined;
  };

  const choice = (value, Icon, label) => (
    <button
      type="button"
      role="radio"
      aria-checked={method === value}
      onClick={() => setMethod(value)}
      className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-left text-sm ${method === value ? "border-primary bg-primary/10" : "border-border text-muted-foreground hover:bg-muted"}`}
    >
      <Icon className="h-4 w-4" aria-hidden="true" /> {label}
    </button>
  );

  return (
    <AuthLayout
      icon={LifeBuoy}
      title="Get back into your account"
      subtitle="With your recovery phrase, private key or a passkey."
      footer={<Link to="/login" className="hover:underline">Back to sign in</Link>}
    >
      {error && <div className="mb-4 rounded-lg bg-destructive/10 p-3 text-sm text-destructive" role="alert">{error}</div>}
      <form onSubmit={submit} className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="rc-username">Username</Label>
          <Input id="rc-username" autoComplete="username" autoCapitalize="none" spellCheck={false} value={username} onChange={(e) => setUsername(e.target.value)} className="h-12" required />
        </div>
        <div role="radiogroup" aria-label="How to prove it's you" className="grid gap-2 sm:grid-cols-2">
          {choice("key", KeyRound, "Phrase or private key")}
          {passkeysSupported() && choice("passkey", Fingerprint, "Passkey")}
        </div>
        {method === "key" ? (
          <div className="space-y-1.5">
            <Label htmlFor="rc-secret">Your 24-word recovery phrase, or your private key</Label>
            <Textarea id="rc-secret" value={secret} onChange={(e) => setSecret(e.target.value)} rows={3} autoComplete="off" autoCapitalize="none" spellCheck={false} className="font-mono text-sm" required />
            <p className="text-xs text-muted-foreground">It stays in this browser. Only a signature made with it is sent.</p>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">You'll be asked for the passkey after choosing a new password.</p>
        )}
        <div className="space-y-2">
          <Label htmlFor="rc-password">New password</Label>
          <Input id="rc-password" type="password" autoComplete="new-password" minLength={10} value={password} onChange={(e) => setPassword(e.target.value)} className="h-12" required />
        </div>
        <div className="space-y-2">
          <Label htmlFor="rc-confirm">Confirm new password</Label>
          <Input id="rc-confirm" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} className="h-12" required />
        </div>
        <Button type="submit" className="h-12 w-full font-medium" disabled={loading}>
          {loading ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Checking…</> : "Set new password and sign in"}
        </Button>
      </form>
      <p className="mt-6 text-xs text-muted-foreground">
        Every other session is signed out. Your devices stay connected; remove any you don't recognise in Settings.
      </p>
      {!SELF_HOSTED && (
        <p className="mt-3 text-sm text-muted-foreground">
          Made your account with an email, and haven't confirmed your recovery phrase yet?{" "}
          <Link to="/forgot-password?email=1" className="font-medium text-primary hover:underline">Reset your password by email</Link>
        </p>
      )}
    </AuthLayout>
  );
}
