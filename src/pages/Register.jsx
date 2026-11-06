import React, { useState } from "react";
import { Link } from "react-router-dom";
import { base44, SELF_HOSTED } from "@/api/base44Client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Loader2, Lock, Mail, UserPlus } from "lucide-react";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import AuthLayout from "@/components/AuthLayout";
import { toast } from "@/components/ui/use-toast";
import { safeReturnTo } from "@/lib/authReturnTo";
import IdentityRegister from "@/pages/identity/IdentityRegister";

function EmailRegister() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [showOtp, setShowOtp] = useState(false);
  const [otpCode, setOtpCode] = useState("");
  const returnTo = safeReturnTo() === "/" ? "/app" : safeReturnTo();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    if (password.length < 10) {
      setError("Use at least 10 characters. A few random words works well.");
      return;
    }
    if (password !== confirmPassword) {
      setError("The passwords don't match.");
      return;
    }
    setLoading(true);
    try {
      const result = await base44.auth.register({ email, password });
      // A self-hosted site without email sending signs new accounts straight in.
      if (result?.access_token) {
        base44.auth.setToken(result.access_token);
        window.location.href = returnTo;
        return;
      }
      setShowOtp(true);
    } catch (err) {
      setError(err?.message || "Couldn't create the account.");
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async () => {
    setError("");
    setLoading(true);
    try {
      const result = await base44.auth.verifyOtp({ email, otpCode });
      if (result?.access_token) base44.auth.setToken(result.access_token);
      window.location.href = returnTo;
    } catch (err) {
      setError(err?.message || "That code didn't work.");
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    setError("");
    try {
      await base44.auth.resendOtp(email);
      toast({ title: "Code sent", description: "Check your inbox for a new code." });
    } catch (err) {
      setError(err?.message || "Couldn't resend the code.");
    }
  };

  if (showOtp) {
    return (
      <AuthLayout icon={Mail} title="Check your inbox" subtitle={`We sent a 6-digit code to ${email}`}>
        {error && <div className="mb-4 rounded-lg bg-destructive/10 p-3 text-sm text-destructive" role="alert">{error}</div>}
        <div className="mb-6 flex justify-center">
          <InputOTP maxLength={6} value={otpCode} onChange={setOtpCode} autoFocus autoComplete="one-time-code">
            <InputOTPGroup>
              {[0, 1, 2, 3, 4, 5].map((i) => <InputOTPSlot key={i} index={i} />)}
            </InputOTPGroup>
          </InputOTP>
        </div>
        <Button className="h-12 w-full font-medium" onClick={handleVerify} disabled={loading || otpCode.length < 6}>
          {loading ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Checking…</> : "Verify and continue"}
        </Button>
        <p className="mt-4 text-center text-sm text-muted-foreground">
          No code?{" "}
          <button type="button" onClick={handleResend} className="font-medium text-primary hover:underline">Send another</button>
        </p>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout
      icon={UserPlus}
      title="Create your account"
      subtitle="Next you'll choose a username and set up encryption."
      footer={
        <>
          Already have an account?{" "}
          <Link to={"/login" + (returnTo !== "/" ? "?returnTo=" + encodeURIComponent(returnTo) : "")} className="font-medium text-primary hover:underline">Sign in</Link>
        </>
      }
    >
      {error && <div className="mb-4 rounded-lg bg-destructive/10 p-3 text-sm text-destructive" role="alert">{error}</div>}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="email">Email</Label>
          <div className="relative">
            <Mail className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input id="email" type="email" autoComplete="email" autoFocus value={email} onChange={(e) => setEmail(e.target.value)} className="h-12 pl-10" required aria-describedby="email-help" />
          </div>
          <p id="email-help" className="text-xs text-muted-foreground">
            Only used to sign in and reset your password. Other members never see it, and an alias address is fine.
          </p>
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
            <Input id="confirm" type="password" autoComplete="new-password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} className="h-12 pl-10" required />
          </div>
        </div>
        <Button type="submit" className="h-12 w-full font-medium" disabled={loading}>
          {loading ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Creating account…</> : "Create account"}
        </Button>
      </form>
    </AuthLayout>
  );
}

/** Self-hosted sites use Commonveil Identity (usernames and passkeys); Base44 signs in by email. */
export default function Register() {
  return SELF_HOSTED ? <IdentityRegister /> : <EmailRegister />;
}
