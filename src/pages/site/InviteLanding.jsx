import React, { useEffect, useState } from "react";
import { Link, Navigate, useLocation, useParams } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/lib/AuthContext";
import { SELF_HOSTED } from "@/api/base44Client";
import { Input } from "@/components/ui/input";
import { inviteInfo, rememberInvite } from "@/lib/secure/invites";
import { InvitePreview } from "@/pages/app/JoinInvite";

/**
 * An invite link opened in a browser: a preview anyone with the link can see, then signing in
 * to join. Signed-in people go straight to joining.
 */
export default function InviteLanding() {
  const { code } = useParams();
  const location = useLocation();
  const { isAuthenticated } = useAuth();
  const secret = location.hash ? location.hash.slice(1) : "";
  const [info, setInfo] = useState(null);
  const [error, setError] = useState("");
  const [home, setHome] = useState("");

  // Someone with an account on another Commonveil site joins from there: their site relays it.
  const [homeError, setHomeError] = useState("");
  const joinFromHome = async (e) => {
    e.preventDefault();
    setHomeError("");
    const res = await fetch(`/api/fed/resolve?q=${encodeURIComponent(home.trim())}`).then((r) => r.json()).catch(() => null);
    if (!res?.home) {
      setHomeError("That isn't a Commonveil handle or site we can reach.");
      return;
    }
    window.location.href = `${res.home_url}/app/join/${code}?site=${encodeURIComponent(window.location.host)}${secret ? `#${secret}` : ""}`;
  };


  useEffect(() => {
    if (isAuthenticated) return undefined;
    let alive = true;
    inviteInfo(code, secret)
      .then((i) => alive && setInfo(i))
      .catch((err) => alive && setError(err.message));
    return () => {
      alive = false;
    };
  }, [code, secret, isAuthenticated]);

  if (isAuthenticated) return <Navigate to={`/app/join/${code}${secret ? `#${secret}` : ""}`} replace />;

  const returnTo = encodeURIComponent(`/app/join/${code}`);
  const keep = () => rememberInvite(code, secret);

  return (
    <div className="container-cv flex min-h-[60vh] items-center justify-center py-16">
      {!info && !error && <p className="flex items-center gap-2 text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Opening the invite…</p>}
      {error && (
        <div className="max-w-sm text-center">
          <h1 className="text-3xl font-semibold">This invite doesn't work</h1>
          <p className="mt-2 text-muted-foreground">{error}</p>
        </div>
      )}
      {info && (
        <InvitePreview info={info}>
          <div className="flex flex-col gap-2">
            <Button asChild className="w-full" onClick={keep}>
              <Link to={`/register?returnTo=${returnTo}`}>Create an account to join</Link>
            </Button>
            <Button asChild variant="outline" className="w-full" onClick={keep}>
              <Link to={`/login?returnTo=${returnTo}`}>I have an account</Link>
            </Button>
          </div>
          {SELF_HOSTED && (
            <form onSubmit={joinFromHome} className="mt-5 border-t border-border pt-4">
              <label htmlFor="home-site" className="text-sm font-medium">Have an account on another Commonveil site?</label>
              <div className="mt-2 flex gap-2">
                <Input id="home-site" value={home} onChange={(e) => setHome(e.target.value)} placeholder="Your handle, like alice.chat.example.org" autoComplete="off" />
                <Button type="submit" variant="outline" disabled={!home.trim()}>Go</Button>
              </div>
              {homeError && <p className="mt-1 text-xs text-destructive">{homeError}</p>}
              <p className="mt-1 text-xs text-muted-foreground">You'll join from your own site, and chat here from there.</p>
            </form>
          )}
          <p className="mt-4 text-xs text-muted-foreground">Commonveil is end-to-end encrypted chat. Your messages are encrypted on your device before they're sent.</p>
        </InvitePreview>
      )}
    </div>
  );
}
