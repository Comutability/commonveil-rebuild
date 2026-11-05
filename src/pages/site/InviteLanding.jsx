import React, { useEffect, useState } from "react";
import { Link, Navigate, useLocation, useParams } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/lib/AuthContext";
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
          <p className="mt-4 text-xs text-muted-foreground">Commonveil is end-to-end encrypted chat. Your messages are encrypted on your device before they're sent.</p>
        </InvitePreview>
      )}
    </div>
  );
}
