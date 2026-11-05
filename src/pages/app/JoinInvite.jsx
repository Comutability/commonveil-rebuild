import React, { useEffect, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { Loader2, Lock, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ErrorNote } from "@/components/site/bits";
import Shell, { NavButton } from "@/components/shell/Shell";
import ServerIcon from "@/components/shell/ServerIcon";
import { useServers } from "@/lib/secure/ServerContext";
import { useSecure } from "@/lib/secure/SecureContext";
import { inviteInfo, recallInvite } from "@/lib/secure/invites";

/** Card for an invite: the server's name (opened with the link's secret), and joining it. */
export function InvitePreview({ info, children }) {
  const look = info.look || { name: "A private server", description: "", icon: "", color: "" };
  return (
    <div className="mx-auto w-full max-w-md rounded-2xl border border-border bg-card p-6 text-center shadow-sm">
      <p className="text-sm text-muted-foreground">You've been invited to join</p>
      <span className="mx-auto mt-4 block w-fit">
        <ServerIcon look={look} size="h-20 w-20" rounded className="!text-2xl" />
      </span>
      <h1 className="mt-4 text-3xl font-semibold">{look.name}</h1>
      {look.description && <p className="mt-2 text-sm text-muted-foreground">{look.description}</p>}
      <p className="mt-3 flex items-center justify-center gap-1.5 text-xs text-muted-foreground">
        <Users className="h-3.5 w-3.5" aria-hidden="true" /> About {info.member_count} {info.member_count === 1 ? "member" : "members"}
      </p>
      {info.sealed && (
        <p className="mt-3 flex items-start gap-1.5 rounded-lg bg-muted px-3 py-2 text-left text-xs text-muted-foreground">
          <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
          This preview was decrypted with the key in your link. Commonveil can't read it.
        </p>
      )}
      {!info.look && <p className="mt-3 text-xs text-muted-foreground">The link didn't include the key to its preview, so the server's name can't be shown. You can still join.</p>}
      <div className="mt-6">{children}</div>
    </div>
  );
}

export default function JoinInvite() {
  const { code } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const { me } = useSecure();
  const { joinServer, servers } = useServers();
  const [secret] = useState(() => (location.hash ? location.hash.slice(1) : recallInvite(code)));
  const [info, setInfo] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    inviteInfo(code, secret)
      .then((i) => alive && setInfo(i))
      .catch((err) => alive && setError(err.message));
    return () => {
      alive = false;
    };
  }, [code, secret]);

  const already = info && servers[info.server_id];
  const listed = me?.privacy?.default_listed;

  const join = async () => {
    setBusy(true);
    setError("");
    try {
      const sid = await joinServer({ code });
      navigate(`/app/s/${sid}`, { replace: true });
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  };

  return (
    <Shell panel={null} mainOpen>
      <div className="flex min-h-0 flex-1 flex-col">
        <header className="flex h-12 shrink-0 items-center border-b border-border/70 px-3 md:hidden"><NavButton /></header>
        <div className="scroll-thin flex flex-1 items-center justify-center overflow-y-auto p-4">
          {!info && !error && <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Opening the invite…</p>}
          {!info && error && (
            <div className="max-w-sm text-center">
              <p className="font-heading text-2xl">This invite doesn't work</p>
              <p className="mt-2 text-sm text-muted-foreground">{error}</p>
              <Button className="mt-5" variant="outline" onClick={() => navigate("/app")}>Go home</Button>
            </div>
          )}
          {info && (
            <InvitePreview info={info}>
              {already ? (
                <Button className="w-full" onClick={() => navigate(`/app/s/${info.server_id}`)}>You're already in. Open it</Button>
              ) : (
                <>
                  <Button className="w-full" onClick={join} disabled={busy}>{busy ? "Joining…" : "Join server"}</Button>
                  <p className="mt-3 text-left text-xs text-muted-foreground">
                    Moderators, and people who see your messages, will see your username.{" "}
                    {listed ? "You'll be listed in its member list (your default)." : "You won't be in its member list unless you choose to be."}{" "}
                    <Link to="/app/settings/privacy" className="text-primary hover:underline">Change your defaults</Link>
                  </p>
                </>
              )}
              <ErrorNote>{error}</ErrorNote>
            </InvitePreview>
          )}
        </div>
      </div>
    </Shell>
  );
}
