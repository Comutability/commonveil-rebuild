import React, { useCallback, useEffect, useState } from "react";
import { Ban, Globe2, KeyRound, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ErrorNote, formatDate } from "@/components/site/bits";
import { appParams } from "@/lib/app-params";

// Other sites this one talks to over the Commonveil Protocol (server/federation): who they are,
// when they were last heard from, and the admin's controls — block a site, or accept a site's new
// key after checking the change was expected. Admins only, self-hosted sites only.

async function ask(method, body) {
  const res = await fetch("/api/admin/federation", {
    method,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${appParams.token || window.localStorage.getItem("base44_access_token") || ""}` },
    body: body ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Couldn't reach this site's federation settings.");
  return data;
}

export default function FederationPanel() {
  const [state, setState] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const [blockHost, setBlockHost] = useState("");

  const refresh = useCallback(async () => {
    try {
      setState(await ask("GET"));
      setError("");
    } catch (err) {
      setError(err.message);
    }
  }, []);
  useEffect(() => {
    refresh();
  }, [refresh]);

  const act = async (action, host) => {
    setBusy(`${action}:${host}`);
    try {
      const r = await ask("POST", { action, host });
      setState((s) => ({ ...s, sites: r.sites }));
      setError("");
      return true;
    } catch (err) {
      setError(err.message);
      return false;
    } finally {
      setBusy("");
    }
  };

  if (!state) return error ? <ErrorNote>{error}</ErrorNote> : <p className="text-sm text-muted-foreground">Loading…</p>;

  return (
    <div className="space-y-6">
      <section className="rounded-lg border p-4">
        <div className="flex items-start gap-3">
          <Globe2 className="mt-0.5 h-5 w-5 text-primary" aria-hidden="true" />
          <div className="min-w-0 flex-1 space-y-1 text-sm">
            <p className="font-medium">{state.enabled ? `This site talks to other Commonveil sites as ${state.host}.` : "Talking to other sites is turned off."}</p>
            {state.enabled ? (
              <>
                <p className="text-muted-foreground">People here have addresses like <span className="font-mono">@name.{state.handle_domain}</span>. Messages stay end-to-end encrypted; other sites only relay what they can't read.</p>
                <p className="text-muted-foreground break-all">Site key: <span className="font-mono">{state.key}</span></p>
              </>
            ) : (
              <p className="text-muted-foreground">Set <span className="font-mono">FEDERATION=on</span> in your <span className="font-mono">.env</span> and restart to turn it on.</p>
            )}
          </div>
          <Button size="sm" variant="ghost" onClick={refresh} aria-label="Refresh"><RefreshCw className="h-4 w-4" /></Button>
        </div>
      </section>

      {error && <ErrorNote>{error}</ErrorNote>}

      <section className="space-y-2">
        <h3 className="text-sm font-semibold">Sites this one has talked to</h3>
        {state.sites.length === 0 ? (
          <p className="text-sm text-muted-foreground">None yet. Sites appear here the first time someone here talks to someone there.</p>
        ) : (
          <ul className="divide-y rounded-lg border">
            {state.sites.map((s) => (
              <li key={s.host} className="flex flex-wrap items-center gap-3 p-3 text-sm">
                <div className="min-w-0 flex-1">
                  <p className="font-medium">{s.name && s.name !== s.host ? `${s.name} (${s.host})` : s.host}{s.blocked && <span className="ml-2 text-destructive">Blocked</span>}</p>
                  <p className="text-xs text-muted-foreground">First seen {formatDate(s.first_seen)}, last heard from {formatDate(s.last_seen)}</p>
                </div>
                <Button size="sm" variant="outline" disabled={Boolean(busy)} onClick={() => act("accept_new_key", s.host)} title="Use this if the site's admin told you they changed its key">
                  <KeyRound className="mr-1 h-4 w-4" aria-hidden="true" />Accept new key
                </Button>
                <Button size="sm" variant={s.blocked ? "outline" : "destructive"} disabled={Boolean(busy)} onClick={() => act(s.blocked ? "unblock" : "block", s.host)}>
                  <Ban className="mr-1 h-4 w-4" aria-hidden="true" />{s.blocked ? "Unblock" : "Block"}
                </Button>
              </li>
            ))}
          </ul>
        )}
        <p className="text-xs text-muted-foreground">If a site's key changes unexpectedly, this site stops talking to it until you accept the new key. Only do that once its admin has confirmed the change.</p>
      </section>

      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={async (e) => {
          e.preventDefault();
          if (blockHost.trim() && (await act("block", blockHost.trim()))) setBlockHost("");
        }}
      >
        <label className="min-w-[14rem] flex-1 text-sm">
          <span className="mb-1 block font-medium">Block a site before it reaches you</span>
          <Input value={blockHost} onChange={(e) => setBlockHost(e.target.value)} placeholder="example.org" maxLength={253} />
        </label>
        <Button type="submit" variant="outline" disabled={!blockHost.trim() || Boolean(busy)}>Block</Button>
      </form>
    </div>
  );
}
