import React, { useCallback, useEffect, useState } from "react";
import { ArrowUpCircle, CheckCircle2, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { ErrorNote, formatDate } from "@/components/site/bits";
import Markdown from "@/components/site/Markdown";
import { appParams } from "@/lib/app-params";

// Updates for a self-hosted site (server/updates.mjs): what's running, whether a newer release
// is out, an Update button, and the choice of automatic updates. Admins only.

async function ask(method, body) {
  const res = await fetch("/api/admin/updates", {
    method,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${appParams.token || window.localStorage.getItem("base44_access_token") || ""}` },
    body: body ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Couldn't reach the update service.");
  return data;
}

/** The update status, refreshed every so often; null while loading. */
export function useUpdates({ every = 60_000 } = {}) {
  const [state, setState] = useState(null);
  const [error, setError] = useState("");
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
    const t = setInterval(refresh, every);
    return () => clearInterval(t);
  }, [refresh, every]);
  return { state, error, refresh, setState };
}

/** A one-line notice for the top of the admin area, when there's something to install. */
export function UpdateBanner({ onOpen }) {
  const { state } = useUpdates({ every: 10 * 60_000 });
  if (!state?.available) return null;
  return (
    <div className="border-b border-[hsl(var(--primary)/0.3)] bg-[hsl(var(--primary)/0.08)]" role="status">
      <div className="mx-auto flex max-w-5xl flex-wrap items-center gap-3 px-4 py-2 text-sm">
        <ArrowUpCircle className="h-4 w-4 text-primary" aria-hidden="true" />
        <span className="flex-1">Commonveil {state.available.version} is out. This site runs {state.current}.</span>
        <Button size="sm" variant="outline" onClick={onOpen}>See what's new</Button>
      </div>
    </div>
  );
}

export default function UpdatesPanel() {
  const { state, error, setState } = useUpdates({ every: 15_000 });
  const [busy, setBusy] = useState("");
  const [failure, setFailure] = useState("");

  const act = async (what, body) => {
    setBusy(what);
    setFailure("");
    try {
      setState(await ask("POST", body));
    } catch (err) {
      setFailure(err.message);
    } finally {
      setBusy("");
    }
  };

  if (!state) return error ? <ErrorNote>{error}</ErrorNote> : <p className="text-sm text-muted-foreground">Checking…</p>;
  const latest = state.available;

  return (
    <div className="max-w-3xl space-y-6">
      <section className="card-cv p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-sm text-muted-foreground">This site is running</p>
            <p className="text-2xl font-semibold">Commonveil {state.current}</p>
            <p className="mt-1 text-xs text-muted-foreground">
              {state.checked_at ? `Last checked ${formatDate(state.checked_at)} at ${new Date(state.checked_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}.` : "Not checked yet."}
            </p>
          </div>
          <Button variant="outline" onClick={() => act("check", { action: "check" })} disabled={Boolean(busy)}>
            <RefreshCw className={`mr-2 h-4 w-4 ${busy === "check" ? "animate-spin" : ""}`} aria-hidden="true" /> Check now
          </Button>
        </div>
        {state.error && <p className="mt-3 text-sm text-destructive">The last check didn't work: {state.error}</p>}
      </section>

      {state.applying ? (
        <section className="card-cv border-primary/40 p-5" role="status">
          <p className="font-medium">Updating to {state.applying.version}…</p>
          <p className="mt-1 text-sm text-muted-foreground">
            The site restarts on the new version in a minute or two, and this page comes back by itself. A copy of the database was saved first ({state.applying.backup}).
          </p>
        </section>
      ) : latest ? (
        <section className="card-cv p-5">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <p className="flex items-center gap-2 font-medium"><ArrowUpCircle className="h-5 w-5 text-primary" aria-hidden="true" /> Commonveil {latest.version} is available</p>
              {latest.published_at && <p className="mt-1 text-xs text-muted-foreground">Released {formatDate(latest.published_at)}</p>}
            </div>
            {state.can_apply ? (
              <Button onClick={() => act("apply", { action: "apply", version: latest.version })} disabled={Boolean(busy)}>
                {busy === "apply" ? "Starting…" : `Update to ${latest.version}`}
              </Button>
            ) : null}
          </div>
          {latest.notes && <div className="mt-4 rounded-lg bg-muted/40 p-4 text-sm"><Markdown>{latest.notes}</Markdown></div>}
          {(state.newer || []).length > 1 && <p className="mt-3 text-xs text-muted-foreground">This includes {state.newer.length} releases since yours.</p>}
          {latest.url && <a href={latest.url} target="_blank" rel="noopener noreferrer" className="mt-3 inline-block text-sm text-primary underline-offset-4 hover:underline">Full release notes</a>}
          {!state.can_apply && (
            <p className="mt-4 text-sm text-muted-foreground">
              This site has no updater, so update from the server: <code className="rounded bg-muted px-1">docker compose pull &amp;&amp; docker compose up -d</code>
            </p>
          )}
        </section>
      ) : (
        <section className="card-cv flex items-center gap-3 p-5">
          <CheckCircle2 className="h-5 w-5 text-[hsl(var(--success,142_60%_40%))]" aria-hidden="true" />
          <p>You're on the newest release.</p>
        </section>
      )}

      <section className="card-cv p-5">
        <label className="flex items-start gap-3">
          <Checkbox checked={state.auto} disabled={!state.can_apply || Boolean(busy)} onCheckedChange={(v) => act("auto", { action: "set_auto", auto: Boolean(v) })} className="mt-0.5" />
          <span>
            <span className="block font-medium">Install updates automatically</span>
            <span className="block text-sm text-muted-foreground">
              New releases are installed in the background soon after they come out, with a copy of the database saved first. If a new version doesn't start properly, the site goes back to the one before. Off: you'll see each release here and choose when to install it.
            </span>
          </span>
        </label>
      </section>
      <ErrorNote>{failure}</ErrorNote>
    </div>
  );
}
