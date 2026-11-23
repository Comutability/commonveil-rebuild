import React, { useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, Check, Info, Loader2, Server } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ErrorNote } from "@/components/site/bits";
import { checkDestination } from "@/lib/identity/siteDiscovery";

const ICONS = { ok: Check, gap: AlertTriangle, note: Info };
const TONES = { ok: "text-primary", gap: "text-[hsl(var(--warning))]", note: "text-muted-foreground" };

/**
 * Preparation only: one public question to another site, and what it answers. Nothing about this
 * account, its actor, its keys or its messages is sent, and nothing is deleted or switched over.
 */
export default function MigrationChecklist() {
  const [host, setHost] = useState("");
  const [state, setState] = useState({ busy: false, error: "", report: null });

  const run = async () => {
    setState({ busy: true, error: "", report: null });
    try {
      const report = await checkDestination(host);
      setState({ busy: false, error: "", report });
    } catch (error) {
      setState({ busy: false, error: error.message || "That address couldn't be checked.", report: null });
    }
  };

  const report = state.report;

  return (
    <div className="space-y-4">
      <div>
        <Label htmlFor="destination-host" className="text-sm">The other site's address</Label>
        <div className="mt-1 flex flex-wrap gap-2">
          <Input
            id="destination-host"
            value={host}
            onChange={(e) => setHost(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !state.busy && host.trim() && run()}
            placeholder="friend.example.org"
            inputMode="url"
            autoComplete="off"
            spellCheck={false}
            className="min-w-0 flex-1 sm:max-w-sm"
          />
          <Button size="sm" onClick={run} disabled={state.busy || !host.trim()}>
            {state.busy ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" aria-hidden="true" /> : <Server className="mr-1.5 h-4 w-4" aria-hidden="true" />}
            {state.busy ? "Checking…" : "Check it"}
          </Button>
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        This asks the other site one public question: its own site document, over HTTPS. Only https names that anyone can reach are checked; local and numeric addresses are refused, redirects are not followed, and the reply is capped. Nothing about you, your actor, your keys or your messages goes with it.
      </p>

      <ErrorNote>{state.error}</ErrorNote>

      {report && (
        <div className="space-y-3 rounded-lg border border-border p-3">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <p className="font-medium">{report.doc?.name ? String(report.doc.name) : report.host}</p>
            <p className="font-mono text-xs text-muted-foreground">{report.host}</p>
          </div>
          <p className={`text-sm ${report.ok ? "text-primary" : "text-[hsl(var(--warning))]"}`}>
            {report.ok
              ? "No gaps in what it advertises. A move would still need the parts below that aren't built."
              : `${report.gaps} ${report.gaps === 1 ? "gap" : "gaps"} would stop a move to this site today.`}
          </p>
          <ul className="space-y-2">
            {report.items.map((item) => {
              const Icon = ICONS[item.state] || Info;
              return (
                <li key={item.id} className="flex gap-2 text-sm">
                  <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${TONES[item.state]}`} aria-hidden="true" />
                  <span>
                    <span className="font-medium">{item.label}</span>
                    <span className="block text-xs text-muted-foreground">{item.detail}</span>
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
      )}

      <div className="rounded-lg border border-border bg-muted/40 p-3 text-sm">
        <p className="font-medium">What you can prepare now</p>
        <ul className="mt-1 list-disc space-y-1 pl-5 text-muted-foreground">
          <li>Your protocol actor, shown above, is the identity that would move.</li>
          <li>
            <Link to="/app/settings/passport" className="text-primary underline-offset-4 hover:underline">Export an identity passport</Link>: a signed, encrypted copy of your ownership key, contacts and messages that only your recovery phrase opens.
          </li>
          <li>Note the fingerprints you'd compare with people afterwards, before anything changes.</li>
        </ul>
        <p className="mt-2 font-medium">What isn't built, and isn't claimed here</p>
        <ul className="mt-1 list-disc space-y-1 pl-5 text-muted-foreground">
          <li>Moving the account or the actor to another site, with a signed notice the destination accepts.</li>
          <li>Copying message history across, or continuing a conversation on two sites at once.</li>
          <li>Deleting anything at this site, or switching it over. Neither happens on this screen, and neither is implemented.</li>
          <li>Cross-instance tests. Until two real sites exchange and check each other's messages, routing stays exactly as it is.</li>
        </ul>
      </div>
    </div>
  );
}