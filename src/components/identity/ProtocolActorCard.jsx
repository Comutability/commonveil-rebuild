import React, { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, Loader2, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ErrorNote, Pill, formatDate } from "@/components/site/bits";
import { callFn } from "@/lib/api";
import { useSecure } from "@/lib/secure/SecureContext";
import { useChat } from "@/lib/secure/ChatContext";
import { describeActor, problemText } from "@/lib/identity/protocolIdentity";

function Row({ label, children }) {
  return (
    <div className="flex flex-col gap-0.5 border-b border-border/60 py-2 last:border-b-0 sm:flex-row sm:gap-4">
      <dt className="w-40 shrink-0 text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-sm">{children}</dd>
    </div>
  );
}

/** The actor this account published to Commonveil, checked on this device rather than taken on trust. */
export default function ProtocolActorCard() {
  const { me } = useSecure();
  const { pq } = useChat();
  const [state, setState] = useState({ loading: true, error: "", actor: null, info: null });
  const username = me?.profile?.username || "";
  const expected = username ? `${username.toLowerCase()}@${window.location.host.toLowerCase()}` : "";

  const load = useCallback(async () => {
    if (!username) {
      setState({ loading: false, error: "", actor: null, info: null });
      return;
    }
    setState((s) => ({ ...s, loading: true, error: "" }));
    try {
      const { actor } = await callFn("protocol", { action: "mine" });
      const info = actor ? describeActor(JSON.parse(actor.document), { handle: expected }) : null;
      setState({ loading: false, error: "", actor, info });
    } catch (error) {
      setState({ loading: false, error: error.message || "Your protocol identity couldn't be read.", actor: null, info: null });
    }
  }, [username, expected]);

  useEffect(() => {
    load();
  }, [load]);

  if (state.loading) {
    return (
      <p className="flex items-center gap-2 text-sm text-muted-foreground" role="status">
        <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Checking your actor document…
      </p>
    );
  }

  if (state.error) {
    return (
      <div className="space-y-3">
        <ErrorNote>{state.error}</ErrorNote>
        <Button size="sm" variant="outline" onClick={load}>Try again</Button>
      </div>
    );
  }

  if (!state.actor) {
    return (
      <div className="space-y-2 text-sm">
        <p className="font-medium">No protocol actor yet</p>
        <p className="max-w-prose text-muted-foreground">
          A protocol actor is a Secure Net identity (CVP-017): a quantum-resistant account key, a signed document saying what it's called and which devices speak for it, and a handle. Commonveil makes one for you the first time you turn the protocol layer on for a device. Until then this account has none, and nothing here is published.
        </p>
        <Button asChild size="sm" variant="outline">
          <Link to="/app/settings/keys">Go to Devices and keys</Link>
        </Button>
      </div>
    );
  }

  const info = state.info;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {info?.ok ? (
          <Pill tone="accent"><ShieldCheck className="mr-1 h-3.5 w-3.5" aria-hidden="true" />Verified on this device</Pill>
        ) : (
          <Pill tone="warn"><AlertTriangle className="mr-1 h-3.5 w-3.5" aria-hidden="true" />Not verified</Pill>
        )}
        <Pill tone={pq.status.enabled ? "accent" : "muted"}>{pq.status.enabled ? "In use on this device" : "Not turned on for this device"}</Pill>
      </div>

      <dl>
        <Row label="Handle"><span className="font-mono break-all">{info?.handle || "—"}</span></Row>
        <Row label="Actor ID"><span className="font-mono text-xs break-all">{info?.id || "—"}</span></Row>
        <Row label="Fingerprint"><span className="font-mono">{info?.fingerprint || "—"}</span></Row>
        <Row label="Account key">{info?.account?.includes(".") ? "Ed25519 + ML-DSA-65 (quantum-resistant)" : "Not quantum-resistant"}</Row>
        <Row label="Devices">{info ? `${info.devices.length} in this actor document${info.former ? `, ${info.former} removed earlier` : ""}` : "—"}</Row>
        <Row label="Version">{info?.seq != null ? `seq ${info.seq}` : "—"}</Row>
        <Row label="Updated">{info?.updated ? formatDate(info.updated) : "—"}</Row>
        <Row label="Actor type">{info?.type || "—"}</Row>
      </dl>

      {!info?.ok && info?.problems?.length > 0 && (
        <div className="rounded-lg border border-[hsl(var(--warning)/0.45)] bg-[hsl(var(--warning)/0.08)] p-3 text-sm">
          <p className="font-medium">This document doesn't check out here.</p>
          <ul className="mt-1 list-disc space-y-1 pl-5 text-muted-foreground">
            {info.problems.map((p) => <li key={p}>{problemText(info.code, p)}</li>)}
          </ul>
          <p className="mt-1 text-muted-foreground">Don't compare this fingerprint with anyone until it verifies: a site can serve a document that doesn't match the key it names.</p>
        </div>
      )}

      <p className="max-w-prose text-sm text-muted-foreground">
        The fingerprint is the first 8 characters of the actor's key id, for reading out when comparing identities. The check happens here in your browser: the site stores the document, it can't alter it without the signature failing.
      </p>

      <div className="rounded-lg border border-border bg-muted/40 p-3 text-sm">
        <p className="font-medium">Your actor is one implementation, not the only one</p>
        <p className="mt-1 text-muted-foreground">
          Secure Net is a transport: an inbox, an outbox and a relay between sites. It doesn't hand out identities. Anyone can make a CVP-017 actor with any compatible application, entirely offline, and bring it here: this Commonveil actor is simply the one this app made for you. Sites relay and store; the key decides who an actor is. Nothing in an actor document grants access to an account, and being able to read one doesn't mean its owner agreed to anything.
        </p>
      </div>
    </div>
  );
}