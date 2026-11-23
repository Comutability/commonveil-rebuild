import React, { useState } from "react";
import { AlertTriangle, FileUp, Loader2, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { ErrorNote, Pill, formatDate } from "@/components/site/bits";
import { describeActor, parseActorJson, problemText } from "@/lib/identity/protocolIdentity";
import { rememberActor, seenActor } from "@/lib/identity/seenActors";

const shortKid = (kid) => (kid ? `${kid.slice(0, 8)}…` : "");

/**
 * Check an actor document made somewhere else. Everything happens in this browser: the file is
 * read locally and never uploaded, and nothing is written to the account. A document that verifies
 * says a key exists and signed this version; it never says who owns it.
 */
export default function ExternalActorVerify() {
  const [text, setText] = useState("");
  const [state, setState] = useState({ busy: false, error: "", result: null });

  const check = async () => {
    setState({ busy: true, error: "", result: null });
    try {
      const record = parseActorJson(text);
      const claimed = record?.body && typeof record.body.id === "string" ? record.body.id : "";
      const previous = claimed ? seenActor(claimed) : null;
      const info = describeActor(record, { minSeq: previous?.seq || 0 });
      if (info.ok) rememberActor(info.id, { seq: info.seq, handle: info.handle });
      setState({ busy: false, error: "", result: { info, previous } });
    } catch (error) {
      setState({ busy: false, error: error.message || "That document couldn't be read.", result: null });
    }
  };

  const choose = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size > 256 * 1024) {
      setState({ busy: false, error: "That file is larger than an actor document can be.", result: null });
      return;
    }
    try {
      const content = await file.text();
      setText(content);
      setState({ busy: false, error: "", result: null });
    } catch {
      setState({ busy: false, error: "That file couldn't be read.", result: null });
    }
  };

  const info = state.result?.info;
  const previous = state.result?.previous;

  return (
    <div className="space-y-3">
      <div>
        <Label htmlFor="actor-document" className="text-sm">Actor document (JSON)</Label>
        <Textarea
          id="actor-document"
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={6}
          spellCheck={false}
          placeholder={'{ "kind": "actor.document", "body": { "handle": "name@host", … }, "sig": { … } }'}
          className="mt-1 font-mono text-xs"
        />
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <Input
          type="file"
          accept="application/json,.json"
          onChange={choose}
          className="h-auto w-auto cursor-pointer py-1.5 text-xs file:mr-3 file:rounded file:border-0 file:bg-secondary file:px-2 file:py-1 file:text-xs"
          aria-label="Choose an actor document file"
        />
        <Button size="sm" onClick={check} disabled={state.busy || !text.trim()}>
          {state.busy ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" aria-hidden="true" /> : <FileUp className="mr-1.5 h-4 w-4" aria-hidden="true" />}
          {state.busy ? "Checking…" : "Check it"}
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">
        Checked here in your browser. The file is read locally and never uploaded, and nothing is saved to your account. Secure Net is the transport; this check uses its own rules, from the frozen library, not a site's word.
      </p>

      <ErrorNote>{state.error}</ErrorNote>

      {info && (
        <div className="space-y-3 rounded-lg border border-border p-3">
          <div className="flex flex-wrap items-center gap-2">
            {info.ok ? (
              <Pill tone="accent"><ShieldCheck className="mr-1 h-3.5 w-3.5" aria-hidden="true" />Signature verified</Pill>
            ) : (
              <Pill tone="warn"><AlertTriangle className="mr-1 h-3.5 w-3.5" aria-hidden="true" />Not verified</Pill>
            )}
            <Pill tone="muted">{info.type || "Actor"}</Pill>
            {info.discoverable ? null : <Pill tone="muted">Not listed publicly</Pill>}
          </div>

          <dl className="text-sm">
            <div className="flex flex-col gap-0.5 border-b border-border/60 py-1.5 sm:flex-row sm:gap-4">
              <dt className="w-32 shrink-0 text-xs uppercase tracking-wide text-muted-foreground">Handle</dt>
              <dd className="font-mono break-all">{info.handle || "—"}{info.name ? <span className="ml-2 font-body text-muted-foreground">({info.name})</span> : null}</dd>
            </div>
            <div className="flex flex-col gap-0.5 border-b border-border/60 py-1.5 sm:flex-row sm:gap-4">
              <dt className="w-32 shrink-0 text-xs uppercase tracking-wide text-muted-foreground">Actor ID</dt>
              <dd className="font-mono text-xs break-all">{info.id || "—"}</dd>
            </div>
            <div className="flex flex-col gap-0.5 border-b border-border/60 py-1.5 sm:flex-row sm:gap-4">
              <dt className="w-32 shrink-0 text-xs uppercase tracking-wide text-muted-foreground">Fingerprint</dt>
              <dd className="font-mono">{info.fingerprint || "—"}</dd>
            </div>
            <div className="flex flex-col gap-0.5 border-b border-border/60 py-1.5 sm:flex-row sm:gap-4">
              <dt className="w-32 shrink-0 text-xs uppercase tracking-wide text-muted-foreground">Account key</dt>
              <dd>{info.account?.includes(".") ? "Ed25519 + ML-DSA-65" : "Not quantum-resistant"}</dd>
            </div>
            <div className="flex flex-col gap-0.5 border-b border-border/60 py-1.5 sm:flex-row sm:gap-4">
              <dt className="w-32 shrink-0 text-xs uppercase tracking-wide text-muted-foreground">Version</dt>
              <dd>
                seq {info.seq ?? "—"}
                {previous?.seq ? <span className="text-muted-foreground"> · this browser last accepted seq {previous.seq}</span> : <span className="text-muted-foreground"> · first version seen here</span>}
              </dd>
            </div>
            <div className="flex flex-col gap-0.5 border-b border-border/60 py-1.5 sm:flex-row sm:gap-4">
              <dt className="w-32 shrink-0 text-xs uppercase tracking-wide text-muted-foreground">Devices</dt>
              <dd className="font-mono text-xs">
                {info.devices.length ? info.devices.map(shortKid).join(", ") : "none"}
                {info.former ? <span className="ml-2 font-body text-muted-foreground">{info.former} listed as removed earlier</span> : null}
              </dd>
            </div>
            <div className="flex flex-col gap-0.5 py-1.5 sm:flex-row sm:gap-4">
              <dt className="w-32 shrink-0 text-xs uppercase tracking-wide text-muted-foreground">Signed</dt>
              <dd>{info.updated ? formatDate(info.updated) : "—"}</dd>
            </div>
          </dl>

          {info.ok ? (
            <p className="text-sm text-muted-foreground">
              The hybrid key signed this version, the id is that key's id, and the device list inside it is signed by the same key. One thing it doesn't show: that whoever is signed in here owns it.
            </p>
          ) : (
            <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
              {info.problems.map((p) => <li key={p}>{problemText(info.code, p)}</li>)}
              <li>Nothing was saved: a document that doesn't verify is never remembered.</li>
            </ul>
          )}
        </div>
      )}

      <div className="rounded-lg border border-border bg-muted/40 p-3 text-sm">
        <p className="flex items-center gap-1.5 font-medium"><AlertTriangle className="h-4 w-4 text-[hsl(var(--warning))]" aria-hidden="true" />Attaching an outside actor to your account is off</p>
        <p className="mt-1 text-muted-foreground">
          A verified document is public and copyable, so on its own it can't prove anything about you or give you anything here. Attaching one would need both of these:
        </p>
        <ol className="mt-2 list-decimal space-y-1 pl-5 text-muted-foreground">
          <li>A fresh one-off challenge from this site's server that the outside actor's own quantum-resistant key signs, so a copied document is useless and an old answer can't be replayed.</li>
          <li>A signature from one of this account's currently certified devices over that same challenge, so nobody can attach someone else's actor to a stranger's account.</li>
        </ol>
        <p className="mt-2 text-muted-foreground">
          Neither is built, so this screen only ever reads. There is no path here that makes an outside actor your identity, and no document is ever treated as proof of ownership.
        </p>
      </div>
    </div>
  );
}