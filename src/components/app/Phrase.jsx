import React, { useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { ErrorNote } from "@/components/site/bits";

/** The 24 words, numbered, for writing down. */
export function PhraseGrid({ phrase }) {
  const words = phrase.split(" ");
  return (
    <ol className="grid grid-cols-2 gap-2 rounded-xl border border-border bg-muted/50 p-4 sm:grid-cols-3 md:grid-cols-4" aria-label="Recovery phrase, 24 words">
      {words.map((w, i) => (
        <li key={i} className="flex items-baseline gap-2 rounded-md bg-card px-3 py-2">
          <span className="w-6 text-right text-xs tabular-nums text-muted-foreground">{i + 1}</span>
          <span className="mono text-[0.95rem] font-medium">{w}</span>
        </li>
      ))}
    </ol>
  );
}

/** Show the phrase, then ask for three of its words back before continuing. */
export function PhraseCheckpoint({ phrase, onConfirmed, confirmLabel = "Finish", busy = false, error }) {
  const [written, setWritten] = useState(false);
  const [checking, setChecking] = useState(false);
  const words = phrase.split(" ");
  const picks = useMemo(() => {
    const idx = new Set();
    const rnd = new Uint32Array(8);
    globalThis.crypto.getRandomValues(rnd);
    for (const r of rnd) {
      idx.add(r % words.length);
      if (idx.size === 3) break;
    }
    return [...idx].sort((a, b) => a - b);
  }, [phrase, words.length]);
  const [answers, setAnswers] = useState({});
  const [mismatch, setMismatch] = useState(false);

  if (!checking) {
    return (
      <div className="space-y-5">
        <PhraseGrid phrase={phrase} />
        <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
          <li>Write the words on paper, in order. Keep it somewhere safe and private.</li>
          <li>Don't screenshot it, email it or store it in notes that sync. Anyone with these words can read your messages.</li>
          <li>We can't show it again or recover it for you.</li>
        </ul>
        <label className="flex items-start gap-3 text-sm">
          <Checkbox checked={written} onCheckedChange={(v) => setWritten(Boolean(v))} className="mt-0.5" />
          <span>I've written down all 24 words, in order.</span>
        </label>
        <Button onClick={() => setChecking(true)} disabled={!written}>Continue</Button>
      </div>
    );
  }

  const submit = (e) => {
    e.preventDefault();
    const ok = picks.every((i) => (answers[i] || "").trim().toLowerCase() === words[i]);
    setMismatch(!ok);
    if (ok) onConfirmed();
  };

  return (
    <form onSubmit={submit} className="space-y-5">
      <p className="text-sm text-muted-foreground">To make sure it's written down correctly, enter these words from your phrase.</p>
      <div className="grid gap-4 sm:grid-cols-3">
        {picks.map((i) => (
          <div key={i} className="space-y-1.5">
            <Label htmlFor={`w${i}`}>Word {i + 1}</Label>
            <Input
              id={`w${i}`}
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              className="mono"
              value={answers[i] || ""}
              onChange={(e) => setAnswers((a) => ({ ...a, [i]: e.target.value }))}
            />
          </div>
        ))}
      </div>
      {mismatch && <ErrorNote>Those don't match. Check your paper copy, or go back and look again.</ErrorNote>}
      <ErrorNote>{error}</ErrorNote>
      <div className="flex gap-3">
        <Button type="submit" disabled={busy}>{busy ? "Working…" : confirmLabel}</Button>
        <Button type="button" variant="ghost" onClick={() => setChecking(false)} disabled={busy}>Show the words again</Button>
      </div>
    </form>
  );
}
