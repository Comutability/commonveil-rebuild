import React, { useState } from "react";
import { BarChart3, Check, Lock } from "lucide-react";

function untilText(iso, closed) {
  if (!iso) return "";
  const ms = Date.parse(iso) - Date.now();
  if (closed || ms <= 0) return "Poll closed";
  const h = Math.round(ms / 3600_000);
  if (h < 1) return `Closes in ${Math.max(1, Math.round(ms / 60_000))} min`;
  if (h < 48) return `Closes in ${h} ${h === 1 ? "hour" : "hours"}`;
  return `Closes in ${Math.round(h / 24)} days`;
}

/**
 * A poll and its results, counted on this device from everyone's encrypted votes.
 * poll: from thread.js (question, options with counts, mine, voters, closed, multi).
 * onVote(choices) sends your choices; an empty list takes your vote back.
 */
export default function PollCard({ poll, onVote, disabled = false, nameOf = (id) => id }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [draft, setDraft] = useState(null);
  const voted = poll.mine.length > 0;
  const showResults = voted || poll.closed;
  const picks = draft ?? poll.mine;

  const send = async (choices) => {
    setBusy(true);
    setError("");
    try {
      await onVote(choices);
      setDraft(null);
    } catch (err) {
      setError(err.message || "Your vote didn't go through. Try again.");
    } finally {
      setBusy(false);
    }
  };

  const choose = (i) => {
    if (disabled || busy || poll.closed) return;
    if (!poll.multi) {
      send(poll.mine.includes(i) ? [] : [i]);
      return;
    }
    const next = picks.includes(i) ? picks.filter((c) => c !== i) : [...picks, i];
    setDraft(next);
  };

  return (
    <div className="mt-1 max-w-md rounded-lg border border-border bg-card p-3" role="group" aria-label={`Poll: ${poll.question}`}>
      <p className="flex items-start gap-2 font-semibold leading-snug">
        <BarChart3 className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
        <span className="min-w-0 break-words">{poll.question}</span>
      </p>
      <p className="mt-0.5 text-xs text-muted-foreground">{poll.multi ? "Choose any number" : "Choose one"}</p>
      <ul className="mt-2 space-y-1.5">
        {poll.options.map((o, i) => {
          const share = poll.voters ? Math.round((o.count / poll.voters) * 100) : 0;
          const picked = picks.includes(i);
          return (
            <li key={i}>
              <button
                type="button"
                onClick={() => choose(i)}
                disabled={disabled || busy || poll.closed}
                aria-pressed={picked}
                title={showResults && o.people.length ? o.people.map(nameOf).join(", ") : undefined}
                className={`relative flex w-full items-center gap-2 overflow-hidden rounded-md border px-3 py-2 text-left text-sm transition-colors disabled:cursor-default ${picked ? "border-primary/70" : "border-border hover:border-primary/40"}`}
              >
                {showResults && <span className="absolute inset-y-0 left-0 bg-primary/15" style={{ width: `${share}%` }} aria-hidden="true" />}
                <span className={`relative flex h-4 w-4 shrink-0 items-center justify-center ${poll.multi ? "rounded-sm" : "rounded-full"} border ${picked ? "border-primary bg-primary text-primary-foreground" : "border-muted-foreground/50"}`} aria-hidden="true">
                  {picked && <Check className="h-3 w-3" />}
                </span>
                <span className="relative min-w-0 flex-1 break-words">{o.text}</span>
                {showResults && <span className="relative shrink-0 text-xs font-medium text-muted-foreground">{share}% ({o.count})</span>}
              </button>
            </li>
          );
        })}
      </ul>
      {error && <p className="mt-2 text-sm text-destructive" role="alert">{error}</p>}
      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
        <span>{poll.voters} {poll.voters === 1 ? "vote" : "votes"}</span>
        <span>{untilText(poll.endsAt, poll.closed)}</span>
        <span className="inline-flex items-center gap-1"><Lock className="h-3 w-3" aria-hidden="true" /> Votes are encrypted</span>
        {poll.multi && draft && !poll.closed && (
          <button type="button" disabled={busy} onClick={() => send(draft)} className="font-medium text-primary hover:underline">
            {draft.length ? "Vote" : "Clear my vote"}
          </button>
        )}
        {!poll.multi && voted && !poll.closed && (
          <button type="button" disabled={busy} onClick={() => send([])} className="font-medium text-primary hover:underline">Remove my vote</button>
        )}
      </div>
    </div>
  );
}
