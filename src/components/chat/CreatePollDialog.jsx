import React, { useEffect, useState } from "react";
import { Plus, X } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { POLL_DURATIONS, POLL_LIMITS, pollPayload } from "@/lib/secure/polls";

const DURATION_LABEL = { 3600: "1 hour", 14400: "4 hours", 28800: "8 hours", 86400: "1 day", 259200: "3 days", 604800: "1 week" };

/** Make a poll. onCreate(payload) sends it. */
export default function CreatePollDialog({ open, onOpenChange, onCreate }) {
  const [question, setQuestion] = useState("");
  const [options, setOptions] = useState(["", ""]);
  const [multi, setMulti] = useState(false);
  const [duration, setDuration] = useState(86_400);
  const [state, setState] = useState({ busy: false, error: "" });

  useEffect(() => {
    if (open) {
      setQuestion("");
      setOptions(["", ""]);
      setMulti(false);
      setDuration(86_400);
      setState({ busy: false, error: "" });
    }
  }, [open]);

  const submit = async (e) => {
    e.preventDefault();
    setState({ busy: true, error: "" });
    try {
      await onCreate(pollPayload({ question, options, multi, durationSeconds: duration }));
      onOpenChange(false);
    } catch (err) {
      setState({ busy: false, error: err.message });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <form onSubmit={submit} className="space-y-4">
          <DialogHeader>
            <DialogTitle>Create a poll</DialogTitle>
            <DialogDescription>The question, answers and votes are encrypted. Commonveil can't see who voted for what.</DialogDescription>
          </DialogHeader>
          <div className="space-y-1.5">
            <Label htmlFor="poll-q">Question</Label>
            <Input id="poll-q" value={question} onChange={(e) => setQuestion(e.target.value)} maxLength={POLL_LIMITS.question} required autoFocus />
          </div>
          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">Answers</legend>
            {options.map((o, i) => (
              <div key={i} className="flex items-center gap-2">
                <Input value={o} onChange={(e) => setOptions((all) => all.map((x, j) => (j === i ? e.target.value : x)))} maxLength={POLL_LIMITS.option} aria-label={`Answer ${i + 1}`} placeholder={`Answer ${i + 1}`} />
                {options.length > POLL_LIMITS.minOptions && (
                  <button type="button" onClick={() => setOptions((all) => all.filter((_, j) => j !== i))} className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground" aria-label={`Remove answer ${i + 1}`}>
                    <X className="h-4 w-4" aria-hidden="true" />
                  </button>
                )}
              </div>
            ))}
            {options.length < POLL_LIMITS.maxOptions && (
              <Button type="button" variant="ghost" size="sm" onClick={() => setOptions((all) => [...all, ""])}>
                <Plus className="mr-1 h-4 w-4" aria-hidden="true" /> Add an answer
              </Button>
            )}
          </fieldset>
          <div className="flex flex-wrap items-center gap-4">
            <label className="flex items-center gap-2 text-sm">
              <Checkbox checked={multi} onCheckedChange={(v) => setMulti(Boolean(v))} />
              Allow more than one answer
            </label>
            <label className="flex items-center gap-2 text-sm">
              Runs for
              <select value={duration} onChange={(e) => setDuration(Number(e.target.value))} className="rounded-md border border-input bg-background px-2 py-1 text-sm">
                {POLL_DURATIONS.map((d) => <option key={d} value={d}>{DURATION_LABEL[d]}</option>)}
              </select>
            </label>
          </div>
          {state.error && <p className="text-sm text-destructive" role="alert">{state.error}</p>}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button type="submit" disabled={state.busy}>{state.busy ? "Encrypting…" : "Post poll"}</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
