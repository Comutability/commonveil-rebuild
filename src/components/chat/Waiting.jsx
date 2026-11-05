import React, { useCallback, useEffect, useState } from "react";
import { Clock, HeartHandshake, X } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { NativeSelect } from "@/components/ui/native-select";
import { useChat } from "@/lib/secure/ChatContext";

const CHECKIN = [[1, "1 hour"], [2, "2 hours"], [4, "4 hours"], [8, "8 hours"], [12, "12 hours"], [24, "1 day"], [48, "2 days"], [72, "3 days"], [168, "1 week"]];
const localInput = (d) => new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);

function left(iso) {
  const ms = Date.parse(iso) - Date.now();
  if (ms <= 0) return "any moment now";
  const m = Math.round(ms / 60_000);
  if (m < 60) return `in ${m} min`;
  const h = Math.round(m / 60);
  if (h < 48) return `in ${h} h`;
  return `in ${Math.round(h / 24)} days`;
}

/**
 * Write now, deliver later (mode "later"), or a safety check-in (mode "checkin"): a message that
 * goes out by itself if you don't tap "I'm OK" in time.
 */
export function WaitDialog({ conversation, mode, open, onOpenChange, onDone }) {
  const { scheduleMessage } = useChat();
  const [text, setText] = useState("");
  const [when, setWhen] = useState("");
  const [hours, setHours] = useState(4);
  const [state, setState] = useState({ busy: false, error: "" });
  useEffect(() => {
    if (!open) return;
    setText(mode === "checkin" ? "I haven't checked in when I said I would. Please try to reach me, and if you can't, check on me." : "");
    setWhen(localInput(new Date(Date.now() + 3600_000)));
    setHours(4);
    setState({ busy: false, error: "" });
  }, [open, mode]);
  const submit = async (e) => {
    e.preventDefault();
    setState({ busy: true, error: "" });
    try {
      await scheduleMessage(conversation, text, mode === "checkin" ? { checkinHours: hours } : { deliverAt: new Date(when) });
      onDone?.();
      onOpenChange(false);
    } catch (err) {
      setState({ busy: false, error: err.message });
    }
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{mode === "checkin" ? "Safety check-in" : "Send later"}</DialogTitle>
          <DialogDescription>
            {mode === "checkin"
              ? "If you don't tap \"I'm OK\" in time, this message is sent here by itself. Useful for a first date, a long walk or a trip. It's encrypted now; nobody sees it unless it's sent."
              : "It's encrypted now and held, unreadable, until then. Only the people here now can read it."}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="wait-text">Message</Label>
            <Textarea id="wait-text" value={text} onChange={(e) => setText(e.target.value)} rows={4} maxLength={4000} required />
          </div>
          {mode === "checkin" ? (
            <div className="space-y-1.5">
              <Label htmlFor="wait-hours">Check in within</Label>
              <NativeSelect id="wait-hours" value={String(hours)} onChange={(e) => setHours(Number(e.target.value))}>
                {CHECKIN.map(([v, l]) => <option key={v} value={String(v)}>{l}</option>)}
              </NativeSelect>
              <p className="text-xs text-muted-foreground">Each "I'm OK" gives you the same time again. Delivery can be up to a few minutes late.</p>
            </div>
          ) : (
            <div className="space-y-1.5">
              <Label htmlFor="wait-when">Deliver</Label>
              <Input id="wait-when" type="datetime-local" value={when} onChange={(e) => setWhen(e.target.value)} required />
              <p className="text-xs text-muted-foreground">Up to a year ahead. It can arrive a few minutes after the time you choose.</p>
            </div>
          )}
          {state.error && <p className="text-sm text-destructive" role="alert">{state.error}</p>}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button type="submit" disabled={state.busy || !text.trim()}>{state.busy ? "Sealing…" : mode === "checkin" ? "Start check-in" : "Schedule"}</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** What you've got waiting in this conversation: scheduled messages and check-ins. */
export function WaitingBar({ conversation, tick }) {
  const { loadScheduled, cancelScheduled, checkIn } = useChat();
  const [items, setItems] = useState([]);
  const [error, setError] = useState("");
  const [, setNow] = useState(0);
  const refresh = useCallback(() => loadScheduled(conversation.id).then(setItems).catch(() => {}), [conversation.id, loadScheduled]);
  useEffect(() => {
    refresh();
    const t = setInterval(() => setNow((n) => n + 1), 30_000);
    return () => clearInterval(t);
  }, [refresh, tick]);
  if (!items.length) return null;
  const act = (fn) => fn().then(refresh).catch((err) => setError(err.message));
  return (
    <div className="border-b border-border bg-muted/40 px-3 py-2 sm:px-4" aria-label="Waiting to be sent">
      <ul className="space-y-1.5">
        {items.map((s) => (
          <li key={s.id} className="flex items-center gap-2 text-sm">
            {s.kind === "checkin" ? <HeartHandshake className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" /> : <Clock className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />}
            <span className="min-w-0 flex-1 truncate">
              <span className="font-medium">{s.kind === "checkin" ? `Check-in: sent ${left(s.deliver_at)} unless you're OK` : `Sends ${left(s.deliver_at)}`}</span>
              <span className="text-muted-foreground"> · {s.text || "…"}</span>
            </span>
            {s.kind === "checkin" && <Button size="sm" onClick={() => act(() => checkIn(s.id))}>I'm OK</Button>}
            <Button size="sm" variant="ghost" onClick={() => act(() => cancelScheduled(s.id))} aria-label={s.kind === "checkin" ? "End check-in" : "Cancel scheduled message"}>
              <X className="h-4 w-4" aria-hidden="true" />
            </Button>
          </li>
        ))}
      </ul>
      {error && <p className="mt-1 text-xs text-destructive" role="alert">{error}</p>}
    </div>
  );
}
