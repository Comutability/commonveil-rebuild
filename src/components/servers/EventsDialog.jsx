import React, { useCallback, useEffect, useMemo, useState } from "react";
import { CalendarDays, CalendarPlus, Download, Loader2, MapPin, Volume2 } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { NativeSelect } from "@/components/ui/native-select";
import { useServers } from "@/lib/secure/ServerContext";
import { useSecure } from "@/lib/secure/SecureContext";
import { P } from "@/lib/secure/permissions";

const when = (iso) => new Date(iso).toLocaleString("en-GB", { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
const localInput = (d) => new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
const endOf = (ev) => (ev.ends_at ? Date.parse(ev.ends_at) : Date.parse(ev.starts_at) + 2 * 3600_000);

/** A calendar file made on this device, so adding an event to a calendar shares it with nobody. */
function icsFor(ev, serverName) {
  const stamp = (t) => new Date(t).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const esc = (s) => String(s || "").replace(/\\/g, "\\\\").replace(/;/g, "\\;").replace(/,/g, "\\,").replace(/\r?\n/g, "\\n");
  return [
    "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Commonveil//Events//EN", "BEGIN:VEVENT",
    `UID:${ev.id}@commonveil`, `DTSTAMP:${stamp(Date.now())}`, `DTSTART:${stamp(ev.starts_at)}`, `DTEND:${stamp(endOf(ev))}`,
    `SUMMARY:${esc(ev.title)}`, `DESCRIPTION:${esc(ev.description)}`, `LOCATION:${esc(ev.where || serverName)}`,
    "END:VEVENT", "END:VCALENDAR", "",
  ].join("\r\n");
}

function download(name, text) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/calendar" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** The server's events, decrypted here, with their answers counted here. */
export function useServerEvents(serverId, active = true) {
  const { loadEvents, openItemOf, keyState } = useServers();
  const { userId, peers } = useSecure();
  const [state, setState] = useState({ loading: true, error: "", events: [] });
  const [tick, setTick] = useState(0);
  const refresh = useCallback(() => setTick((t) => t + 1), []);
  const peerCount = Object.keys(peers || {}).length;
  useEffect(() => {
    if (!active) return undefined;
    let alive = true;
    (async () => {
      try {
        const { events, rsvps } = await loadEvents(serverId);
        const out = [];
        for (const ev of events) {
          const r = await openItemOf(serverId, "event", ev.item);
          if (r.status !== "ok" && r.status !== "unverified") continue;
          // The event's first item has the event's id as its own; later edits name it inside.
          if (ev.item.item_id !== ev.event_id && r.content.event_id !== ev.event_id) continue;
          const answers = { going: [], maybe: [] };
          let mine = null;
          for (const a of rsvps.filter((x) => x.event_id === ev.event_id)) {
            const o = await openItemOf(serverId, "rsvp", a.item);
            // An answer only counts from the person it's about.
            if ((o.status !== "ok" && o.status !== "unverified") || a.item.sender_id !== a.user_id || o.content.event_id !== ev.event_id) continue;
            answers[o.content.status].push(a.user_id);
            if (a.user_id === userId) mine = o.content.status;
          }
          out.push({ id: ev.event_id, creatorId: ev.creator_id, ...r.content, answers, mine });
        }
        out.sort((a, b) => Date.parse(a.starts_at) - Date.parse(b.starts_at));
        if (alive) setState({ loading: false, error: "", events: out });
      } catch (err) {
        if (alive) setState((s) => ({ ...s, loading: false, error: err.message }));
      }
    })();
    return () => {
      alive = false;
    };
  }, [serverId, active, tick, peerCount, loadEvents, openItemOf, userId, keyState]);
  return { ...state, refresh };
}

function EventForm({ serverId, initial = null, onDone, onCancel }) {
  const { servers, channelName, createEvent, updateEvent } = useServers();
  const voices = (servers[serverId]?.channels || []).filter((c) => c.kind === "voice" || c.kind === "stage");
  const start = initial ? new Date(initial.starts_at) : new Date(Math.ceil(Date.now() / 3600_000) * 3600_000 + 86_400_000);
  const [f, setF] = useState({
    title: initial?.title || "",
    description: initial?.description || "",
    start: localInput(start),
    end: initial?.ends_at ? localInput(new Date(initial.ends_at)) : "",
    voice: initial?.voice_channel_id || "",
    place: initial?.place || "",
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const set = (k) => (e) => setF((x) => ({ ...x, [k]: e.target.value }));
  const submit = async (e) => {
    e.preventDefault();
    setError("");
    const startsAt = new Date(f.start);
    if (!f.title.trim() || Number.isNaN(startsAt.getTime())) return setError("Give the event a name and a start time.");
    const endsAt = f.end ? new Date(f.end) : null;
    if (endsAt && endsAt <= startsAt) return setError("The end has to be after the start.");
    const content = { title: f.title.trim(), description: f.description.trim(), starts_at: startsAt.toISOString(), ends_at: endsAt ? endsAt.toISOString() : "", voice_channel_id: f.voice, place: f.voice ? "" : f.place.trim() };
    setBusy(true);
    try {
      if (initial) await updateEvent(serverId, initial.id, content);
      else await createEvent(serverId, content);
      onDone();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="space-y-3">
      <div className="space-y-1.5">
        <Label htmlFor="ev-title">Name</Label>
        <Input id="ev-title" value={f.title} onChange={set("title")} maxLength={100} required />
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label htmlFor="ev-start">Starts</Label>
          <Input id="ev-start" type="datetime-local" value={f.start} onChange={set("start")} required />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="ev-end">Ends (optional)</Label>
          <Input id="ev-end" type="datetime-local" value={f.end} onChange={set("end")} />
        </div>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="ev-where">Where</Label>
        <NativeSelect id="ev-where" value={f.voice} onChange={set("voice")}>
          <option value="">Somewhere else</option>
          {voices.map((c) => <option key={c.id} value={c.id}>Voice channel: {channelName(c)}</option>)}
        </NativeSelect>
        {!f.voice && <Input value={f.place} onChange={set("place")} maxLength={100} placeholder="A place or a link (optional)" aria-label="Place" />}
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="ev-desc">Description (optional)</Label>
        <Textarea id="ev-desc" value={f.description} onChange={set("description")} maxLength={1000} rows={3} />
      </div>
      {error && <p className="text-sm text-destructive" role="alert">{error}</p>}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onCancel} disabled={busy}>Back</Button>
        <Button type="submit" disabled={busy}>{busy ? "Saving…" : initial ? "Save changes" : "Schedule event"}</Button>
      </div>
    </form>
  );
}

function EventCard({ serverId, ev, onChanged, onEdit }) {
  const { rsvp, cancelEvent, can, channelName, servers, serverLook, memberName } = useServers();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const voice = ev.voice_channel_id ? (servers[serverId]?.channels || []).find((c) => c.id === ev.voice_channel_id) : null;
  const where = voice ? channelName(voice) : ev.place;
  const now = Date.now();
  const live = Date.parse(ev.starts_at) <= now && endOf(ev) > now;
  const manage = can(serverId, P.MANAGE_EVENTS);
  const run = async (fn) => {
    setBusy(true);
    setError("");
    try {
      await fn();
      onChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };
  const answer = (status) => run(() => rsvp(serverId, ev.id, ev.mine === status ? null : status));
  return (
    <li className="rounded-lg border border-border p-4">
      <p className={`text-xs font-semibold ${live ? "text-emerald-600 dark:text-emerald-400" : "text-primary"}`}>{live ? "Happening now" : when(ev.starts_at)}{ev.ends_at && !live ? ` to ${new Date(ev.ends_at).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })}` : ""}</p>
      <h3 className="mt-0.5 font-heading text-lg font-semibold">{ev.title}</h3>
      {where && (
        <p className="mt-1 flex items-center gap-1.5 text-sm text-muted-foreground">
          {voice ? <Volume2 className="h-4 w-4" aria-hidden="true" /> : <MapPin className="h-4 w-4" aria-hidden="true" />} {where}
        </p>
      )}
      {ev.description && <p className="mt-2 whitespace-pre-wrap text-sm">{ev.description}</p>}
      <p className="mt-2 text-xs text-muted-foreground" title={[...ev.answers.going, ...ev.answers.maybe].map((u) => memberName(serverId, u)).join(", ")}>
        {ev.answers.going.length} going, {ev.answers.maybe.length} maybe
      </p>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Button size="sm" variant={ev.mine === "going" ? "default" : "outline"} disabled={busy} onClick={() => answer("going")} aria-pressed={ev.mine === "going"}>Going</Button>
        <Button size="sm" variant={ev.mine === "maybe" ? "default" : "outline"} disabled={busy} onClick={() => answer("maybe")} aria-pressed={ev.mine === "maybe"}>Maybe</Button>
        <Button size="sm" variant="ghost" onClick={() => download(`${ev.title.replace(/[^\w -]+/g, "").slice(0, 40) || "event"}.ics`, icsFor({ ...ev, where }, serverLook(serverId).name))}>
          <Download className="mr-1.5 h-4 w-4" aria-hidden="true" /> Add to calendar
        </Button>
        {manage && (
          <>
            <Button size="sm" variant="ghost" disabled={busy} onClick={onEdit}>Edit</Button>
            <Button size="sm" variant="ghost" className="text-destructive" disabled={busy} onClick={() => run(() => cancelEvent(serverId, ev.id))}>Cancel event</Button>
          </>
        )}
      </div>
      {error && <p className="mt-2 text-sm text-destructive" role="alert">{error}</p>}
    </li>
  );
}

/** Events: what's coming up, answering them, and (for people who manage events) scheduling. */
export default function EventsDialog({ serverId, open, onOpenChange }) {
  const { can } = useServers();
  const { loading, error, events, refresh } = useServerEvents(serverId, open);
  const [form, setForm] = useState(null); // null | "new" | event
  const upcoming = useMemo(() => events.filter((ev) => endOf(ev) > Date.now()), [events]);
  return (
    <Dialog open={open} onOpenChange={(v) => { onOpenChange(v); if (!v) setForm(null); }}>
      <DialogContent className="max-h-[85dvh] max-w-lg overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{form ? (form === "new" ? "Schedule an event" : "Edit event") : "Events"}</DialogTitle>
          <DialogDescription>Encrypted like everything else here: the service knows there's an event, and who answered, but not what, when or where.</DialogDescription>
        </DialogHeader>
        {form ? (
          <EventForm serverId={serverId} initial={form === "new" ? null : form} onCancel={() => setForm(null)} onDone={() => { setForm(null); refresh(); }} />
        ) : (
          <>
            {can(serverId, P.MANAGE_EVENTS) && (
              <Button size="sm" className="self-start" onClick={() => setForm("new")}><CalendarPlus className="mr-1.5 h-4 w-4" aria-hidden="true" /> Schedule an event</Button>
            )}
            {loading && <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Loading events…</p>}
            {error && <p className="text-sm text-destructive" role="alert">{error}</p>}
            {!loading && !error && upcoming.length === 0 && (
              <p className="flex items-center gap-2 py-4 text-sm text-muted-foreground"><CalendarDays className="h-4 w-4" aria-hidden="true" /> Nothing's scheduled.</p>
            )}
            <ul className="space-y-3">
              {upcoming.map((ev) => <EventCard key={ev.id} serverId={serverId} ev={ev} onChanged={refresh} onEdit={() => setForm(ev)} />)}
            </ul>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
