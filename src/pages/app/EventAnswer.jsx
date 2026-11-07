import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { CalendarDays, CalendarX, Loader2, MapPin, MessageSquare } from "lucide-react";
import { Button } from "@/components/ui/button";
import Shell from "@/components/shell/Shell";
import { callFn } from "@/lib/api";
import { useServers } from "@/lib/secure/ServerContext";
import { useServerEvents } from "@/components/servers/EventsDialog";

const when = (iso) =>
  new Date(iso).toLocaleString("en-GB", { weekday: "long", day: "numeric", month: "long", hour: "2-digit", minute: "2-digit" });
const endOf = (ev) => (ev.ends_at ? Date.parse(ev.ends_at) : Date.parse(ev.starts_at) + 2 * 3600_000);

function Panel() {
  return (
    <nav aria-label="Event" className="flex h-full min-h-0 flex-col">
      <div className="flex h-12 shrink-0 items-center border-b border-border/70 px-4 shadow-sm">
        <h2 className="font-heading text-[1.05rem] font-semibold">An event</h2>
      </div>
      <ul className="space-y-0.5 px-2 py-3">
        <li>
          <Link to="/app" className="panel-item"><MessageSquare className="h-4 w-4" aria-hidden="true" /> Your messages</Link>
        </li>
        <li>
          <Link to="/app/discover" className="panel-item"><CalendarDays className="h-4 w-4" aria-hidden="true" /> Discover servers</Link>
        </li>
      </ul>
    </nav>
  );
}

function Notice({ title, children }) {
  return (
    <div className="card-cv px-6 py-10 text-center">
      <CalendarX className="mx-auto h-8 w-8 text-muted-foreground" aria-hidden="true" />
      <h2 className="mt-4 font-heading text-xl font-semibold">{title}</h2>
      <div className="mt-2 space-y-3 text-sm text-muted-foreground">{children}</div>
      <div className="mt-6 flex flex-wrap justify-center gap-2">
        <Button asChild variant="outline"><Link to="/app">Your messages</Link></Button>
        <Button asChild><Link to="/app/discover">Find servers to join</Link></Button>
      </div>
    </div>
  );
}

/** One event, decrypted in the member's own browser, with the three answers. */
function Answer({ serverId, eventId }) {
  const { rsvp, serverLook, memberName } = useServers();
  const { loading, error, events, refresh } = useServerEvents(serverId);
  const [busy, setBusy] = useState(false);
  const [declined, setDeclined] = useState(false);
  const [fail, setFail] = useState("");
  const ev = events.find((x) => x.id === eventId);

  if (loading) {
    return (
      <p className="flex items-center gap-2 text-sm text-muted-foreground" role="status">
        <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Opening the invitation…
      </p>
    );
  }
  if (error) return <Notice title="Couldn't open it">{error}</Notice>;
  if (!ev) return <Notice title="This event has been cancelled">Ask whoever shared the link, or come back later.</Notice>;

  const finished = endOf(ev) < Date.now();
  const answer = async (status) => {
    setBusy(true);
    setFail("");
    try {
      await rsvp(serverId, eventId, status);
      setDeclined(status === null);
      refresh();
    } catch (err) {
      setFail(err.message);
    } finally {
      setBusy(false);
    }
  };
  const where = ev.place;

  return (
    <div className="card-cv p-6">
      <p className="eyebrow">{serverLook(serverId).name}</p>
      <p className="mt-2 text-sm text-muted-foreground">{when(ev.starts_at)}{ev.ends_at ? ` to ${new Date(ev.ends_at).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })}` : ""}</p>
      <h2 className="mt-1 font-heading text-2xl font-semibold">{ev.title}</h2>
      {where && (
        <p className="mt-2 flex items-center gap-1.5 text-sm text-muted-foreground">
          <MapPin className="h-4 w-4" aria-hidden="true" /> {where}
        </p>
      )}
      {ev.description && <p className="mt-3 whitespace-pre-wrap text-[0.95rem]">{ev.description}</p>}
      <p className="mt-3 text-xs text-muted-foreground" title={[...ev.answers.going, ...ev.answers.maybe].map((u) => memberName(serverId, u)).join(", ")}>
        {ev.answers.going.length} going, {ev.answers.maybe.length} maybe
      </p>
      {finished ? (
        <p className="mt-4 text-sm text-muted-foreground">This event has finished.</p>
      ) : (
        <div className="mt-5">
          <p className="text-sm font-medium">{ev.mine ? "You're in. Change your answer any time." : "Are you coming?"}</p>
          <div className="mt-2 flex flex-wrap gap-2">
            <Button disabled={busy} variant={ev.mine === "going" ? "default" : "outline"} aria-pressed={ev.mine === "going"} onClick={() => answer("going")}>Going</Button>
            <Button disabled={busy} variant={ev.mine === "maybe" ? "default" : "outline"} aria-pressed={ev.mine === "maybe"} onClick={() => answer("maybe")}>Maybe</Button>
            <Button disabled={busy} variant={!ev.mine && declined ? "default" : "outline"} aria-pressed={!ev.mine && declined} onClick={() => answer(null)}>Not going</Button>
          </div>
          {fail && <p className="mt-2 text-sm text-destructive" role="alert">{fail}</p>}
        </div>
      )}
    </div>
  );
}

/** The page a shared event link opens: it finds the event's server, then asks for your answer. */
export default function EventAnswer() {
  const { eventId } = useParams();
  const { loadState } = useServers();
  const [state, setState] = useState({ phase: "loading", serverId: "", error: "" });

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const { server_id: serverId } = await callFn("events", { action: "shared_event", event_id: eventId });
        await loadState(serverId);
        if (alive) setState({ phase: "ready", serverId, error: "" });
      } catch (err) {
        if (alive) setState({ phase: "error", serverId: "", error: err.message });
      }
    })();
    return () => {
      alive = false;
    };
  }, [eventId, loadState]);

  return (
    <Shell panel={<Panel />} mainOpen>
      <div className="flex min-h-0 flex-1 flex-col">
        <header className="flex h-12 shrink-0 items-center border-b border-border/70 px-3 shadow-sm sm:px-4">
          <h1 className="font-heading text-[1.05rem] font-semibold">Event invitation</h1>
        </header>
        <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-xl px-4 py-8">
            {state.phase === "loading" && (
              <p className="flex items-center gap-2 text-sm text-muted-foreground" role="status">
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Finding the event…
              </p>
            )}
            {state.phase === "error" && (
              <Notice title="This invitation isn't for you">
                <p>{state.error}</p>
                <p>Events are encrypted to the members of their server, so only people who are in it can see one.</p>
              </Notice>
            )}
            {state.phase === "ready" && <Answer serverId={state.serverId} eventId={eventId} />}
          </div>
        </div>
      </div>
    </Shell>
  );
}