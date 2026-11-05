import React, { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowLeft, CheckCircle2, Loader2, Lock, RotateCcw, Ticket } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ErrorNote } from "@/components/site/bits";
import { useServers } from "@/lib/secure/ServerContext";
import { useChat } from "@/lib/secure/ChatContext";
import { useSecure } from "@/lib/secure/SecureContext";
import { P } from "@/lib/secure/permissions";
import { stamp } from "@/components/chat/MessageRow";
import ConversationView from "@/components/chat/ConversationView";
import ConversationInfoDialog from "@/components/chat/ConversationInfoDialog";
import ChannelHeader from "./ChannelHeader";

function TicketList({ serverId, channel }) {
  const navigate = useNavigate();
  const { userId } = useSecure();
  const { listTickets, openTicket, memberName, can, channelTopic } = useServers();
  const [tickets, setTickets] = useState(null);
  const [state, setState] = useState({ busy: false, error: "" });
  const staff = can(serverId, P.MANAGE_TICKETS);

  const load = useCallback(() => listTickets(serverId).then((t) => setTickets(t.filter((x) => !x.channel_id || x.channel_id === channel.id))).catch((err) => setState({ busy: false, error: err.message })), [listTickets, serverId, channel.id]);
  useEffect(() => {
    load();
  }, [load]);

  const open = async () => {
    setState({ busy: true, error: "" });
    try {
      const res = await openTicket(serverId, channel.id);
      navigate(`/app/s/${serverId}/${channel.id}/${res.conversation_id}`);
    } catch (err) {
      setState({ busy: false, error: err.message });
    }
  };

  const mine = (tickets || []).filter((t) => t.opened_by === userId);
  const others = (tickets || []).filter((t) => t.opened_by !== userId);

  const Row = ({ t }) => (
    <li>
      <Link to={`/app/s/${serverId}/${channel.id}/${t.conversation_id}`} className="flex items-center gap-3 rounded-lg border border-border bg-card px-4 py-3 transition-colors hover:bg-[hsl(var(--chat-hover))]">
        <Ticket className={`h-5 w-5 shrink-0 ${t.status === "open" ? "text-primary" : "text-muted-foreground"}`} aria-hidden="true" />
        <span className="min-w-0 flex-1">
          <span className="block font-medium">Ticket {t.number}{t.opened_by !== userId ? ` from ${memberName(serverId, t.opened_by)}` : ""}</span>
          <span className="block text-xs text-muted-foreground">Opened {stamp(t.created_date)}{t.last_message_at ? `, last message ${stamp(t.last_message_at)}` : ""}</span>
        </span>
        <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${t.status === "open" ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground"}`}>{t.status === "open" ? "Open" : "Closed"}</span>
      </Link>
    </li>
  );

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <ChannelHeader serverId={serverId} channel={channel} />
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl space-y-6 px-4 py-8">
          <section className="rounded-xl border border-border bg-card p-5 sm:p-6">
            <h2 className="flex items-center gap-2 text-2xl font-semibold"><Ticket className="h-6 w-6 text-primary" aria-hidden="true" /> Get help privately</h2>
            <p className="mt-2 text-[0.95rem] leading-relaxed">{channelTopic(channel) || "Open a ticket to talk to the support team in private."}</p>
            <ul className="mt-3 space-y-1.5 text-sm text-muted-foreground">
              <li className="flex gap-2"><Lock className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" /> A ticket is an end-to-end encrypted group with you and the support team. Nobody else in the server can see it.</li>
              <li className="flex gap-2"><Lock className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" /> You'll see exactly who's in it before you send anything.</li>
              <li className="flex gap-2"><Lock className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" /> Staff will never ask for your recovery phrase, passcode or link code.</li>
            </ul>
            <ErrorNote>{state.error}</ErrorNote>
            <Button className="mt-4" onClick={open} disabled={state.busy}>{state.busy ? "Opening…" : "Open a ticket"}</Button>
          </section>
          {!tickets && !state.error && <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Loading tickets…</p>}
          {mine.length > 0 && (
            <section>
              <h3 className="mb-2 text-sm font-semibold text-muted-foreground">Your tickets</h3>
              <ul className="space-y-2">{mine.map((t) => <Row key={t.conversation_id} t={t} />)}</ul>
            </section>
          )}
          {staff && (
            <section>
              <h3 className="mb-2 text-sm font-semibold text-muted-foreground">Tickets you're helping with</h3>
              {others.length ? <ul className="space-y-2">{others.map((t) => <Row key={t.conversation_id} t={t} />)}</ul> : <p className="text-sm text-muted-foreground">None right now.</p>}
            </section>
          )}
        </div>
      </div>
    </div>
  );
}

function TicketConversation({ serverId, channel, conversationId }) {
  const navigate = useNavigate();
  const { conversations, refreshConversation } = useChat();
  const { setTicketStatus, can } = useServers();
  const { userId } = useSecure();
  const [infoOpen, setInfoOpen] = useState(false);
  const [state, setState] = useState({ busy: false, error: "" });
  const conversation = conversations.find((c) => c.id === conversationId);

  useEffect(() => {
    if (!conversation) refreshConversation(conversationId).catch((err) => setState({ busy: false, error: err.message }));
  }, [conversation, conversationId, refreshConversation]);

  if (!conversation) {
    return (
      <div className="flex flex-1 items-center justify-center p-8 text-sm text-muted-foreground">
        {state.error ? <ErrorNote>{state.error}</ErrorNote> : <><Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" /> Opening the ticket…</>}
      </div>
    );
  }
  const ticket = conversation.ticket || {};
  const canClose = ticket.opened_by === userId || can(serverId, P.MANAGE_TICKETS);
  const toggle = async () => {
    setState({ busy: true, error: "" });
    try {
      await setTicketStatus(serverId, conversationId, ticket.status === "open" ? "closed" : "open");
      await refreshConversation(conversationId);
      setState({ busy: false, error: "" });
    } catch (err) {
      setState({ busy: false, error: err.message });
    }
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex shrink-0 items-center gap-2 border-b border-border/70 bg-panel px-3 py-1.5 text-sm sm:px-4">
        <Link to={`/app/s/${serverId}/${channel.id}`} className="flex items-center gap-1 rounded-md px-1.5 py-1 text-muted-foreground hover:bg-muted hover:text-foreground">
          <ArrowLeft className="h-4 w-4" aria-hidden="true" /> All tickets
        </Link>
        <span className="font-medium">Ticket {ticket.number}</span>
        <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${ticket.status === "open" ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground"}`}>{ticket.status === "open" ? "Open" : "Closed"}</span>
        {canClose && (
          <Button size="sm" variant="ghost" className="ml-auto" disabled={state.busy} onClick={toggle}>
            {ticket.status === "open" ? <><CheckCircle2 className="mr-1.5 h-4 w-4" aria-hidden="true" /> Close ticket</> : <><RotateCcw className="mr-1.5 h-4 w-4" aria-hidden="true" /> Reopen</>}
          </Button>
        )}
      </div>
      {state.error && <p className="px-4 py-2 text-sm text-destructive">{state.error}</p>}
      <div className="min-h-0 flex-1">
        <ConversationView conversation={conversation} onBack={() => navigate(`/app/s/${serverId}/${channel.id}`)} onInfo={() => setInfoOpen(true)} />
      </div>
      <ConversationInfoDialog conversation={conversation} open={infoOpen} onOpenChange={setInfoOpen} onLeft={() => navigate(`/app/s/${serverId}/${channel.id}`)} />
    </div>
  );
}

export default function TicketsView({ serverId, channel, ticketId }) {
  return ticketId ? <TicketConversation serverId={serverId} channel={channel} conversationId={ticketId} /> : <TicketList serverId={serverId} channel={channel} />;
}
