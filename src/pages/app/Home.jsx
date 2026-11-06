import React, { useEffect, useState } from "react";
import { Navigate, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Compass, Eye, EyeOff, Link2, MessageSquarePlus, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useChat } from "@/lib/secure/ChatContext";
import { useSecure } from "@/lib/secure/SecureContext";
import Shell, { NavButton } from "@/components/shell/Shell";
import HomeSidebar from "@/components/home/HomeSidebar";
import ConversationView from "@/components/chat/ConversationView";
import NewConversationDialog from "@/components/chat/NewConversationDialog";
import ConversationInfoDialog from "@/components/chat/ConversationInfoDialog";
import CreateServerDialog, { parseInvite } from "@/components/servers/CreateServerDialog";

const SEES = [
  "Your username, and the profile details you choose to share",
  "Who's in each conversation and server, and their roles",
  "When something is sent, and roughly how big it is, files included",
  "Which channels a server has and how they're set up, but not their names",
  "The public card of a server its admins list in Discover",
];
const NEVER = [
  "What you write: messages, posts, replies, edits, reactions, polls, files and events",
  "Server, channel and role names, nicknames, rules, emoji, AutoMod rules and group names",
  "Your calls, which go straight between devices",
  "What you search for and what you've read, which stay on this device",
];

function HomeWelcome({ onNew }) {
  const navigate = useNavigate();
  const { me } = useSecure();
  const [creating, setCreating] = useState(false);
  const [invite, setInvite] = useState("");
  const [inviteError, setInviteError] = useState("");
  const name = me?.profile?.display_name || me?.profile?.username || "";

  const join = (e) => {
    e.preventDefault();
    const parsed = parseInvite(invite);
    if (!parsed) {
      setInviteError("That doesn't look like an invite link.");
      return;
    }
    navigate(`/app/join/${parsed.code}${parsed.site ? `?site=${encodeURIComponent(parsed.site)}` : ""}${parsed.secret ? `#${parsed.secret}` : ""}`);
  };

  const actions = [
    { icon: MessageSquarePlus, title: "Start a conversation", text: "With someone's exact username. One person, or a small group.", onClick: onNew },
    { icon: Plus, title: "Create a server", text: "A place for your group, with channels, roles and voice.", onClick: () => setCreating(true) },
    { icon: Compass, title: "Find a community", text: "Servers whose admins chose to list them.", onClick: () => navigate("/app/discover") },
  ];

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <header className="flex h-12 shrink-0 items-center gap-2 border-b border-border/70 px-3 shadow-sm sm:px-4">
        <NavButton />
        <h1 className="font-heading text-[1.05rem] font-semibold">Home</h1>
      </header>
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-3xl px-4 py-10 sm:px-8">
          <h2 className="text-4xl font-semibold leading-tight">{name ? `Hello, ${name}.` : "Hello."}</h2>
          <p className="mt-2 max-w-prose text-muted-foreground">Everything you send here is encrypted on this device first. Here's where to start.</p>

          <ul className="mt-8 divide-y divide-border border-y border-border">
            {actions.map((a) => (
              <li key={a.title}>
                <button type="button" onClick={a.onClick} className="flex w-full items-center gap-4 py-4 text-left transition-colors hover:bg-[hsl(var(--chat-hover))] sm:px-2">
                  <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary/12 text-primary"><a.icon className="h-5 w-5" aria-hidden="true" /></span>
                  <span>
                    <span className="block font-medium">{a.title}</span>
                    <span className="block text-sm text-muted-foreground">{a.text}</span>
                  </span>
                </button>
              </li>
            ))}
            <li className="py-4 sm:px-2">
              <form onSubmit={join} className="flex items-center gap-4">
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary/12 text-primary"><Link2 className="h-5 w-5" aria-hidden="true" /></span>
                <Input value={invite} onChange={(e) => { setInvite(e.target.value); setInviteError(""); }} placeholder="Paste an invite link to join a server" aria-label="Invite link" />
                <Button type="submit" variant="outline" disabled={!invite.trim()}>Join</Button>
              </form>
              {inviteError && <p className="ml-14 mt-1 text-sm text-destructive">{inviteError}</p>}
            </li>
          </ul>

          <section className="mt-12" aria-labelledby="ledger">
            <h2 id="ledger" className="text-2xl font-semibold">What Commonveil can and can't see</h2>
            <p className="mt-1 max-w-prose text-sm text-muted-foreground">A service has to know some things to deliver messages. This is all of it, so you can decide what to share.</p>
            <div className="mt-5 grid gap-8 sm:grid-cols-2">
              <div>
                <p className="flex items-center gap-2 font-medium"><Eye className="h-4 w-4 text-muted-foreground" aria-hidden="true" /> Can see</p>
                <ul className="mt-2 space-y-2 text-sm text-muted-foreground">
                  {SEES.map((s) => <li key={s} className="border-l-2 border-border pl-3">{s}</li>)}
                </ul>
              </div>
              <div>
                <p className="flex items-center gap-2 font-medium text-primary"><EyeOff className="h-4 w-4" aria-hidden="true" /> Never sees</p>
                <ul className="mt-2 space-y-2 text-sm">
                  {NEVER.map((s) => <li key={s} className="border-l-2 border-primary/50 pl-3">{s}</li>)}
                </ul>
              </div>
            </div>
          </section>
        </div>
      </div>
      <CreateServerDialog open={creating} onOpenChange={setCreating} />
    </div>
  );
}

export default function Home() {
  const { conversationId } = useParams();
  const navigate = useNavigate();
  const { conversations, loaded } = useChat();
  const [newOpen, setNewOpen] = useState(false);
  const [infoOpen, setInfoOpen] = useState(false);
  // /app?to=name.example.org (from someone's profile page) opens a conversation with them.
  const [params, setParams] = useSearchParams();
  const [prefill, setPrefill] = useState("");
  useEffect(() => {
    const to = params.get("to");
    if (!to) return;
    setPrefill(to.slice(0, 280));
    setNewOpen(true);
    setParams({}, { replace: true });
  }, [params, setParams]);
  const active = conversations.find((c) => c.id === conversationId) || null;

  // A support ticket lives in its server.
  if (active?.server_id && active.ticket?.channel_id) {
    return <Navigate to={`/app/s/${active.server_id}/${active.ticket.channel_id}/${active.id}`} replace />;
  }

  return (
    <Shell panel={<HomeSidebar activeId={conversationId} onNew={() => setNewOpen(true)} />} mainOpen={Boolean(conversationId)}>
      {active ? (
        <ConversationView conversation={active} onBack={() => navigate("/app")} onInfo={() => setInfoOpen(true)} />
      ) : conversationId && loaded ? (
        <div className="flex flex-1 flex-col">
          <header className="flex h-12 items-center border-b border-border/70 px-3 md:hidden"><NavButton /></header>
          <div className="flex flex-1 flex-col items-center justify-center p-8 text-center">
            <p className="font-heading text-xl">That conversation isn't available</p>
            <p className="mt-1 text-sm text-muted-foreground">You may have left it, or it was deleted.</p>
          </div>
        </div>
      ) : (
        <HomeWelcome onNew={() => setNewOpen(true)} />
      )}
      <NewConversationDialog open={newOpen} onOpenChange={(v) => { setNewOpen(v); if (!v) setPrefill(""); }} initialUsername={prefill} onCreated={(c) => navigate(`/app/c/${c.id}`)} />
      <ConversationInfoDialog conversation={active} open={infoOpen && Boolean(active)} onOpenChange={setInfoOpen} onLeft={() => navigate("/app")} />
    </Shell>
  );
}
