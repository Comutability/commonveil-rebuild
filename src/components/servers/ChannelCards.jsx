import React, { useState } from "react";
import { Link } from "react-router-dom";
import { BookOpen, Check, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ErrorNote } from "@/components/site/bits";
import { useServers } from "@/lib/secure/ServerContext";
import { templateServer } from "@/lib/secure/serverTemplates";
import { ChannelIcon, historyNote } from "./channelBits";

/** The top of a channel, once there's nothing earlier to load. */
export function ChannelStart({ serverId, channel }) {
  const { channelName, channelTopic } = useServers();
  return (
    <div className="px-4 pb-4 pt-10">
      <span className="flex h-16 w-16 items-center justify-center rounded-full bg-muted text-muted-foreground">
        <ChannelIcon kind={channel.kind} isPrivate={channel.private} className="h-9 w-9" />
      </span>
      <h2 className="mt-3 text-3xl font-semibold">Welcome to #{channelName(channel)}</h2>
      <p className="mt-1 text-muted-foreground">{channelTopic(channel) || `This is the start of #${channelName(channel)}.`}</p>
      <p className="mt-2 flex items-start gap-1.5 text-sm text-muted-foreground">
        <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
        <span>{historyNote(channel)}</span>
      </p>
      <span className="hidden">{serverId}</span>
    </div>
  );
}

/** A template server's welcome: what the place is for, where to start, and how privacy works here. */
export function WelcomeCard({ serverId }) {
  const { servers, serverLook, channelName } = useServers();
  const e = servers[serverId];
  const welcome = templateServer(e?.server?.template)?.welcome;
  if (!welcome) return null;
  const byKey = (key) => e.channels?.find((c) => c.template_key === key);
  const look = serverLook(serverId);
  return (
    <article className="mx-4 mt-6 overflow-hidden rounded-xl border border-border bg-card">
      <div className="h-2" style={{ backgroundColor: look.color || "hsl(var(--primary))" }} aria-hidden="true" />
      <div className="space-y-4 p-5 sm:p-6">
        <h2 className="text-2xl font-semibold">{welcome.title}</h2>
        <p className="max-w-prose text-[0.98rem] leading-relaxed">{welcome.body}</p>
        <ol className="space-y-2">
          {welcome.steps.map((step, i) => {
            const ch = byKey(step.channel);
            return (
              <li key={step.channel} className="flex items-start gap-3">
                <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/15 text-xs font-semibold text-primary">{i + 1}</span>
                <span className="text-sm">
                  {ch ? (
                    <Link to={`/app/s/${serverId}/${ch.id}`} className="font-medium text-primary hover:underline">#{channelName(ch)}</Link>
                  ) : (
                    <span className="font-medium">#{step.channel}</span>
                  )}{" "}
                  {step.text}
                </span>
              </li>
            );
          })}
        </ol>
        <div className="rounded-lg bg-muted/70 p-4">
          <p className="flex items-center gap-1.5 text-sm font-semibold"><ShieldCheck className="h-4 w-4 text-primary" aria-hidden="true" /> How privacy works here</p>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-muted-foreground">
            {welcome.privacy.map((line) => <li key={line}>{line}</li>)}
          </ul>
        </div>
      </div>
    </article>
  );
}

/** The server's rules, and agreeing to them when the server asks members to before posting. */
export function RulesCard({ serverId, compact = false }) {
  const { servers, serverRules, act, can } = useServers();
  const [state, setState] = useState({ busy: false, error: "" });
  const e = servers[serverId];
  if (!e) return null;
  const { rules, intro } = serverRules(serverId);
  const required = e.server.settings?.rules_required;
  const accepted = Boolean(e.member?.rules_accepted_at);
  const accept = async () => {
    setState({ busy: true, error: "" });
    try {
      await act(serverId, "accept_rules", {});
      setState({ busy: false, error: "" });
    } catch (err) {
      setState({ busy: false, error: err.message });
    }
  };
  return (
    <article className={`rounded-xl border border-border bg-card ${compact ? "p-4" : "mx-4 mt-6 p-5 sm:p-6"}`}>
      <h2 className="flex items-center gap-2 text-2xl font-semibold"><BookOpen className="h-5 w-5 text-primary" aria-hidden="true" /> Rules</h2>
      {intro && <p className="mt-2 max-w-prose text-sm text-muted-foreground">{intro}</p>}
      {rules.length ? (
        <ol className="mt-4 space-y-3">
          {rules.map((r, i) => (
            <li key={i} className="flex gap-3">
              <span className="font-heading text-lg font-semibold text-primary">{i + 1}.</span>
              <span className="pt-0.5 text-[0.95rem] leading-relaxed">{r}</span>
            </li>
          ))}
        </ol>
      ) : (
        <p className="mt-3 text-sm text-muted-foreground">This server hasn't written its rules yet.{can(serverId, 1 << 10) ? " Add them in Server settings." : ""}</p>
      )}
      {required && (
        <div className="mt-5 flex flex-wrap items-center gap-3 border-t border-border pt-4">
          {accepted ? (
            <p className="flex items-center gap-1.5 text-sm text-primary"><Check className="h-4 w-4" aria-hidden="true" /> You've accepted the rules.</p>
          ) : (
            <>
              <p className="text-sm text-muted-foreground">This server asks members to accept its rules before posting.</p>
              <Button onClick={accept} disabled={state.busy}>{state.busy ? "Saving…" : "I've read and accept the rules"}</Button>
            </>
          )}
        </div>
      )}
      <ErrorNote>{state.error}</ErrorNote>
    </article>
  );
}
