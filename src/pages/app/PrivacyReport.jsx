import React, { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, CircleDashed, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ErrorNote, formatDate } from "@/components/site/bits";
import { callFn } from "@/lib/api";
import { useSecure } from "@/lib/secure/SecureContext";
import { useChat } from "@/lib/secure/ChatContext";
import { usePresence } from "@/lib/secure/PresenceContext";
import { SettingsGroup, SettingsTitle } from "@/components/settings/SettingsLayout";

const VISIBILITY = {
  shared: "people you share a conversation or server with",
  conversations: "only people you have a conversation with",
  nobody: "nobody",
};
const DM_POLICY = {
  anyone: "anyone who knows your username",
  servers: "people you share a server with",
  nobody: "nobody new",
};

const count = (c) => (c && typeof c === "object" ? `${c.count}${c.more ? "+" : ""}` : String(c ?? 0));

/**
 * Suggestions worked out on this device, from settings it already knows. Nothing about which
 * ones you follow is sent anywhere.
 */
function checkup({ lockInfo, presence, me, peers, conversations, userId }) {
  const privacy = me?.privacy || {};
  const people = new Set(conversations.filter((c) => !c.server_id).flatMap((c) => c.member_ids || []).filter((id) => id !== userId));
  const unverified = [...people].filter((id) => !peers?.[id]?.verified).length;
  const untimed = conversations.filter((c) => !c.server_id && !(Number(c.expire_seconds) > 0)).length;
  return [
    {
      done: Boolean(lockInfo),
      title: "Lock this browser with a passcode",
      why: "Your keys are encrypted with it, so someone using this device can't read your messages.",
      to: "/app/settings/keys",
    },
    {
      done: people.size === 0 || unverified === 0,
      title: unverified ? `Compare safety numbers with ${unverified} ${unverified === 1 ? "person" : "people"}` : "Compare safety numbers",
      why: "Comparing them in person or on a call proves no one is sitting in the middle.",
      to: "/app",
    },
    {
      done: untimed === 0,
      title: untimed ? `Turn on disappearing messages in ${untimed} ${untimed === 1 ? "conversation" : "conversations"}` : "Use disappearing messages",
      why: "Messages that delete themselves can't leak later. Set it from a conversation's info.",
      to: "/app",
    },
    {
      done: !presence?.presence,
      title: "Keep your online status private",
      why: "Others can tell when you're around while it's on.",
      to: "/app/settings/privacy",
    },
    {
      done: privacy.profile_visibility !== "shared",
      title: "Show your profile to fewer people",
      why: "Right now everyone in your servers can see your display name and bio.",
      to: "/app/settings/privacy",
    },
    {
      done: privacy.dm_policy !== "anyone",
      title: "Limit who can start a conversation with you",
      why: "Anyone who knows your username can message you now.",
      to: "/app/settings/privacy",
    },
    {
      done: Boolean(me?.auto_delete?.days),
      title: "Delete your account if you stop using it",
      why: "If you ever walk away, nothing of yours is left behind.",
      to: "/app/settings/data",
    },
  ];
}

function Row({ label, children }) {
  return (
    <div className="flex flex-wrap justify-between gap-x-4 gap-y-1 border-b border-border/60 py-2 text-sm last:border-0">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="text-right font-medium">{children}</dd>
    </div>
  );
}

export default function PrivacyReport() {
  const { me, peers, lockInfo, userId } = useSecure();
  const { conversations } = useChat();
  const { settings: presence } = usePresence();
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      setReport(await callFn("profile", { action: "privacy_report" }));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);

  const items = checkup({ lockInfo, presence, me, peers, conversations, userId: userId || me?.user?.id });
  const done = items.filter((i) => i.done).length;
  const a = report?.account;
  const shared = a ? Object.entries(a.shared_profile).filter(([, v]) => v).map(([k]) => k.replace("_", " ")) : [];

  return (
    <>
      <SettingsTitle intro="Everything Commonveil holds about you, and what you can do to share less. Messages, files, names of groups and reports are end-to-end encrypted: the service stores them but can't read them, so this page can only count them.">
        Privacy report
      </SettingsTitle>

      <SettingsGroup title={`Privacy checkup: ${done} of ${items.length}`} description="Worked out on this device. Which suggestions you follow is never sent anywhere.">
        <ul className="space-y-3">
          {items.map((i) => (
            <li key={i.title} className="flex items-start gap-3">
              {i.done
                ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-[hsl(var(--success,142_60%_40%))]" aria-label="Done" />
                : <CircleDashed className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-label="Not yet" />}
              <span className="min-w-0 flex-1 text-sm">
                <span className={`block font-medium ${i.done ? "text-muted-foreground" : ""}`}>{i.title}</span>
                {!i.done && <span className="block text-xs text-muted-foreground">{i.why}</span>}
              </span>
              {!i.done && <Link to={i.to} className="shrink-0 text-sm text-primary underline-offset-4 hover:underline">Fix</Link>}
            </li>
          ))}
        </ul>
      </SettingsGroup>

      <ErrorNote>{error}</ErrorNote>
      {!report && !error && <p className="text-sm text-muted-foreground">Asking the service what it holds…</p>}

      {report && (
        <>
          <SettingsGroup title="Your account" description="What the service needs to let you sign in and be found by people who know your username.">
            <dl>
              <Row label="Username">@{a.username}</Row>
              <Row label="Sign-in address">{a.email_hint || "Not shown"}</Row>
              <Row label="Joined">{a.created ? formatDate(a.created) : "Unknown"}</Row>
              <Row label="Profile details you've filled in">{shared.length ? shared.join(", ") : "None"}</Row>
              <Row label="Who sees your profile">{VISIBILITY[a.profile_visibility] || a.profile_visibility}</Row>
              <Row label="Who can start a conversation">{DM_POLICY[a.dm_policy] || a.dm_policy}</Row>
              <Row label="Last day you were active">{a.auto_delete_days ? (a.last_active_day || "Today") : "Not recorded"}</Row>
            </dl>
            {!a.auto_delete_days && <p className="mt-2 text-xs text-muted-foreground">Commonveil doesn't record when you use it. It only notes the day if you've asked for your account to be deleted after a while without use.</p>}
          </SettingsGroup>

          <SettingsGroup title="Devices" description="Each device has its own keys. The service knows the name you gave it and, to the day, when it was last used.">
            <dl>
              {report.devices.map((d, i) => (
                <Row key={i} label={d.label || "Unnamed device"}>
                  {d.status}{d.last_seen_day ? `, last used ${d.last_seen_day}` : ""}
                </Row>
              ))}
            </dl>
          </SettingsGroup>

          <SettingsGroup title="Who you talk to" description="The service has to know who is in a conversation to deliver to them. It can't see what's said, or the names of groups.">
            <dl>
              <Row label="Direct conversations">{report.conversations.direct}</Row>
              <Row label="Groups">{report.conversations.groups}</Row>
              <Row label="Server tickets">{report.conversations.tickets}</Row>
              <Row label="Different people">{report.conversations.people}</Row>
              <Row label="With disappearing messages">{report.conversations.disappearing}</Row>
              <Row label="Set to self-destruct">{report.conversations.self_destructing}</Row>
              <Row label="Servers you're in">{report.servers.count}</Row>
              <Row label="Servers listing you as a member">{report.servers.listed}</Row>
            </dl>
          </SettingsGroup>

          <SettingsGroup title="Stored, encrypted" description="Counted, never read. Disappearing messages and self-destructing conversations are erased when their time is up.">
            <dl>
              <Row label="Messages you've sent that still exist">{count(report.stored.messages_sent)}</Row>
              <Row label="Files you've uploaded">{count(report.stored.files_uploaded)}</Row>
              <Row label="Scheduled messages and check-ins waiting">{count(report.stored.scheduled)}</Row>
              <Row label="Reports to server moderators">{count(report.stored.reports_to_moderators)}</Row>
              <Row label="Reports to Commonveil">{count(report.stored.reports_to_commonveil)}</Row>
              <Row label="People you've blocked">{count(report.stored.blocks)}</Row>
            </dl>
          </SettingsGroup>

          <SettingsGroup title="Never collected">
            <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
              <li>What your messages, files, polls, reports or group names say.</li>
              <li>Your contacts, phone number, location or IP history.</li>
              <li>When you're online, typing or reading, unless you turn status on, and even then it isn't stored.</li>
              <li>Your quiet hours, mutes, searches and theme: they stay on your device.</li>
              <li>Advertising or tracking identifiers. There are none.</li>
            </ul>
          </SettingsGroup>
        </>
      )}

      <div className="mt-4 flex flex-wrap gap-2">
        <Button variant="outline" size="sm" onClick={load} disabled={busy}>
          <RefreshCw className="mr-2 h-4 w-4" aria-hidden="true" /> Check again
        </Button>
        <Button asChild variant="outline" size="sm">
          <Link to="/app/settings/data">Download or delete your data</Link>
        </Button>
      </div>
    </>
  );
}
