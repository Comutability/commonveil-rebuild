import React, { useCallback, useEffect, useState } from "react";
import { AlertTriangle, ArrowUpRight, Check, Loader2, ShieldAlert, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { NativeSelect } from "@/components/ui/native-select";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ErrorNote } from "@/components/site/bits";
import { callFn } from "@/lib/api";
import { useServers } from "@/lib/secure/ServerContext";
import { SettingsGroup, SettingsTitle } from "./SettingsLayout";
import { REASON_LABELS } from "@/components/servers/ReportDialog";
import MemberCard from "@/components/servers/MemberCard";

const when = (v) => new Date(String(v).replace(/Z?$/, "Z")).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" });
const STATUS_LABEL = { open: "Open", resolved: "Dealt with", dismissed: "No action needed", escalated: "Sent to Commonveil" };

/** Send a report on to the Commonveil team: the moderator decides what to share, readably. */
function EscalateDialog({ serverId, report, open, onOpenChange, onDone }) {
  const { modCall, serverLook, memberName } = useServers();
  const content = report?.opened?.content;
  const [reason, setReason] = useState("other");
  const [details, setDetails] = useState("");
  const [state, setState] = useState({ busy: false, error: "" });
  useEffect(() => {
    if (!open || !report) return;
    setReason(content?.reason || "other");
    setDetails([content?.note, content?.quote?.text ? `Reported message: "${content.quote.text}"` : ""].filter(Boolean).join("\n\n"));
    setState({ busy: false, error: "" });
  }, [open, report, content]);
  if (!report) return null;
  const submit = async (e) => {
    e.preventDefault();
    setState({ busy: true, error: "" });
    try {
      await modCall("escalate", { server_id: serverId, report_id: report.report_id, reason, details, server_name: serverLook(serverId).name });
      onDone();
      onOpenChange(false);
    } catch (err) {
      setState({ busy: false, error: err.message });
    }
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Send to the Commonveil team</DialogTitle>
          <DialogDescription>
            For things that break the law or Commonveil's rules, or that are more than your team can handle. Our team can't read anything in your server, so they see only what you write here, in readable form.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="space-y-3">
          <p className="text-sm">About <strong>{memberName(serverId, report.target_id)}</strong>, reported {when(report.created_date)}.</p>
          <div className="space-y-1.5">
            <Label htmlFor="esc-reason">What kind of problem</Label>
            <NativeSelect id="esc-reason" value={reason} onChange={(e) => setReason(e.target.value)}>
              {Object.entries(REASON_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </NativeSelect>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="esc-details">What to share</Label>
            <Textarea id="esc-details" value={details} onChange={(e) => setDetails(e.target.value)} rows={6} maxLength={4000} required />
            <p className="text-xs text-muted-foreground">Edit this down to what's needed. Don't include other people's private details.</p>
          </div>
          {state.error && <p className="text-sm text-destructive" role="alert">{state.error}</p>}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button type="submit" disabled={state.busy || !details.trim()}>{state.busy ? "Sending…" : "Send to Commonveil"}</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function ReportCard({ serverId, r, onChanged, onEscalate, onOpenMember }) {
  const { modCall, memberName, warnMember } = useServers();
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const c = r.opened?.content;
  const run = async (label, fn) => {
    setBusy(label);
    setError("");
    try {
      await fn();
      onChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  };
  return (
    <li className="space-y-2 rounded-lg border border-border p-4">
      <div className="flex flex-wrap items-baseline gap-x-2 text-sm">
        <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${r.status === "open" ? "bg-[hsl(var(--warning)/0.15)] text-[hsl(var(--warning))]" : "bg-muted text-muted-foreground"}`}>{STATUS_LABEL[r.status]}</span>
        <button type="button" className="font-semibold hover:underline" onClick={() => onOpenMember(r.target_id)}>{memberName(serverId, r.target_id)}</button>
        <span className="text-muted-foreground">reported by</span>
        <button type="button" className="hover:underline" onClick={() => onOpenMember(r.reporter_id)}>{memberName(serverId, r.reporter_id)}</button>
        <span className="text-xs text-muted-foreground">{when(r.created_date)}</span>
      </div>
      {!c ? (
        <p className="text-sm italic text-muted-foreground">{r.opened?.status === "locked" ? "This device can't open this report." : "Decrypting…"}</p>
      ) : (
        <>
          <p className="text-sm font-medium">{REASON_LABELS[c.reason] || c.reason}{r.opened.status === "unverified" ? <span className="ml-2 text-xs font-normal text-[hsl(var(--warning))]">(sender not verified)</span> : null}</p>
          {c.note && <p className="whitespace-pre-wrap text-sm">{c.note}</p>}
          {c.quote && <blockquote className="whitespace-pre-wrap border-l-4 border-border pl-3 text-sm text-muted-foreground">{c.quote.text}</blockquote>}
        </>
      )}
      {r.status === "open" && (
        <div className="flex flex-wrap gap-2 pt-1">
          <Button size="sm" variant="outline" disabled={Boolean(busy)} onClick={() => run("warn", async () => {
            await warnMember(serverId, r.target_id, c ? `${REASON_LABELS[c.reason]}${c.note ? `: ${c.note}` : ""}` : "", { reportId: r.report_id });
            await modCall("set_report_status", { server_id: serverId, report_id: r.report_id, status: "resolved" });
          })}><ShieldAlert className="mr-1.5 h-4 w-4" aria-hidden="true" /> Warn and close</Button>
          <Button size="sm" variant="outline" disabled={Boolean(busy)} onClick={() => onOpenMember(r.target_id)}>More actions</Button>
          <Button size="sm" variant="outline" disabled={Boolean(busy)} onClick={() => run("resolve", () => modCall("set_report_status", { server_id: serverId, report_id: r.report_id, status: "resolved" }))}><Check className="mr-1.5 h-4 w-4" aria-hidden="true" /> Dealt with</Button>
          <Button size="sm" variant="ghost" disabled={Boolean(busy)} onClick={() => run("dismiss", () => modCall("set_report_status", { server_id: serverId, report_id: r.report_id, status: "dismissed" }))}><X className="mr-1.5 h-4 w-4" aria-hidden="true" /> No action</Button>
          <Button size="sm" variant="ghost" disabled={Boolean(busy)} onClick={() => onEscalate(r)}><ArrowUpRight className="mr-1.5 h-4 w-4" aria-hidden="true" /> Send to Commonveil</Button>
        </div>
      )}
      {r.status !== "open" && r.handled_by && <p className="text-xs text-muted-foreground">By {memberName(serverId, r.handled_by)}, {when(r.handled_at)}</p>}
      {error && <p className="text-sm text-destructive" role="alert">{error}</p>}
    </li>
  );
}

/** The report queue: reports sent to you as a moderator, opened on this device. */
export function ReportsQueue({ sid }) {
  const { loadReports } = useServers();
  const [filter, setFilter] = useState("open");
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [escalating, setEscalating] = useState(null);
  const [card, setCard] = useState(null);
  const refresh = useCallback(() => {
    setError("");
    loadReports(sid).then(setData).catch((err) => setError(err.message));
  }, [sid, loadReports]);
  useEffect(() => refresh(), [refresh]);
  const list = (data?.reports || []).filter((r) => (filter === "open" ? r.status === "open" : r.status !== "open"));
  return (
    <>
      <SettingsTitle intro="Reports are encrypted to the moderators who were here when they were sent, so only you and they can read them. The service knows who reported whom and when, nothing more.">Reports</SettingsTitle>
      <div className="mb-4 flex gap-2">
        <Button size="sm" variant={filter === "open" ? "default" : "outline"} onClick={() => setFilter("open")}>Open</Button>
        <Button size="sm" variant={filter === "closed" ? "default" : "outline"} onClick={() => setFilter("closed")}>Closed</Button>
      </div>
      <ErrorNote>{error}</ErrorNote>
      {!data && !error && <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Loading reports…</p>}
      {data && list.length === 0 && <p className="text-sm text-muted-foreground">{filter === "open" ? "No open reports. Nice." : "Nothing closed yet."}</p>}
      <ul className="space-y-3">
        {list.map((r) => <ReportCard key={r.report_id} serverId={sid} r={r} onChanged={refresh} onEscalate={setEscalating} onOpenMember={setCard} />)}
      </ul>
      <EscalateDialog serverId={sid} report={escalating} open={Boolean(escalating)} onOpenChange={(v) => !v && setEscalating(null)} onDone={refresh} />
      <MemberCard serverId={sid} userId={card} open={Boolean(card)} onOpenChange={(v) => !v && setCard(null)} />
    </>
  );
}

const STEP_ACTIONS = [["timeout", "Time out"], ["kick", "Kick"], ["ban", "Ban"]];
const STEP_MINUTES = [[10, "10 minutes"], [60, "1 hour"], [360, "6 hours"], [1440, "1 day"], [10080, "1 week"], [40320, "28 days"]];

/** The server's automatic moderation: warning steps, flood, raid and staff limits. */
export function ModerationRules({ sid }) {
  const { servers } = useServers();
  const [policy, setPolicy] = useState(null);
  const [raidAt, setRaidAt] = useState("");
  const [state, setState] = useState({ busy: false, msg: "", error: "" });
  const { modCall } = useServers();
  const owner = servers[sid]?.server?.owner_id === servers[sid]?.member?.user_id;
  useEffect(() => {
    callFn("moderation", { action: "policy", server_id: sid }).then((r) => { setPolicy(r.policy); setRaidAt(r.raid_detected_at); }).catch((err) => setState({ busy: false, msg: "", error: err.message }));
  }, [sid]);
  if (!policy) return <ErrorNote>{state.error}</ErrorNote>;
  const save = async (next, extra = {}) => {
    setState({ busy: true, msg: "", error: "" });
    try {
      const r = await modCall("set_policy", { server_id: sid, policy: next, ...extra });
      setPolicy(r.policy);
      if (extra.clear_raid) setRaidAt("");
      setState({ busy: false, msg: "Saved.", error: "" });
    } catch (err) {
      setState({ busy: false, msg: "", error: err.message });
    }
  };
  const steps = policy.thresholds;
  const setStep = (i, changes) => save({ ...policy, thresholds: steps.map((t, j) => (j === i ? { ...t, ...changes } : t)) });
  const toggle = (label, checked, onChange, help, disabled = false) => (
    <label className="flex items-center justify-between gap-4 py-2">
      <span className="text-sm"><span className="block font-medium">{label}</span>{help && <span className="block text-xs text-muted-foreground">{help}</span>}</span>
      <Switch checked={checked} disabled={state.busy || disabled} onCheckedChange={onChange} />
    </label>
  );
  return (
    <>
      {raidAt && (
        <div className="mb-4 flex items-start gap-3 rounded-lg border border-[hsl(var(--warning)/0.4)] bg-[hsl(var(--warning)/0.1)] p-3 text-sm">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[hsl(var(--warning))]" aria-hidden="true" />
          <p className="flex-1">Raid protection paused joining on {when(raidAt)}. Turn "Pause joining" off above once it's calm.</p>
          <Button size="sm" variant="outline" onClick={() => save(policy, { clear_raid: true })}>Dismiss</Button>
        </div>
      )}
      <SettingsGroup title="Warnings" description="Moderators warn people from their profile or from a report. When someone reaches one of these counts, the server acts by itself. Warnings older than the window stop counting.">
        <ul className="space-y-2">
          {steps.map((t, i) => (
            <li key={i} className="flex flex-wrap items-center gap-2 text-sm">
              <span>At</span>
              <NativeSelect aria-label="Number of warnings" value={String(t.count)} disabled={state.busy} onChange={(e) => setStep(i, { count: Number(e.target.value) })} className="w-20">
                {Array.from({ length: 20 }, (_, n) => n + 1).map((n) => <option key={n} value={String(n)}>{n}</option>)}
              </NativeSelect>
              <span>warnings:</span>
              <NativeSelect aria-label="What happens" value={t.action} disabled={state.busy} onChange={(e) => setStep(i, { action: e.target.value, minutes: e.target.value === "timeout" ? 60 : 0 })} className="w-32">
                {STEP_ACTIONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
              </NativeSelect>
              {t.action !== "kick" && (
                <NativeSelect aria-label="For how long" value={String(t.minutes)} disabled={state.busy} onChange={(e) => setStep(i, { minutes: Number(e.target.value) })} className="w-36">
                  {t.action === "ban" && <option value="0">For good</option>}
                  {STEP_MINUTES.map(([v, l]) => <option key={v} value={String(v)}>{l}</option>)}
                </NativeSelect>
              )}
              <Button size="sm" variant="ghost" disabled={state.busy} onClick={() => save({ ...policy, thresholds: steps.filter((_, j) => j !== i) })} aria-label="Remove this step"><X className="h-4 w-4" aria-hidden="true" /></Button>
            </li>
          ))}
        </ul>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          {steps.length < 5 && <Button size="sm" variant="outline" disabled={state.busy} onClick={() => save({ ...policy, thresholds: [...steps, { count: Math.min(20, (steps.at(-1)?.count || 0) + 2), action: "ban", minutes: 0 }] })}>Add a step</Button>}
          <span className="flex items-center gap-2 text-sm">
            <Label htmlFor="warn-window">Count warnings from the last</Label>
            <NativeSelect id="warn-window" value={String(policy.warn_window_days)} disabled={state.busy} onChange={(e) => save({ ...policy, warn_window_days: Number(e.target.value) })} className="w-28">
              {[[7, "week"], [30, "30 days"], [90, "90 days"], [365, "year"]].map(([v, l]) => <option key={v} value={String(v)}>{l}</option>)}
            </NativeSelect>
          </span>
        </div>
      </SettingsGroup>
      <SettingsGroup title="Spam and raids" description="These work from counts and times alone, so they need nothing decrypted. Staff aren't affected.">
        {toggle("Flood protection", policy.flood.enabled, (v) => save({ ...policy, flood: { ...policy.flood, enabled: v } }), "Time out anyone who sends too many messages too quickly.")}
        {policy.flood.enabled && (
          <div className="flex flex-wrap items-center gap-2 pb-2 text-sm">
            <NativeSelect aria-label="Messages" value={String(policy.flood.messages)} disabled={state.busy} onChange={(e) => save({ ...policy, flood: { ...policy.flood, messages: Number(e.target.value) } })} className="w-20">
              {[5, 8, 12, 20].map((n) => <option key={n} value={String(n)}>{n}</option>)}
            </NativeSelect>
            <span>messages in</span>
            <NativeSelect aria-label="Seconds" value={String(policy.flood.seconds)} disabled={state.busy} onChange={(e) => save({ ...policy, flood: { ...policy.flood, seconds: Number(e.target.value) } })} className="w-28">
              {[5, 10, 30].map((n) => <option key={n} value={String(n)}>{n} seconds</option>)}
            </NativeSelect>
            <span>times them out for</span>
            <NativeSelect aria-label="Timeout" value={String(policy.flood.timeout_minutes)} disabled={state.busy} onChange={(e) => save({ ...policy, flood: { ...policy.flood, timeout_minutes: Number(e.target.value) } })} className="w-32">
              {[[1, "1 minute"], [5, "5 minutes"], [10, "10 minutes"], [60, "1 hour"]].map(([v, l]) => <option key={v} value={String(v)}>{l}</option>)}
            </NativeSelect>
          </div>
        )}
        {toggle("Raid protection", policy.raid.enabled, (v) => save({ ...policy, raid: { ...policy.raid, enabled: v } }), "Pause joining by itself when lots of people join at once.")}
        {policy.raid.enabled && (
          <div className="flex items-center gap-2 pb-2 text-sm">
            <span>More than</span>
            <NativeSelect aria-label="Joins per minute" value={String(policy.raid.joins_per_minute)} disabled={state.busy} onChange={(e) => save({ ...policy, raid: { ...policy.raid, joins_per_minute: Number(e.target.value) } })} className="w-20">
              {[5, 10, 20, 50].map((n) => <option key={n} value={String(n)}>{n}</option>)}
            </NativeSelect>
            <span>joins in a minute</span>
          </div>
        )}
      </SettingsGroup>
      <SettingsGroup title="Staff limits" description="Stops a compromised or rogue staff account wrecking the server: anyone but the owner who bans, kicks, times out or deletes channels or roles too many times in ten minutes is stopped, and loses their roles until the owner gives them back.">
        {toggle("Limit staff actions", policy.nuke.enabled, (v) => save({ ...policy, nuke: { ...policy.nuke, enabled: v } }), owner ? null : "Only the owner can turn this off.", !owner && policy.nuke.enabled)}
        {policy.nuke.enabled && (
          <div className="flex items-center gap-2 pb-2 text-sm">
            <span>At most</span>
            <NativeSelect aria-label="Actions" value={String(policy.nuke.limit)} disabled={state.busy} onChange={(e) => save({ ...policy, nuke: { ...policy.nuke, limit: Number(e.target.value) } })} className="w-20">
              {[3, 5, 10, 20].map((n) => <option key={n} value={String(n)}>{n}</option>)}
            </NativeSelect>
            <span>such actions in ten minutes</span>
          </div>
        )}
      </SettingsGroup>
      {state.error && <p className="text-sm text-destructive" role="alert">{state.error}</p>}
      {state.msg && <p className="text-sm text-primary">{state.msg}</p>}
    </>
  );
}

/** Every case in the server: who did what to whom, with reasons opened here. */
export function CaseLog({ sid }) {
  const { loadCases, memberName } = useServers();
  const [cases, setCases] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    loadCases(sid).then((r) => setCases(r.cases)).catch((err) => setError(err.message));
  }, [sid, loadCases]);
  const label = { warn: "warned", note: "added a note on", timeout: "timed out", kick: "kicked", ban: "banned", unban: "unbanned", purge: "deleted messages from", quarantine: "took the roles of" };
  return (
    <SettingsGroup title="Cases" description="A record of moderation here. Reasons are encrypted with the server's key and opened on this device.">
      <ErrorNote>{error}</ErrorNote>
      {!cases && !error && <p className="text-sm text-muted-foreground">Loading…</p>}
      {cases && cases.length === 0 && <p className="text-sm text-muted-foreground">No cases yet.</p>}
      <ul className="divide-y divide-border">
        {(cases || []).map((c) => (
          <li key={c.case_id} className="py-2 text-sm">
            <span className="font-semibold">#{c.case_number}</span>{" "}
            {c.actor_id === "system" ? "The server's rules" : memberName(sid, c.actor_id)} {label[c.action] || c.action} <strong>{memberName(sid, c.target_id)}</strong>
            {c.minutes ? ` (${c.minutes >= 1440 ? `${Math.round(c.minutes / 1440)} d` : c.minutes >= 60 ? `${Math.round(c.minutes / 60)} h` : `${c.minutes} min`})` : ""}
            <span className="text-xs text-muted-foreground"> {when(c.created_at)}</span>
            {c.reasonText && <span className="block whitespace-pre-wrap text-muted-foreground">{c.reasonText}</span>}
          </li>
        ))}
      </ul>
    </SettingsGroup>
  );
}
