import React, { useEffect, useState } from "react";
import { Flag, ShieldCheck } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { callFn } from "@/lib/api";
import { useServers } from "@/lib/secure/ServerContext";

export const REASON_LABELS = {
  spam: "Spam or scams",
  harassment: "Harassment or bullying",
  hate: "Hate speech",
  sexual: "Unwanted sexual content",
  violence: "Threats or violence",
  self_harm: "Someone may be at risk of harming themselves",
  scam: "Fraud or phishing",
  illegal: "Something illegal",
  under_16: "They seem to be under 16",
  other: "Something else",
};
// The Commonveil team's own report reasons.
const TEAM_REASON = { spam: "spam", scam: "spam", harassment: "harassment", hate: "harassment", violence: "harassment", illegal: "illegal", under_16: "under_16" };

/**
 * Report someone (and optionally one of their messages) to this server's moderators. The report
 * is encrypted to the moderators. Optionally, the reporter can also tell the Commonveil team, which
 * means sharing what they write with us in readable form.
 */
export default function ReportDialog({ serverId, target, message = null, open, onOpenChange }) {
  const { reportToMods, memberName } = useServers();
  const [reason, setReason] = useState("harassment");
  const [note, setNote] = useState("");
  const [include, setInclude] = useState(true);
  const [team, setTeam] = useState(false);
  const [state, setState] = useState({ busy: false, error: "", done: false });

  useEffect(() => {
    if (open) {
      setReason("harassment");
      setNote("");
      setInclude(Boolean(message));
      setTeam(false);
      setState({ busy: false, error: "", done: false });
    }
  }, [open, message]);

  if (!target) return null;
  const name = memberName(serverId, target);

  const submit = async (e) => {
    e.preventDefault();
    setState({ busy: true, error: "", done: false });
    try {
      let toMods = true;
      try {
        await reportToMods(serverId, {
          targetId: target, reason, note,
          quote: include && message ? { text: message.text, author_id: target, sent_at: message.sentAt || "" } : null,
          channelId: message?.channelId || "", msgId: message?.msgId || "",
        });
      } catch (err) {
        if (!team) throw err;
        toMods = false;
      }
      if (team) {
        const details = [note.trim(), include && message ? `Reported message: "${message.text}"` : ""].filter(Boolean).join("\n\n").slice(0, 2000);
        await callFn("safety", { action: "report", user_id: target, reason: TEAM_REASON[reason] || "other", details });
      }
      setState({ busy: false, error: "", done: toMods ? "mods" : "team" });
    } catch (err) {
      setState({ busy: false, error: err.message, done: false });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90dvh] max-w-md overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Report {name}</DialogTitle>
          <DialogDescription>Sent to this server's moderators, encrypted so only they can read it. They'll see that it came from you; {name} won't.</DialogDescription>
        </DialogHeader>
        {state.done ? (
          <div className="space-y-3 text-sm">
            <p className="flex items-start gap-2"><ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" /> {state.done === "mods" ? "Sent to the moderators." : "Sent to the Commonveil team."} Thanks for looking out for people here.</p>
            {reason === "self_harm" && <p className="rounded-md bg-muted p-3">If someone is in immediate danger, contact your local emergency services.</p>}
            <p className="text-muted-foreground">You can also block them from their profile, so they can't message you.</p>
            <Button onClick={() => onOpenChange(false)}>Done</Button>
          </div>
        ) : (
          <form onSubmit={submit} className="space-y-4">
            <fieldset className="space-y-1.5">
              <legend className="mb-1 text-sm font-medium">What's wrong?</legend>
              {Object.entries(REASON_LABELS).map(([v, l]) => (
                <label key={v} className="flex items-center gap-2 text-sm">
                  <input type="radio" name="report-reason" value={v} checked={reason === v} onChange={() => setReason(v)} className="accent-[hsl(var(--primary))]" />
                  {l}
                </label>
              ))}
            </fieldset>
            {message && (
              <label className="flex items-start gap-2 text-sm">
                <Checkbox checked={include} onCheckedChange={(v) => setInclude(Boolean(v))} className="mt-0.5" />
                <span>
                  Include the message
                  <span className="mt-1 block max-h-20 overflow-hidden rounded bg-muted px-2 py-1 text-xs text-muted-foreground">{message.text || "(no text)"}</span>
                </span>
              </label>
            )}
            <div className="space-y-1.5">
              <Label htmlFor="report-note">Anything moderators should know (optional)</Label>
              <Textarea id="report-note" value={note} onChange={(e) => setNote(e.target.value)} maxLength={1000} rows={3} />
            </div>
            <label className="flex items-start gap-2 text-sm">
              <Checkbox checked={team} onCheckedChange={(v) => setTeam(Boolean(v))} className="mt-0.5" />
              <span>
                Also tell the Commonveil team
                <span className="block text-xs text-muted-foreground">For things that break the law or Commonveil's rules. What you write (and the message, if included) is shared with our team in readable form, since they can't read anything otherwise.</span>
              </span>
            </label>
            {state.error && <p className="text-sm text-destructive" role="alert">{state.error}</p>}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={state.busy}>Cancel</Button>
              <Button type="submit" disabled={state.busy}><Flag className="mr-1.5 h-4 w-4" aria-hidden="true" /> {state.busy ? "Sending…" : "Send report"}</Button>
            </div>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
