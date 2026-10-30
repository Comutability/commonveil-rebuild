import React, { useMemo, useState } from "react";
import { AlertTriangle, Ban, Flag, LogOut, ShieldCheck } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { NativeSelect } from "@/components/ui/native-select";
import { ErrorNote } from "@/components/site/bits";
import { callFn } from "@/lib/api";
import { useChat } from "@/lib/secure/ChatContext";
import { useSecure } from "@/lib/secure/SecureContext";
import { groupDigits, headDigest, safetyNumber } from "@/lib/crypto/identity.js";
import Avatar from "./Avatar";

function SafetyNumber({ peerId }) {
  const { userId, chainDigest, peers, markVerified, acceptKeyChange } = useSecure();
  const peer = peers[peerId];
  const [show, setShow] = useState(false);
  // Covers both accounts' whole key histories, not just the newest keys.
  const number = useMemo(() => {
    if (!peer?.chain || !chainDigest) return null;
    return safetyNumber({ user_id: userId, digest: chainDigest }, { user_id: peerId, digest: headDigest(peer.chain) });
  }, [peer, chainDigest, userId, peerId]);

  if (!peer) return <p className="text-xs text-muted-foreground">Checking keys…</p>;
  if (!peer.ready) return <p className="text-xs text-destructive">{peer.broken ? "Their published keys failed verification." : "No keys yet."}</p>;

  return (
    <div className="space-y-2">
      {peer.changed && (
        <div className="rounded-lg border border-[hsl(var(--warning)/0.4)] bg-[hsl(var(--warning)/0.1)] p-3 text-sm">
          <p className="flex items-center gap-1.5 font-semibold"><AlertTriangle className="h-4 w-4" aria-hidden="true" /> Their security keys changed</p>
          <p className="mt-1 text-muted-foreground">
            If they told you they reset their account, this is expected. If not, check the new safety number with them in person or over a
            call before continuing. Until you do, messages that only the new keys vouch for are marked unverified.
          </p>
          {number && <p className="mono mt-2 rounded-lg bg-background p-2 text-center text-xs leading-relaxed tracking-wide">{groupDigits(number, 5)}</p>}
          <Button size="sm" className="mt-2" onClick={() => acceptKeyChange(peerId)}>I understand, continue</Button>
        </div>
      )}
      {!peer.changed && (
        <>
          <button type="button" className="text-sm font-medium text-primary hover:underline" onClick={() => setShow((v) => !v)} aria-expanded={show}>
            {show ? "Hide safety number" : "Show safety number"}
          </button>
          {show && number && (
            <div className="space-y-2">
              <p className="mono rounded-lg bg-muted p-3 text-center text-sm leading-relaxed tracking-wide">{groupDigits(number, 5)}</p>
              <p className="text-xs text-muted-foreground">Compare this with what they see, in person or on a call. If every digit matches, nobody is in between.</p>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={Boolean(peer.verified)} onCheckedChange={(v) => markVerified(peerId, Boolean(v))} />
                Mark as verified
              </label>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function ReportForm({ userId, conversationId, onDone }) {
  const [reason, setReason] = useState("");
  const [details, setDetails] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await callFn("safety", { action: "report", user_id: userId, conversation_id: conversationId, reason, details });
      onDone("Report sent. Thank you.");
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="space-y-3 rounded-lg border border-border p-4">
      <p className="text-sm text-muted-foreground">Staff can't read your messages. Paste anything they need to see.</p>
      <NativeSelect value={reason} onChange={(e) => setReason(e.target.value)} aria-label="Reason">
        <option value="" disabled>Reason</option>
        <option value="spam">Spam</option>
        <option value="harassment">Harassment</option>
        <option value="impersonation">Impersonation</option>
        <option value="illegal">Illegal content</option>
        <option value="other">Something else</option>
      </NativeSelect>
      <Textarea value={details} onChange={(e) => setDetails(e.target.value)} maxLength={2000} rows={4} placeholder="What happened? (optional)" aria-label="Details" />
      <ErrorNote>{error}</ErrorNote>
      <Button type="submit" size="sm" disabled={!reason || busy}>{busy ? "Sending…" : "Send report"}</Button>
    </form>
  );
}

export default function ConversationInfoDialog({ conversation, open, onOpenChange, onLeft }) {
  const { userId } = useSecure();
  const { nameOf, profiles, conversationName, setTitle, addMembers, leave, titles } = useChat();
  const [title, setTitleInput] = useState("");
  const [adding, setAdding] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [reporting, setReporting] = useState(false);
  const [blocked, setBlocked] = useState(false);

  if (!conversation) return null;
  const isGroup = conversation.kind === "group";
  const others = conversation.member_ids.filter((m) => m !== userId);
  // Only a name whose signature checks out is kept (and re-encrypted for newcomers): never vouch for one that doesn't.
  const verifiedTitle = titles[conversation.id]?.status === "ok" ? titles[conversation.id].text || "" : "";
  const currentTitle = verifiedTitle;

  const run = async (fn) => {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await fn();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(v) => { onOpenChange(v); if (!v) { setReporting(false); setError(""); setMessage(""); } }}>
      <DialogContent className="max-h-[90dvh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{conversationName(conversation)}</DialogTitle>
          <DialogDescription>
            {isGroup ? `${conversation.member_ids.length} people · ` : ""}End-to-end encrypted. Verify safety numbers to be sure nobody is in between.
          </DialogDescription>
        </DialogHeader>

        <ul className="space-y-4">
          {others.map((id) => (
            <li key={id} className="flex gap-3">
              <Avatar id={id} name={nameOf(id)} size="h-9 w-9" />
              <div className="min-w-0 flex-1 space-y-1">
                <p className="font-medium">
                  {nameOf(id)} {profiles[id] && <span className="text-sm font-normal text-muted-foreground">@{profiles[id].username}</span>}
                </p>
                <SafetyNumber peerId={id} />
              </div>
            </li>
          ))}
        </ul>

        {isGroup && (
          <div className="space-y-4 border-t border-border pt-4">
            <div className="space-y-1.5">
              <Label htmlFor="rename">Group name</Label>
              <div className="flex gap-2">
                <Input id="rename" defaultValue={currentTitle} onChange={(e) => setTitleInput(e.target.value)} maxLength={80} />
                <Button variant="outline" disabled={busy || !title.trim()} onClick={() => run(async () => { await setTitle(conversation, title.trim()); setMessage("Name updated."); })}>Save</Button>
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="add-person">Add someone</Label>
              <div className="flex gap-2">
                <Input id="add-person" value={adding} onChange={(e) => setAdding(e.target.value)} placeholder="@username" autoComplete="off" autoCapitalize="none" />
                <Button
                  variant="outline"
                  disabled={busy || !adding.trim()}
                  onClick={() => run(async () => {
                    const updated = await addMembers(conversation, [adding.trim().replace(/^@/, "")]);
                    if (currentTitle) await setTitle(updated, currentTitle);
                    setAdding("");
                    setMessage("Added. They'll see messages from now on.");
                  })}
                >
                  Add
                </Button>
              </div>
            </div>
            <Button variant="ghost" className="text-destructive" disabled={busy} onClick={() => run(async () => { await leave(conversation); onOpenChange(false); onLeft?.(); })}>
              <LogOut className="mr-2 h-4 w-4" aria-hidden="true" /> Leave group
            </Button>
          </div>
        )}

        {!isGroup && others[0] && (
          <div className="flex flex-wrap gap-2 border-t border-border pt-4">
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => run(async () => {
                await callFn("safety", { action: blocked ? "unblock" : "block", user_id: others[0] });
                setBlocked(!blocked);
                setMessage(blocked ? "Unblocked." : "Blocked. Neither of you can message the other.");
              })}
            >
              <Ban className="mr-2 h-4 w-4" aria-hidden="true" /> {blocked ? "Unblock" : "Block"}
            </Button>
            <Button variant="outline" onClick={() => setReporting((v) => !v)}>
              <Flag className="mr-2 h-4 w-4" aria-hidden="true" /> Report
            </Button>
          </div>
        )}
        {reporting && others[0] && <ReportForm userId={others[0]} conversationId={conversation.id} onDone={(m) => { setReporting(false); setMessage(m); }} />}

        {message && <p className="flex items-center gap-1.5 text-sm text-primary"><ShieldCheck className="h-4 w-4" aria-hidden="true" /> {message}</p>}
        <ErrorNote>{error}</ErrorNote>
      </DialogContent>
    </Dialog>
  );
}
