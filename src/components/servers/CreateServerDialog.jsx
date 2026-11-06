import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, Lock, Users } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ErrorNote } from "@/components/site/bits";
import { useServers } from "@/lib/secure/ServerContext";
import { useSecure } from "@/lib/secure/SecureContext";
import { COLORS, STARTERS } from "@/lib/secure/serverTemplates";
import ServerIcon from "@/components/shell/ServerIcon";

/** An invite link, or the code from one, as { code, secret, site } (site: another Commonveil site's address). */
export function parseInvite(text) {
  const raw = String(text || "").trim();
  if (!raw) return null;
  let code = "";
  let secret = "";
  let site = "";
  const m = raw.match(/\/invite\/([A-Za-z0-9]{8,16})(?:#([A-Za-z0-9_-]+))?/);
  if (m) {
    code = m[1];
    secret = m[2] || "";
    try {
      const u = new URL(raw);
      if (u.host && u.host !== window.location.host) site = u.host;
    } catch {
      // just a path: this site
    }
  } else {
    const [c, s] = raw.split("#");
    if (/^[A-Za-z0-9]{8,16}$/.test(c)) {
      code = c;
      secret = s && /^[A-Za-z0-9_-]+$/.test(s) ? s : "";
    }
  }
  return code ? { code, secret, site } : null;
}

export function ColorPicker({ value, onChange, label = "Colour" }) {
  return (
    <div role="radiogroup" aria-label={label} className="flex flex-wrap gap-2">
      {COLORS.map((c) => (
        <button
          key={c}
          type="button"
          role="radio"
          aria-checked={value === c}
          aria-label={c}
          onClick={() => onChange(c)}
          className={`h-7 w-7 rounded-full ring-offset-2 ring-offset-background transition-shadow ${value === c ? "ring-2 ring-foreground" : "hover:ring-2 hover:ring-border"}`}
          style={{ backgroundColor: c }}
        />
      ))}
    </div>
  );
}

export default function CreateServerDialog({ open, onOpenChange }) {
  const navigate = useNavigate();
  const { createServer } = useServers();
  const { me } = useSecure();
  const [step, setStep] = useState("choose");
  const [template, setTemplate] = useState("blank");
  const [name, setName] = useState("");
  const [icon, setIcon] = useState("");
  const [color, setColor] = useState(COLORS[0]);
  const [invite, setInvite] = useState("");
  const [state, setState] = useState({ busy: false, error: "" });

  useEffect(() => {
    if (!open) return;
    setStep("choose");
    setTemplate("blank");
    setName(me?.profile ? `${me.profile.display_name || me.profile.username}'s server` : "My server");
    setIcon("");
    setColor(COLORS[Math.floor(Math.random() * COLORS.length)]);
    setInvite("");
    setState({ busy: false, error: "" });
  }, [open, me]);

  const create = async (e) => {
    e.preventDefault();
    if (!name.trim()) return;
    setState({ busy: true, error: "" });
    try {
      const sid = await createServer({ template, name: name.trim(), icon: icon.trim(), color });
      onOpenChange(false);
      navigate(`/app/s/${sid}`);
    } catch (err) {
      setState({ busy: false, error: err.message });
    }
  };

  const join = (e) => {
    e.preventDefault();
    const parsed = parseInvite(invite);
    if (!parsed) {
      setState({ busy: false, error: "That doesn't look like an invite link. It looks like …/invite/AbCd1234#…" });
      return;
    }
    onOpenChange(false);
    navigate(`/app/join/${parsed.code}${parsed.site ? `?site=${encodeURIComponent(parsed.site)}` : ""}${parsed.secret ? `#${parsed.secret}` : ""}`);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        {step === "choose" && (
          <>
            <DialogHeader>
              <DialogTitle>Create a server</DialogTitle>
              <DialogDescription>A place for your group, end-to-end encrypted. Pick a starting point; you can change everything later.</DialogDescription>
            </DialogHeader>
            <ul className="space-y-2">
              {STARTERS.map((t) => (
                <li key={t.key}>
                  <button
                    type="button"
                    onClick={() => {
                      setTemplate(t.key);
                      setStep("details");
                    }}
                    className="flex w-full items-start gap-3 rounded-lg border border-border px-4 py-3 text-left transition-colors hover:bg-muted"
                  >
                    <Users className="mt-0.5 h-5 w-5 shrink-0 text-primary" aria-hidden="true" />
                    <span>
                      <span className="block font-medium">{t.title}</span>
                      <span className="block text-sm text-muted-foreground">{t.text}</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
            <div className="border-t border-border pt-4">
              <p className="font-heading text-lg">Have an invite?</p>
              <form onSubmit={join} className="mt-2 flex gap-2">
                <Input value={invite} onChange={(e) => setInvite(e.target.value)} placeholder="Paste an invite link" aria-label="Invite link" />
                <Button type="submit" variant="outline" disabled={!invite.trim()}>Join</Button>
              </form>
              <ErrorNote>{state.error}</ErrorNote>
            </div>
          </>
        )}
        {step === "details" && (
          <form onSubmit={create} className="space-y-5">
            <DialogHeader>
              <DialogTitle>Name your server</DialogTitle>
              <DialogDescription>Only members can see its name and icon: they're encrypted on your device like everything else.</DialogDescription>
            </DialogHeader>
            <div className="flex items-center gap-4">
              <ServerIcon look={{ name: name || "?", icon, color }} size="h-16 w-16" rounded />
              <div className="min-w-0 flex-1 space-y-1.5">
                <Label htmlFor="server-icon">Icon</Label>
                <Input id="server-icon" value={icon} onChange={(e) => setIcon(e.target.value.slice(0, 8))} placeholder="An emoji or two letters" maxLength={8} />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="server-name">Server name</Label>
              <Input id="server-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} required autoFocus />
            </div>
            <div className="space-y-1.5">
              <Label>Colour</Label>
              <ColorPicker value={color} onChange={setColor} />
            </div>
            <p className="flex items-start gap-2 text-sm text-muted-foreground">
              <Lock className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
              Your device makes the server's keys now. People you invite get copies sealed to their own keys.
            </p>
            <ErrorNote>{state.error}</ErrorNote>
            <div className="flex items-center justify-between gap-2">
              <Button type="button" variant="ghost" onClick={() => setStep("choose")} disabled={state.busy}>
                <ArrowLeft className="mr-1 h-4 w-4" aria-hidden="true" /> Back
              </Button>
              <Button type="submit" disabled={state.busy || !name.trim()}>{state.busy ? "Creating and encrypting…" : "Create server"}</Button>
            </div>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
