import React, { useCallback, useEffect, useRef, useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { NativeSelect } from "@/components/ui/native-select";
import { ErrorNote } from "@/components/site/bits";
import { useServers } from "@/lib/secure/ServerContext";
import { MAX_ONBOARDING_STEPS } from "@/lib/secure/serverProtocol";
import { SettingsGroup, SettingsTitle } from "@/components/settings/SettingsLayout";
import OnboardingCard from "@/components/servers/OnboardingCard";

const EMPTY = { welcome: "", steps: [] };

/** The welcome a new member gets: written here, encrypted with the server's keys, shown once on their device. */
export default function OnboardingSettings({ sid }) {
  const { servers, serverLook, serverOnboarding, channelName, setServerSet } = useServers();
  const current = serverOnboarding(sid);
  const look = serverLook(sid);
  const e = servers[sid];
  const channels = (e?.channels || []).filter((c) => c.kind !== "category");

  const [form, setFormState] = useState(() => ({ welcome: current.welcome, steps: current.steps }));
  const [state, setState] = useState({ busy: false, msg: "", error: "" });
  const edited = useRef(false);
  const setForm = useCallback((fn) => {
    edited.current = true;
    setFormState(fn);
  }, []);
  // Until someone edits, follow what arrives from the server (it may still be decrypting).
  const currentKey = current.steps.map((s) => `${s.channel_id}:${s.label}`).join("|");
  useEffect(() => {
    if (edited.current) return;
    setFormState({ welcome: current.welcome, steps: current.steps });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [current.welcome, currentKey]);

  const save = async () => {
    const steps = form.steps.filter((s) => s.label.trim() && s.channel_id);
    const welcome = form.welcome.trim();
    setState({ busy: true, msg: "", error: "" });
    try {
      await setServerSet(sid, "onboarding", welcome || steps.length ? { welcome, steps } : null);
      edited.current = false;
      setState({ busy: false, msg: welcome || steps.length ? "Saved." : "Off. New members see nothing.", error: "" });
    } catch (err) {
      setState({ busy: false, msg: "", error: err.message });
    }
  };

  const setStep = (i, changes) => setForm((f) => ({ ...f, steps: f.steps.map((s, j) => (j === i ? { ...s, ...changes } : s)) }));

  return (
    <>
      <SettingsTitle intro="Shown once to each new member, on their own device, after they join. The welcome and the steps are encrypted with the server's keys: Commonveil can't read them, and can't tell who read what." help="create-a-server">Onboarding</SettingsTitle>

      <SettingsGroup title="Welcome" description="Say who this place is for and what happens here. Leave it empty to use the server's description.">
        <div className="space-y-1.5">
          <Label htmlFor="ob-welcome">Message</Label>
          <Textarea id="ob-welcome" rows={4} maxLength={600} value={form.welcome} onChange={(ev) => setForm((f) => ({ ...f, welcome: ev.target.value }))} placeholder="Hi! I made this server so that…" />
          <p className="text-xs text-muted-foreground">{form.welcome.length} of 600 characters.</p>
        </div>
      </SettingsGroup>

      <SettingsGroup title="Where to start" description={`Up to ${MAX_ONBOARDING_STEPS} things worth doing first, each opening a channel. A short line and the channel is enough.`}>
        <ol className="space-y-2">
          {form.steps.map((s, i) => (
            <li key={i} className="flex flex-wrap items-center gap-2 sm:flex-nowrap">
              <Input value={s.label} maxLength={60} aria-label={`Step ${i + 1}`} placeholder="Introduce yourself" onChange={(ev) => setStep(i, { label: ev.target.value })} className="min-w-0 flex-1" />
              <NativeSelect value={s.channel_id || ""} aria-label={`Channel for step ${i + 1}`} onChange={(ev) => setStep(i, { channel_id: ev.target.value })} className="w-44 shrink-0">
                <option value="">Choose a channel</option>
                {channels.map((c) => <option key={c.id} value={c.id}>{channelName(c)}</option>)}
              </NativeSelect>
              <Button type="button" variant="ghost" size="icon" aria-label={`Remove step ${i + 1}`} onClick={() => setForm((f) => ({ ...f, steps: f.steps.filter((_, j) => j !== i) }))}>
                <Trash2 className="h-4 w-4" aria-hidden="true" />
              </Button>
            </li>
          ))}
        </ol>
        <Button type="button" variant="outline" size="sm" className="mt-3" disabled={form.steps.length >= MAX_ONBOARDING_STEPS} onClick={() => setForm((f) => ({ ...f, steps: [...f.steps, { label: "", channel_id: channels[0]?.id || "" }] }))}>
          <Plus className="mr-1.5 h-4 w-4" aria-hidden="true" /> Add a step
        </Button>
      </SettingsGroup>

      <SettingsGroup title="What they see">
        <OnboardingCard
          preview
          look={look}
          welcome={form.welcome.trim()}
          steps={form.steps.filter((s) => s.label.trim() && s.channel_id).map((s) => ({ ...s, label: `${channelName(channels.find((c) => c.id === s.channel_id))} — ${s.label}` }))}
          rulesRequired={Boolean(e?.server.settings.rules_required)}
        />
        <div className="mt-4 flex items-center gap-2">
          <Button type="button" disabled={state.busy} onClick={save}>{state.busy ? "Encrypting and saving…" : "Save welcome"}</Button>
          {current.welcome || current.steps.length ? (
            <Button type="button" variant="ghost" disabled={state.busy} onClick={() => { setFormState(EMPTY); edited.current = true; }}>Clear</Button>
          ) : null}
        </div>
        {state.msg && <p className="mt-2 text-sm text-primary">{state.msg}</p>}
        <ErrorNote>{state.error}</ErrorNote>
      </SettingsGroup>
    </>
  );
}