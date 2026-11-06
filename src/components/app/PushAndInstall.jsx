import React, { useEffect, useState } from "react";
import { BellRing, Download, Share } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ErrorNote } from "@/components/site/bits";
import { SettingsGroup } from "@/components/settings/SettingsLayout";
import { pushState, pushSupported, sendTestPush, turnOffPush, turnOnPush } from "@/lib/pwa/push";
import { install, isIos, isStandalone, useApp } from "@/lib/pwa/app";

/** Push notifications on this device: off until turned on, and they never say anything. */
export function PushSection() {
  const [state, setState] = useState("checking");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const refresh = () => pushState().then(setState).catch(() => setState("unavailable"));
  useEffect(() => {
    refresh();
  }, []);

  const run = async (fn, done) => {
    setBusy(true);
    setError("");
    setNote("");
    try {
      await fn();
      if (done) setNote(done);
    } catch (err) {
      setError(err.message || "That didn't work.");
    } finally {
      setBusy(false);
      refresh();
    }
  };

  const needsInstall = isIos() && !isStandalone();
  return (
    <SettingsGroup
      title="Push notifications"
      description="Get told when there's something new, even when Commonveil is closed. A notification only ever says “New message” or “New activity”: never who it's from, which conversation, or a word of what was said. So your phone or browser, and the company behind it, keep no record of any of that."
    >
      {state === "unsupported" || needsInstall ? (
        <p className="text-sm text-muted-foreground">
          {needsInstall ? "On iPhone and iPad, add Commonveil to your Home Screen first (below), then open it from there to turn these on." : "This browser can't receive push notifications."}
        </p>
      ) : state === "blocked" ? (
        <p className="text-sm text-muted-foreground">Notifications are blocked for this site. Allow them in your browser's settings for this site, then come back here.</p>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <p className="mr-2 text-sm font-medium" role="status">{state === "on" ? "On for this device" : state === "checking" ? "Checking…" : "Off for this device"}</p>
          {state === "on" ? (
            <>
              <Button size="sm" variant="outline" disabled={busy} onClick={() => run(sendTestPush, "Sent. It should arrive in a few seconds.")}>Send a test</Button>
              <Button size="sm" variant="outline" disabled={busy} onClick={() => run(turnOffPush)}>Turn off</Button>
            </>
          ) : (
            <Button size="sm" disabled={busy || state === "checking"} onClick={() => run(turnOnPush, "On. You'll be told about new messages.")}>
              <BellRing className="mr-1.5 h-4 w-4" aria-hidden="true" />Turn on
            </Button>
          )}
        </div>
      )}
      <ErrorNote>{error}</ErrorNote>
      {note && <p className="mt-2 text-sm text-primary" role="status">{note}</p>}
      <ul className="mt-3 list-disc space-y-1 pl-5 text-xs text-muted-foreground">
        <li>Pushes travel through your browser's push service (Google, Mozilla, Apple or Microsoft), encrypted so they can't read them. Even decrypted, a push holds only a one-time code.</li>
        <li>Tapping one opens Commonveil, which asks where to go. Quiet hours and focus keep them silent.</li>
        <li>For conversations only. Servers stay quiet; check them when you open the app.</li>
        <li>Turned on per device. Signing out turns them off here.</li>
      </ul>
    </SettingsGroup>
  );
}

/** Installing Commonveil as an app: still a web app, from this site, with nothing extra to trust. */
export function InstallSection() {
  const { installPrompt, installed } = useApp();
  const [outcome, setOutcome] = useState("");
  const standalone = installed || isStandalone();
  return (
    <SettingsGroup
      title="Install the app"
      description="Commonveil works as an app on your phone, tablet or computer: its own window and icon, opening straight to your messages. It's still this website, so there's no app store, no separate download to trust, and updates arrive by themselves."
    >
      {standalone ? (
        <p className="text-sm" role="status">You're using the installed app.</p>
      ) : installPrompt ? (
        <Button size="sm" onClick={async () => setOutcome(await install())}>
          <Download className="mr-1.5 h-4 w-4" aria-hidden="true" />Install Commonveil
        </Button>
      ) : isIos() ? (
        <p className="flex flex-wrap items-center gap-1 text-sm">
          In Safari, tap <Share className="inline h-4 w-4" aria-label="Share" /> Share, then <span className="font-medium">Add to Home Screen</span>.
        </p>
      ) : (
        <p className="text-sm text-muted-foreground">Use your browser's menu: look for <span className="font-medium text-foreground">Install</span>, <span className="font-medium text-foreground">Install app</span> or <span className="font-medium text-foreground">Add to Home screen</span>.</p>
      )}
      {outcome === "dismissed" && <p className="mt-2 text-xs text-muted-foreground">No problem. You can install it from here any time.</p>}
    </SettingsGroup>
  );
}

export { pushSupported };
