import React, { useEffect, useState } from "react";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { SettingsGroup, SettingsTitle } from "@/components/settings/SettingsLayout";
import { setOfflineMode, useOffline } from "@/lib/offline/mode";
import { waiting } from "@/lib/offline/outbox";
import { useSecure } from "@/lib/secure/SecureContext";
import { SELF_HOSTED } from "@/api/base44Client";

/** Offline mode: send now, deliver later (docs/OFFLINE.md). */
export default function OfflineSettings() {
  const { userId } = useSecure();
  const { chosen, cutOff } = useOffline();
  const [count, setCount] = useState(null);
  useEffect(() => {
    let live = true;
    const load = () => waiting(userId).then((list) => live && setCount(list.length)).catch(() => {});
    load();
    const t = setInterval(load, 5000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, [userId]);

  return (
    <>
      <SettingsTitle intro="Keep writing when there's no connection. Messages are encrypted and signed on this device straight away, and go out when you're back." help="offline-mode">
        Offline mode
      </SettingsTitle>

      <SettingsGroup>
        <div className="flex items-start gap-3">
          <Checkbox id="offline-mode" checked={chosen} onCheckedChange={(v) => setOfflineMode(v === true)} />
          <div className="space-y-1">
            <Label htmlFor="offline-mode" className="font-medium">Offline mode</Label>
            <p className="text-sm text-muted-foreground">
              This device stops reaching the server. Messages you send wait here, already encrypted, and go out in order when you turn it off. Useful on a metered or watched connection, or to save battery.
            </p>
          </div>
        </div>
        <p className="mt-4 text-sm" role="status">
          {cutOff && !chosen ? "You're offline right now. " : ""}
          {count === null ? "" : count === 0 ? "Nothing is waiting to be sent." : count === 1 ? "1 message is waiting to be sent." : `${count} messages are waiting to be sent.`}
        </p>
      </SettingsGroup>

      <SettingsGroup title="What happens while you're offline">
        <ul className="list-disc space-y-1.5 pl-5 text-sm text-muted-foreground">
          <li>Messages to conversations and server channels are sealed to the people in them as they are now.</li>
          <li>They wait in this browser for up to a week. Nothing is kept in plain text; this device opens its own copy to show you.</li>
          <li>When you're back, they're sent oldest first, and show the time you wrote them.</li>
          <li>If something changed while you were away (someone joined, or a channel's keys moved on), the message is marked "Not sent", with Send again to seal it afresh.</li>
          <li>Keep this tab open: the app needs the server to start up.</li>
        </ul>
      </SettingsGroup>

      {SELF_HOSTED && (
        <SettingsGroup title="No internet at all?" description="A Commonveil site doesn't need the internet: only a network. Run one on a small computer with its own Wi-Fi, and everyone in range can chat on it. When its internet link comes back, it catches up with other sites by itself.">
          <p className="text-sm text-muted-foreground">Ask whoever runs this site, or see the guide to running a local site in docs/OFFLINE.md.</p>
        </SettingsGroup>
      )}
    </>
  );
}
