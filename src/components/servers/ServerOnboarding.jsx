import React, { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { Dialog, DialogContent, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { useServers } from "@/lib/secure/ServerContext";
import OnboardingCard from "@/components/servers/OnboardingCard";

/**
 * The welcome a server shows someone who has just joined. Shown once on each device: which
 * member opened which channel is not something the service needs to know, so it's remembered here.
 * Staff don't get it (they can see it in the server's settings instead).
 */
export default function ServerOnboarding({ serverId }) {
  const navigate = useNavigate();
  const { servers, prefs, serverLook, serverOnboarding, channelName, markOnboarded, isStaffIn } = useServers();
  const e = servers[serverId];
  const look = serverLook(serverId);
  const onboarding = serverOnboarding(serverId);
  const channels = e?.channels || [];

  const steps = useMemo(
    () => onboarding.steps.filter((s) => channels.some((c) => c.id === s.channel_id)),
    [onboarding.steps, channels],
  );
  const rulesChannel = channels.find((c) => c.kind === "rules") || channels.find((c) => c.template_key === "rules");

  const open = Boolean(
    e?.status === "ready" &&
    !prefs.onboarded?.[serverId] &&
    !isStaffIn(serverId, e.member) &&
    (onboarding.welcome || steps.length),
  );
  if (!open) return null;

  const go = (channelId) => {
    markOnboarded(serverId);
    navigate(`/app/s/${serverId}/${channelId}`);
  };

  return (
    <Dialog open onOpenChange={(v) => !v && markOnboarded(serverId)}>
      <DialogContent className="max-w-lg p-0">
        <div className="p-4 pb-0">
          <DialogTitle className="sr-only">{`Welcome to ${look.name}`}</DialogTitle>
          <DialogDescription className="sr-only">What this server is about and where to start.</DialogDescription>
        </div>
        <div className="p-4 pt-0">
          <OnboardingCard
            look={look}
            welcome={onboarding.welcome}
            steps={steps.map((s) => ({ ...s, label: `${channelName(channels.find((c) => c.id === s.channel_id))} — ${s.label}` }))}
            rulesRequired={Boolean(e.server.settings.rules_required && !e.member.rules_accepted_at)}
            onOpenStep={(s) => go(s.channel_id)}
            onOpenRules={rulesChannel ? () => go(rulesChannel.id) : null}
            onDone={() => markOnboarded(serverId)}
          />
        </div>
      </DialogContent>
    </Dialog>
  );
}