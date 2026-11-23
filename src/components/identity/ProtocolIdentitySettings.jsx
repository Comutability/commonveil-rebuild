import React from "react";
import { SettingsGroup, SettingsTitle } from "@/components/settings/SettingsLayout";
import ProtocolActorCard from "@/components/identity/ProtocolActorCard";
import ExternalActorVerify from "@/components/identity/ExternalActorVerify";
import MigrationChecklist from "@/components/identity/MigrationChecklist";

/**
 * Settings, Protocol identity: the actor this account has on this site, a way to check an actor
 * document made elsewhere, and preparation for another site. Read-only throughout.
 */
export default function ProtocolIdentitySettings() {
  return (
    <>
      <SettingsTitle intro="Your Secure Net identity here, checked on this device: what it is, how to compare it with someone, and what another site would need to look like before a move could even be considered." help="other-sites">
        Protocol identity
      </SettingsTitle>
      <SettingsGroup title="Your Commonveil actor">
        <ProtocolActorCard />
      </SettingsGroup>
      <SettingsGroup
        title="Check another actor document"
        description="An actor can be made by any compatible application, with no site involved. Paste or choose one to check it here."
      >
        <ExternalActorVerify />
      </SettingsGroup>
      <SettingsGroup
        title="Preparing a move to another site"
        description="A compatibility check against a destination, not a move. Secure Net carries messages between sites; it doesn't issue identities, and this site doesn't own yours."
      >
        <MigrationChecklist />
      </SettingsGroup>
    </>
  );
}