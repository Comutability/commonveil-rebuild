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
        title="Protocol and migration readiness"
        description="The Secure Net protocol is independent of Commonveil and can be implemented by other compatible applications."
      >
        <div className="space-y-3 text-sm">
          <p>
            Commonveil can verify signed independent actor documents and check another site's
            advertised transport capabilities. The self-hosted Rust server also contains an
            experimental encrypted-transfer staging prototype using Secure Net's draft
            migration validation rules.
          </p>
          <p className="text-muted-foreground">
            This is <strong>not an active migration service</strong>. The staging API is disabled
            by default in Docker, is not offered by the hosted site, and cannot move a live
            account or redirect an encrypted inbox. The browser still uses the last
            compatible Secure Net JavaScript library for its existing messaging and actor
            verification. The browser has an experimental, device-only encrypted reconciliation
            report helper, while the newer signed transfer and reconciliation checks run in the
            Rust development backend. Neither is wired into a live account migration flow.
            An independently reviewed recipient-device authorisation and importer are still required.
          </p>
          <p className="text-muted-foreground">
            Your existing messages, contacts, keys and routing are not changed by viewing
            these checks. Do not delete the original account after exporting a passport.
          </p>
        </div>
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