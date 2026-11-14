// The backend functions, exactly as Base44 runs them (base44/functions/*/entry.ts), wired to the
// self-hosted store. The handlers in base44/shared are the same code on both.
import { runAction } from "../base44/shared/http.ts";
import { profileActions } from "../base44/shared/handlers/profile.ts";
import { keysActions } from "../base44/shared/handlers/keys.ts";
import { conversationActions } from "../base44/shared/handlers/conversations.ts";
import { messageActions } from "../base44/shared/handlers/messages.ts";
import { adminActions, safetyActions } from "../base44/shared/handlers/safety.ts";
import { disclosureActions } from "../base44/shared/handlers/disclosure.ts";
import { inviteActions, serverActions } from "../base44/shared/handlers/servers.ts";
import { serverMessageActions } from "../base44/shared/handlers/serverMessages.ts";
import { voiceActions } from "../base44/shared/handlers/voice.ts";
import { FILES_MAX_BODY, fileActions } from "../base44/shared/handlers/files.ts";
import { eventActions } from "../base44/shared/handlers/events.ts";
import { moderationActions } from "../base44/shared/handlers/moderation.ts";
import { identityActions } from "../base44/shared/handlers/identity.ts";
import { notificationActions } from "../base44/shared/handlers/notifications.ts";
import { protocolActions } from "../base44/shared/handlers/protocol.ts";
import { snipActions } from "../base44/shared/handlers/snips.ts";

export { runMaintenance } from "../base44/shared/maintenance.ts";

/** name -> [actions, options]. identity: the site's sign-in settings (handlers/identity.ts). */
export function functionTable({ defaultAdmins, identity, snipForum = null }) {
  return {
    ...(identity ? { identity: [identityActions(identity), { allowAnonymous: true }] } : {}),
    notifications: [notificationActions],
    profile: [profileActions],
    keys: [keysActions],
    conversations: [conversationActions],
    messages: [messageActions],
    safety: [safetyActions],
    admin: [adminActions],
    disclose: [disclosureActions, { allowAnonymous: true }],
    invite: [inviteActions, { allowAnonymous: true }],
    servers: [serverActions({ defaultAdmins: () => defaultAdmins })],
    channels: [serverMessageActions],
    voice: [voiceActions],
    files: [fileActions, { maxBodyBytes: FILES_MAX_BODY }],
    events: [eventActions],
    moderation: [moderationActions],
    protocol: [protocolActions],
    // Off on self-hosted sites unless SNIP_FORUM=on (docs/SNIP_FORUM.md).
    snips: [snipActions({ enabled: () => Boolean(snipForum?.enabled), repo: () => snipForum?.repo || "", token: () => snipForum?.token || "" })],
  };
}

export { runAction, FILES_MAX_BODY };
