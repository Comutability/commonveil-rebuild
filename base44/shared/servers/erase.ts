// Deleting a server, and taking a deleted account out of every server it was in.
// Like account deletion, every record is overwritten with blanks before it's deleted (Base44
// keeps deleted records in a recycle bin), and the work picks up where it stopped if it runs out
// of time.
import { byAge } from "../store.ts";
import { BLANK_SERVER_MESSAGE, refreshAccess } from "./model.ts";
import { removeMember } from "./build.ts";

const BATCH = 200;

/** Delete a server and everything in it. Returns true when finished; false means call again. */
export async function eraseServer(sr: any, server: any, deadline: number) {
  if (server.status !== "deleting") await sr.entities.Server.update(server.id, { status: "deleting" });
  const sid = server.id;
  for (;;) {
    if (Date.now() > deadline) return false;
    const rows = await sr.entities.ServerMessage.filter({ server_id: sid }, "created_date", BATCH);
    if (!rows.length) break;
    for (const m of rows) {
      await sr.entities.ServerMessage.update(m.id, BLANK_SERVER_MESSAGE);
      await sr.entities.ServerMessage.delete(m.id);
    }
  }
  const members = await sr.entities.ServerMember.filter({ server_id: sid }, "created_date", 10_000);
  for (const m of members) {
    if (Date.now() > deadline) return false;
    await sr.entities.ServerMember.update(m.id, { nick_envelope: "", role_ids: [] });
    await sr.entities.ServerMember.delete(m.id);
    await refreshAccess(sr, m.user_id);
  }
  for (const entity of ["KeyGrant", "KeyGeneration", "KeyChain", "Invite", "ServerBan", "AuditEntry", "EventRsvp", "ServerEvent", "ServerReport", "ModCase", "Channel", "Role"]) {
    if (Date.now() > deadline) return false;
    await sr.entities[entity].deleteMany({ server_id: sid });
  }
  // Support tickets stay as the private groups they are, no longer tied to the server.
  for (const c of await sr.entities.Conversation.filter({ server_id: sid }, "created_date", 1000)) {
    await sr.entities.Conversation.update(c.id, { server_id: "", ticket_channel_id: "" });
  }
  await sr.entities.Server.update(sid, { profile_envelope: "", rules_envelope: "", emoji_envelope: "", stickers_envelope: "", automod_envelope: "", onboarding_envelope: "", public_name: "", public_description: "", public_tags: [] });
  await sr.entities.Server.delete(sid);
  return true;
}

/**
 * An account being deleted: out of every server (its keys go with it), its messages blanked,
 * and servers it owned handed to their longest-standing member, or deleted if it was alone.
 */
export async function eraseServerTraces(sr: any, userId: string, deadline: number, now: Date) {
  const memberships = (await sr.entities.ServerMember.filter({ user_id: userId }, "created_date", 500)).sort(byAge);
  for (const m of memberships) {
    if (Date.now() > deadline) return false;
    const [server] = await sr.entities.Server.filter({ audience_id: m.server_id }, "created_date", 1);
    if (server && server.owner_id === userId) {
      const others = (await sr.entities.ServerMember.filter({ server_id: server.id }, "joined_at", 2)).filter((x: any) => x.user_id !== userId);
      if (!others.length && !server.is_default) {
        if (!(await eraseServer(sr, server, deadline))) return false;
        continue;
      }
      await sr.entities.Server.update(server.id, { owner_id: others[0]?.user_id || "" });
    }
    await removeMember(sr, m.server_id, userId, { reason: "deleted", now });
  }
  for (;;) {
    if (Date.now() > deadline) return false;
    const rows = (await sr.entities.ServerMessage.filter({ sender_id: userId }, "created_date", BATCH)).filter((x: any) => !x.deleted || x.envelope);
    if (!rows.length) break;
    for (const m of rows) {
      await sr.entities.ServerMessage.update(m.id, BLANK_SERVER_MESSAGE);
      await sr.entities.ServerMessage.delete(m.id);
    }
  }
  await sr.entities.KeyGrant.deleteMany({ user_id: userId });
  await sr.entities.EventRsvp.deleteMany({ user_id: userId });
  // Reports they sent, and cases about them, go with the account.
  await sr.entities.ServerReport.deleteMany({ reporter_id: userId });
  await sr.entities.ModCase.deleteMany({ target_id: userId });
  return true;
}