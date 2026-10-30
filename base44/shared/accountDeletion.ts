// Deleting an account.
//
// Base44 moves deleted records to a "Recently deleted" bin rather than erasing them, and a
// backend function can't empty that bin. So every record is first overwritten with blanks,
// then deleted: whatever stays in the bin holds nothing readable.
//
// The work is ordered so it can stop at any point and be resumed by calling again:
// 1. Leave every conversation (direct messages are removed for both people), so nothing new
//    can be sent from the account. 2. Remove everything else the account sent or owns.
// 3. Published keys before devices: once the keys are gone, a resumed call no longer needs a
//    device signature, so a half-finished deletion can't get stuck. 4. The profile last. Its
//    username is retired first, on its own: otherwise someone could claim it and pose as this
//    member to people who knew them.

const PAGE = 100;
const CONCURRENCY = 5;

export class OutOfTime extends Error {}

function checkTime(deadline: number) {
  if (Date.now() > deadline) throw new OutOfTime("deletion paused");
}

async function inChunks<T>(items: T[], fn: (item: T) => Promise<unknown>) {
  for (let i = 0; i < items.length; i += CONCURRENCY) {
    await Promise.all(items.slice(i, i + CONCURRENCY).map(fn));
  }
}

/** Blank, then delete, every record matching the query. */
async function blankAndDeleteAll(sr: any, entity: string, query: any, blank: Record<string, unknown>, deadline: number) {
  for (;;) {
    checkTime(deadline);
    const rows = await sr.entities[entity].filter(query, "created_date", PAGE);
    if (!rows.length) return;
    await inChunks(rows, async (row: any) => {
      await sr.entities[entity].update(row.id, blank);
      await sr.entities[entity].delete(row.id);
    });
  }
}

const BLANK = {
  Message: { conversation_id: "", msg_id: "", sender_id: "", device_id: "", envelope: "", signature: "", sent_at: "", recipient_ids: [], deleted: true },
  Conversation: {
    member_ids: [], dm_key: "", created_by: "", title_envelope: "", title_item_id: "", title_sender_id: "",
    title_device_id: "", title_sent_at: "", title_signature: "", last_message_at: "",
  },
  Block: { user_id: "", blocked_user_id: "" },
  Report: { reporter_id: "", reported_user_id: "", conversation_id: "", details: "", resolution_note: "", handled_by: "" },
  KeyEnvelope: { user_id: "", device_id: "", recovery_pub: "", key_sign_pub: "", sealed: "", created_by_device_id: "" },
  AccountKey: { user_id: "", ecdh_pub: "", sign_pub: "", recovery_pub: "", recovery_mac: "", signature: "", issued_at: "" },
  ResetRequest: {
    user_id: "", device_id: "", device_label: "", device_sign_pub: "", device_box_pub: "", statement: "", cert: "",
    recovery_sealed: "", recovery_pub: "", key_sign_pub: "", ended_by: "",
  },
  Device: {
    user_id: "", device_id: "", label: "", sign_pub: "", box_pub: "", cert_issued_at: "", cert_signature: "",
    approved_by_device_id: "", approved_at: "", pending_expires_at: "", revoked_at: "", last_seen_at: "",
  },
  Profile: { user_id: "", username: "", username_key: "", display_name: "", bio: "" },
};

export async function isRetiredUsername(sr: any, key: string) {
  return (await sr.entities.RetiredUsername.filter({ username_key: key }, "created_date", 1)).length > 0;
}

async function retireUsername(sr: any, key: string) {
  if (!(await isRetiredUsername(sr, key))) await sr.entities.RetiredUsername.create({ username_key: key });
}

/** Blank and delete a conversation with all its messages. Throws OutOfTime if the deadline passes. */
export async function eraseConversation(sr: any, conversationId: string, deadline: number) {
  await blankAndDeleteAll(sr, "Message", { conversation_id: conversationId }, BLANK.Message, deadline);
  await sr.entities.Conversation.update(conversationId, BLANK.Conversation);
  await sr.entities.Conversation.delete(conversationId);
}

/**
 * Remove everything belonging to userId. Returns true when finished, false if it ran out
 * of time (call again to continue).
 */
export async function purgeAccount(sr: any, userId: string, deadline: number): Promise<boolean> {
  try {
    // 1. Conversations. Direct messages go entirely; groups lose this member.
    for (;;) {
      checkTime(deadline);
      const convs = await sr.entities.Conversation.filter({ member_ids: userId }, "created_date", PAGE);
      if (!convs.length) break;
      for (const c of convs) {
        const rest = (c.member_ids || []).filter((m: string) => m !== userId);
        if (c.kind === "dm" || rest.length === 0) {
          await eraseConversation(sr, c.id, deadline);
        } else {
          const changes: Record<string, unknown> = { member_ids: rest };
          if (c.created_by === userId) changes.created_by = "";
          // A group name set by this member can't be verified once their keys are gone.
          if (c.title_sender_id === userId) {
            Object.assign(changes, { title_envelope: "", title_item_id: "", title_sender_id: "", title_device_id: "", title_sent_at: "", title_signature: "" });
          }
          await sr.entities.Conversation.update(c.id, changes);
        }
      }
    }
    // 2. Everything else the account sent or is named in.
    await blankAndDeleteAll(sr, "Message", { sender_id: userId }, BLANK.Message, deadline);
    await blankAndDeleteAll(sr, "Block", { user_id: userId }, BLANK.Block, deadline);
    await blankAndDeleteAll(sr, "Block", { blocked_user_id: userId }, BLANK.Block, deadline);
    // Reports this account made go. Reports other people made about it stay, so a deletion
    // can't wipe the record of abuse; they only ever held the reporter's own words.
    await blankAndDeleteAll(sr, "Report", { reporter_id: userId }, BLANK.Report, deadline);
    await blankAndDeleteAll(sr, "ResetRequest", { user_id: userId }, BLANK.ResetRequest, deadline);
    // Security reports are about the app, not the person: keep them, but unlink the account.
    for (const r of await sr.entities.SecurityReport.filter({ reporter_user_id: userId }, "created_date", 500)) {
      await sr.entities.SecurityReport.update(r.id, { reporter_user_id: "" });
    }
    // 3. Keys: sealed keyrings, then published keys, then devices (see the note at the top).
    await blankAndDeleteAll(sr, "KeyEnvelope", { user_id: userId }, BLANK.KeyEnvelope, deadline);
    await blankAndDeleteAll(sr, "AccountKey", { user_id: userId }, BLANK.AccountKey, deadline);
    await blankAndDeleteAll(sr, "Device", { user_id: userId }, BLANK.Device, deadline);
    // 4. The profile, after retiring its username.
    for (;;) {
      checkTime(deadline);
      const profiles = await sr.entities.Profile.filter({ user_id: userId }, "created_date", PAGE);
      if (!profiles.length) break;
      for (const p of profiles) {
        if (p.username_key) await retireUsername(sr, p.username_key);
        await sr.entities.Profile.update(p.id, BLANK.Profile);
        await sr.entities.Profile.delete(p.id);
      }
    }
    return true;
  } catch (error) {
    if (error instanceof OutOfTime) return false;
    throw error;
  }
}

/**
 * Remove the member's Base44 sign-in. Base44 keeps removed users in its own bin for 30 days
 * before erasing them, and never lets an app remove its owner.
 */
export async function removePlatformUser(sr: any, userId: string): Promise<boolean> {
  try {
    await sr.entities.User.delete(userId);
    return true;
  } catch {
    return false;
  }
}
