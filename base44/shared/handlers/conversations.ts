// Direct messages and small groups. Membership is server-side metadata; names
// and messages are end-to-end encrypted.
import { ApiError, LIMITS, id, isoTime, randomIdField, str, type Actions } from "../http.ts";
import { parseEnvelopeShape, verifyItemSignature } from "../verify.ts";
import { signedByActiveDevice } from "../deviceAuth.ts";
import { OutOfTime, eraseConversation } from "../accountDeletion.ts";
import {
  accountKeysOf,
  assertWrapsMatchMembers,
  blockedEitherWay,
  byAge,
  conversationForMember,
  conversationOut,
  enforceRate,
  myConversations,
  profileOf,
  rateLimited,
  requireActiveDevice,
  withinRate,
  withRow,
} from "../store.ts";

const USERNAME_RE = /^[A-Za-z0-9_]{3,20}$/;

async function requireSelfReady(sr: any, userId: string) {
  if (!(await profileOf(sr, userId))) throw new ApiError(409, "PROFILE_REQUIRED", "Choose a username first.");
  if (!(await accountKeysOf(sr, userId)).length) throw new ApiError(409, "SETUP_REQUIRED", "Finish setting up encryption first.");
}

/** Resolve exact usernames to user ids. Missing and blocked look the same. */
async function resolveUsernames(sr: any, me: string, usernames: unknown, max: number) {
  if (!Array.isArray(usernames) || usernames.length === 0 || usernames.length > max) {
    throw new ApiError(400, "BAD_FIELD", "Add between 1 and " + max + " people.");
  }
  const keys = [...new Set(usernames.map((u) => {
    if (typeof u !== "string" || !USERNAME_RE.test(u.trim())) throw new ApiError(400, "BAD_USERNAME", "One of those usernames isn't valid.");
    return u.trim().toLowerCase();
  }))];
  const rows = await sr.entities.Profile.filter({ username_key: { $in: keys } }, "created_date", 200);
  const ids: string[] = [];
  for (const key of keys) {
    const p = rows.find((r: any) => r.username_key === key);
    if (!p || (p.user_id !== me && (await blockedEitherWay(sr, me, p.user_id)))) {
      throw new ApiError(404, "NOT_FOUND", `No member has the username "${key}".`);
    }
    if (!(await accountKeysOf(sr, p.user_id)).length) {
      throw new ApiError(409, "MEMBER_NOT_READY", `${p.username} hasn't finished setting up encryption yet.`);
    }
    if (p.user_id !== me) ids.push(p.user_id);
  }
  return ids;
}

export const conversationActions: Actions = {
  async list({ sr, user }) {
    const rows = await myConversations(sr, user.id);
    return { conversations: rows.map(conversationOut) };
  },

  async get({ sr, user, body }) {
    const conv = await conversationForMember(sr, user.id, id(body.conversation_id, "conversation"));
    return { conversation: conversationOut(conv) };
  },

  /** Starting a conversation, like changing who's in one, needs a device signature, not just a session. */
  async create_dm(ctx) {
    const { sr, user, now } = ctx;
    const { data } = await signedByActiveDevice(ctx, "create_dm");
    await requireSelfReady(sr, user.id);
    const [other] = await resolveUsernames(sr, user.id, [data.username], 1);
    if (!other) throw new ApiError(400, "BAD_FIELD", "That's your own username.");
    const dmKey = [user.id, other].sort().join(":");
    const existing = (await sr.entities.Conversation.filter({ dm_key: dmKey }, "created_date", 5)).sort(byAge);
    if (existing[0]) return { conversation: conversationOut(existing[0]), created: false };
    await enforceRate(sr, "Conversation", { creator_id: user.id }, 3600_000, LIMITS.conversationsPerHour, now, "starting conversations");
    const members = [user.id, other];
    const created = await sr.entities.Conversation.create({ kind: "dm", member_ids: members, dm_key: dmKey, creator_id: user.id });
    if (!(await withinRate(sr, "Conversation", { creator_id: user.id }, 3600_000, LIMITS.conversationsPerHour, now, created))) {
      await sr.entities.Conversation.delete(created.id);
      throw rateLimited("starting conversations");
    }
    const all = withRow(await sr.entities.Conversation.filter({ dm_key: dmKey }, "created_date", 5), created);
    if (all[0].id !== created.id) {
      await sr.entities.Conversation.delete(created.id);
      return { conversation: conversationOut(all[0]), created: false };
    }
    return { conversation: conversationOut(created), created: true };
  },

  async create_group(ctx) {
    const { sr, user, now } = ctx;
    const { data } = await signedByActiveDevice(ctx, "create_group");
    await requireSelfReady(sr, user.id);
    const others = await resolveUsernames(sr, user.id, data.usernames, LIMITS.maxGroupMembers - 1);
    if (!others.length) throw new ApiError(400, "BAD_FIELD", "Add at least one other person.");
    await enforceRate(sr, "Conversation", { creator_id: user.id }, 3600_000, LIMITS.conversationsPerHour, now, "starting conversations");
    const members = [user.id, ...others];
    const created = await sr.entities.Conversation.create({ kind: "group", member_ids: members, creator_id: user.id });
    if (!(await withinRate(sr, "Conversation", { creator_id: user.id }, 3600_000, LIMITS.conversationsPerHour, now, created))) {
      await sr.entities.Conversation.delete(created.id);
      throw rateLimited("starting conversations");
    }
    return { conversation: conversationOut(created) };
  },

  /** Adding someone exposes future messages to them, so it needs a device signature, not just a session. */
  async add_members(ctx) {
    const { sr, user } = ctx;
    const { data } = await signedByActiveDevice(ctx, "add_members");
    const conv = await conversationForMember(sr, user.id, id(data.conversation_id, "conversation"));
    if (conv.kind !== "group") throw new ApiError(400, "NOT_GROUP", "You can only add people to a group.");
    const ids = await resolveUsernames(sr, user.id, data.usernames, LIMITS.maxGroupMembers);
    const next = [...new Set([...conv.member_ids, ...ids])];
    if (next.length > LIMITS.maxGroupMembers) throw new ApiError(409, "GROUP_FULL", `Groups can have up to ${LIMITS.maxGroupMembers} people.`);
    const updated = await sr.entities.Conversation.update(conv.id, { member_ids: next });
    return { conversation: conversationOut({ ...conv, ...updated, member_ids: next }) };
  },

  async leave(ctx) {
    const { sr, user } = ctx;
    const { data } = await signedByActiveDevice(ctx, "leave");
    const conv = await conversationForMember(sr, user.id, id(data.conversation_id, "conversation"));
    if (conv.kind !== "group") {
      throw new ApiError(400, "DM_LEAVE", "You can't leave a direct message. Block the member if you need to stop contact.");
    }
    const next = conv.member_ids.filter((m: string) => m !== user.id);
    if (next.length === 0) {
      // Last one out: the group and its messages go, blanked first like an account deletion.
      try {
        await eraseConversation(sr, conv.id, Date.now() + 45_000);
      } catch (error) {
        if (error instanceof OutOfTime) throw new ApiError(503, "TRY_AGAIN", "Still removing this group's messages. Try again to finish.");
        throw error;
      }
    } else {
      await sr.entities.Conversation.update(conv.id, { member_ids: next });
    }
    return { ok: true };
  },

  /** Set or re-encrypt the group name, e.g. after adding people. */
  async set_title({ sr, user, body, now }) {
    const conv = await conversationForMember(sr, user.id, id(body.conversation_id, "conversation"));
    if (conv.kind !== "group") throw new ApiError(400, "NOT_GROUP", "Only groups have names.");
    const device = await requireActiveDevice(sr, user.id, randomIdField(body.device_id, "device id"));
    const itemId = randomIdField(body.item_id, "item id");
    const sentAt = isoTime(body.sent_at, "sent time");
    if (Math.abs(now.getTime() - Date.parse(sentAt)) > LIMITS.sentAtSkewMs) {
      throw new ApiError(400, "CLOCK_SKEW", "Your device clock looks wrong. Check it and try again.");
    }
    const envelope = str(body.envelope, "group name", LIMITS.maxTitleEnvelopeChars);
    const wraps = parseEnvelopeShape(envelope, LIMITS.maxTitleEnvelopeChars);
    await assertWrapsMatchMembers(sr, wraps, conv.member_ids);
    const ok = await verifyItemSignature({
      kind: "title", conversation_id: conv.id, item_id: itemId, sender_id: user.id, device_id: device.device_id,
      envelope, sent_at: sentAt, signature: body.signature, signPub: device.sign_pub,
    });
    if (!ok) throw new ApiError(403, "SIGNATURE_INVALID", "The group name's signature didn't verify.");
    const updated = await sr.entities.Conversation.update(conv.id, {
      title_envelope: envelope,
      title_item_id: itemId,
      title_sender_id: user.id,
      title_device_id: device.device_id,
      title_sent_at: sentAt,
      title_signature: body.signature,
    });
    return { conversation: conversationOut({ ...conv, ...updated }) };
  },
};
