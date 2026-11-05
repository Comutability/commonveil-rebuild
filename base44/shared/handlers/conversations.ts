// Direct messages and small groups. Membership is server-side metadata; names
// and messages are end-to-end encrypted.
import { ApiError, LIMITS, id, isoTime, randomIdField, str, type Actions } from "../http.ts";
import { parseEnvelopeShape, verifyItemSignature } from "../verify.ts";
import { signedByActiveDevice } from "../deviceAuth.ts";
import { OutOfTime, eraseConversation } from "../accountDeletion.ts";
import {
  EXPIRY_CHOICES,
  accountKeysOf,
  adminsOf,
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
  requireGroupAdmin,
  withinRate,
  withoutMember,
  withRow,
} from "../store.ts";

/** A group name set by someone who's no longer in the group can't be checked by the others, so it goes. */
const TITLE_CLEARED = { title_envelope: "", title_item_id: "", title_sender_id: "", title_device_id: "", title_sent_at: "", title_signature: "" };

const USERNAME_RE = /^[A-Za-z0-9_]{3,20}$/;

/**
 * Whether someone accepts a new conversation from me: anyone who knows their username (the
 * default), only people they share a server with (one that counts for this), or nobody new.
 */
async function acceptsFrom(sr: any, own: any, me: string, profile: any) {
  const policy = profile?.dm_policy || "anyone";
  if (policy === "anyone") return true;
  if (policy === "nobody") return false;
  const mine = await own.entities.ServerMember.filter({ user_id: me }, "created_date", 200);
  const serverIds = [...new Set(mine.map((m: any) => m.server_id))];
  if (!serverIds.length) return false;
  const theirs = await sr.entities.ServerMember.filter({ server_id: { $in: serverIds }, user_id: profile.user_id }, "created_date", 200);
  if (!theirs.length) return false;
  const servers = await sr.entities.Server.filter({ audience_id: { $in: theirs.map((m: any) => m.server_id) } }, "created_date", 200);
  return servers.some((s: any) => s.allow_member_dms !== false && s.status !== "deleting");
}

async function requireAccepts(sr: any, own: any, me: string, userIds: string[]) {
  if (!userIds.length) return;
  const profiles = await sr.entities.Profile.filter({ user_id: { $in: userIds } }, "created_date", userIds.length + 5);
  for (const p of profiles) {
    if (!(await acceptsFrom(sr, own, me, p))) throw new ApiError(403, "NOT_ACCEPTING", `${p.username} isn't accepting new conversations.`);
  }
}

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
  // Reads with the caller's own access (see Ctx).
  async list({ own, user }) {
    const rows = await myConversations(own, user.id);
    return { conversations: rows.map(conversationOut) };
  },

  async get({ own, user, body }) {
    const conv = await conversationForMember(own, user.id, id(body.conversation_id, "conversation"));
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
    await requireAccepts(sr, ctx.own, user.id, [other]);
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
    await requireAccepts(sr, ctx.own, user.id, others);
    await enforceRate(sr, "Conversation", { creator_id: user.id }, 3600_000, LIMITS.conversationsPerHour, now, "starting conversations");
    const members = [user.id, ...others];
    const created = await sr.entities.Conversation.create({ kind: "group", member_ids: members, admin_ids: [user.id], creator_id: user.id });
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
    requireGroupAdmin(conv, user.id, "add people");
    const ids = await resolveUsernames(sr, user.id, data.usernames, LIMITS.maxGroupMembers);
    await requireAccepts(sr, ctx.own, user.id, ids.filter((i) => !conv.member_ids.includes(i)));
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
    const next = withoutMember(conv, user.id);
    if (next.member_ids.length === 0) {
      // Last one out: the group and its messages go, blanked first like an account deletion.
      try {
        await eraseConversation(sr, conv.id, Date.now() + 45_000);
      } catch (error) {
        if (error instanceof OutOfTime) throw new ApiError(503, "TRY_AGAIN", "Still removing this group's messages. Try again to finish.");
        throw error;
      }
    } else {
      await sr.entities.Conversation.update(conv.id, { ...next, ...(conv.title_sender_id === user.id ? TITLE_CLEARED : {}) });
    }
    return { ok: true };
  },

  /** An admin removes someone from a group. They keep what they already received; nothing new is sealed to them. */
  async remove_member(ctx) {
    const { sr, user } = ctx;
    const { data } = await signedByActiveDevice(ctx, "remove_member");
    const conv = await conversationForMember(sr, user.id, id(data.conversation_id, "conversation"));
    if (conv.kind !== "group") throw new ApiError(400, "NOT_GROUP", "Only groups have members to remove.");
    requireGroupAdmin(conv, user.id, "remove people");
    const target = id(data.user_id, "member");
    if (target === user.id) throw new ApiError(400, "BAD_FIELD", "To leave the group yourself, use Leave group.");
    if (!conv.member_ids.includes(target)) throw new ApiError(404, "NOT_MEMBER", "That person isn't in this group.");
    const next = withoutMember(conv, target);
    const updated = await sr.entities.Conversation.update(conv.id, { ...next, ...(conv.title_sender_id === target ? TITLE_CLEARED : {}) });
    return { conversation: conversationOut({ ...conv, ...updated, ...next }) };
  },

  /** An admin makes another member an admin, or stops being one while another admin remains. */
  async set_admin(ctx) {
    const { sr, user } = ctx;
    const { data } = await signedByActiveDevice(ctx, "set_admin");
    const conv = await conversationForMember(sr, user.id, id(data.conversation_id, "conversation"));
    if (conv.kind !== "group") throw new ApiError(400, "NOT_GROUP", "Only groups have admins.");
    requireGroupAdmin(conv, user.id, "choose admins");
    const target = id(data.user_id, "member");
    if (!conv.member_ids.includes(target)) throw new ApiError(404, "NOT_MEMBER", "That person isn't in this group.");
    if (typeof data.admin !== "boolean") throw new ApiError(400, "BAD_FIELD", "Say whether they should be an admin.");
    const current = adminsOf(conv);
    const admin_ids = data.admin ? [...new Set([...current, target])] : current.filter((a) => a !== target);
    if (!admin_ids.length) throw new ApiError(409, "LAST_ADMIN", "A group needs at least one admin. Make someone else an admin first.");
    const updated = await sr.entities.Conversation.update(conv.id, { admin_ids });
    return { conversation: conversationOut({ ...conv, ...updated, admin_ids }) };
  },

  /**
   * Disappearing messages: from now on, each message is deleted this long after it's sent.
   * Either person in a direct message can change it; in a group, only admins. The new
   * timer and who set it are shown to everyone in the conversation.
   */
  async set_expiry(ctx) {
    const { sr, user, now } = ctx;
    const { data } = await signedByActiveDevice(ctx, "set_expiry");
    const conv = await conversationForMember(sr, user.id, id(data.conversation_id, "conversation"));
    requireGroupAdmin(conv, user.id, "change disappearing messages");
    const seconds = Number(data.seconds);
    if (!EXPIRY_CHOICES.includes(seconds)) throw new ApiError(400, "BAD_FIELD", "Choose off, a day, a week or four weeks.");
    const changes = { expire_seconds: seconds, expiry_set_by: user.id, expiry_set_at: now.toISOString() };
    const updated = await sr.entities.Conversation.update(conv.id, changes);
    return { conversation: conversationOut({ ...conv, ...updated, ...changes }) };
  },

  /**
   * Self-destruct: the whole conversation (every message and file, for everyone) is deleted at
   * this time. Either person in a direct message, or a group's admins, set it; 0 turns it off.
   */
  async set_self_destruct(ctx) {
    const { sr, user, now } = ctx;
    const { data } = await signedByActiveDevice(ctx, "set_self_destruct");
    const conv = await conversationForMember(sr, user.id, id(data.conversation_id, "conversation"));
    if (conv.server_id) throw new ApiError(400, "BAD_FIELD", "Support tickets can't self-destruct.");
    requireGroupAdmin(conv, user.id, "set a self-destruct time");
    const hours = Number(data.hours);
    if (![0, 1, 6, 24, 72, 168, 720].includes(hours)) throw new ApiError(400, "BAD_FIELD", "Choose off, or a time from an hour to 30 days.");
    const changes = { destroy_at: hours ? new Date(now.getTime() + hours * 3600_000).toISOString() : "", destroy_set_by: hours ? user.id : "" };
    const updated = await sr.entities.Conversation.update(conv.id, changes);
    return { conversation: conversationOut({ ...conv, ...updated, ...changes }) };
  },

  /** Set or re-encrypt the group name, e.g. after adding people. */
  async set_title({ sr, own, user, body, now }) {
    const conv = await conversationForMember(own, user.id, id(body.conversation_id, "conversation"));
    if (conv.kind !== "group") throw new ApiError(400, "NOT_GROUP", "Only groups have names.");
    requireGroupAdmin(conv, user.id, "rename the group");
    const device = await requireActiveDevice(own, user.id, randomIdField(body.device_id, "device id"));
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
