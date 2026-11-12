// Encrypted messages. The server checks membership, the sending device, the
// signature and that every current member got a copy of the key, then stores
// ciphertext it cannot read.
import { conversationPath, notifyPeople } from "./notifications.ts";
import { ApiError, LIMITS, id, int, isoTime, platformTime, randomIdField, str, type Actions } from "../http.ts";
import { checkSentAt, parseEnvelopeShape, verifyItemSignature } from "../verify.ts";
import { signedByActiveDevice } from "../deviceAuth.ts";
import { pollServers } from "./serverMessages.ts";
import { scheduledActions } from "./scheduled.ts";
import {
  addressedTo,
  assertWrapsMatchMembers,
  blockedEitherWay,
  conversationForMember,
  conversationOut,
  enforceRate,
  isLive,
  messageOut,
  myConversations,
  rateLimited,
  requireActiveDevice,
  withinRate,
} from "../store.ts";

/** How far behind "now" a poll cursor stays, so rows that show up late in queries aren't skipped. */
const SETTLE_MS = 5_000;

const BLANK_MESSAGE = {
  conversation_id: "", msg_id: "", sender_id: "", device_id: "", envelope: "", signature: "", sent_at: "", recipient_ids: [], deleted: true,
};

export const messageActions: Actions = {
  ...scheduledActions,
  /**
   * Reads that only touch the sender's own rows use their own access; the block check and
   * the other members' key versions need the service role (see Ctx).
   */
  async send({ sr, own, user, body, now, push }: any) {
    const conv = await conversationForMember(own, user.id, id(body.conversation_id, "conversation"));
    if (conv.kind === "dm") {
      const other = conv.member_ids.find((m: string) => m !== user.id);
      if (other && (await blockedEitherWay(sr, user.id, other))) throw new ApiError(403, "BLOCKED", "You can't message this member.");
    }
    const device = await requireActiveDevice(own, user.id, randomIdField(body.device_id, "device id"));
    const msgId = randomIdField(body.msg_id, "message id");
    const sentAt = isoTime(body.sent_at, "sent time");
    checkSentAt(sentAt, now, body.queued);
    const envelope = typeof body.envelope === "string" ? body.envelope : "";
    const wraps = parseEnvelopeShape(envelope, LIMITS.maxEnvelopeChars);
    await assertWrapsMatchMembers(sr, wraps, conv.member_ids);
    const ok = await verifyItemSignature({
      kind: "message", conversation_id: conv.id, item_id: msgId, sender_id: user.id, device_id: device.device_id,
      envelope, sent_at: sentAt, signature: body.signature, signPub: device.sign_pub,
    });
    if (!ok) throw new ApiError(403, "SIGNATURE_INVALID", "The message signature didn't verify, so it wasn't sent.");
    // A message that's waiting (send later, or a check-in) is reserved: its signature covers what it
    // says, not when it may go, so it can't be sent early through here by whoever holds a session
    // (CV-09). It goes when it's due, or the sender cancels it and sends something new.
    // Only someone with messages waiting needs the (shared) lookup.
    const [myProfile] = await own.entities.Profile.filter({ user_id: user.id }, "created_date", 1);
    if ((Number(myProfile?.scheduled_waiting) || 0) > 0) {
      const waiting = await sr.entities.ScheduledMessage.filter({ conversation_id: conv.id, msg_id: msgId }, "created_date", 1);
      if (waiting.some((w: any) => w.deliver_at)) throw new ApiError(409, "SCHEDULED_ITEM", "That message is waiting to be sent at its time.");
    }
    // A retry of a send that was stored but whose answer got lost: same message id, same message.
    // (Every message is sealed to its sender too, so the sender's own access sees it.)
    const duplicate = await own.entities.Message.filter({ conversation_id: conv.id, msg_id: msgId }, "created_date", 1);
    if (duplicate.length) {
      if (duplicate[0].sender_id !== user.id) throw new ApiError(409, "DUPLICATE_ID", "That message id is already taken. Please try again.");
      if (String(conv.last_message_at || "") < String(duplicate[0].created_date)) {
        await sr.entities.Conversation.update(conv.id, { last_message_at: duplicate[0].created_date });
      }
      return { message: messageOut(duplicate[0]), duplicate: true };
    }
    await enforceRate(own, "Message", { sender_id: user.id }, 60_000, LIMITS.messagesPerMinute, now, "sending messages");
    // Disappearing messages: the conversation's timer when the message arrives decides when it's deleted.
    const lifetime = Number(conv.expire_seconds) || 0;
    const message = await sr.entities.Message.create({
      conversation_id: conv.id,
      msg_id: msgId,
      sender_id: user.id,
      device_id: device.device_id,
      envelope,
      signature: body.signature,
      sent_at: sentAt,
      recipient_ids: wraps.map((w) => w.u),
      deleted: false,
      ...(lifetime > 0 ? { expires_at: new Date(now.getTime() + lifetime * 1000).toISOString() } : {}),
    });
    if (!(await withinRate(own, "Message", { sender_id: user.id }, 60_000, LIMITS.messagesPerMinute, now, message))) {
      await sr.entities.Message.update(message.id, BLANK_MESSAGE);
      await sr.entities.Message.delete(message.id);
      throw rateLimited("sending messages");
    }
    await sr.entities.Conversation.update(conv.id, { last_message_at: message.created_date || platformTime(now) });
    // Tell the others' devices there's something new, and nothing more (handlers/notifications.ts).
    await notifyPeople(sr, push, conv.member_ids.filter((m: string) => m !== user.id), { kind: "message", path: conversationPath(conv.id), placeId: conv.id });
    return { message: messageOut(message) };
  },

  /** Page backwards through one conversation. Read with the caller's own access (see Ctx). */
  async list({ own, user, body, now }) {
    const conv = await conversationForMember(own, user.id, id(body.conversation_id, "conversation"));
    const limit = body.limit === undefined ? LIMITS.pageSize : int(body.limit, "limit", 1, LIMITS.pageSize);
    const query: any = { conversation_id: conv.id, ...addressedTo(user.id) };
    if (body.before !== undefined) query.created_date = { $lt: str(body.before, "cursor", 40) };
    const rows = await own.entities.Message.filter(query, "-created_date", limit + 1);
    // Paging follows the rows as stored, so `before` is the cursor for the next page even when
    // messages whose time is up were left out of this one.
    const page = rows.slice(0, limit);
    return {
      messages: page.filter((m: any) => isLive(m, now)).map(messageOut).reverse(),
      has_more: rows.length > limit,
      before: page.length ? page[page.length - 1].created_date : null,
    };
  },

  /**
   * Messages addressed to you that changed since a cursor. This runs every few seconds for
   * everyone, so it's one query, made with the caller's own access (see Ctx). Pass
   * conversations_since now and then to get conversation changes too (their own cursor).
   * Without a cursor, returns starting cursors and nothing else.
   */
  async poll({ own, user, body, now }) {
    if (body.since === undefined) {
      const start = platformTime(new Date(now.getTime() - 5_000));
      return { cursor: start, conversations_cursor: start, servers_cursor: start, server_changes_cursor: start, messages: [], conversations: [], conversation_ids: [] };
    }
    const since = str(body.since, "cursor", 40);
    // A row can turn up in queries a moment after it's written, so the cursor never passes
    // "a few seconds ago": anything that recent comes again next time, and the client merges it.
    const settled = platformTime(new Date(now.getTime() - SETTLE_MS));
    const rows = await own.entities.Message.filter(
      { recipient_ids: user.id, updated_date: { $gte: since } },
      "updated_date",
      LIMITS.pollLimit + 1,
    );
    const page = rows.slice(0, LIMITS.pollLimit);
    const hasMore = rows.length > LIMITS.pollLimit;
    let cursor = since;
    for (const m of page) if (String(m.updated_date) > cursor) cursor = String(m.updated_date);
    if (!hasMore && cursor > settled) cursor = settled > since ? settled : since;
    const out: Record<string, unknown> = { cursor, messages: page.filter((m: any) => isLive(m, now)).map(messageOut), has_more: hasMore };

    if (body.conversations_since !== undefined) {
      const convSince = str(body.conversations_since, "cursor", 40);
      const convs = await myConversations(own, user.id);
      const changed = convs.filter((c: any) => String(c.updated_date) >= convSince);
      let convCursor = convSince;
      for (const c of changed) if (String(c.updated_date) > convCursor) convCursor = String(c.updated_date);
      if (convCursor > settled) convCursor = settled > convSince ? settled : convSince;
      Object.assign(out, { conversations: changed.map(conversationOut), conversation_ids: convs.map((c: any) => c.id), conversations_cursor: convCursor });
    }

    // Servers: their messages on their own cursor, and now and then server changes on another (see serverMessages.ts).
    if (body.servers_since !== undefined) {
      const changesSince = body.server_changes_since === undefined ? undefined : str(body.server_changes_since, "cursor", 40);
      Object.assign(out, await pollServers(own, user.id, { since: str(body.servers_since, "cursor", 40), changesSince }, settled, LIMITS.pollLimit, now));
    }
    return out;
  },

  /** Delete your own message for everyone. People may already have read it. Needs a device signature. */
  async delete(ctx) {
    const { sr, own, user, now } = ctx;
    const { data } = await signedByActiveDevice(ctx, "delete");
    let message: any = null;
    try {
      message = await own.entities.Message.get(id(data.message_id, "message"));
    } catch {
      message = null;
    }
    if (!message || message.sender_id !== user.id) throw new ApiError(404, "NOT_FOUND", "Message not found.");
    if (!message.deleted) {
      await sr.entities.Message.update(message.id, { deleted: true, envelope: "", signature: "", deleted_at: now.toISOString() });
    }
    return { ok: true };
  },
};

