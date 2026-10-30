// Encrypted messages. The server checks membership, the sending device, the
// signature and that every current member got a copy of the key, then stores
// ciphertext it cannot read.
import { ApiError, LIMITS, id, int, isoTime, platformTime, randomIdField, str, type Actions } from "../http.ts";
import { parseEnvelopeShape, verifyItemSignature } from "../verify.ts";
import { signedByActiveDevice } from "../deviceAuth.ts";
import {
  addressedTo,
  assertWrapsMatchMembers,
  blockedEitherWay,
  conversationForMember,
  conversationOut,
  enforceRate,
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
  async send({ sr, user, body, now }) {
    const conv = await conversationForMember(sr, user.id, id(body.conversation_id, "conversation"));
    if (conv.kind === "dm") {
      const other = conv.member_ids.find((m: string) => m !== user.id);
      if (other && (await blockedEitherWay(sr, user.id, other))) throw new ApiError(403, "BLOCKED", "You can't message this member.");
    }
    const device = await requireActiveDevice(sr, user.id, randomIdField(body.device_id, "device id"));
    const msgId = randomIdField(body.msg_id, "message id");
    const sentAt = isoTime(body.sent_at, "sent time");
    if (Math.abs(now.getTime() - Date.parse(sentAt)) > LIMITS.sentAtSkewMs) {
      throw new ApiError(400, "CLOCK_SKEW", "Your device clock looks wrong. Check it and try again.");
    }
    const envelope = typeof body.envelope === "string" ? body.envelope : "";
    const wraps = parseEnvelopeShape(envelope, LIMITS.maxEnvelopeChars);
    await assertWrapsMatchMembers(sr, wraps, conv.member_ids);
    const ok = await verifyItemSignature({
      kind: "message", conversation_id: conv.id, item_id: msgId, sender_id: user.id, device_id: device.device_id,
      envelope, sent_at: sentAt, signature: body.signature, signPub: device.sign_pub,
    });
    if (!ok) throw new ApiError(403, "SIGNATURE_INVALID", "The message signature didn't verify, so it wasn't sent.");
    // A retry of a send that was stored but whose answer got lost: same message id, same message.
    const duplicate = await sr.entities.Message.filter({ conversation_id: conv.id, msg_id: msgId }, "created_date", 1);
    if (duplicate.length) {
      if (duplicate[0].sender_id !== user.id) throw new ApiError(409, "DUPLICATE_ID", "That message id is already taken. Please try again.");
      if (String(conv.last_message_at || "") < String(duplicate[0].created_date)) {
        await sr.entities.Conversation.update(conv.id, { last_message_at: duplicate[0].created_date });
      }
      return { message: messageOut(duplicate[0]), duplicate: true };
    }
    await enforceRate(sr, "Message", { sender_id: user.id }, 60_000, LIMITS.messagesPerMinute, now, "sending messages");
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
    });
    if (!(await withinRate(sr, "Message", { sender_id: user.id }, 60_000, LIMITS.messagesPerMinute, now, message))) {
      await sr.entities.Message.update(message.id, BLANK_MESSAGE);
      await sr.entities.Message.delete(message.id);
      throw rateLimited("sending messages");
    }
    await sr.entities.Conversation.update(conv.id, { last_message_at: message.created_date || platformTime(now) });
    return { message: messageOut(message) };
  },

  /** Page backwards through one conversation. */
  async list({ sr, user, body }) {
    const conv = await conversationForMember(sr, user.id, id(body.conversation_id, "conversation"));
    const limit = body.limit === undefined ? LIMITS.pageSize : int(body.limit, "limit", 1, LIMITS.pageSize);
    const query: any = { conversation_id: conv.id, ...addressedTo(user.id) };
    if (body.before !== undefined) query.created_date = { $lt: str(body.before, "cursor", 40) };
    const rows = await sr.entities.Message.filter(query, "-created_date", limit + 1);
    return { messages: rows.slice(0, limit).map(messageOut).reverse(), has_more: rows.length > limit };
  },

  /**
   * Messages addressed to you that changed since a cursor: one query, as this runs every few
   * seconds for everyone and Base44 limits how many queries an app makes. Pass
   * conversations_since now and then to get conversation changes too (their own cursor).
   * Without a cursor, returns starting cursors and nothing else.
   */
  async poll({ sr, user, body, now }) {
    if (body.since === undefined) {
      const start = platformTime(new Date(now.getTime() - 5_000));
      return { cursor: start, conversations_cursor: start, messages: [], conversations: [], conversation_ids: [] };
    }
    const since = str(body.since, "cursor", 40);
    // A row can turn up in queries a moment after it's written, so the cursor never passes
    // "a few seconds ago": anything that recent comes again next time, and the client merges it.
    const settled = platformTime(new Date(now.getTime() - SETTLE_MS));
    const rows = await sr.entities.Message.filter(
      { recipient_ids: user.id, updated_date: { $gte: since } },
      "updated_date",
      LIMITS.pollLimit + 1,
    );
    const page = rows.slice(0, LIMITS.pollLimit);
    const hasMore = rows.length > LIMITS.pollLimit;
    let cursor = since;
    for (const m of page) if (String(m.updated_date) > cursor) cursor = String(m.updated_date);
    if (!hasMore && cursor > settled) cursor = settled > since ? settled : since;
    const out: Record<string, unknown> = { cursor, messages: page.map(messageOut), has_more: hasMore };

    if (body.conversations_since !== undefined) {
      const convSince = str(body.conversations_since, "cursor", 40);
      const convs = await myConversations(sr, user.id);
      const changed = convs.filter((c: any) => String(c.updated_date) >= convSince);
      let convCursor = convSince;
      for (const c of changed) if (String(c.updated_date) > convCursor) convCursor = String(c.updated_date);
      if (convCursor > settled) convCursor = settled > convSince ? settled : convSince;
      Object.assign(out, { conversations: changed.map(conversationOut), conversation_ids: convs.map((c: any) => c.id), conversations_cursor: convCursor });
    }
    return out;
  },

  /** Delete your own message for everyone. People may already have read it. Needs a device signature. */
  async delete(ctx) {
    const { sr, user, now } = ctx;
    const { data } = await signedByActiveDevice(ctx, "delete");
    let message: any = null;
    try {
      message = await sr.entities.Message.get(id(data.message_id, "message"));
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

