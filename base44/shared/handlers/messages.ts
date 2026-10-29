// Encrypted messages. The server checks membership, the sending device, the
// signature and that every current member got a copy of the key, then stores
// ciphertext it cannot read.
import { ApiError, LIMITS, id, int, isoTime, platformTime, randomIdField, str, type Actions } from "../http.ts";
import { parseEnvelopeShape, verifyItemSignature } from "../verify.ts";
import {
  assertWrapsMatchMembers,
  blockedEitherWay,
  conversationForMember,
  conversationOut,
  enforceRate,
  messageOut,
  myConversations,
  requireActiveDevice,
} from "../store.ts";

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
    const duplicate = await sr.entities.Message.filter({ conversation_id: conv.id, msg_id: msgId }, "created_date", 1);
    if (duplicate.length) return { message: messageOut(duplicate[0]), duplicate: true };
    await enforceRate(sr, "Message", { sender_id: user.id }, 60_000, LIMITS.messagesPerMinute, now, "sending messages");
    const message = await sr.entities.Message.create({
      conversation_id: conv.id,
      msg_id: msgId,
      sender_id: user.id,
      device_id: device.device_id,
      envelope,
      signature: body.signature,
      sent_at: sentAt,
      deleted: false,
    });
    await sr.entities.Conversation.update(conv.id, { last_message_at: message.created_date || platformTime(now) });
    return { message: messageOut(message) };
  },

  /** Page backwards through one conversation. */
  async list({ sr, user, body }) {
    const conv = await conversationForMember(sr, user.id, id(body.conversation_id, "conversation"));
    const limit = body.limit === undefined ? LIMITS.pageSize : int(body.limit, "limit", 1, LIMITS.pageSize);
    const query: any = { conversation_id: conv.id };
    if (body.before !== undefined) query.created_date = { $lt: str(body.before, "cursor", 40) };
    const rows = await sr.entities.Message.filter(query, "-created_date", limit + 1);
    return { messages: rows.slice(0, limit).map(messageOut).reverse(), has_more: rows.length > limit };
  },

  /**
   * Everything that changed since a cursor, across all your conversations.
   * Without a cursor, returns a starting cursor and nothing else.
   */
  async poll({ sr, user, body, now }) {
    if (body.since === undefined) return { cursor: platformTime(new Date(now.getTime() - 5_000)), messages: [], conversations: [], conversation_ids: [] };
    const since = str(body.since, "cursor", 40);
    const convs = await myConversations(sr, user.id);
    const ids = convs.map((c: any) => c.id);
    const conversations = convs.filter((c: any) => String(c.updated_date) >= since).map(conversationOut);
    let rows: any[] = [];
    if (ids.length) {
      rows = await sr.entities.Message.filter(
        { conversation_id: { $in: ids }, updated_date: { $gte: since } },
        "updated_date",
        LIMITS.pollLimit + 1,
      );
    }
    const messages = rows.slice(0, LIMITS.pollLimit).map(messageOut);
    let cursor = since;
    for (const m of rows.slice(0, LIMITS.pollLimit)) if (String(m.updated_date) > cursor) cursor = String(m.updated_date);
    for (const c of conversations) if (String(c.updated_date) > cursor) cursor = String(c.updated_date);
    return { cursor, messages, conversations, conversation_ids: ids, has_more: rows.length > LIMITS.pollLimit };
  },

  /** Delete your own message for everyone. People may already have read it. */
  async delete({ sr, user, body, now }) {
    let message: any = null;
    try {
      message = await sr.entities.Message.get(id(body.message_id, "message"));
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

