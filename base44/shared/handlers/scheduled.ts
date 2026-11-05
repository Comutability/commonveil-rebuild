// Messages that wait: "send later", and safety check-ins (a message that goes out by itself
// unless you check in first). Either way it's an ordinary end-to-end encrypted message, sealed
// and signed when it's written, which the service holds without reading and delivers when it's
// due. Recipients can't see it, or that it exists, until then: it's kept apart from messages.
import { ApiError, LIMITS, id, isoTime, platformTime, randomIdField, type Actions, type Ctx } from "../http.ts";
import { parseEnvelopeShape, verifyItemSignature } from "../verify.ts";
import { signedByActiveDevice } from "../deviceAuth.ts";
import { assertWrapsMatchMembers, blockedEitherWay, conversationForMember, rateLimited, requireActiveDevice } from "../store.ts";

export const SCHEDULE_LIMITS = Object.freeze({ pendingPerUser: 50, maxDays: 366, minSeconds: 60, perDelivery: 200 });
export const CHECKIN_HOURS = Object.freeze([1, 2, 4, 8, 12, 24, 48, 72, 168]);

const BLANK = { envelope: "", signature: "", msg_id: "", recipient_ids: [], deliver_at: "" };

const scheduledOut = (r: any) => ({
  id: r.id, conversation_id: r.conversation_id, kind: r.kind, deliver_at: r.deliver_at, checkin_hours: Number(r.checkin_hours) || 0,
  msg_id: r.msg_id, sender_id: r.sender_id, device_id: r.device_id, envelope: r.envelope, signature: r.signature, sent_at: r.sent_at,
  created_date: r.created_date,
});

async function mine(ctx: Ctx, rowId: string) {
  const row = await ctx.sr.entities.ScheduledMessage.get(id(rowId, "scheduled message")).catch(() => null);
  if (!row || row.sender_id !== ctx.user.id || !row.deliver_at) throw new ApiError(404, "NOT_FOUND", "That scheduled message isn't waiting any more.");
  return row;
}

/** Deliver what's due: into the conversation, for whoever is still in it. */
export async function deliverDue(sr: any, now: Date, deadline: number, only: any = {}) {
  const due = await sr.entities.ScheduledMessage.filter({ ...only, deliver_at: { $gt: "", $lte: now.toISOString() } }, "deliver_at", SCHEDULE_LIMITS.perDelivery);
  let delivered = 0;
  for (const row of due) {
    if (Date.now() > deadline) break;
    const conv = await sr.entities.Conversation.get(row.conversation_id).catch(() => null);
    const members: string[] = conv?.member_ids || [];
    let ok = Boolean(conv) && members.includes(row.sender_id);
    if (ok && conv.kind === "dm") {
      const other = members.find((m) => m !== row.sender_id);
      if (other && (await blockedEitherWay(sr, row.sender_id, other))) ok = false;
    }
    // Only people it was sealed to and who are still here; nobody added since can read it anyway.
    const recipients = (row.recipient_ids || []).filter((u: string) => members.includes(u));
    if (ok && recipients.length) {
      const [dup] = await sr.entities.Message.filter({ conversation_id: conv.id, msg_id: row.msg_id }, "created_date", 1);
      if (!dup) {
        const lifetime = Number(conv.expire_seconds) || 0;
        const m = await sr.entities.Message.create({
          conversation_id: conv.id, msg_id: row.msg_id, sender_id: row.sender_id, device_id: row.device_id, envelope: row.envelope,
          signature: row.signature, sent_at: row.sent_at, recipient_ids: recipients, deleted: false, scheduled: true,
          ...(lifetime > 0 ? { expires_at: new Date(now.getTime() + lifetime * 1000).toISOString() } : {}),
        });
        await sr.entities.Conversation.update(conv.id, { last_message_at: m.created_date || platformTime(now) });
        delivered += 1;
      }
    }
    await sr.entities.ScheduledMessage.update(row.id, BLANK).catch(() => null);
    await sr.entities.ScheduledMessage.delete(row.id).catch(() => null);
  }
  return delivered;
}

export const scheduledActions: Actions = {
  /**
   * Hold a message until deliver_at ("later"), or until a check-in is missed ("checkin":
   * delivered checkin_hours from now unless you check in). The body is what send takes.
   */
  async schedule(ctx: Ctx) {
    const { sr, own, user, body, now } = ctx;
    const conv = await conversationForMember(own, user.id, id(body.conversation_id, "conversation"));
    const kind = body.kind === "checkin" ? "checkin" : "later";
    let deliverAt: Date;
    let hours = 0;
    if (kind === "checkin") {
      hours = Number(body.checkin_hours);
      if (!CHECKIN_HOURS.includes(hours)) throw new ApiError(400, "BAD_FIELD", "Choose how long until you check in.");
      deliverAt = new Date(now.getTime() + hours * 3600_000);
    } else {
      deliverAt = new Date(isoTime(body.deliver_at, "delivery time"));
      const ahead = deliverAt.getTime() - now.getTime();
      if (ahead < SCHEDULE_LIMITS.minSeconds * 1000 || ahead > SCHEDULE_LIMITS.maxDays * 86_400_000) throw new ApiError(400, "BAD_FIELD", "Choose a time from a minute to a year from now.");
    }
    const pending = await sr.entities.ScheduledMessage.filter({ sender_id: user.id }, "created_date", SCHEDULE_LIMITS.pendingPerUser + 1);
    if (pending.filter((r: any) => r.deliver_at).length >= SCHEDULE_LIMITS.pendingPerUser) throw rateLimited("scheduling messages (you have the most waiting you can)");
    const device = await requireActiveDevice(own, user.id, randomIdField(body.device_id, "device id"));
    const msgId = randomIdField(body.msg_id, "message id");
    const sentAt = isoTime(body.sent_at, "sent time");
    if (Math.abs(now.getTime() - Date.parse(sentAt)) > LIMITS.sentAtSkewMs) throw new ApiError(400, "CLOCK_SKEW", "Your device clock looks wrong. Check it and try again.");
    const envelope = typeof body.envelope === "string" ? body.envelope : "";
    const wraps = parseEnvelopeShape(envelope, LIMITS.maxEnvelopeChars);
    await assertWrapsMatchMembers(sr, wraps, conv.member_ids);
    const ok = await verifyItemSignature({ kind: "message", conversation_id: conv.id, item_id: msgId, sender_id: user.id, device_id: device.device_id, envelope, sent_at: sentAt, signature: body.signature, signPub: device.sign_pub });
    if (!ok) throw new ApiError(403, "SIGNATURE_INVALID", "The message signature didn't verify.");
    const row = await sr.entities.ScheduledMessage.create({
      conversation_id: conv.id, sender_id: user.id, device_id: device.device_id, msg_id: msgId, envelope, signature: body.signature, sent_at: sentAt,
      recipient_ids: wraps.map((w) => w.u), deliver_at: deliverAt.toISOString(), kind, checkin_hours: hours,
    });
    return { scheduled: scheduledOut(row) };
  },

  /** Your messages that are waiting, so your app can show (and open) them. */
  async scheduled(ctx: Ctx) {
    const { sr, user, body } = ctx;
    const q: any = { sender_id: user.id };
    if (body.conversation_id) q.conversation_id = id(body.conversation_id, "conversation");
    const rows = (await sr.entities.ScheduledMessage.filter(q, "deliver_at", 100)).filter((r: any) => r.deliver_at);
    return { scheduled: rows.map(scheduledOut) };
  },

  /** Cancel one. Signed by your device, so a stolen password can't silence a check-in... or fake one. */
  async cancel_scheduled(ctx: Ctx) {
    const { data } = await signedByActiveDevice(ctx, "cancel_scheduled");
    const row = await mine(ctx, data.id);
    await ctx.sr.entities.ScheduledMessage.update(row.id, BLANK);
    await ctx.sr.entities.ScheduledMessage.delete(row.id);
    return { ok: true };
  },

  /** "I'm OK": push a check-in's deadline on by its interval. Also needs your device. */
  async check_in(ctx: Ctx) {
    const { data } = await signedByActiveDevice(ctx, "check_in");
    const row = await mine(ctx, data.id);
    if (row.kind !== "checkin") throw new ApiError(400, "BAD_FIELD", "That isn't a check-in.");
    const deliverAt = new Date(ctx.now.getTime() + (Number(row.checkin_hours) || 24) * 3600_000).toISOString();
    await ctx.sr.entities.ScheduledMessage.update(row.id, { deliver_at: deliverAt });
    return { deliver_at: deliverAt };
  },

  /** Sender's app nudge: deliver anything of yours that's due now, rather than waiting for the next run. */
  async deliver_mine(ctx: Ctx) {
    const { sr, user, now } = ctx;
    return { delivered: await deliverDue(sr, now, Date.now() + 20_000, { sender_id: user.id }) };
  },
};
