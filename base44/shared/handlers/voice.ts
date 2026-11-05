// Voice calls. This function only hands out a one-minute, single-use pass to join one call,
// after checking membership and permissions. The call itself runs in the VoiceRoom actor, which
// passes connection set-up between devices and nothing else: audio and video go directly between
// devices, encrypted end to end, and never reach Commonveil.
import { ApiError, id, type Actions, type Ctx } from "../http.ts";
import { signedByActiveDevice } from "../deviceAuth.ts";
import { P, has } from "../permissions.ts";
import { channelIn, permsOf, requireMember, serverParts } from "../servers/model.ts";
import { rateLimited } from "../store.ts";

export const VOICE_LIMITS = { perCall: 8, perStage: 16, ticketSeconds: 60, ticketsPerMinute: 6 };

/** The actor room for a voice or stage channel's call. */
export const voiceRoomId = (serverId: string, channelId: string) => `${serverId}.${channelId}`;
/** The actor room for one call in a conversation. */
export const callRoomId = (conversationId: string, callId: string) => `dm.${conversationId}.${callId}`;

const CALL_ID_RE = /^[A-Za-z0-9_-]{8,32}$/;

async function issue(ctx: Ctx, device: any, room: string, { canSpeak, canModerate, stage }: { canSpeak: boolean; canModerate: boolean; stage: boolean }) {
  const { sr, user, now } = ctx;
  // Old passes are useless after a minute: clear this account's, and slow down floods.
  const mine = await sr.entities.VoiceTicket.filter({ user_id: user.id }, "-created_date", 50);
  const recent = mine.filter((t: any) => now.getTime() - Date.parse(t.created_date || t.expires_at) < 60_000);
  if (recent.length >= VOICE_LIMITS.ticketsPerMinute) throw rateLimited("joining calls");
  await Promise.all(mine.filter((t: any) => Date.parse(t.expires_at) < now.getTime()).map((t: any) => sr.entities.VoiceTicket.delete(t.id).catch(() => null)));
  const row = await sr.entities.VoiceTicket.create({
    room,
    user_id: user.id,
    device_id: device.device_id,
    can_speak: canSpeak,
    can_moderate: canModerate,
    stage,
    expires_at: new Date(now.getTime() + VOICE_LIMITS.ticketSeconds * 1000).toISOString(),
  });
  return { ticket: row.id, room, can_speak: canSpeak, can_moderate: canModerate, stage, max_people: stage ? VOICE_LIMITS.perStage : VOICE_LIMITS.perCall };
}

export const voiceActions: Actions = {
  /** Check you may join this voice or stage channel's call, and get a pass for it. */
  async voice_ticket(ctx: Ctx) {
    const { sr, user, now } = ctx;
    const { device, data } = await signedByActiveDevice(ctx, "voice_ticket");
    const serverId = id(data.server_id, "server");
    const member = await requireMember(ctx.own, serverId, user.id);
    const parts = await serverParts(sr, serverId);
    const channel = channelIn(parts, id(data.channel_id, "channel"));
    if (channel.kind !== "voice" && channel.kind !== "stage") throw new ApiError(400, "BAD_FIELD", "That isn't a voice channel.");
    const perms = permsOf(parts, member, channel);
    if (!has(perms, P.VIEW_CHANNEL) || !has(perms, P.CONNECT)) {
      throw new ApiError(403, "MISSING_PERMISSION", "You don't have permission to join this call.");
    }
    if (member.timeout_until && Date.parse(member.timeout_until) > now.getTime()) {
      throw new ApiError(403, "TIMED_OUT", "You're timed out in this server, so you can't join calls for now.");
    }
    const stage = channel.kind === "stage";
    // On a stage, moderators speak; everyone else listens until a moderator brings them up.
    const canModerate = has(perms, P.MUTE_MEMBERS);
    const canSpeak = stage ? canModerate : has(perms, P.SPEAK);
    return issue(ctx, device, voiceRoomId(serverId, channel.id), { canSpeak, canModerate, stage });
  },

  /** A pass for one call in a conversation (a direct message or a group). */
  async call_ticket(ctx: Ctx) {
    const { sr, user } = ctx;
    const { device, data } = await signedByActiveDevice(ctx, "call_ticket");
    const conv = await sr.entities.Conversation.get(id(data.conversation_id, "conversation")).catch(() => null);
    if (!conv || !(conv.member_ids || []).includes(user.id)) throw new ApiError(404, "NOT_FOUND", "Conversation not found.");
    const callId = typeof data.call_id === "string" && CALL_ID_RE.test(data.call_id) ? data.call_id : null;
    if (!callId) throw new ApiError(400, "BAD_FIELD", "Invalid call.");
    return issue(ctx, device, callRoomId(conv.id, callId), { canSpeak: true, canModerate: false, stage: false });
  },
};
