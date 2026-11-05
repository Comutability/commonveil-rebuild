// Voice calls. This function only hands out a one-minute, single-use pass to join one voice
// channel's call, after checking membership and permissions. The call itself runs in the
// VoiceRoom actor, which passes connection set-up between members' devices and nothing else:
// audio goes directly between devices, encrypted end to end, and never reaches Commonveil.
import { ApiError, id, type Actions, type Ctx } from "../http.ts";
import { signedByActiveDevice } from "../deviceAuth.ts";
import { P, has } from "../permissions.ts";
import { channelIn, permsOf, requireMember, serverParts } from "../servers/model.ts";
import { rateLimited } from "../store.ts";

export const VOICE_LIMITS = { perCall: 8, ticketSeconds: 60, ticketsPerMinute: 6 };

/** The actor room for a voice channel's call. */
export const voiceRoomId = (serverId: string, channelId: string) => `${serverId}.${channelId}`;

export const voiceActions: Actions = {
  /** Check you may join this voice channel's call, and get a pass for it. */
  async voice_ticket(ctx: Ctx) {
    const { sr, user, now } = ctx;
    const { device, data } = await signedByActiveDevice(ctx, "voice_ticket");
    const serverId = id(data.server_id, "server");
    const member = await requireMember(ctx.own, serverId, user.id);
    const parts = await serverParts(sr, serverId);
    const channel = channelIn(parts, id(data.channel_id, "channel"));
    if (channel.kind !== "voice") throw new ApiError(400, "BAD_FIELD", "That isn't a voice channel.");
    const perms = permsOf(parts, member, channel);
    if (!has(perms, P.VIEW_CHANNEL) || !has(perms, P.CONNECT)) {
      throw new ApiError(403, "MISSING_PERMISSION", "You don't have permission to join this call.");
    }
    if (member.timeout_until && Date.parse(member.timeout_until) > now.getTime()) {
      throw new ApiError(403, "TIMED_OUT", "You're timed out in this server, so you can't join calls for now.");
    }
    // Old passes are useless after a minute: clear this account's, and slow down floods.
    const mine = await sr.entities.VoiceTicket.filter({ user_id: user.id }, "-created_date", 50);
    const recent = mine.filter((t: any) => now.getTime() - Date.parse(t.created_date || t.expires_at) < 60_000);
    if (recent.length >= VOICE_LIMITS.ticketsPerMinute) throw rateLimited("joining calls");
    await Promise.all(mine.filter((t: any) => Date.parse(t.expires_at) < now.getTime()).map((t: any) => sr.entities.VoiceTicket.delete(t.id).catch(() => null)));
    const room = voiceRoomId(serverId, channel.id);
    const canSpeak = has(perms, P.SPEAK);
    const row = await sr.entities.VoiceTicket.create({
      room,
      user_id: user.id,
      device_id: device.device_id,
      can_speak: canSpeak,
      expires_at: new Date(now.getTime() + VOICE_LIMITS.ticketSeconds * 1000).toISOString(),
    });
    return { ticket: row.id, room, can_speak: canSpeak, max_people: VOICE_LIMITS.perCall };
  },
};
