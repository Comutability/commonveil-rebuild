// Messages in server channels. Like direct messages, the service checks who's sending, the
// device and its signature, and stores ciphertext it can't read. Unlike them, every member of
// a channel reads with the channel's shared key, so a message is one row however big the server.
//
// One thing the service does see: whether a row is a message, a reaction, an edit or a forum
// post (`kind`). It needs that to apply channel permissions (in announcement channels members can
// react but not post). Readers check the encrypted payload says the same, or ignore the row.
import { ApiError, LIMITS, id, int, isoTime, platformTime, randomIdField, str, type Actions } from "../http.ts";
import { signedByActiveDevice } from "../deviceAuth.ts";
import { verifyServerItemSignature } from "../verify.ts";
import { P, channelPermissions, has } from "../permissions.ts";
import { countSince, profileOf, rateLimited, requireActiveDevice } from "../store.ts";
import {
  MESSAGE_KINDS,
  SERVER_LIMITS,
  audit,
  chainForChannel,
  generationsOf,
  latestGeneration,
  parseItemEnvelope,
  requireMember,
  requirePerm,
  serverMessageOut,
  serverOut,
  serverParts,
  stepAt,
} from "../servers/model.ts";

const KINDS = ["message", "reaction", "edit", "post"] as const;

/** The caller's view of one channel, read with their own access: the row rules hide private channels they can't see. */
async function channelView(own: any, serverId: string, channelId: string, userId: string) {
  const member = await requireMember(own, serverId, userId);
  const [servers, roles, channels] = await Promise.all([
    own.entities.Server.filter({ audience_id: serverId }, "created_date", 1),
    own.entities.Role.filter({ server_id: serverId }, "position", SERVER_LIMITS.rolesPerServer + 5),
    own.entities.Channel.filter({ server_id: serverId }, "position", SERVER_LIMITS.channelsPerServer + 5),
  ]);
  const server = servers[0];
  const channel = channels.find((c: any) => c.id === channelId);
  if (!server || server.status === "deleting" || !channel) throw new ApiError(404, "CHANNEL_NOT_FOUND", "Channel not found.");
  const perms = channelPermissions(server, roles, member, channel);
  if (!has(perms, P.VIEW_CHANNEL)) throw new ApiError(404, "CHANNEL_NOT_FOUND", "Channel not found.");
  return { member, server, roles, channel, perms };
}

const isLive = (m: any, now: Date) => !m.expires_at || Date.parse(m.expires_at) > now.getTime();

/** Messages before someone joined, in a channel that only shows newcomers what came after. */
function hiddenFromNewcomer(view: any, m: any) {
  const joinedOnly = view.channel.history === "joined" || !has(view.perms, P.READ_HISTORY);
  return joinedOnly && Date.parse(m.sent_at || 0) < Date.parse(view.member.joined_at) - 60_000;
}

export const serverMessageActions: Actions = {
  async send({ sr, own, user, body, now }) {
    const serverId = id(body.server_id, "server");
    const view = await channelView(own, serverId, id(body.channel_id, "channel"), user.id);
    const { member, server, channel, perms } = view;
    if (!MESSAGE_KINDS.has(channel.kind)) throw new ApiError(400, "BAD_FIELD", "You can't post in this kind of channel.");
    const kind = KINDS.includes(body.kind) ? body.kind : null;
    if (!kind) throw new ApiError(400, "BAD_FIELD", "Invalid message kind.");
    const threadId = body.thread_id ? randomIdField(body.thread_id, "post") : "";
    if (kind === "post") {
      if (channel.kind !== "forum" || threadId) throw new ApiError(400, "BAD_FIELD", "Posts start in forum channels.");
      requirePerm(perms, P.CREATE_POSTS, "start posts here");
    } else if (kind === "reaction") {
      requirePerm(perms, P.ADD_REACTIONS, "react here");
    } else {
      requirePerm(perms, P.SEND_MESSAGES, "post here");
      if (channel.kind === "forum" && !threadId) throw new ApiError(400, "BAD_FIELD", "In a forum, reply to a post or start one.");
    }
    if (member.timeout_until && Date.parse(member.timeout_until) > now.getTime()) throw new ApiError(403, "TIMED_OUT", "You're timed out in this server for now.");
    const staff = has(perms, P.MANAGE_MESSAGES) || has(perms, P.MANAGE_SERVER);
    if (!staff) {
      if (server.rules_required && !member.rules_accepted_at) throw new ApiError(403, "RULES_REQUIRED", "Read and accept the server's rules first.");
      const memberMinutes = Number(server.min_member_minutes) || 0;
      if (memberMinutes && now.getTime() - Date.parse(member.joined_at) < memberMinutes * 60_000) {
        throw new ApiError(403, "TOO_NEW", `New members can post ${memberMinutes} minutes after joining.`);
      }
      const accountMinutes = Number(server.min_account_minutes) || 0;
      if (accountMinutes) {
        const profile = await profileOf(own, user.id);
        if (!profile || now.getTime() - Date.parse(String(profile.created_date).replace(/Z?$/, "Z")) < accountMinutes * 60_000) {
          throw new ApiError(403, "ACCOUNT_TOO_NEW", "Your account is too new to post here yet.");
        }
      }
    }
    if (threadId) {
      const [post] = await own.entities.ServerMessage.filter({ channel_id: channel.id, msg_id: threadId, kind: "post" }, "created_date", 1);
      if (!post || post.deleted) throw new ApiError(404, "NOT_FOUND", "That post isn't here any more.");
    }
    const device = await requireActiveDevice(own, user.id, randomIdField(body.device_id, "device id"));
    const msgId = randomIdField(body.msg_id, "message id");
    const sentAt = isoTime(body.sent_at, "sent time");
    if (Math.abs(now.getTime() - Date.parse(sentAt)) > LIMITS.sentAtSkewMs) throw new ApiError(400, "CLOCK_SKEW", "Your device clock looks wrong. Check it and try again.");
    const envelope = str(body.envelope, "message", SERVER_LIMITS.maxMessageEnvelopeChars);
    const env = parseItemEnvelope(envelope);
    const chainId = chainForChannel(serverId, channel);
    const gens = await own.entities.KeyGeneration.filter({ server_id: serverId, chain_id: chainId }, "created_date", 500);
    const latest = latestGeneration(gens, chainId);
    if (!latest) throw new ApiError(409, "NO_KEYS_YET", "This channel's encryption is still being set up. Try again in a moment.");
    if (env.chain !== chainId || env.gen !== Number(latest.generation) || env.step !== stepAt(chainId, latest.started_at, Date.parse(sentAt))) {
      throw new ApiError(409, "STALE_SERVER_KEYS", "This channel's keys changed. Refreshing and trying again.");
    }
    const ok = await verifyServerItemSignature({
      kind: "message", server_id: serverId, channel_id: channel.id, item_id: msgId, sender_id: user.id, device_id: device.device_id,
      envelope, sent_at: sentAt, signature: body.signature, signPub: device.sign_pub,
    });
    if (!ok) throw new ApiError(403, "SIGNATURE_INVALID", "The message signature didn't verify, so it wasn't sent.");
    const duplicate = await own.entities.ServerMessage.filter({ channel_id: channel.id, msg_id: msgId }, "created_date", 1);
    if (duplicate.length) {
      if (duplicate[0].sender_id !== user.id) throw new ApiError(409, "DUPLICATE_ID", "That message id is already taken. Please try again.");
      return { message: serverMessageOut(duplicate[0]), duplicate: true };
    }
    if (!staff && (kind === "message" || kind === "post") && Number(channel.slowmode_seconds) > 0) {
      const [last] = await own.entities.ServerMessage.filter({ channel_id: channel.id, sender_id: user.id, kind: { $in: ["message", "post"] } }, "-created_date", 1);
      const wait = last ? Date.parse(String(last.created_date).replace(/Z?$/, "Z")) + Number(channel.slowmode_seconds) * 1000 - now.getTime() : 0;
      if (wait > 0) throw new ApiError(429, "SLOWMODE", `Slow mode is on here: you can post again in ${Math.ceil(wait / 1000)} seconds.`);
    }
    const recent = await countSince(own, "ServerMessage", { sender_id: user.id }, new Date(now.getTime() - 60_000), SERVER_LIMITS.messagesPerMinute);
    if (recent >= SERVER_LIMITS.messagesPerMinute) throw rateLimited("sending messages");
    const lifetime = Number(channel.expire_seconds) || 0;
    const message = await sr.entities.ServerMessage.create({
      server_id: serverId, channel_id: channel.id, audience_id: channel.private ? channel.id : serverId,
      msg_id: msgId, kind, thread_id: threadId, sender_id: user.id, device_id: device.device_id,
      envelope, signature: body.signature, sent_at: sentAt, deleted: false, pinned: false,
      ...(kind === "post" ? { last_reply_at: platformTime(now), reply_count: 0 } : {}),
      ...(lifetime > 0 ? { expires_at: new Date(now.getTime() + lifetime * 1000).toISOString() } : {}),
    });
    if (kind === "message" || kind === "post") await sr.entities.Channel.update(channel.id, { last_message_at: message.created_date || platformTime(now) });
    if (threadId && kind === "message") {
      const [post] = await sr.entities.ServerMessage.filter({ channel_id: channel.id, msg_id: threadId, kind: "post" }, "created_date", 1);
      if (post) await sr.entities.ServerMessage.update(post.id, { last_reply_at: message.created_date || platformTime(now), reply_count: (Number(post.reply_count) || 0) + 1 });
    }
    return { message: serverMessageOut(message) };
  },

  /**
   * Page back through a channel, a forum's posts, or one post's replies. Read with the caller's
   * own access. In channels that only show newcomers what came after they joined, earlier
   * messages aren't listed (and couldn't be read with the keys they were given).
   */
  async list({ own, user, body, now }) {
    const serverId = id(body.server_id, "server");
    const view = await channelView(own, serverId, id(body.channel_id, "channel"), user.id);
    const limit = body.limit === undefined ? SERVER_LIMITS.pageSize : int(body.limit, "limit", 1, SERVER_LIMITS.pageSize);
    let query: any;
    let sort = "-created_date";
    if (body.posts) {
      query = { channel_id: view.channel.id, kind: "post" };
      sort = "-last_reply_at";
      if (body.before !== undefined) query.last_reply_at = { $lt: str(body.before, "cursor", 40) };
    } else {
      query = { channel_id: view.channel.id, thread_id: body.thread_id ? randomIdField(body.thread_id, "post") : "" };
      if (body.before !== undefined) query.created_date = { $lt: str(body.before, "cursor", 40) };
    }
    const rows = await own.entities.ServerMessage.filter(query, sort, limit + 1);
    const page = rows.slice(0, limit);
    let extra: any[] = [];
    if (body.thread_id && body.before === undefined) {
      extra = await own.entities.ServerMessage.filter({ channel_id: view.channel.id, msg_id: body.thread_id, kind: "post" }, "created_date", 1);
    }
    const cursorField = body.posts ? "last_reply_at" : "created_date";
    return {
      messages: [...extra, ...page]
        .filter((m: any) => isLive(m, now) && !hiddenFromNewcomer(view, m))
        .map(serverMessageOut)
        .reverse(),
      has_more: rows.length > limit,
      before: page.length ? page[page.length - 1][cursorField] : null,
    };
  },

  /** Pinned messages in a channel. */
  async pins({ own, user, body, now }) {
    const serverId = id(body.server_id, "server");
    const view = await channelView(own, serverId, id(body.channel_id, "channel"), user.id);
    const rows = await own.entities.ServerMessage.filter({ channel_id: view.channel.id, pinned: true }, "-created_date", 50);
    return { messages: rows.filter((m: any) => isLive(m, now) && !m.deleted && !hiddenFromNewcomer(view, m)).map(serverMessageOut) };
  },

  /** Delete a message: your own, or anyone's with MANAGE_MESSAGES. It's blanked for everyone. */
  async delete(ctx) {
    const { sr, own, user, now } = ctx;
    const { data } = await signedByActiveDevice(ctx, "delete_server_message");
    const serverId = id(data.server_id, "server");
    const [message] = await own.entities.ServerMessage.filter({ server_id: serverId, channel_id: id(data.channel_id, "channel"), msg_id: randomIdField(data.msg_id, "message") }, "created_date", 1);
    if (!message) throw new ApiError(404, "NOT_FOUND", "Message not found.");
    if (message.sender_id !== user.id) {
      const view = await channelView(own, serverId, message.channel_id, user.id);
      requirePerm(view.perms, P.MANAGE_MESSAGES, "delete other people's messages");
      const parts = await serverParts(sr, serverId);
      await audit(sr, parts.server, user.id, "message_delete", "member", message.sender_id, "", now);
    }
    if (!message.deleted) {
      await sr.entities.ServerMessage.update(message.id, { envelope: "", signature: "", deleted: true, deleted_by: user.id, deleted_at: now.toISOString(), pinned: false });
    }
    return { ok: true };
  },

  async pin(ctx) {
    const { sr, own, user, now } = ctx;
    const { data } = await signedByActiveDevice(ctx, "pin_server_message");
    const serverId = id(data.server_id, "server");
    const view = await channelView(own, serverId, id(data.channel_id, "channel"), user.id);
    requirePerm(view.perms, P.MANAGE_MESSAGES, "pin messages");
    const [message] = await own.entities.ServerMessage.filter({ channel_id: view.channel.id, msg_id: randomIdField(data.msg_id, "message") }, "created_date", 1);
    if (!message || message.deleted) throw new ApiError(404, "NOT_FOUND", "Message not found.");
    const pinned = data.pinned !== false;
    await sr.entities.ServerMessage.update(message.id, { pinned });
    const parts = await serverParts(sr, serverId);
    await audit(sr, parts.server, user.id, pinned ? "message_pin" : "message_unpin", "channel", view.channel.id, "", now);
    return { ok: true };
  },
};

/**
 * Server changes for a member's poll (messages.poll calls this when asked): messages in their
 * servers and private channels since the cursor, and servers whose rows changed. One query each,
 * with the member's own access.
 */
export async function pollServers(own: any, userId: string, since: string, settled: string, limit: number, now: Date, withMemberships: boolean) {
  const [rows, servers, memberships] = await Promise.all([
    own.entities.ServerMessage.filter({ updated_date: { $gte: since } }, "updated_date", limit + 1),
    own.entities.Server.filter({ updated_date: { $gte: since } }, "updated_date", 100),
    withMemberships ? own.entities.ServerMember.filter({ user_id: userId }, "created_date", SERVER_LIMITS.serversPerUser + 10) : Promise.resolve(null),
  ]);
  const page = rows.slice(0, limit);
  const hasMore = rows.length > limit;
  let cursor = since;
  for (const m of page) if (String(m.updated_date) > cursor) cursor = String(m.updated_date);
  for (const s of servers) if (String(s.updated_date) > cursor && !hasMore) cursor = String(s.updated_date);
  if (!hasMore && cursor > settled) cursor = settled > since ? settled : since;
  return {
    server_messages: page.filter((m: any) => isLive(m, now)).map(serverMessageOut),
    servers: servers.filter((s: any) => s.status !== "deleting").map(serverOut),
    server_ids: memberships ? [...new Set(memberships.map((m: any) => m.server_id))] : undefined,
    servers_cursor: cursor,
    servers_more: hasMore,
  };
}
