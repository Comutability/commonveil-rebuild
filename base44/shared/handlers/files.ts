// Attachments. Files are encrypted on the sender's device, in parts, before they reach this
// function: it stores ciphertext it can't read, as private files, and hands out short-lived
// links only to people who can see where the file was sent. The file's key, name and type
// travel inside the end-to-end encrypted message, never here.
import { ApiError, id, randomIdField, type Actions, type Ctx } from "../http.ts";
import { signedByActiveDevice } from "../deviceAuth.ts";
import { P, has } from "../permissions.ts";
import { channelIn, permsOf, requireMember, serverParts } from "../servers/model.ts";
import { countSince, rateLimited } from "../store.ts";

export const FILE_LIMITS = Object.freeze({
  /** Bytes of ciphertext in one part (the last part can be smaller). */
  partBytes: 768 * 1024,
  /** Parts in one file: up to about 10 MB. */
  maxParts: 14,
  /** Parts one account can upload in ten minutes. */
  partsPer10Min: 150,
  /** How long a download link works. */
  linkSeconds: 300,
  /** Links handed out in one request. */
  maxLinks: 60,
});

/** Body size the files function accepts: one part, base64, plus the signed request around it. */
export const FILES_MAX_BODY = Math.ceil((FILE_LIMITS.partBytes * 4) / 3) + 16 * 1024;

const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

function decodePart(data: unknown): Uint8Array {
  if (typeof data !== "string" || !data.length || data.length % 4 !== 0 || !B64_RE.test(data)) throw new ApiError(400, "BAD_FIELD", "Invalid file part.");
  const bin = atob(data);
  if (bin.length > FILE_LIMITS.partBytes || bin.length < 29) throw new ApiError(413, "TOO_LARGE", "That file part is too large.");
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

/** May this person see things posted at this place? Returns where, for the row. */
async function placeFor(ctx: Ctx, data: any, { sending }: { sending: boolean }) {
  const { sr, user } = ctx;
  if (data.scope === "server") {
    const serverId = id(data.server_id, "server");
    const member = await requireMember(ctx.own, serverId, user.id);
    const parts = await serverParts(sr, serverId);
    const channel = channelIn(parts, id(data.channel_id, "channel"));
    const perms = permsOf(parts, member, channel);
    if (!has(perms, P.VIEW_CHANNEL)) throw new ApiError(404, "NOT_FOUND", "Not found.");
    if (sending) {
      if (!has(perms, P.SEND_MESSAGES) && !has(perms, P.CREATE_POSTS)) throw new ApiError(403, "MISSING_PERMISSION", "You can't post files here.");
      if (member.timeout_until && Date.parse(member.timeout_until) > ctx.now.getTime()) throw new ApiError(403, "TIMED_OUT", "You're timed out in this server.");
    }
    return { scope: "server", scope_id: serverId, channel_id: channel.id };
  }
  if (data.scope === "conversation") {
    const conv = await sr.entities.Conversation.get(id(data.conversation_id, "conversation")).catch(() => null);
    if (!conv || !(conv.member_ids || []).includes(user.id)) throw new ApiError(404, "NOT_FOUND", "Not found.");
    return { scope: "conversation", scope_id: conv.id, channel_id: "" };
  }
  throw new ApiError(400, "BAD_FIELD", "Invalid place.");
}

export const fileActions: Actions = {
  /** Store one encrypted part of a file about to be sent. Returns its handle for the message. */
  async upload_part(ctx: Ctx) {
    const { sr, user, now } = ctx;
    const { data } = await signedByActiveDevice(ctx, "upload_part", { maxBytes: FILES_MAX_BODY });
    const place = await placeFor(ctx, data, { sending: true });
    const msgId = randomIdField(data.msg_id, "message id");
    const part = Number(data.part);
    const parts = Number(data.parts);
    if (!Number.isInteger(parts) || parts < 1 || parts > FILE_LIMITS.maxParts || !Number.isInteger(part) || part < 0 || part >= parts) {
      throw new ApiError(400, "BAD_FIELD", "That file is too large: files can be up to 10 MB.");
    }
    const bytes = decodePart(data.data);
    // Parts are uploaded before their message is sent. A message id that's already in use (anyone's)
    // can't have parts added to it, so nobody can hang files on someone else's message.
    if (await messageRow(sr, { ...place, msg_id: msgId })) throw new ApiError(409, "DUPLICATE_ID", "That message has already been sent.");
    if ((await countSince(sr, "Attachment", { owner_id: user.id }, new Date(now.getTime() - 600_000), FILE_LIMITS.partsPer10Min)) >= FILE_LIMITS.partsPer10Min) {
      throw rateLimited("uploading files");
    }
    const file = new File([bytes], `${msgId}-${part}.bin`, { type: "application/octet-stream" });
    const { file_uri } = await sr.integrations.Core.UploadPrivateFile({ file });
    if (typeof file_uri !== "string" || !file_uri) throw new ApiError(502, "UPLOAD_FAILED", "The file couldn't be stored. Try again.");
    const row = await sr.entities.Attachment.create({ ...place, owner_id: user.id, msg_id: msgId, part, parts, size: bytes.length, file_uri, swept_at: "" });
    return { file_id: row.id };
  },

  /** Short-lived download links for parts you can see. Unknown or unreachable ones are left out. */
  async download_links(ctx: Ctx) {
    const { sr, body } = ctx;
    const ids = Array.isArray(body.file_ids) ? [...new Set(body.file_ids.filter((x: unknown) => typeof x === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(x)))].slice(0, FILE_LIMITS.maxLinks) : [];
    if (!ids.length) return { links: {} };
    const rows = await sr.entities.Attachment.filter({ id: { $in: ids } }, "created_date", ids.length);
    const allowed = new Map<string, boolean>();
    const live = new Map<string, boolean>();
    const links: Record<string, string> = {};
    for (const row of rows) {
      const key = `${row.scope}:${row.scope_id}:${row.channel_id}`;
      // A message's files are all in one place: a request spanning many places is refused there.
      if (!allowed.has(key) && allowed.size >= 5) continue;
      if (!allowed.has(key)) {
        const ok = await placeFor(ctx, row.scope === "server" ? { scope: "server", server_id: row.scope_id, channel_id: row.channel_id } : { scope: "conversation", conversation_id: row.scope_id }, { sending: false })
          .then(() => true)
          .catch(() => false);
        allowed.set(key, ok);
      }
      if (!allowed.get(key)) continue;
      // A file goes with its message: once that's deleted or has disappeared, so has the file.
      const msgKey = `${row.scope}:${row.msg_id}:${row.owner_id}`;
      if (!live.has(msgKey)) live.set(msgKey, await messageExists(sr, row));
      if (!live.get(msgKey)) continue;
      const { signed_url } = await sr.integrations.Core.CreateFileSignedUrl({ file_uri: row.file_uri, expires_in: FILE_LIMITS.linkSeconds });
      if (typeof signed_url === "string") links[row.id] = signed_url;
    }
    return { links };
  },
};

async function messageRow(sr: any, row: any) {
  const found = row.scope === "server"
    ? await sr.entities.ServerMessage.filter({ msg_id: row.msg_id, server_id: row.scope_id }, "created_date", 1)
    : await sr.entities.Message.filter({ msg_id: row.msg_id, conversation_id: row.scope_id }, "created_date", 1);
  return found[0] || null;
}

/** The file's message exists, wasn't deleted, and was sent by whoever uploaded the file. */
async function messageExists(sr: any, row: any) {
  const m = await messageRow(sr, row);
  const expired = m?.expires_at && Date.parse(m.expires_at) <= Date.now();
  return Boolean(m && !m.deleted && !expired && m.sender_id === row.owner_id);
}

/**
 * Scheduled clean-up: forget parts whose message no longer exists (deleted, disappeared, or
 * never sent; an hour's grace covers one still being sent). Rows still in use are checked again
 * a day later. Links already stop working the moment a message goes (see download_links).
 */
export async function forgetOrphanedFiles(sr: any, now: Date, deadline: number) {
  const hourAgo = new Date(now.getTime() - 3600_000).toISOString().replace("Z", "");
  const dayAgo = new Date(now.getTime() - 86_400_000).toISOString();
  const fresh = await sr.entities.Attachment.filter({ swept_at: "", created_date: { $lte: hourAgo } }, "created_date", 100);
  const stale = await sr.entities.Attachment.filter({ swept_at: { $gt: "", $lte: dayAgo } }, "swept_at", 100);
  const seen = new Map<string, boolean>();
  let removed = 0;
  for (const row of [...fresh, ...stale]) {
    if (Date.now() > deadline) break;
    const key = `${row.scope}:${row.msg_id}:${row.owner_id}`;
    if (!seen.has(key)) seen.set(key, await messageExists(sr, row));
    if (seen.get(key)) await sr.entities.Attachment.update(row.id, { swept_at: now.toISOString() }).catch(() => null);
    else {
      await sr.entities.Attachment.delete(row.id).catch(() => null);
      removed += 1;
    }
  }
  return removed;
}
