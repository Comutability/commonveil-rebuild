// Attachments, encrypted on this device before upload. Each file gets its own random 256-bit
// key; it's split into parts and each part sealed with AES-256-GCM (IV: a random 8-byte prefix
// and the part number; additional data: the part number, the number of parts and the size), so
// parts can't be swapped, dropped or reordered unnoticed. The key, name, type and size travel
// inside the end-to-end encrypted message; the service only ever holds the sealed parts.
import { fromB64, toB64, utf8 } from "../crypto/encoding.js";

export const MAX_FILE_BYTES = 10 * 1024 * 1024;
export const MAX_ATTACHMENTS = 10;
/** Plaintext per part, so a sealed part (plus its 16-byte tag) fits the service's part size. */
export const PART_PLAIN = 768 * 1024 - 16;

const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

const aad = (i, parts, size) => utf8(`commonveil/file/v1|${i}|${parts}|${size}`);
function ivFor(prefix, i) {
  const iv = new Uint8Array(12);
  iv.set(prefix, 0);
  new DataView(iv.buffer).setUint32(8, i);
  return iv;
}

/** What kind of preview a file gets, from its declared type. */
export function previewKind(type) {
  if (/^image\/(png|jpe?g|gif|webp|avif)$/i.test(type)) return "image";
  if (/^video\/(mp4|webm|ogg)$/i.test(type)) return "video";
  if (/^audio\//i.test(type)) return "audio";
  return "file";
}

async function imageSize(file) {
  if (previewKind(file.type) !== "image" || typeof createImageBitmap !== "function") return {};
  try {
    const bmp = await createImageBitmap(file);
    const out = { w: bmp.width, h: bmp.height };
    bmp.close?.();
    return out;
  } catch {
    return {};
  }
}

/**
 * Seal a file. Returns { meta, parts } where parts are the sealed pieces to upload and meta is
 * what goes in the message (once the parts' handles are added as meta.ids).
 * extra: { voice: true, duration } for a voice message.
 */
export async function sealFile(file, extra = {}) {
  if (file.size > MAX_FILE_BYTES) throw new Error(`${file.name || "That file"} is over 10 MB.`);
  if (file.size === 0) throw new Error(`${file.name || "That file"} is empty.`);
  const bytes = new Uint8Array(await file.arrayBuffer());
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt"]);
  const prefix = crypto.getRandomValues(new Uint8Array(8));
  const count = Math.max(1, Math.ceil(bytes.length / PART_PLAIN));
  const parts = [];
  for (let i = 0; i < count; i += 1) {
    const chunk = bytes.subarray(i * PART_PLAIN, (i + 1) * PART_PLAIN);
    parts.push(new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: ivFor(prefix, i), additionalData: aad(i, count, bytes.length) }, key, chunk)));
  }
  const meta = {
    name: String(file.name || (extra.voice ? "Voice message" : "file")).slice(0, 200),
    type: String(file.type || "application/octet-stream").slice(0, 100),
    size: bytes.length,
    key: toB64(raw),
    ivp: toB64(prefix),
    parts: count,
    ...(await imageSize(file)),
    ...(extra.voice ? { voice: true, duration: Math.max(0, Math.min(3600, Math.round(extra.duration || 0))) } : {}),
  };
  raw.fill(0);
  return { meta, parts };
}

/** Open a file from its sealed parts, in order. Throws if any part fails its check. */
export async function openFile(meta, parts) {
  if (parts.length !== meta.parts) throw new Error("Part of this file is missing.");
  const key = await crypto.subtle.importKey("raw", fromB64(meta.key), { name: "AES-GCM" }, false, ["decrypt"]);
  const prefix = fromB64(meta.ivp);
  const out = [];
  for (let i = 0; i < parts.length; i += 1) {
    try {
      out.push(new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivFor(prefix, i), additionalData: aad(i, meta.parts, meta.size) }, key, parts[i])));
    } catch {
      throw new Error("This file failed its integrity check.");
    }
  }
  const total = out.reduce((n, p) => n + p.length, 0);
  if (total !== meta.size) throw new Error("This file failed its integrity check.");
  // Shown with its declared type only for previews we draw ourselves; everything else downloads as data.
  const kind = previewKind(meta.type);
  return new Blob(out, { type: kind === "file" ? "application/octet-stream" : meta.type });
}

/** An attachment from a decrypted message, checked field by field, or null. */
export function cleanAttachment(a) {
  if (!a || typeof a !== "object") return null;
  const parts = Number(a.parts);
  if (!Number.isInteger(parts) || parts < 1 || parts > 14) return null;
  if (!Array.isArray(a.ids) || a.ids.length !== parts || !a.ids.every((x) => typeof x === "string" && ID_RE.test(x))) return null;
  if (typeof a.key !== "string" || !B64_RE.test(a.key) || typeof a.ivp !== "string" || !B64_RE.test(a.ivp)) return null;
  const size = Number(a.size);
  if (!Number.isInteger(size) || size < 1 || size > MAX_FILE_BYTES) return null;
  const out = {
    ids: a.ids.slice(),
    name: typeof a.name === "string" && a.name.trim() ? a.name.replace(/[\r\n/\\]+/g, " ").slice(0, 200) : "file",
    type: typeof a.type === "string" ? a.type.slice(0, 100) : "application/octet-stream",
    size,
    key: a.key,
    ivp: a.ivp,
    parts,
  };
  if (Number.isInteger(a.w) && Number.isInteger(a.h) && a.w > 0 && a.h > 0 && a.w <= 20_000 && a.h <= 20_000) Object.assign(out, { w: a.w, h: a.h });
  if (a.voice === true) Object.assign(out, { voice: true, duration: Math.max(0, Math.min(3600, Number(a.duration) || 0)) });
  if (a.spoiler === true) out.spoiler = true;
  return out;
}

export function cleanAttachments(list) {
  if (!Array.isArray(list)) return [];
  return list.map(cleanAttachment).filter(Boolean).slice(0, MAX_ATTACHMENTS);
}

export function sizeLabel(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
