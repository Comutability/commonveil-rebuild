// A server's own emoji and stickers. They're small images, made on the uploader's device and
// kept in one encrypted item per set: the service stores the set without seeing the pictures or
// their names. In messages an emoji is written <:name:id>; a reaction with one is "c:id".

export const EMOJI_LIMITS = Object.freeze({ emoji: 40, stickers: 8, emojiPx: 64, stickerPx: 160, emojiChars: 3200, stickerChars: 18_000 });
export const EMOJI_NAME_RE = /^[a-z0-9_]{2,32}$/;
export const EMOJI_ID_RE = /^[a-z0-9]{8}$/;
export const CUSTOM_TOKEN_RE = /<:([a-z0-9_]{2,32}):([a-z0-9]{8})>/g;
const IMG_RE = /^data:image\/(webp|png);base64,[A-Za-z0-9+/]+=*$/;

export const isCustomReaction = (v) => typeof v === "string" && /^c:[a-z0-9]{8}$/.test(v);
export const customToken = (e) => `<:${e.name}:${e.id}>`;

export function newEmojiId() {
  const abc = "abcdefghijklmnopqrstuvwxyz0123456789";
  return [...crypto.getRandomValues(new Uint8Array(8))].map((b) => abc[b % 36]).join("");
}

/** A name from a file name: lower case, letters, digits and underscores. */
export function nameFromFile(name) {
  const base = String(name || "").replace(/\.[^.]+$/, "").toLowerCase().replace(/[^a-z0-9_]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 32);
  return base.length >= 2 ? base : "emoji";
}

/** One set (kind "emoji" or "stickers") from a decrypted item, checked entry by entry. */
export function cleanSet(kind, payload) {
  const max = kind === "stickers" ? EMOJI_LIMITS.stickers : EMOJI_LIMITS.emoji;
  const chars = kind === "stickers" ? EMOJI_LIMITS.stickerChars : EMOJI_LIMITS.emojiChars;
  const list = Array.isArray(payload?.items) ? payload.items : [];
  const seen = new Set();
  const out = [];
  for (const x of list) {
    if (!x || typeof x !== "object" || !EMOJI_ID_RE.test(x.id) || !EMOJI_NAME_RE.test(x.name) || seen.has(x.id)) continue;
    if (typeof x.img !== "string" || x.img.length > chars || !IMG_RE.test(x.img)) continue;
    seen.add(x.id);
    out.push({ id: x.id, name: x.name, img: x.img });
    if (out.length >= max) break;
  }
  return { items: out };
}

/**
 * Shrink a picture to a square of px pixels (letterboxed, transparent) as WebP, or PNG where
 * WebP isn't available, lowering quality until it fits maxChars. Done on this device.
 */
export async function imageForSet(file, kind) {
  const px = kind === "stickers" ? EMOJI_LIMITS.stickerPx : EMOJI_LIMITS.emojiPx;
  const maxChars = kind === "stickers" ? EMOJI_LIMITS.stickerChars : EMOJI_LIMITS.emojiChars;
  if (!/^image\/(png|jpeg|webp|gif)$/.test(file.type)) throw new Error("Use a PNG, JPEG, WebP or GIF picture.");
  if (file.size > 4 * 1024 * 1024) throw new Error("That picture is over 4 MB.");
  let bmp;
  try {
    bmp = await createImageBitmap(file);
  } catch {
    throw new Error("That picture couldn't be read.");
  }
  const canvas = document.createElement("canvas");
  canvas.width = px;
  canvas.height = px;
  const g = canvas.getContext("2d");
  const scale = Math.min(px / bmp.width, px / bmp.height);
  const w = Math.round(bmp.width * scale);
  const h = Math.round(bmp.height * scale);
  g.imageSmoothingQuality = "high";
  g.drawImage(bmp, (px - w) / 2, (px - h) / 2, w, h);
  bmp.close?.();
  for (const q of [0.9, 0.8, 0.65, 0.5, 0.35]) {
    const url = canvas.toDataURL("image/webp", q);
    if (url.startsWith("data:image/webp") && url.length <= maxChars) return url;
  }
  const png = canvas.toDataURL("image/png");
  if (png.length <= maxChars) return png;
  throw new Error("That picture has too much detail to fit. Try a simpler one.");
}
