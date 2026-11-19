// Moving sealed attachments to and from the service. Everything here handles ciphertext only:
// sealing and opening happen in attachments.js, on this device.
import { ApiError, callFn } from "@/lib/api";
import { toB64 } from "../crypto/encoding.js";
import { signedRequest } from "./protocol.js";
import { openFile, sealFile, MAX_ATTACHMENTS, PART_PLAIN } from "./attachments.js";

/** A sealed part is never bigger than this (its plaintext plus the 16-byte tag). */
const MAX_PART = PART_PLAIN + 16;

const RETRY_MS = [800, 2500];
const transient = (err) => err instanceof ApiError && (err.status === 0 || err.status === 429 || err.status >= 500);
async function retry(fn) {
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await fn();
    } catch (err) {
      if (!transient(err) || attempt >= RETRY_MS.length) throw err;
      await new Promise((r) => setTimeout(r, RETRY_MS[attempt]));
    }
  }
}

/**
 * Seal and upload files for a message that will be sent with msgId.
 * place: { scope: "server", server_id, channel_id } or { scope: "conversation", conversation_id }.
 * items: [{ file, voice?, duration?, spoiler? }]. onProgress(doneParts, totalParts).
 * Returns the attachment list to put in the message.
 */
export async function uploadAttachments({ userId, device, place, msgId, items, onProgress }) {
  if (items.length > MAX_ATTACHMENTS) throw new Error(`You can attach up to ${MAX_ATTACHMENTS} files to one message.`);
  const sealed = [];
  for (const it of items) sealed.push({ it, ...(await sealFile(it.file, it)) });
  const total = sealed.reduce((n, s) => n + s.parts.length, 0);
  let done = 0;
  onProgress?.(0, total);
  const out = [];
  for (const s of sealed) {
    const ids = await uploadParts({ userId, device, place, msgId, parts: s.parts, onPart: () => onProgress?.(++done, total) });
    out.push({ ...s.meta, ids, ...(s.it.spoiler ? { spoiler: true } : {}) });
  }
  return out;
}

async function uploadParts({ userId, device, place, msgId, parts, onPart }) {
  const ids = [];
  for (let i = 0; i < parts.length; i += 1) {
    const payload = { ...place, msg_id: msgId, part: i, parts: parts.length, data: toB64(parts[i]) };
    const res = await retry(async () => callFn("files", await signedRequest({ userId, device, action: "upload_part", payload })));
    ids.push(res.file_id);
    onPart?.();
  }
  return ids;
}

/**
 * Attachments being forwarded somewhere else: the same sealed parts are copied to the new place
 * (the key goes along inside the new message). Nothing is decrypted or re-encrypted.
 */
export async function copyAttachments({ userId, device, place, msgId, attachments }) {
  const out = [];
  for (const a of attachments) {
    const parts = await fetchParts(a);
    const ids = await uploadParts({ userId, device, place, msgId, parts });
    out.push(forwardedCopy(a, ids));
  }
  return out;
}

/** An attachment as it goes into a new message: where the original was posted (see thread.js) isn't part of it. */
export function forwardedCopy(meta, ids) {
  const out = { ...meta, ids };
  delete out.place;
  return out;
}

// The ids that say where a file was posted, so the request reaches the site that holds it.
const PLACE_KEYS = ["conversation_id", "server_id", "channel_id"];
function placeFields(place) {
  const out = {};
  for (const k of PLACE_KEYS) if (typeof place?.[k] === "string" && place[k]) out[k] = place[k];
  return out;
}

// Download links last a few minutes, so they're asked for when needed, in batches. A request about
// a place hosted on another site is answered by that site, so a link is kept only for an id that
// was asked for, and only for the place it was asked about: no site can hand out links for files
// posted somewhere else, and so learn when they're opened.
const linkCache = new Map(); // place + file id -> { url, until }
const cacheKey = (place, id) => `${JSON.stringify(placeFields(place))}|${id}`;

/** Download links for a file's parts, in order (null where there's none). */
export async function linksFor(ids, place) {
  const now = Date.now();
  const missing = ids.filter((id) => !(linkCache.get(cacheKey(place, id))?.until > now));
  for (let i = 0; i < missing.length; i += 60) {
    const batch = missing.slice(i, i + 60);
    let links;
    try {
      ({ links } = await retry(() => callFn("files", { action: "download_links", file_ids: batch, ...placeFields(place) })));
    } catch (err) {
      // Only another site answers "not found" here: one that doesn't share files across sites.
      if (err instanceof ApiError && err.status === 404) throw new Error("This file is on a site that doesn't share files with other sites yet.");
      throw err;
    }
    for (const id of batch) if (typeof links?.[id] === "string") linkCache.set(cacheKey(place, id), { url: links[id], until: now + 240_000 });
  }
  return ids.map((id) => linkCache.get(cacheKey(place, id))?.url || null);
}

/** For tests: forget every link. */
export function clearLinks() {
  linkCache.clear();
}

async function fetchParts(meta) {
  const urls = await linksFor(meta.ids, meta.place);
  if (urls.some((u) => !u)) throw new Error("This file is no longer available.");
  const parts = [];
  for (const url of urls) {
    const res = await fetch(url, { credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store" });
    if (!res.ok) throw new Error("This file couldn't be downloaded. Try again.");
    const declared = Number(res.headers.get("content-length"));
    if (declared > MAX_PART) throw new Error("This file failed its integrity check.");
    const bytes = new Uint8Array(await res.arrayBuffer());
    if (bytes.length > MAX_PART) throw new Error("This file failed its integrity check.");
    parts.push(bytes);
  }
  return parts;
}

// Opened files stay in memory for this tab only, as blob URLs, a limited number at a time.
const opened = new Map(); // what the file is -> Promise<{ blob, url }>
const MAX_OPEN = 40;
// Everything that decides what a file opens to, so a message that names another file's parts
// can't show that file's decrypted copy as its own.
const openedKey = (meta) => JSON.stringify([placeFields(meta.place), meta.ids, meta.key, meta.ivp, meta.type || ""]);

/** The decrypted file as { blob, url }. Throws with a message for people if it can't be had. */
export function openAttachment(meta) {
  const key = openedKey(meta);
  if (opened.has(key)) {
    const p = opened.get(key);
    opened.delete(key);
    opened.set(key, p);
    return p;
  }
  const p = (async () => {
    const blob = await openFile(meta, await fetchParts(meta));
    return { blob, url: URL.createObjectURL(blob) };
  })();
  p.catch(() => opened.delete(key));
  opened.set(key, p);
  while (opened.size > MAX_OPEN) {
    const [oldKey, oldP] = opened.entries().next().value;
    opened.delete(oldKey);
    oldP.then((o) => URL.revokeObjectURL(o.url)).catch(() => {});
  }
  return p;
}

/** Save a decrypted copy to the device. */
export async function saveAttachment(meta) {
  const { blob } = await openAttachment(meta);
  const url = URL.createObjectURL(new Blob([blob], { type: "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = meta.name || "file";
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}
