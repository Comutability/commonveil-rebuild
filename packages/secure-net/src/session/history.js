// Moving history to a new device (CVP-016, "New devices").
//
// The old device seals the history under a fresh random key, in chunks, and hands the chunks to
// any untrusted store or relay. It sends the key and a manifest to the new device over their
// one-to-one session, which only exists once the person has linked the new device (comparing
// link codes) and the new device is on the account's signed device list. So no site ever holds
// both the chunks and the key. With no old device to hand, a new device starts with no history.
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { b64u, fromB64u, utf8, concat, equalBytes } from "../core/bytes.js";
import { canonicalBytes } from "../core/canonical.js";
import { SessionError, random, seal, open, LABEL } from "./primitives.js";

export const CHUNK_SIZE = 256 * 1024;
const chunkKey = (key, i) => hkdf(sha256, key, new Uint8Array(32), utf8(`${LABEL}/history/${i}`), 32);
const chunkAd = (manifest, i) => concat(utf8(`${LABEL}/history\n`), canonicalBytes({ id: manifest.id, chunks: manifest.chunks, i }));

/**
 * Seal history items (any JSON values, e.g. decrypted messages with their metadata) for transfer.
 * Returns { offer, chunks }: send `offer` over the one-to-one session with the new device, and
 * put `chunks` (base64url strings) wherever is convenient. Each chunk is bound to its place, so
 * chunks can't be dropped, reordered or swapped in from another transfer without it showing.
 */
export async function sealHistory(items, { chunkSize = CHUNK_SIZE, note } = {}) {
  const key = random(32);
  const bytes = canonicalBytes(items);
  const parts = [];
  for (let at = 0; at < bytes.length || parts.length === 0; at += chunkSize) parts.push(bytes.slice(at, at + chunkSize));
  const manifest = { id: b64u(random(16)), chunks: parts.length, count: items.length, size: bytes.length };
  const chunks = [];
  for (let i = 0; i < parts.length; i += 1) chunks.push(b64u(await seal(chunkKey(key, i), parts[i], chunkAd(manifest, i), "history")));
  manifest.digest = b64u(sha256(utf8(chunks.join("."))));
  const offer = { type: "history", key: b64u(key), manifest };
  if (note) offer.note = String(note).slice(0, 200);
  return { offer, chunks };
}

/** Open a history transfer on the new device, with the offer that came over the session. */
export async function openHistory(offer, chunks) {
  const m = offer?.manifest;
  if (offer?.type !== "history" || !m || !Number.isSafeInteger(m.chunks) || m.chunks < 1) throw new SessionError("BAD_MESSAGE", "Not a history offer");
  if (!Array.isArray(chunks) || chunks.length !== m.chunks) throw new SessionError("INCOMPLETE", `Expected ${m.chunks} chunks, got ${chunks?.length ?? 0}`);
  if (!equalBytes(sha256(utf8(chunks.join("."))), fromB64u(m.digest))) throw new SessionError("TAMPERED", "History chunks don't match the manifest");
  const key = fromB64u(offer.key);
  const parts = [];
  for (let i = 0; i < chunks.length; i += 1) parts.push(await open(chunkKey(key, i), fromB64u(chunks[i]), chunkAd(m, i), "history"));
  const all = concat(...parts);
  if (all.length !== m.size) throw new SessionError("TAMPERED", "History is the wrong size");
  const items = JSON.parse(new TextDecoder().decode(all));
  if (!Array.isArray(items) || items.length !== m.count) throw new SessionError("TAMPERED", "History has the wrong number of items");
  return items;
}
