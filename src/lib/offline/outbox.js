// Messages waiting to be sent (docs/OFFLINE.md). Each one is the finished request: already
// encrypted to the conversation's members and signed by this device, so what waits here is the
// same ciphertext the server would hold. Nothing is stored in plain text: the app shows a waiting
// message by opening its own copy, like any other message.
//
// Kept in this browser's IndexedDB, per account. A message waits up to a week (the server's limit
// for one written offline); after that it's marked as not sent, with the choice to send it again.
import { createStore, del, entries, get, set } from "idb-keyval";

const store = typeof indexedDB !== "undefined" ? createStore("commonveil-outbox", "items") : undefined;
const key = (userId, msgId) => `${userId}:${msgId}`;
export const MAX_AGE_MS = 7 * 24 * 3600 * 1000;

/**
 * entry: { msg_id, fn: "messages" | "channels", body, place: { conversation_id } | { server_id, channel_id, thread_id } }.
 * Answers the stored entry.
 */
export async function queue(userId, entry) {
  const stored = { ...entry, queued_at: new Date().toISOString(), failed: "" };
  await set(key(userId, entry.msg_id), stored, store);
  return stored;
}

/** This account's waiting messages, oldest first. */
export async function waiting(userId) {
  if (!store) return [];
  const all = await entries(store);
  return all
    .filter(([k]) => String(k).startsWith(`${userId}:`))
    .map(([, v]) => v)
    .sort((a, b) => String(a.body?.sent_at || "").localeCompare(String(b.body?.sent_at || "")));
}

export async function remove(userId, msgId) {
  await del(key(userId, msgId), store);
}

export async function markFailed(userId, msgId, reason) {
  const current = await get(key(userId, msgId), store);
  if (current) await set(key(userId, msgId), { ...current, failed: String(reason || "It couldn't be sent.") }, store);
}

/** Your own site has it and is passing it on (the conversation's site couldn't be reached). */
export async function markHeld(userId, msgId, site) {
  const current = await get(key(userId, msgId), store);
  if (current) await set(key(userId, msgId), { ...current, held: String(site || "") }, store);
}

/** The message as the app shows it while it waits: like one from the server, marked as waiting. */
export function asMessage(entry, userId) {
  const b = entry.body;
  return {
    id: `waiting:${b.msg_id}`,
    msg_id: b.msg_id,
    sender_id: userId,
    device_id: b.device_id,
    envelope: b.envelope,
    signature: b.signature,
    sent_at: b.sent_at,
    created_date: b.sent_at,
    deleted: false,
    ...(entry.place || {}),
    waiting: true,
    failed: entry.failed || "",
    held: entry.held || "",
  };
}
