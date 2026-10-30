// "Download my data": everything the service holds about your account, put together and
// decrypted here in your browser, then saved as a file. Nothing is sent anywhere to make it,
// and it never includes your keys.
import { ApiError, callFn } from "@/lib/api";
import * as P from "./protocol.js";
import { buildThread } from "./thread.js";

const PAUSE_MS = 150;
const RETRY_MS = [2_000, 5_000, 10_000, 20_000];
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Ask, waiting and asking again while the service is busy. */
async function ask(fn, body) {
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await callFn(fn, body);
    } catch (err) {
      const busy = err instanceof ApiError && (err.code === "UPSTREAM_BUSY" || err.code === "NETWORK");
      if (!busy || attempt >= RETRY_MS.length) throw err;
      await sleep(RETRY_MS[attempt]);
    }
  }
}

const STATUS_WORDS = {
  ok: "verified",
  unverified: "not verified",
  locked: "can't be read on this browser",
  deleted: "deleted",
};

/**
 * Put the export together. sec: what SecureContext provides (userId, me, status, keyring,
 * chainOf, devicesOf, ownMinCertVersion, loadPeers). email: the sign-in address, if known.
 * onProgress(text) is told what's happening.
 */
export async function buildExport(sec, { email = null, onProgress = () => {} } = {}) {
  const { userId, keyring } = sec;
  if (!keyring) throw new Error("Your keys need to be open on this browser to read your messages.");

  onProgress("Your profile and devices");
  const me = await ask("profile", { action: "me" });
  const status = await ask("keys", { action: "status" });
  const { conversations } = await ask("conversations", { action: "list" });
  const memberIds = [...new Set(conversations.flatMap((c) => c.member_ids))].filter((id) => id !== userId);

  onProgress("The people you talk to");
  await sec.loadPeers(memberIds, { force: true }).catch(() => {});
  const profiles = {};
  for (let i = 0; i < memberIds.length; i += 100) {
    const { profiles: rows } = await ask("profile", { action: "get_many", user_ids: memberIds.slice(i, i + 100) });
    for (const p of rows) profiles[p.user_id] = p;
  }
  const person = (id) => {
    if (id === userId) return { user_id: id, username: me.profile?.username || "", display_name: me.profile?.display_name || "", you: true };
    const p = profiles[id];
    return p ? { user_id: id, username: p.username, display_name: p.display_name } : { user_id: id, username: null, display_name: "Former member" };
  };
  const label = (id) => {
    const p = person(id);
    return p.you ? "You" : p.username ? `@${p.username}` : p.display_name;
  };

  const open = (kind, item) => P.openItem({
    kind,
    item,
    userId,
    keyring,
    senderChain: sec.chainOf(item.sender_id),
    senderDevices: sec.devicesOf(item.sender_id),
    minCertVersion: item.sender_id === userId ? sec.ownMinCertVersion : 1,
  });

  const out = [];
  for (let n = 0; n < conversations.length; n += 1) {
    const c = conversations[n];
    onProgress(`Conversation ${n + 1} of ${conversations.length}`);
    const list = [];
    let before;
    for (;;) {
      const page = await ask("messages", { action: "list", conversation_id: c.id, ...(before ? { before } : {}) });
      list.push(...page.messages);
      if (!page.has_more || !page.before) break;
      before = page.before;
      await sleep(PAUSE_MS);
    }
    list.sort((a, b) => String(a.created_date).localeCompare(String(b.created_date)));
    const opened = {};
    for (const m of list) opened[m.id] = await open("message", m);
    const rows = buildThread(list, opened, { userId });
    let name = null;
    if (c.kind === "group" && c.title) {
      const t = await open("title", { ...c.title, conversation_id: c.id });
      if (t.status === "ok") name = t.text;
    }
    out.push({
      kind: c.kind === "dm" ? "direct message" : "group",
      name,
      started: c.created_date,
      members: c.member_ids.map(person),
      admins: c.kind === "group" ? (c.admin_ids || []).map(label) : undefined,
      disappearing_messages: c.expire_seconds ? `after ${c.expire_seconds / 3600} hours` : "off",
      messages: rows.map((row) => ({
        sent: row.m.sent_at,
        from: label(row.m.sender_id),
        status: STATUS_WORDS[row.result?.status] || "not opened",
        text: row.result?.status === "ok" || row.result?.status === "unverified" ? row.text : null,
        edited: row.edited || undefined,
        reply_to: row.replyTo?.row ? { sent: row.replyTo.row.m.sent_at, from: label(row.replyTo.row.m.sender_id) } : row.replyTo ? "an earlier message" : undefined,
        reactions: row.reactions.length ? row.reactions.map((r) => ({ emoji: r.emoji, from: r.people.map(label) })) : undefined,
        disappears: row.m.expires_at || undefined,
      })),
    });
  }

  onProgress("Blocked people and reports");
  const { blocked } = await ask("safety", { action: "list_blocks" });
  const { reports } = await ask("safety", { action: "my_reports" });

  return {
    format: "commonveil-export-1",
    exported_at: new Date().toISOString(),
    about: [
      "Everything Commonveil holds about your account, decrypted in your browser. Nothing was sent anywhere to make this file.",
      "It holds your messages in readable form: keep it somewhere safe, and delete it when you no longer need it.",
      "Your encryption keys and recovery phrase are not included.",
      "Messages that couldn't be decrypted on the browser that made this are listed without their text.",
    ],
    account: {
      user_id: userId,
      sign_in_email: email || undefined,
      username: me.profile?.username,
      display_name: me.profile?.display_name,
      about: me.profile?.bio || "",
      staff: me.user?.role === "admin",
      delete_when_unused: me.auto_delete?.days ? { after_days: me.auto_delete.days, last_used: me.auto_delete.last_active_on } : "off",
    },
    devices: status.devices.map((d) => ({
      name: d.label,
      status: d.status,
      added: d.approved_at || d.created_date,
      added_by: d.approved_via,
      last_seen: d.last_seen_at || undefined,
      removed: d.revoked_at || undefined,
      removed_because: d.revoked_reason || undefined,
    })),
    public_keys: status.statements.map((s) => ({ version: s.version, issued: s.issued_at })),
    key_resets: status.resets.map((r) => ({ requested: r.requested_at, from: r.device_label, status: r.status })),
    conversations: out,
    blocked: blocked.map((p) => ({ username: p.username, display_name: p.display_name })),
    reports_you_made: reports.map((r) => ({ about: label(r.reported_user_id), reason: r.reason, details: r.details, status: r.status, sent: r.created_date })),
  };
}

/** Save it as a file, without it leaving the browser. */
export function downloadJson(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
