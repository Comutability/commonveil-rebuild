// Opening invite links: the code goes to the service; the secret after # never does. While
// someone signs in, the secret waits in this tab's session storage (gone when the tab closes).
import { callFn } from "@/lib/api";
import { openInvitePreview } from "../crypto/serverKeys.js";

const KEY = "commonveil:pending-invite";

export function rememberInvite(code, secret) {
  try {
    window.sessionStorage.setItem(KEY, JSON.stringify({ code, secret, at: Date.now() }));
  } catch {
    /* storage refused: the preview just won't show after signing in */
  }
}

/** The secret for this code, if this tab remembered one in the last hour. Forgotten once read. */
export function recallInvite(code) {
  try {
    const saved = JSON.parse(window.sessionStorage.getItem(KEY) || "null");
    window.sessionStorage.removeItem(KEY);
    if (saved && saved.code === code && Date.now() - saved.at < 3600_000) return saved.secret || "";
  } catch {
    /* nothing remembered */
  }
  return "";
}

/**
 * What an invite shows before joining: { server_id, look: { name, description, icon, color } | null,
 * member_count, expires_at, sealed (the preview was encrypted and opened with the link's secret) }.
 */
/** site: the invite's own site, when it's another Commonveil site (self-hosted sites only). */
export async function inviteInfo(code, secret, site = "") {
  const info = await callFn("invite", { action: "invite_info", code, ...(site ? { _site: site } : {}) });
  let look = null;
  let sealed = false;
  if (info.preview && secret) {
    const opened = await openInvitePreview({ code, secret, sealed: info.preview });
    if (opened && typeof opened.name === "string") {
      look = { name: opened.name.slice(0, 100), description: String(opened.description || "").slice(0, 500), icon: String(opened.icon || "").slice(0, 8), color: /^#[0-9a-f]{6}$/i.test(opened.color || "") ? opened.color : "" };
      sealed = true;
    }
  }
  if (!look && info.public?.name) look = { name: info.public.name, description: info.public.description || "", icon: info.public.icon || "", color: info.public.color || "" };
  return { server_id: info.server_id, look, member_count: info.member_count, expires_at: info.expires_at, sealed };
}
