// Putting several sites' answers together (docs/FEDERATION.md): shared by self-hosted sites
// (server/federation) and the hosted site (federation/hosted.ts).

/** Actions that, with no conversation or server named, mean "everything of mine", here and elsewhere. */
export const FAN_OUT = {
  "messages.poll": "merge",
  "conversations.list": "merge",
  "servers.list": "merge",
  "messages.scheduled": "merge",
  "messages.deliver_mine": "merge",
  "keys.peer_keys": "people",
  "profile.get_many": "people",
};

export const CURSOR_FIELDS = { since: "cursor", conversations_since: "conversations_cursor", servers_since: "servers_cursor", server_changes_since: "server_changes_cursor" };

const b64u = (text: string) => btoa(String.fromCharCode(...new TextEncoder().encode(text))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export const unb64u = (text: string) => new TextDecoder().decode(Uint8Array.from(atob(String(text).replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)));

/** Put the answers from several sites together: lists joined, cursors kept per site, flags combined. */
export function mergeResults(results: any[]): any {
  const out: any = {};
  const ok = results.filter((r) => r.data);
  for (const { data } of ok) {
    for (const [k, v] of Object.entries(data)) {
      if (Object.values(CURSOR_FIELDS).includes(k)) continue;
      if (Array.isArray(v)) {
        out[k] ||= [];
        for (const x of v) {
          if (x && typeof x === "object" && typeof x.id === "string" ? !out[k].some((y) => y?.id === x.id) : !out[k].includes(x)) out[k].push(x);
        }
      } else if (typeof v === "boolean") out[k] = Boolean(out[k]) || v;
      else if (v && typeof v === "object") out[k] = { ...(out[k] || {}), ...v };
      else if (!(k in out)) out[k] = v;
    }
  }
  for (const cursorKey of Object.values(CURSOR_FIELDS)) {
    const local = results[0].data?.[cursorKey];
    if (local === undefined) continue;
    const others: any = {};
    for (const r of results.slice(1)) {
      const field = Object.keys(CURSOR_FIELDS).find((f) => CURSOR_FIELDS[f] === cursorKey);
      const c = r.data ? r.data[cursorKey] : r.keep?.[field];
      if (typeof c === "string") others[r.host] = c;
    }
    out[cursorKey] = Object.keys(others).length ? `${local}~${b64u(JSON.stringify(others))}` : local;
  }
  return out;
}
