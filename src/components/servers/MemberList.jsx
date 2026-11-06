import React, { useEffect, useMemo, useState } from "react";
import { EyeOff, Loader2 } from "lucide-react";
import { useServers } from "@/lib/secure/ServerContext";
import Avatar from "@/components/chat/Avatar";
import { usePresence } from "@/lib/secure/PresenceContext";
import MemberCard from "./MemberCard";

/**
 * Who's here, as far as each person chose: staff always, everyone else only if they opted in.
 * There's no online status: Commonveil doesn't track when you're around.
 */
export default function MemberList({ serverId, className = "" }) {
  const s = useServers();
  const { servers, memberLists, loadMembers, memberName, memberColor, roleName, roleColor, profileOf, act, isStaffIn } = s;
  const e = servers[serverId];
  const list = memberLists[serverId];
  const [error, setError] = useState("");
  const [card, setCard] = useState(null);
  const [busy, setBusy] = useState(false);
  const presence = usePresence();

  useEffect(() => {
    let alive = true;
    const load = () => loadMembers(serverId).then(() => alive && setError("")).catch((err) => alive && setError(err.message));
    load();
    const t = setInterval(() => document.visibilityState === "visible" && load(), 60_000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [serverId, loadMembers]);

  const groups = useMemo(() => {
    if (!list || !e?.roles) return [];
    const hoisted = e.roles.filter((r) => !r.is_everyone && r.hoist).sort((a, b) => b.position - a.position);
    const placed = new Set();
    const out = [];
    const owner = e.server.owner_id;
    for (const role of hoisted) {
      const people = list.members.filter((m) => !placed.has(m.user_id) && (m.role_ids || []).includes(role.id));
      people.forEach((m) => placed.add(m.user_id));
      if (people.length) out.push({ key: role.id, label: roleName(role), color: roleColor(role), people });
    }
    const rest = list.members.filter((m) => !placed.has(m.user_id));
    const ownerRow = rest.find((m) => m.user_id === owner);
    if (ownerRow) out.unshift({ key: "owner", label: "Owner", color: "", people: [ownerRow] });
    const others = rest.filter((m) => m.user_id !== owner);
    if (others.length) out.push({ key: "members", label: "Members", color: "", people: others });
    const byName = (a, b) => memberName(serverId, a.user_id).localeCompare(memberName(serverId, b.user_id));
    for (const g of out) g.people.sort(byName);
    return out;
  }, [list, e, roleName, roleColor, memberName, serverId]);

  if (!e) return null;
  const mode = e.server.settings?.member_list || "opt_in";
  const shown = list ? list.members.length : 0;
  const hidden = list ? Math.max(0, list.count - shown) : 0;
  const meListed = e.member?.listed;
  // Staff are always listed, so members can see who runs the server. A toggle would do nothing for them.
  const meStaff = Boolean(e.member) && isStaffIn(serverId, e.member);

  return (
    <aside aria-label="Members" className={`scroll-thin flex h-full w-60 shrink-0 flex-col overflow-y-auto bg-panel ${className}`}>
      <div className="px-4 pb-2 pt-5">
        {list && <p className="text-sm font-semibold">{list.count} {list.count === 1 ? "member" : "members"}</p>}
      </div>
      {!list && !error && (
        <p className="flex items-center gap-2 px-4 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Loading…</p>
      )}
      {error && <p className="px-4 text-sm text-destructive">{error}</p>}
      {groups.map((g) => (
        <section key={g.key} className="mb-3" aria-label={g.label}>
          <h3 className="px-4 pb-1 text-xs font-semibold text-muted-foreground">{g.label}, {g.people.length}</h3>
          <ul className="px-2">
            {g.people.map((m) => {
              const p = profileOf(serverId, m.user_id);
              const color = memberColor(serverId, m);
              return (
                <li key={m.user_id}>
                  <button type="button" onClick={() => setCard(m.user_id)} className="panel-item">
                    <span className="relative shrink-0">
                      <Avatar id={m.user_id} name={memberName(serverId, m.user_id)} emoji={p?.avatar_emoji} image={p?.avatar_image} accent={p?.accent_color} size="h-8 w-8" />
                      {presence.statusIn("s", serverId, m.user_id) && (
                        <span
                          className={`absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full border-2 border-[hsl(var(--panel))] ${presence.statusIn("s", serverId, m.user_id) === "online" ? "bg-emerald-500" : "bg-amber-400"}`}
                          title={presence.statusIn("s", serverId, m.user_id) === "online" ? "Online" : "Away"}
                          aria-label={presence.statusIn("s", serverId, m.user_id) === "online" ? "Online" : "Away"}
                        />
                      )}
                    </span>
                    <span className="min-w-0 text-left">
                      <span className="block truncate font-medium" style={color ? { color } : undefined}>{memberName(serverId, m.user_id)}</span>
                      {m.timeout_until && <span className="block text-xs text-muted-foreground">Timed out</span>}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        </section>
      ))}
      {list && (
        <div className="mt-auto space-y-2 border-t border-border/60 px-4 py-3 text-xs text-muted-foreground">
          {mode === "count_only" ? (
            <p className="flex gap-1.5"><EyeOff className="h-3.5 w-3.5 shrink-0" aria-hidden="true" /> This server doesn't list its members. Staff are still shown.</p>
          ) : hidden > 0 ? (
            <p className="flex gap-1.5">
              <EyeOff className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              {hidden} {hidden === 1 ? "member isn't" : "members aren't"} listed. {mode === "staff_only" ? "Only staff are listed here." : "Members choose whether to be listed."}
            </p>
          ) : null}
          {mode !== "count_only" && meStaff && <p>You're listed here because you're staff. Members can always see who runs the server.</p>}
          {mode === "opt_in" && !meStaff && (
            <p>
              {meListed ? "You're listed here." : "You're not listed here."}{" "}
              <button
                type="button"
                disabled={busy}
                className="font-medium text-primary hover:underline"
                onClick={async () => {
                  setBusy(true);
                  try {
                    await act(serverId, "set_listed", { listed: !meListed });
                    await loadMembers(serverId, { force: true });
                  } catch (err) {
                    setError(err.message);
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {meListed ? "Stop listing me" : "List me"}
              </button>
            </p>
          )}
        </div>
      )}
      <MemberCard serverId={serverId} userId={card} open={Boolean(card)} onOpenChange={(v) => !v && setCard(null)} />
    </aside>
  );
}
