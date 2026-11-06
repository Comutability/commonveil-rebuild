import React, { useCallback, useMemo } from "react";
import { useServers } from "@/lib/secure/ServerContext";
import { useSecure } from "@/lib/secure/SecureContext";
import { P, has } from "@/lib/secure/permissions";
import { MESSAGE_KINDS } from "@/lib/secure/ServerContext";
import { ChannelIcon } from "./channelBits";
import Avatar from "@/components/chat/Avatar";
import { customToken } from "@/lib/customEmoji";
import { searchEmoji } from "@/lib/emoji";

const MENTION_RE = /(^|[^\w@])@([A-Za-z0-9_]{3,20})\b/g;

/**
 * Mentions and channel links for one server: what the composer suggests, what a sent message
 * says it mentions, and how a received one is shown. All worked out on this device from people
 * and channels it already knows about.
 */
export function useServerText(serverId, channelId) {
  const { userId } = useSecure();
  const s = useServers();
  const { servers, memberLists, rows, profileOf, memberName, channelName, roleName, can, permsFor } = s;
  const e = servers[serverId];

  /** People this device knows are in the server: the member list, and anyone who's posted here. */
  const people = useMemo(() => {
    const ids = new Set((memberLists[serverId]?.members || []).map((m) => m.user_id));
    for (const m of rows[channelId] || []) ids.add(m.sender_id);
    ids.add(userId);
    const out = [];
    for (const id of ids) {
      const p = profileOf(serverId, id);
      if (p?.username) out.push({ id, username: p.username, name: memberName(serverId, id), profile: p });
    }
    return out;
  }, [memberLists, rows, serverId, channelId, userId, profileOf, memberName]);

  const roles = useMemo(() => (e?.roles || []).filter((r) => !r.is_everyone && r.mentionable && /^[A-Za-z0-9_]{3,20}$/.test(roleName(r))), [e, roleName]);

  const channels = useMemo(() => (e?.channels || []).filter((c) => MESSAGE_KINDS.has(c.kind) && has(permsFor(serverId, c), P.VIEW_CHANNEL)), [e, serverId, permsFor]);

  const channel = e?.channels?.find((c) => c.id === channelId) || null;
  const canEveryone = channel ? can(serverId, P.MENTION_EVERYONE, channel) : false;

  const custom = useMemo(() => s.serverEmoji(serverId), [s.serverEmoji, serverId]); // eslint-disable-line react-hooks/exhaustive-deps
  const suggest = useCallback((kind, query) => {
    const q = query.toLowerCase();
    if (kind === ":") {
      if (q.length < 2) return [];
      const mine = custom.emoji.filter((x) => x.name.includes(q)).map((x) => ({ id: `c:${x.id}`, label: `:${x.name}:`, sub: "This server", insert: customToken(x), icon: <img src={x.img} alt="" className="h-5 w-5" /> }));
      const std = searchEmoji(q).slice(0, 8).map((x) => ({ id: x.e, label: `:${x.name.replace(/ /g, "_")}:`, insert: x.e, icon: <span className="text-lg leading-none" aria-hidden="true">{x.e}</span> }));
      return [...mine, ...std];
    }
    if (kind === "#") {
      return channels
        .filter((c) => channelName(c).toLowerCase().includes(q))
        .map((c) => ({ id: c.id, label: channelName(c), insert: `#${channelName(c)}`, icon: <ChannelIcon kind={c.kind} className="h-4 w-4 text-muted-foreground" /> }));
    }
    const list = people
      .filter((p) => p.username.toLowerCase().startsWith(q) || p.name.toLowerCase().includes(q))
      .map((p) => ({
        id: p.id,
        label: p.name,
        sub: `@${p.username}`,
        insert: `@${p.username}`,
        icon: <Avatar id={p.id} name={p.name} emoji={p.profile.avatar_emoji} image={p.profile.avatar_image} accent={p.profile.accent_color} size="h-6 w-6" />,
      }));
    const extra = [];
    if (canEveryone && "everyone".startsWith(q)) extra.push({ id: "@everyone", label: "@everyone", sub: "Everyone who can see this channel", insert: "@everyone" });
    for (const r of roles) if (roleName(r).toLowerCase().startsWith(q)) extra.push({ id: `role:${r.id}`, label: `@${roleName(r)}`, sub: "Role", insert: `@${roleName(r)}` });
    return [...list, ...extra];
  }, [channels, people, roles, canEveryone, channelName, roleName, custom]);

  /** What a message about to be sent mentions. */
  const mentionsIn = useCallback((text) => {
    const users = new Set();
    const roleIds = new Set();
    let everyone = false;
    for (const m of String(text).matchAll(MENTION_RE)) {
      const word = m[2].toLowerCase();
      if ((word === "everyone" || word === "here") && canEveryone) {
        everyone = true;
        continue;
      }
      const person = people.find((p) => p.username.toLowerCase() === word);
      if (person) users.add(person.id);
      const role = roles.find((r) => roleName(r).toLowerCase() === word);
      if (role) roleIds.add(role.id);
    }
    return { users: [...users], roles: [...roleIds], everyone };
  }, [people, roles, roleName, canEveryone]);

  /** How mentions and #channels in a received message are shown. */
  const ctx = useMemo(() => ({
    resolveUser: (username) => {
      const u = username.toLowerCase();
      const p = people.find((x) => x.username.toLowerCase() === u);
      if (p) return { name: p.name, self: p.id === userId };
      const r = roles.find((x) => roleName(x).toLowerCase() === u);
      return r ? { name: roleName(r), self: (e?.member?.role_ids || []).includes(r.id) } : null;
    },
    resolveChannel: (name) => {
      const c = channels.find((x) => channelName(x) === name);
      return c ? { name: channelName(c), to: `/app/s/${serverId}/${c.id}` } : null;
    },
    resolveEmoji: (id) => custom.byId.get(id) || null,
    customEmoji: custom.emoji,
  }), [people, roles, channels, roleName, channelName, userId, serverId, e, custom]);

  return { suggest, mentionsIn, ctx, people };
}
