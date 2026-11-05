// Scheduled events and the answers to them. An event's title, description, place and times are
// one encrypted item, and so is each answer (going or maybe): the service stores both without
// reading them. It does know that a server has an event, and which members answered.
import { ApiError, id, randomIdField, type Actions, type Ctx } from "../http.ts";
import { signedByActiveDevice } from "../deviceAuth.ts";
import { P, has } from "../permissions.ts";
import { acceptItem, audit, generationsOf, itemFields, itemOut, permsOf, requireMember, serverParts } from "../servers/model.ts";

export const EVENT_LIMITS = Object.freeze({ perServer: 50, rsvpsListed: 2000 });

async function signedMember(ctx: Ctx, action: string) {
  const { data } = await signedByActiveDevice(ctx, action);
  const serverId = id(data.server_id, "server");
  const member = await requireMember(ctx.own, serverId, ctx.user.id);
  const parts = await serverParts(ctx.sr, serverId);
  return { data, serverId, member, parts, perms: permsOf(parts, member) };
}

const eventOut = (e: any) => ({ event_id: e.event_id, creator_id: e.creator_id, created_date: e.created_date, item: itemOut(e, "event") });
const rsvpOut = (r: any) => ({ event_id: r.event_id, user_id: r.user_id, item: itemOut(r, "rsvp") });

async function eventRow(sr: any, serverId: string, eventId: string) {
  const [row] = await sr.entities.ServerEvent.filter({ server_id: serverId, event_id: eventId }, "created_date", 1);
  if (!row) throw new ApiError(404, "NOT_FOUND", "That event isn't here any more.");
  return row;
}

export const eventActions: Actions = {
  /** A server's events and the answers to them, read with the member's own access. */
  async list({ own, user, body }) {
    const serverId = id(body.server_id, "server");
    await requireMember(own, serverId, user.id);
    const events = await own.entities.ServerEvent.filter({ audience_id: serverId }, "created_date", EVENT_LIMITS.perServer);
    const rsvps = events.length ? await own.entities.EventRsvp.filter({ audience_id: serverId }, "created_date", EVENT_LIMITS.rsvpsListed) : [];
    return { events: events.map(eventOut), rsvps: rsvps.map(rsvpOut) };
  },

  async create_event(ctx) {
    const { sr, user, now } = ctx;
    const { data, serverId, parts, perms } = await signedMember(ctx, "create_event");
    if (!has(perms, P.MANAGE_EVENTS)) throw new ApiError(403, "MISSING_PERMISSION", "You can't schedule events here.");
    const count = (await sr.entities.ServerEvent.filter({ server_id: serverId }, "created_date", EVENT_LIMITS.perServer + 1)).length;
    if (count >= EVENT_LIMITS.perServer) throw new ApiError(409, "LIMIT_REACHED", `A server can have up to ${EVENT_LIMITS.perServer} events. Cancel an old one first.`);
    const accepted = await acceptItem(ctx, { kind: "event", serverId, item: data.item, gens: await generationsOf(sr, serverId) });
    const row = await sr.entities.ServerEvent.create({ server_id: serverId, audience_id: serverId, event_id: accepted.item_id, creator_id: user.id, ...itemFields("event", accepted) });
    await audit(sr, parts.server, user.id, "event_create", "server", serverId, "", now);
    return { event: eventOut(row) };
  },

  async update_event(ctx) {
    const { sr, user, now } = ctx;
    const { data, serverId, parts, perms } = await signedMember(ctx, "update_event");
    if (!has(perms, P.MANAGE_EVENTS)) throw new ApiError(403, "MISSING_PERMISSION", "You can't change events here.");
    const row = await eventRow(sr, serverId, randomIdField(data.event_id, "event"));
    const accepted = await acceptItem(ctx, { kind: "event", serverId, item: data.item, gens: await generationsOf(sr, serverId) });
    const fields = itemFields("event", accepted);
    // The event keeps its id; the new item's own id is only for its signature.
    await sr.entities.ServerEvent.update(row.id, fields);
    await audit(sr, parts.server, user.id, "event_update", "server", serverId, "", now);
    return { event: eventOut({ ...row, ...fields }) };
  },

  async cancel_event(ctx) {
    const { sr, user, now } = ctx;
    const { data, serverId, parts, perms } = await signedMember(ctx, "cancel_event");
    if (!has(perms, P.MANAGE_EVENTS)) throw new ApiError(403, "MISSING_PERMISSION", "You can't cancel events here.");
    const row = await eventRow(sr, serverId, randomIdField(data.event_id, "event"));
    await sr.entities.EventRsvp.deleteMany({ server_id: serverId, event_id: row.event_id });
    await sr.entities.ServerEvent.update(row.id, itemFields("event", { envelope: "", item_id: "", sender_id: "", device_id: "", sent_at: "", signature: "" }));
    await sr.entities.ServerEvent.delete(row.id);
    await audit(sr, parts.server, user.id, "event_cancel", "server", serverId, "", now);
    return { ok: true };
  },

  /** Your answer to an event, or (item: null) take it back. */
  async rsvp(ctx) {
    const { sr, user } = ctx;
    const { data, serverId, perms } = await signedMember(ctx, "rsvp");
    if (!has(perms, P.VIEW_CHANNEL)) throw new ApiError(403, "MISSING_PERMISSION", "You can't answer events here.");
    const row = await eventRow(sr, serverId, randomIdField(data.event_id, "event"));
    const mine = await sr.entities.EventRsvp.filter({ server_id: serverId, event_id: row.event_id, user_id: user.id }, "created_date", 5);
    for (const r of mine) await sr.entities.EventRsvp.delete(r.id);
    if (data.item === null) return { ok: true };
    const accepted = await acceptItem(ctx, { kind: "rsvp", serverId, item: data.item, gens: await generationsOf(sr, serverId) });
    await sr.entities.EventRsvp.create({ server_id: serverId, audience_id: serverId, event_id: row.event_id, user_id: user.id, ...itemFields("rsvp", accepted) });
    return { ok: true };
  },
};
