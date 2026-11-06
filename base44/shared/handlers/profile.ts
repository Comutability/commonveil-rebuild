// Usernames and profiles. There is no member directory: you can look someone up
// only by their exact username, and see profiles of people you share a
// conversation or a server with, as far as each person chose to show them.
import { ApiError, HANDLE_RE, cleanText, idList, type Actions } from "../http.ts";
import { AUTO_DELETE_DAYS, accountKeysOf, blockedEitherWay, contactsOf, dayOf, profileFor, profileOf, publicProfile, serverPeersOf, withRow } from "../store.ts";
import { signedByActiveDevice } from "../deviceAuth.ts";
import { isRetiredUsername, purgeAccount, removePlatformUser } from "../accountDeletion.ts";

/** How long one call may spend deleting before it returns and asks to be called again. */
const DELETION_BUDGET_MS = 45_000;

function autoDeleteOut(p: any) {
  const days = Number(p?.delete_after_days) || 0;
  return { days, last_active_on: days ? p.last_active_at || null : null, warned: Boolean(days && p.inactive_warned_at) };
}

/** Your own privacy choices, as you set them. */
function privacyOut(p: any) {
  return {
    profile_visibility: p?.profile_visibility || "shared",
    dm_policy: p?.dm_policy || "anyone",
    default_listed: Boolean(p?.default_listed),
  };
}

/** Profile colours on offer. Anything else is refused, so a colour can't carry a message. */
export const ACCENT_COLORS = Object.freeze(["", "teal", "sky", "indigo", "violet", "rose", "amber", "lime", "slate"]);

const EMOJI_RE = /^\p{Extended_Pictographic}(\u200d\p{Extended_Pictographic}|\ufe0f|[\u{1f3fb}-\u{1f3ff}])*$/u;

const USERNAME_RE = /^[A-Za-z0-9_]{3,20}$/;
const RESERVED = new Set([
  "admin", "administrator", "root", "system", "support", "help", "staff", "moderator", "mod", "mods",
  "commonveil", "security", "official", "team", "null", "undefined", "anonymous", "everyone", "here",
  "abuse", "postmaster", "webmaster", "info", "noreply", "no_reply",
]);

function normaliseUsername(value: unknown) {
  if (typeof value !== "string" || !USERNAME_RE.test(value.trim())) {
    throw new ApiError(400, "BAD_USERNAME", "Usernames are 3-20 characters: letters, numbers and underscores.");
  }
  const username = value.trim();
  return { username, key: username.toLowerCase() };
}

/** Count rows up to a cap, so a privacy report never turns into a heavy query. */
async function countUpTo(db: any, entity: string, query: any, cap = 1000) {
  const rows = await db.entities[entity].filter(query, "-created_date", cap + 1);
  return { count: Math.min(rows.length, cap), more: rows.length > cap, oldest: rows.length ? rows[Math.min(rows.length, cap) - 1].created_date : null };
}

// A profile picture: a small WebP, PNG or JPEG made on the person's device (at most 160 by 160),
// kept inline with the profile, so showing it never makes anyone's device fetch an image from
// anywhere. "" removes it. A stored field holds at most 20,000 characters, so the picture has to
// stay well under that: one larger fails the whole save.
const AVATAR_MAX_CHARS = 18_000;
const AVATAR_MAGIC: Record<string, (b: Uint8Array) => boolean> = {
  webp: (b) => b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50,
  png: (b) => b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47,
  jpeg: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff,
};

function avatarImage(value: unknown): string {
  if (value === "" || value === null) return "";
  const m = typeof value === "string" && value.length <= AVATAR_MAX_CHARS ? /^data:image\/(webp|png|jpeg);base64,([A-Za-z0-9+/]+={0,2})$/.exec(value) : null;
  if (!m) throw new ApiError(400, "BAD_FIELD", "That picture is too large or isn't an image. Try a smaller one.");
  let bytes: Uint8Array;
  try {
    bytes = Uint8Array.from(atob(m[2].slice(0, 32)), (c) => c.charCodeAt(0));
  } catch {
    throw new ApiError(400, "BAD_FIELD", "That picture couldn't be read.");
  }
  if (!AVATAR_MAGIC[m[1]](bytes)) throw new ApiError(400, "BAD_FIELD", "That picture couldn't be read.");
  return value;
}

export const profileActions: Actions = {
  /**
   * Your privacy report: everything the service holds about you, as it holds it. Nothing here
   * is new data; it's what the other features already need, listed for you.
   */
  async privacy_report({ sr, own, user }) {
    const profile = await profileOf(own, user.id);
    const devices = await own.entities.Device.filter({ user_id: user.id }, "created_date", 50);
    const convs = await own.entities.Conversation.filter({ member_ids: user.id }, "created_date", 500);
    const memberships = await own.entities.ServerMember.filter({ user_id: user.id }, "created_date", 200);
    const [sent, files, scheduled, serverReports, teamReports, blocks] = await Promise.all([
      countUpTo(own, "Message", { sender_id: user.id }),
      countUpTo(sr, "Attachment", { owner_id: user.id }),
      countUpTo(sr, "ScheduledMessage", { sender_id: user.id }, 100),
      countUpTo(sr, "ServerReport", { reporter_id: user.id }, 200),
      countUpTo(sr, "Report", { reporter_id: user.id }, 200),
      countUpTo(sr, "Block", { user_id: user.id }, 500),
    ]);
    const email = String(user.email || "");
    const at = email.indexOf("@");
    return {
      account: {
        created: user.created_date || null,
        email_hint: at > 1 ? `${email[0]}${"•".repeat(Math.min(6, at - 1))}${email.slice(at)}` : "",
        username: profile?.username || "",
        shared_profile: { display_name: Boolean(profile?.display_name), bio: Boolean(profile?.bio), pronouns: Boolean(profile?.pronouns), avatar: Boolean(profile?.avatar_emoji), picture: Boolean(profile?.avatar_image) },
        profile_visibility: profile?.profile_visibility || "shared",
        dm_policy: profile?.dm_policy || "anyone",
        auto_delete_days: Number(profile?.delete_after_days) || 0,
        last_active_day: profile?.last_active_at ? String(profile.last_active_at).slice(0, 10) : null,
      },
      devices: devices.map((d: any) => ({ label: d.label || "", status: d.status, added: d.approved_at || d.created_date, last_seen_day: d.last_seen_at ? String(d.last_seen_at).slice(0, 10) : null })),
      conversations: {
        direct: convs.filter((c: any) => c.kind === "dm").length,
        groups: convs.filter((c: any) => c.kind === "group" && !c.server_id).length,
        tickets: convs.filter((c: any) => c.server_id).length,
        people: new Set(convs.flatMap((c: any) => c.member_ids || []).filter((u: string) => u !== user.id)).size,
        disappearing: convs.filter((c: any) => Number(c.expire_seconds) > 0).length,
        self_destructing: convs.filter((c: any) => c.destroy_at).length,
      },
      servers: { count: memberships.length, listed: memberships.filter((m: any) => m.listed).length },
      stored: { messages_sent: sent, files_uploaded: files, scheduled, reports_to_moderators: serverReports, reports_to_commonveil: teamReports, blocks },
    };
  },

  /** Read with the member's own access (see Ctx): every page load asks. */
  async me({ sr, own, user, now }) {
    const profile = await profileOf(own, user.id);
    const keys = await accountKeysOf(own, user.id);
    // Only accounts set to delete themselves after a stretch without use note when they were
    // last used: the day, at most once a day. Coming back also withdraws any warning sent.
    const today = dayOf(now);
    if (profile && Number(profile.delete_after_days) > 0 && (profile.last_active_at !== today || profile.inactive_warned_at)) {
      await sr.entities.Profile.update(profile.id, { last_active_at: today, inactive_warned_at: "" });
      Object.assign(profile, { last_active_at: today, inactive_warned_at: "" });
    }
    return {
      user: { id: user.id, role: user.role === "admin" ? "admin" : "user" },
      profile: profile ? publicProfile(profile) : null,
      privacy: profile ? privacyOut(profile) : null,
      encryption_ready: keys.length > 0,
      auto_delete: profile ? autoDeleteOut(profile) : null,
    };
  },

  /**
   * Opt in to (or out of) deleting the account after a stretch without use. A week before,
   * the account's sign-in address is emailed; signing in in the meantime keeps the account.
   * Turning it off clears the last-used day. Needs a device signature.
   */
  async set_auto_delete(ctx) {
    const { sr, own, user, now } = ctx;
    if (user.role === "admin") {
      throw new ApiError(403, "STAFF_ACCOUNT", "Staff accounts can't be set to delete themselves.");
    }
    const { data } = await signedByActiveDevice(ctx, "set_auto_delete");
    if (!AUTO_DELETE_DAYS.includes(data.days)) throw new ApiError(400, "BAD_FIELD", "Choose one of the offered periods.");
    const profile = await profileOf(own, user.id);
    if (!profile) throw new ApiError(409, "PROFILE_REQUIRED", "Choose a username first.");
    const fields = data.days
      ? { delete_after_days: data.days, last_active_at: dayOf(now), inactive_warned_at: "" }
      : { delete_after_days: 0, last_active_at: "", inactive_warned_at: "" };
    const updated = await sr.entities.Profile.update(profile.id, fields);
    return { auto_delete: autoDeleteOut({ ...profile, ...fields, ...updated }) };
  },

  async claim_username({ sr, user, body }) {
    const { username, key } = normaliseUsername(body.username);
    // Names of deleted accounts stay retired, so no one can take over someone's old name.
    if (RESERVED.has(key) || (await isRetiredUsername(sr, key))) throw new ApiError(409, "USERNAME_TAKEN", "That username isn't available.");
    const display_name = cleanText(body.display_name, 50) || username;
    if (await profileOf(sr, user.id)) throw new ApiError(409, "ALREADY_CLAIMED", "You already have a username.");
    const taken = await sr.entities.Profile.filter({ username_key: key }, "created_date", 1);
    if (taken.length) throw new ApiError(409, "USERNAME_TAKEN", "That username is taken.");

    const created = await sr.entities.Profile.create({ user_id: user.id, username, username_key: key, display_name, bio: "" });

    // Two people (or two tabs) can race for the same name. Oldest claim wins.
    const sameName = withRow(await sr.entities.Profile.filter({ username_key: key }, "created_date", 10), created);
    const mine = withRow(await sr.entities.Profile.filter({ user_id: user.id }, "created_date", 10), created);
    if (sameName[0].id !== created.id || mine[0].id !== created.id) {
      await sr.entities.Profile.delete(created.id);
      if (mine[0] && mine[0].id !== created.id) throw new ApiError(409, "ALREADY_CLAIMED", "You already have a username.");
      throw new ApiError(409, "USERNAME_TAKEN", "That username is taken.");
    }
    return { profile: publicProfile(created) };
  },

  /** Your profile and privacy choices. Only what's offered is accepted. */
  async update({ sr, user, body }) {
    const profile = await profileOf(sr, user.id);
    if (!profile) throw new ApiError(409, "PROFILE_REQUIRED", "Choose a username first.");
    const changes: Record<string, unknown> = {};
    if (body.display_name !== undefined) changes.display_name = cleanText(body.display_name, 50) || profile.username;
    if (body.bio !== undefined) changes.bio = cleanText(body.bio, 280);
    if (body.pronouns !== undefined) changes.pronouns = cleanText(body.pronouns, 30);
    if (body.accent_color !== undefined) {
      if (!ACCENT_COLORS.includes(body.accent_color)) throw new ApiError(400, "BAD_FIELD", "Choose one of the offered colours.");
      changes.accent_color = body.accent_color;
    }
    if (body.avatar_emoji !== undefined) {
      const emoji = typeof body.avatar_emoji === "string" ? body.avatar_emoji.trim() : "";
      if (emoji && (emoji.length > 16 || !EMOJI_RE.test(emoji))) throw new ApiError(400, "BAD_FIELD", "Choose a single emoji.");
      changes.avatar_emoji = emoji;
    }
    if (body.avatar_image !== undefined) changes.avatar_image = avatarImage(body.avatar_image);
    if (body.profile_visibility !== undefined) {
      if (!["shared", "conversations", "nobody"].includes(body.profile_visibility)) throw new ApiError(400, "BAD_FIELD", "Invalid choice.");
      changes.profile_visibility = body.profile_visibility;
    }
    if (body.dm_policy !== undefined) {
      if (!["anyone", "servers", "nobody"].includes(body.dm_policy)) throw new ApiError(400, "BAD_FIELD", "Invalid choice.");
      changes.dm_policy = body.dm_policy;
    }
    if (body.default_listed !== undefined) {
      if (typeof body.default_listed !== "boolean") throw new ApiError(400, "BAD_FIELD", "Invalid choice.");
      changes.default_listed = body.default_listed;
    }
    const updated = Object.keys(changes).length ? await sr.entities.Profile.update(profile.id, changes) : profile;
    const merged = { ...profile, ...updated, ...changes };
    return { profile: publicProfile(merged), privacy: privacyOut(merged) };
  },

  /** Exact-match lookup. Blocked pairs can't find each other. */
  async find({ sr, user, body, federation }) {
    const raw = typeof body.username === "string" ? body.username.trim().replace(/^@/, "").toLowerCase() : "";
    let key: string;
    if (federation && HANDLE_RE.test(raw)) {
      // Someone on another site, found through their site (which checks they accept contact).
      if (!(await federation.resolveHandle(raw, user.id))) throw new ApiError(404, "NOT_FOUND", "Nobody can be reached at that address.");
      key = raw;
    } else {
      key = normaliseUsername(body.username).key;
    }
    const rows = await sr.entities.Profile.filter({ username_key: key }, "created_date", 1);
    const target = rows[0];
    if (!target || (target.user_id !== user.id && (await blockedEitherWay(sr, user.id, target.user_id)))) {
      throw new ApiError(404, "NOT_FOUND", "No member has that username.");
    }
    const keys = await accountKeysOf(sr, target.user_id);
    return { profile: publicProfile(target), encryption_ready: keys.length > 0 };
  },

  /**
   * Delete the account and everything in it. While the account has published keys, the
   * request must be signed by one of its devices. Returns done:false if it needs another call.
   */
  async delete_account(ctx) {
    const { sr, user, body } = ctx;
    if (user.role === "admin") {
      throw new ApiError(403, "STAFF_ACCOUNT", "Staff accounts can't be deleted here. The app owner removes staff access in Base44.");
    }
    const hasKeys = (await sr.entities.AccountKey.filter({ user_id: user.id }, "created_date", 1)).length > 0;
    let confirm: unknown;
    if (hasKeys) {
      confirm = (await signedByActiveDevice(ctx, "delete_account")).data.confirm;
    } else if (typeof body.payload === "string") {
      try {
        confirm = JSON.parse(body.payload)?.confirm;
      } catch {
        confirm = undefined;
      }
    } else {
      confirm = body.confirm;
    }
    if (confirm !== "DELETE") throw new ApiError(400, "CONFIRM_REQUIRED", "Type DELETE to confirm.");
    const finished = await purgeAccount(sr, user.id, Date.now() + DELETION_BUDGET_MS);
    if (!finished) return { done: false };
    return { done: true, sign_in_removed: await removePlatformUser(sr, user.id) };
  },

  /**
   * Profiles for people you share a conversation or a server with, as much of each as that
   * person chose to show (see profileFor). Others are left out.
   */
  async get_many({ sr, own, user, body }) {
    const ids = idList(body.user_ids, "user ids", 100);
    const contacts = await contactsOf(own, user.id);
    const peers = await serverPeersOf(sr, own, user.id, ids.filter((i) => !contacts.has(i)));
    const wanted = ids.filter((i) => contacts.has(i) || peers.has(i));
    if (!wanted.length) return { profiles: [] };
    const rows = await sr.entities.Profile.filter({ user_id: { $in: wanted } }, "created_date", 200);
    return { profiles: rows.map((p: any) => (p.user_id === user.id ? publicProfile(p) : profileFor(p, { contact: contacts.has(p.user_id) }))) };
  },
};