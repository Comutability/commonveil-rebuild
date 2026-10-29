// Usernames and profiles. There is no member directory: you can look someone up
// only by their exact username, and see profiles of people you share a
// conversation with.
import { ApiError, cleanText, idList, type Actions } from "../http.ts";
import { accountKeysOf, blockedEitherWay, contactsOf, profileOf, publicProfile } from "../store.ts";

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

export const profileActions: Actions = {
  async me({ sr, user }) {
    const profile = await profileOf(sr, user.id);
    const keys = await accountKeysOf(sr, user.id);
    return {
      user: { id: user.id, role: user.role === "admin" ? "admin" : "user" },
      profile: profile ? publicProfile(profile) : null,
      encryption_ready: keys.length > 0,
    };
  },

  async claim_username({ sr, user, body }) {
    const { username, key } = normaliseUsername(body.username);
    if (RESERVED.has(key)) throw new ApiError(409, "USERNAME_TAKEN", "That username isn't available.");
    const display_name = cleanText(body.display_name, 50) || username;
    if (await profileOf(sr, user.id)) throw new ApiError(409, "ALREADY_CLAIMED", "You already have a username.");
    const taken = await sr.entities.Profile.filter({ username_key: key }, "created_date", 1);
    if (taken.length) throw new ApiError(409, "USERNAME_TAKEN", "That username is taken.");

    const created = await sr.entities.Profile.create({ user_id: user.id, username, username_key: key, display_name, bio: "" });

    // Two people (or two tabs) can race for the same name. Oldest claim wins.
    const byOrder = (a: any, b: any) => String(a.created_date).localeCompare(String(b.created_date)) || String(a.id).localeCompare(String(b.id));
    const sameName = (await sr.entities.Profile.filter({ username_key: key }, "created_date", 10)).sort(byOrder);
    const mine = (await sr.entities.Profile.filter({ user_id: user.id }, "created_date", 10)).sort(byOrder);
    if (sameName[0]?.id !== created.id || mine[0]?.id !== created.id) {
      await sr.entities.Profile.delete(created.id);
      if (mine[0] && mine[0].id !== created.id) throw new ApiError(409, "ALREADY_CLAIMED", "You already have a username.");
      throw new ApiError(409, "USERNAME_TAKEN", "That username is taken.");
    }
    return { profile: publicProfile(created) };
  },

  async update({ sr, user, body }) {
    const profile = await profileOf(sr, user.id);
    if (!profile) throw new ApiError(409, "PROFILE_REQUIRED", "Choose a username first.");
    const changes: Record<string, string> = {};
    if (body.display_name !== undefined) changes.display_name = cleanText(body.display_name, 50) || profile.username;
    if (body.bio !== undefined) changes.bio = cleanText(body.bio, 280);
    const updated = Object.keys(changes).length ? await sr.entities.Profile.update(profile.id, changes) : profile;
    return { profile: publicProfile({ ...profile, ...updated }) };
  },

  /** Exact-match lookup. Blocked pairs can't find each other. */
  async find({ sr, user, body }) {
    const { key } = normaliseUsername(body.username);
    const rows = await sr.entities.Profile.filter({ username_key: key }, "created_date", 1);
    const target = rows[0];
    if (!target || (target.user_id !== user.id && (await blockedEitherWay(sr, user.id, target.user_id)))) {
      throw new ApiError(404, "NOT_FOUND", "No member has that username.");
    }
    const keys = await accountKeysOf(sr, target.user_id);
    return { profile: publicProfile(target), encryption_ready: keys.length > 0 };
  },

  /** Profiles for people you share a conversation with. Others are left out. */
  async get_many({ sr, user, body }) {
    const ids = idList(body.user_ids, "user ids", 100);
    const allowed = await contactsOf(sr, user.id);
    const wanted = ids.filter((i) => allowed.has(i));
    if (!wanted.length) return { profiles: [] };
    const rows = await sr.entities.Profile.filter({ user_id: { $in: wanted } }, "created_date", 200);
    return { profiles: rows.map(publicProfile) };
  },
};
