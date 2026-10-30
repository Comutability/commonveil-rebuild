// Usernames and profiles. There is no member directory: you can look someone up
// only by their exact username, and see profiles of people you share a
// conversation with.
import { ApiError, cleanText, idList, type Actions } from "../http.ts";
import { AUTO_DELETE_DAYS, accountKeysOf, blockedEitherWay, contactsOf, dayOf, profileOf, publicProfile, withRow } from "../store.ts";
import { signedByActiveDevice } from "../deviceAuth.ts";
import { isRetiredUsername, purgeAccount, removePlatformUser } from "../accountDeletion.ts";

/** How long one call may spend deleting before it returns and asks to be called again. */
const DELETION_BUDGET_MS = 45_000;

function autoDeleteOut(p: any) {
  const days = Number(p?.delete_after_days) || 0;
  return { days, last_active_on: days ? p.last_active_at || null : null, warned: Boolean(days && p.inactive_warned_at) };
}

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

  /** Profiles for people you share a conversation with. Others are left out. */
  async get_many({ sr, own, user, body }) {
    const ids = idList(body.user_ids, "user ids", 100);
    const allowed = await contactsOf(own, user.id);
    const wanted = ids.filter((i) => allowed.has(i));
    if (!wanted.length) return { profiles: [] };
    const rows = await sr.entities.Profile.filter({ user_id: { $in: wanted } }, "created_date", 200);
    return { profiles: rows.map(publicProfile) };
  },
};
