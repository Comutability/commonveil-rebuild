// Account keys and devices.
//
// Trust rules the server enforces (it can't read keys, but it can refuse):
// - The first key statement must be self-signed; every later one must be signed
//   by the previous key, except an explicit account reset.
// - A device becomes active only with a certificate signed by the account's
//   current key: from an approving device, or from a device that opened the
//   recovery backup with the phrase. A signed-in session alone is never enough.
// - Sensitive actions carry a proof signed by an active device's own key.
import { ApiError, LIMITS, idList, int, parsePlatformTime, randomIdField, type Actions, type Ctx } from "../http.ts";
import { parseDevice, parseStatement, requireSealed, verifyCert, verifyProof, verifyStatement } from "../verify.ts";
import {
  accountKeysOf,
  contactsOf,
  deviceOf,
  deviceOut,
  devicesOf,
  latestKeyOf,
  peerDeviceOut,
  pendingExpired,
  profileOf,
  requireActiveDevice,
  statementOut,
} from "../store.ts";

function payloadOf(body: any): { json: string; data: any } {
  if (typeof body.payload !== "string" || body.payload.length === 0 || body.payload.length > LIMITS.maxBodyBytes) {
    throw new ApiError(400, "BAD_PAYLOAD", "Missing payload.");
  }
  let data: any;
  try {
    data = JSON.parse(body.payload);
  } catch {
    throw new ApiError(400, "BAD_PAYLOAD", "Invalid payload.");
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) throw new ApiError(400, "BAD_PAYLOAD", "Invalid payload.");
  return { json: body.payload, data };
}

/** The request is signed by one of this account's active devices. */
async function signedByActiveDevice(ctx: Ctx, action: string) {
  const { json, data } = payloadOf(ctx.body);
  if (!ctx.body.proof || typeof ctx.body.proof !== "object") {
    throw new ApiError(401, "PROOF_REQUIRED", "This action must come from one of your devices.");
  }
  const deviceId = randomIdField(ctx.body.proof?.device_id, "device id");
  const device = await requireActiveDevice(ctx.sr, ctx.user.id, deviceId);
  await verifyProof({ userId: ctx.user.id, action, payloadJson: json, proof: ctx.body.proof, signPub: device.sign_pub, now: ctx.now });
  return { device, data };
}

/** The request is signed by the new device it describes (proves it holds that key). */
async function signedByNewDevice(ctx: Ctx, action: string) {
  const { json, data } = payloadOf(ctx.body);
  const device = await parseDevice(data.device);
  const proofDevice = await verifyProof({ userId: ctx.user.id, action, payloadJson: json, proof: ctx.body.proof, signPub: device.sign_pub, now: ctx.now });
  if (proofDevice !== device.device_id) throw new ApiError(403, "PROOF_INVALID", "This device couldn't prove it's yours.");
  return { device, data };
}

async function expireStalePending(sr: any, devices: any[], now: Date) {
  for (const d of devices) {
    if (pendingExpired(d, now)) {
      await sr.entities.Device.update(d.id, { status: "revoked", revoked_reason: "expired", revoked_at: now.toISOString() });
      d.status = "revoked";
      d.revoked_reason = "expired";
    }
  }
}

const liveDevices = (devices: any[], now: Date) =>
  devices.filter((d) => d.status === "active" || (d.status === "pending" && !pendingExpired(d, now)));

function requireKeyringEnvelope(raw: any, version: number, signPub: string, name: string) {
  if (!raw || typeof raw !== "object" || raw.keyring_version !== version || raw.key_sign_pub !== signPub) {
    throw new ApiError(409, "STALE_KEYS", "Your keys changed on another device. Refresh and try again.");
  }
  return requireSealed(raw.sealed, name);
}

/** Oldest row wins when two requests race to create the same thing. */
const byAge = (a: any, b: any) =>
  String(a.created_date).localeCompare(String(b.created_date)) || String(a.id).localeCompare(String(b.id));

async function publishKey(sr: any, userId: string, statement: any, isReset: boolean) {
  const key = await sr.entities.AccountKey.create({ ...statement, is_reset: isReset });
  const sameVersion = (await sr.entities.AccountKey.filter({ user_id: userId, version: statement.version }, "created_date", 10)).sort(byAge);
  if (sameVersion[0]?.id !== key.id) {
    await sr.entities.AccountKey.delete(key.id);
    return null;
  }
  return key;
}

export const keysActions: Actions = {
  async status({ sr, user, now }) {
    const [keys, devices, envelopes] = await Promise.all([
      accountKeysOf(sr, user.id),
      devicesOf(sr, user.id),
      sr.entities.KeyEnvelope.filter({ user_id: user.id }, "-created_date", 300),
    ]);
    const latest = latestKeyOf(keys);
    const recovery = latest
      ? envelopes.find((e: any) => e.kind === "recovery" && e.keyring_version === latest.version && e.key_sign_pub === latest.sign_pub)
      : null;
    const waiting = new Set(
      envelopes
        .filter((e: any) => e.kind === "device" && latest && e.keyring_version === latest.version && e.key_sign_pub === latest.sign_pub)
        .map((e: any) => e.device_id),
    );
    return {
      statements: keys.map(statementOut),
      devices: devices.map((d: any) => ({ ...deviceOut(d, now), keys_waiting: waiting.has(d.device_id) })),
      recovery: recovery ? { keyring_version: recovery.keyring_version, recovery_pub: recovery.recovery_pub } : null,
    };
  },

  /** First device on an account: publish key version 1, the device, and the recovery backup. */
  async init_account(ctx) {
    const { sr, user, now } = ctx;
    const { device, data } = await signedByNewDevice(ctx, "init_account");
    if (!(await profileOf(sr, user.id))) throw new ApiError(409, "PROFILE_REQUIRED", "Choose a username first.");
    if ((await accountKeysOf(sr, user.id)).length) {
      throw new ApiError(409, "ALREADY_INITIALISED", "Encryption is already set up for this account. Link this device instead.");
    }
    const statement = await parseStatement(data.statement, user.id);
    if (statement.version !== 1 || statement.signed_by_version !== 1) throw new ApiError(400, "BAD_STATEMENT", "The first key must be version 1.");
    if (!(await verifyStatement(statement, statement.sign_pub))) throw new ApiError(403, "STATEMENT_INVALID", "The key statement failed its signature check.");
    const cert = await verifyCert(data.cert, user.id, device, 1, statement.sign_pub);
    const recoverySealed = requireKeyringEnvelope(data.recovery, 1, statement.sign_pub, "recovery backup");

    const key = await publishKey(sr, user.id, statement, false);
    if (!key) throw new ApiError(409, "ALREADY_INITIALISED", "Encryption was just set up from another device. Link this device instead.");
    const at = now.toISOString();
    await sr.entities.Device.create({
      user_id: user.id,
      ...device,
      status: "active",
      cert_key_version: 1,
      cert_issued_at: cert.issued_at,
      cert_signature: cert.signature,
      approved_via: "first_device",
      approved_at: at,
      synced_key_version: 1,
      last_seen_at: at,
    });
    await sr.entities.KeyEnvelope.create({
      user_id: user.id,
      kind: "recovery",
      keyring_version: 1,
      recovery_pub: statement.recovery_pub,
      key_sign_pub: statement.sign_pub,
      sealed: recoverySealed,
      created_by_device_id: device.device_id,
    });
    return { ok: true, version: 1 };
  },

  /** A new browser asks to join. It stays pending until approved or recovered. */
  async register_device(ctx) {
    const { sr, user, now } = ctx;
    const { device } = await signedByNewDevice(ctx, "register_device");
    if (!(await accountKeysOf(sr, user.id)).length) throw new ApiError(409, "NOT_INITIALISED", "Encryption isn't set up for this account yet.");
    const devices = await devicesOf(sr, user.id);
    await expireStalePending(sr, devices, now);
    if (devices.some((d: any) => d.device_id === device.device_id)) throw new ApiError(409, "DEVICE_EXISTS", "This device is already registered.");
    const live = liveDevices(devices, now);
    if (live.length >= LIMITS.maxDevices) {
      throw new ApiError(409, "TOO_MANY_DEVICES", `You can have up to ${LIMITS.maxDevices} devices. Remove one first.`);
    }
    if (live.filter((d: any) => d.status === "pending").length >= LIMITS.maxPendingDevices) {
      throw new ApiError(429, "TOO_MANY_PENDING", "Too many devices are waiting for approval. Approve or deny them first.");
    }
    const row = await sr.entities.Device.create({
      user_id: user.id,
      ...device,
      status: "pending",
      pending_expires_at: new Date(now.getTime() + LIMITS.pendingDeviceMinutes * 60_000).toISOString(),
    });
    return { device: deviceOut(row, now) };
  },

  /** An active device approves a pending one: certificate plus the keyring sealed to it. */
  async approve_device(ctx) {
    const { sr, user, now } = ctx;
    const { device: approver, data } = await signedByActiveDevice(ctx, "approve_device");
    const targetId = randomIdField(data.target_device_id, "device id");
    const target = await deviceOf(sr, user.id, targetId);
    if (!target || target.status !== "pending" || target.device_id === approver.device_id) {
      throw new ApiError(409, "NOT_PENDING", "That device isn't waiting for approval.");
    }
    if (pendingExpired(target, now)) throw new ApiError(410, "REQUEST_EXPIRED", "That request expired. Start linking again on the new device.");
    const latest = latestKeyOf(await accountKeysOf(sr, user.id));
    const cert = await verifyCert(data.cert, user.id, target, latest.version, latest.sign_pub);
    const sealed = requireKeyringEnvelope(data.envelope, latest.version, latest.sign_pub, "keys for the new device");
    // Envelope first, then activation: an interrupted approval leaves the device pending, never active without keys.
    await sr.entities.KeyEnvelope.create({
      user_id: user.id,
      kind: "device",
      device_id: target.device_id,
      keyring_version: latest.version,
      key_sign_pub: latest.sign_pub,
      sealed,
      created_by_device_id: approver.device_id,
    });
    const updated = await sr.entities.Device.update(target.id, {
      status: "active",
      cert_key_version: latest.version,
      cert_issued_at: cert.issued_at,
      cert_signature: cert.signature,
      approved_by_device_id: approver.device_id,
      approved_via: "device_approval",
      approved_at: now.toISOString(),
    });
    return { device: deviceOut({ ...target, ...updated }, now) };
  },

  async deny_device(ctx) {
    const { sr, user, now } = ctx;
    const { data } = await signedByActiveDevice(ctx, "deny_device");
    const target = await deviceOf(sr, user.id, randomIdField(data.target_device_id, "device id"));
    if (!target || target.status !== "pending") throw new ApiError(409, "NOT_PENDING", "That device isn't waiting for approval.");
    await sr.entities.Device.update(target.id, { status: "revoked", revoked_reason: "denied", revoked_at: now.toISOString() });
    return { ok: true };
  },

  /** A device checks its own status and collects any keyring sealed to it. */
  async device_sync({ sr, user, body, now }) {
    const deviceId = randomIdField(body.device_id, "device id");
    const device = await deviceOf(sr, user.id, deviceId);
    if (!device) throw new ApiError(404, "DEVICE_UNKNOWN", "This device isn't registered to your account.");
    const latest = latestKeyOf(await accountKeysOf(sr, user.id));
    let envelope = null;
    if (device.status === "active" && latest) {
      const rows = await sr.entities.KeyEnvelope.filter(
        { user_id: user.id, kind: "device", device_id: deviceId, keyring_version: latest.version, key_sign_pub: latest.sign_pub },
        "-created_date",
        1,
      );
      if (rows[0]) envelope = { keyring_version: rows[0].keyring_version, key_sign_pub: rows[0].key_sign_pub, sealed: JSON.parse(rows[0].sealed) };
    }
    if (device.status === "active" && (!device.last_seen_at || now.getTime() - Date.parse(device.last_seen_at) > 10 * 60_000)) {
      await sr.entities.Device.update(device.id, { last_seen_at: now.toISOString() });
    }
    return { device: deviceOut(device, now), latest_version: latest?.version ?? null, envelope };
  },

  /** The device confirms it now holds this keyring version; its copies are deleted. */
  async ack_envelopes(ctx) {
    const { sr, user } = ctx;
    const { device, data } = await signedByActiveDevice(ctx, "ack_envelopes");
    const version = int(data.keyring_version, "keyring version");
    const latest = latestKeyOf(await accountKeysOf(sr, user.id));
    if (!latest || version > latest.version) throw new ApiError(400, "BAD_FIELD", "Unknown keyring version.");
    const rows = await sr.entities.KeyEnvelope.filter({ user_id: user.id, kind: "device", device_id: device.device_id }, "created_date", 100);
    for (const r of rows) if (r.keyring_version <= version) await sr.entities.KeyEnvelope.delete(r.id);
    if (!device.synced_key_version || device.synced_key_version < version) {
      await sr.entities.Device.update(device.id, { synced_key_version: version });
    }
    return { ok: true };
  },

  /** An up-to-date device re-sends the current keyring to one that missed it. */
  async send_keyring(ctx) {
    const { sr, user } = ctx;
    const { device: sender, data } = await signedByActiveDevice(ctx, "send_keyring");
    const target = await deviceOf(sr, user.id, randomIdField(data.target_device_id, "device id"));
    if (!target || target.status !== "active" || target.device_id === sender.device_id) {
      throw new ApiError(409, "NOT_ACTIVE", "That device isn't active.");
    }
    const latest = latestKeyOf(await accountKeysOf(sr, user.id));
    const sealed = requireKeyringEnvelope(data.envelope, latest.version, latest.sign_pub, "device keys");
    const old = await sr.entities.KeyEnvelope.filter({ user_id: user.id, kind: "device", device_id: target.device_id }, "created_date", 100);
    await sr.entities.KeyEnvelope.create({
      user_id: user.id,
      kind: "device",
      device_id: target.device_id,
      keyring_version: latest.version,
      key_sign_pub: latest.sign_pub,
      sealed,
      created_by_device_id: sender.device_id,
    });
    for (const r of old) await sr.entities.KeyEnvelope.delete(r.id);
    return { ok: true };
  },

  /** The encrypted recovery backup. Useless without the 24-word phrase. */
  async get_recovery({ sr, user }) {
    const keys = await accountKeysOf(sr, user.id);
    const latest = latestKeyOf(keys);
    if (!latest) throw new ApiError(409, "NOT_INITIALISED", "Encryption isn't set up for this account yet.");
    const rows = await sr.entities.KeyEnvelope.filter(
      { user_id: user.id, kind: "recovery", keyring_version: latest.version, key_sign_pub: latest.sign_pub },
      "-created_date",
      1,
    );
    if (!rows[0]) throw new ApiError(404, "NO_BACKUP", "No recovery backup was found for your current keys.");
    return {
      statements: keys.map(statementOut),
      recovery: { keyring_version: rows[0].keyring_version, recovery_pub: rows[0].recovery_pub, sealed: JSON.parse(rows[0].sealed) },
    };
  },

  /** A device that opened the recovery backup certifies itself with the account key. */
  async recover_device(ctx) {
    const { sr, user, now } = ctx;
    const { device, data } = await signedByNewDevice(ctx, "recover_device");
    const latest = latestKeyOf(await accountKeysOf(sr, user.id));
    if (!latest) throw new ApiError(409, "NOT_INITIALISED", "Encryption isn't set up for this account yet.");
    const cert = await verifyCert(data.cert, user.id, device, latest.version, latest.sign_pub);
    const devices = await devicesOf(sr, user.id);
    await expireStalePending(sr, devices, now);
    const at = now.toISOString();
    const fields = {
      status: "active",
      cert_key_version: latest.version,
      cert_issued_at: cert.issued_at,
      cert_signature: cert.signature,
      approved_via: "recovery_phrase",
      approved_at: at,
      synced_key_version: latest.version,
      last_seen_at: at,
    };
    const existing = devices.find((d: any) => d.device_id === device.device_id);
    if (existing) {
      // A pending link request from this same browser can be completed by recovery instead.
      if (existing.status !== "pending" || existing.sign_pub !== device.sign_pub || existing.box_pub !== device.box_pub) {
        throw new ApiError(409, "DEVICE_EXISTS", "This device is already registered.");
      }
      const updated = await sr.entities.Device.update(existing.id, fields);
      return { device: deviceOut({ ...existing, ...updated }, now) };
    }
    if (liveDevices(devices, now).length >= LIMITS.maxDevices) {
      throw new ApiError(409, "TOO_MANY_DEVICES", `You can have up to ${LIMITS.maxDevices} devices. Remove one first.`);
    }
    const row = await sr.entities.Device.create({ user_id: user.id, ...device, ...fields });
    return { device: deviceOut(row, now) };
  },

  /** Remove a device. The caller should rotate keys straight after if the device may be in someone else's hands. */
  async revoke_device(ctx) {
    const { sr, user, now } = ctx;
    const { device: actor, data } = await signedByActiveDevice(ctx, "revoke_device");
    const target = await deviceOf(sr, user.id, randomIdField(data.target_device_id, "device id"));
    if (!target) throw new ApiError(404, "DEVICE_UNKNOWN", "That device isn't registered to your account.");
    if (target.status !== "revoked") {
      await sr.entities.Device.update(target.id, { status: "revoked", revoked_reason: "removed", revoked_at: now.toISOString() });
    }
    const envelopes = await sr.entities.KeyEnvelope.filter({ user_id: user.id, kind: "device", device_id: target.device_id }, "created_date", 100);
    for (const e of envelopes) await sr.entities.KeyEnvelope.delete(e.id);
    const remaining = (await devicesOf(sr, user.id)).filter((d: any) => d.status === "active");
    return { remaining: remaining.map((d: any) => deviceOut(d, now)), revoked_self: target.device_id === actor.device_id };
  },

  /**
   * Publish a new key version, signed by the current one. Every remaining active
   * device gets a new certificate and a sealed copy of the new keyring; the
   * recovery backup is replaced. Also used to change the recovery phrase.
   */
  async rotate_keys(ctx) {
    const { sr, user } = ctx;
    const { device: actor, data } = await signedByActiveDevice(ctx, "rotate_keys");
    const latest = latestKeyOf(await accountKeysOf(sr, user.id));
    if (!latest) throw new ApiError(409, "NOT_INITIALISED", "Encryption isn't set up for this account yet.");
    const statement = await parseStatement(data.statement, user.id);
    if (statement.version !== latest.version + 1 || statement.signed_by_version !== latest.version) {
      throw new ApiError(409, "STALE_KEYS", "Your keys changed on another device. Refresh and try again.");
    }
    if (!(await verifyStatement(statement, latest.sign_pub))) throw new ApiError(403, "STATEMENT_INVALID", "The new key wasn't signed by your current key.");

    const active = (await devicesOf(sr, user.id)).filter((d: any) => d.status === "active");
    const certs = Array.isArray(data.certs) ? data.certs : [];
    const envelopes = Array.isArray(data.envelopes) ? data.envelopes : [];
    const changed = () => new ApiError(409, "DEVICES_CHANGED", "Your device list changed. Refresh and try again.");
    if (certs.length !== active.length) throw changed();
    const verifiedCerts = new Map<string, any>();
    for (const d of active) {
      const raw = certs.find((c: any) => c && c.device_id === d.device_id);
      if (!raw) throw changed();
      verifiedCerts.set(d.device_id, await verifyCert(raw, user.id, d, statement.version, statement.sign_pub));
    }
    const others = active.filter((d: any) => d.device_id !== actor.device_id);
    if (envelopes.length !== others.length) throw changed();
    const sealedFor = new Map<string, string>();
    for (const d of others) {
      const e = envelopes.find((x: any) => x && x.device_id === d.device_id);
      if (!e) throw changed();
      sealedFor.set(d.device_id, requireKeyringEnvelope(e, statement.version, statement.sign_pub, "device keys"));
    }
    const recoverySealed = requireKeyringEnvelope(data.recovery, statement.version, statement.sign_pub, "recovery backup");

    // Writes before the commit point are harmless: nothing uses envelopes for an unpublished version.
    const created: any[] = [];
    for (const [deviceId, sealed] of sealedFor) {
      created.push(await sr.entities.KeyEnvelope.create({
        user_id: user.id, kind: "device", device_id: deviceId, keyring_version: statement.version,
        key_sign_pub: statement.sign_pub, sealed, created_by_device_id: actor.device_id,
      }));
    }
    created.push(await sr.entities.KeyEnvelope.create({
      user_id: user.id, kind: "recovery", keyring_version: statement.version, recovery_pub: statement.recovery_pub,
      key_sign_pub: statement.sign_pub, sealed: recoverySealed, created_by_device_id: actor.device_id,
    }));

    const key = await publishKey(sr, user.id, statement, false); // commit point
    if (!key) {
      for (const row of created) await sr.entities.KeyEnvelope.delete(row.id);
      throw new ApiError(409, "STALE_KEYS", "Another device changed your keys at the same moment. Refresh and try again.");
    }
    for (const d of active) {
      const c = verifiedCerts.get(d.device_id);
      const fields: any = { cert_key_version: statement.version, cert_issued_at: c.issued_at, cert_signature: c.signature };
      if (d.device_id === actor.device_id) fields.synced_key_version = statement.version;
      await sr.entities.Device.update(d.id, fields);
    }
    // Clean up: older device copies, and every backup the old phrase could open if the phrase changed.
    const all = await sr.entities.KeyEnvelope.filter({ user_id: user.id }, "created_date", 500);
    for (const e of all) {
      const staleDeviceCopy = e.kind === "device" && e.keyring_version < statement.version;
      const oldPhraseBackup = e.kind === "recovery" && e.recovery_pub !== statement.recovery_pub;
      const olderBackup = e.kind === "recovery" && e.keyring_version < statement.version;
      if (staleDeviceCopy || oldPhraseBackup || olderBackup) await sr.entities.KeyEnvelope.delete(e.id);
    }
    return { ok: true, version: statement.version };
  },

  /**
   * Lost every device and the phrase: start a new, unlinked identity.
   * Old messages become unreadable and contacts see that your keys changed.
   */
  async reset_account(ctx) {
    const { sr, user, now } = ctx;
    const { device, data } = await signedByNewDevice(ctx, "reset_account");
    if (data.confirm !== "RESET") throw new ApiError(400, "CONFIRM_REQUIRED", "Type RESET to confirm.");
    const keys = await accountKeysOf(sr, user.id);
    const latest = latestKeyOf(keys);
    if (!latest) throw new ApiError(409, "NOT_INITIALISED", "Encryption isn't set up yet, so there's nothing to reset.");
    const recentResets = keys.filter((k: any) => k.is_reset && now.getTime() - parsePlatformTime(k.created_date) < 24 * 3600_000).length;
    if (recentResets >= LIMITS.resetsPerDay) throw new ApiError(429, "RATE_LIMITED", "Too many resets today. Please try again tomorrow.");
    const statement = await parseStatement(data.statement, user.id);
    if (statement.version !== latest.version + 1 || statement.signed_by_version !== statement.version) {
      throw new ApiError(409, "STALE_KEYS", "Your keys changed. Refresh and try again.");
    }
    if (!(await verifyStatement(statement, statement.sign_pub))) throw new ApiError(403, "STATEMENT_INVALID", "The key statement failed its signature check.");
    const cert = await verifyCert(data.cert, user.id, device, statement.version, statement.sign_pub);
    const recoverySealed = requireKeyringEnvelope(data.recovery, statement.version, statement.sign_pub, "recovery backup");

    const key = await publishKey(sr, user.id, statement, true);
    if (!key) throw new ApiError(409, "STALE_KEYS", "Your keys changed at the same moment. Refresh and try again.");
    const at = now.toISOString();
    const devices = await devicesOf(sr, user.id);
    for (const d of devices) {
      if (d.status !== "revoked" && d.device_id !== device.device_id) {
        await sr.entities.Device.update(d.id, { status: "revoked", revoked_reason: "account_reset", revoked_at: at });
      }
    }
    for (const e of await sr.entities.KeyEnvelope.filter({ user_id: user.id }, "created_date", 500)) {
      await sr.entities.KeyEnvelope.delete(e.id);
    }
    const fields = {
      status: "active",
      cert_key_version: statement.version,
      cert_issued_at: cert.issued_at,
      cert_signature: cert.signature,
      approved_via: "account_reset",
      approved_at: at,
      synced_key_version: statement.version,
      last_seen_at: at,
    };
    const existing = devices.find((d: any) => d.device_id === device.device_id);
    if (existing) await sr.entities.Device.update(existing.id, { ...fields, sign_pub: device.sign_pub, box_pub: device.box_pub });
    else await sr.entities.Device.create({ user_id: user.id, ...device, ...fields });
    await sr.entities.KeyEnvelope.create({
      user_id: user.id, kind: "recovery", keyring_version: statement.version, recovery_pub: statement.recovery_pub,
      key_sign_pub: statement.sign_pub, sealed: recoverySealed, created_by_device_id: device.device_id,
    });
    return { ok: true, version: statement.version };
  },

  /** Public keys and device certificates for people you share a conversation with. */
  async peer_keys({ sr, user, body }) {
    const ids = idList(body.user_ids, "user ids", 50);
    const allowed = await contactsOf(sr, user.id);
    const wanted = ids.filter((i) => allowed.has(i));
    const out: Record<string, { statements: any[]; devices: any[] }> = {};
    if (!wanted.length) return { keys: out };
    const [keyRows, deviceRows] = await Promise.all([
      sr.entities.AccountKey.filter({ user_id: { $in: wanted } }, "version", 5000),
      sr.entities.Device.filter({ user_id: { $in: wanted }, status: { $in: ["active", "revoked"] } }, "created_date", 5000),
    ]);
    for (const uid of wanted) out[uid] = { statements: [], devices: [] };
    const seen = new Set<string>();
    for (const k of [...keyRows].sort(byAge)) {
      const tag = `${k.user_id}:${k.version}`;
      if (seen.has(tag)) continue; // a lost race leaves at most a moment's duplicate; oldest wins
      seen.add(tag);
      out[k.user_id]?.statements.push(statementOut(k));
    }
    for (const uid of wanted) out[uid].statements.sort((a, b) => a.version - b.version);
    for (const d of deviceRows) if (d.cert_signature) out[d.user_id]?.devices.push(peerDeviceOut(d));
    return { keys: out };
  },
};
