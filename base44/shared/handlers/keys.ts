// Account keys and devices.
//
// Trust rules the server enforces (it can't read keys, but it can refuse):
// - The first key statement must be self-signed; every later one must be signed
//   by the previous key, except an account reset. Statements made with the recovery
//   phrase to hand (setup, a new phrase, a reset) must carry its anchor.
// - A device becomes active only with a certificate signed by the account's
//   current key: from an approving device, or from a device that opened the
//   recovery backup with the phrase. A signed-in session alone is never enough.
// - A reset (every device and the phrase lost) waits LIMITS.resetDelayHours, and any
//   of the account's devices, or the phrase, can cancel it. A password alone can ask
//   for one, but can't take the account over before its owner has had time to stop it.
// - Sensitive actions carry a proof signed by an active device's own key.
import { ApiError, LIMITS, id, idList, int, parsePlatformTime, randomIdField, type Actions, type Ctx } from "../http.ts";
import {
  parseDevice,
  parseStatement,
  requireKemKey,
  requireRecoveryAnchor,
  requireSealed,
  verifyCert,
  verifyDeviceKemSig,
  verifyProof,
  verifyStatement,
} from "../verify.ts";
import { needRotation } from "../servers/model.ts";
import { bumpEpoch } from "../identity/sessions.ts";
import { payloadOf, signedByActiveDevice } from "../deviceAuth.ts";
import { emailNotice, newDeviceEmail, phraseUsedEmail, resetDoneEmail, resetRequestedEmail } from "../notify.ts";
import {
  accountKeysOf,
  contactsOf,
  deviceOf,
  deviceOut,
  devicesOf,
  enforceRate,
  latestKeyOf,
  ownStatementOut,
  peerDeviceOut,
  pendingExpired,
  profileOf,
  rateLimited,
  serverPeersOf,
  statementOut,
  uniqueVersions,
  withinRate,
  withRow,
} from "../store.ts";

const DAY = 24 * 3600_000;

/** The most rows Base44 returns from one query. */
const QUERY_CAP = 5000;

/**
 * Rows for several people in one query. If it comes back full, someone's history may have been
 * cut short, so ask person by person instead (at most perPerson rows each).
 */
async function forEveryone(sr: any, entity: string, query: any, sort: string, perPerson: number, userIds: string[]) {
  const rows = await sr.entities[entity].filter({ ...query, user_id: { $in: userIds } }, sort, QUERY_CAP);
  if (rows.length < QUERY_CAP) return rows;
  const parts = await Promise.all(userIds.map((uid) => sr.entities[entity].filter({ ...query, user_id: uid }, sort, perPerson)));
  return parts.flat();
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

async function publishKey(sr: any, userId: string, statement: any, isReset: boolean) {
  const key = await sr.entities.AccountKey.create({ ...statement, is_reset: isReset });
  const sameVersion = withRow(await sr.entities.AccountKey.filter({ user_id: userId, version: statement.version }, "created_date", 10), key);
  if (sameVersion[0].id !== key.id) {
    await sr.entities.AccountKey.delete(key.id);
    return null;
  }
  return key;
}

// ---------- resets ----------

const resetOut = (r: any) => ({
  id: r.id,
  device_id: r.device_id,
  device_label: r.device_label || "A browser",
  requested_at: r.created_date,
  effective_at: r.effective_at,
  status: r.status,
  ended_by: r.ended_by || "",
});

async function waitingResets(sr: any, userId: string) {
  return sr.entities.ResetRequest.filter({ user_id: userId, status: "waiting" }, "created_date", 20);
}

async function endResets(sr: any, rows: any[], status: string, by: string, now: Date) {
  for (const r of rows) await sr.entities.ResetRequest.update(r.id, { status, ended_by: by, ended_at: now.toISOString() });
}

/** The request is signed by the browser a reset request came from. */
async function signedByResetDevice(ctx: Ctx, action: string) {
  const { json, data } = payloadOf(ctx.body);
  const request = await ctx.sr.entities.ResetRequest.get(id(data.request_id, "request")).catch(() => null);
  if (!request || request.user_id !== ctx.user.id) throw new ApiError(404, "NOT_FOUND", "That reset request wasn't found.");
  const proofDevice = await verifyProof({ userId: ctx.user.id, action, payloadJson: json, proof: ctx.body.proof, signPub: request.device_sign_pub, now: ctx.now });
  if (proofDevice !== request.device_id) throw new ApiError(403, "PROOF_INVALID", "This browser couldn't prove it made the request.");
  return request;
}

/**
 * Security emails (see notify.ts) are best effort and never stop the change they describe:
 * the account's own devices show the same thing in the app.
 */
async function tell(sr: any, user: any, email: { subject: string; lines: string[] }): Promise<boolean> {
  return emailNotice(sr, user.email, email.subject, email.lines);
}

export const keysActions: Actions = {
  /** The account's own keys, devices and resets, read with the member's own access (see Ctx). */
  async status({ sr, own, user, now }) {
    const [keyRows, devices, envelopes, resets] = await Promise.all([
      accountKeysOf(own, user.id),
      devicesOf(own, user.id),
      own.entities.KeyEnvelope.filter({ user_id: user.id }, "-created_date", 300),
      own.entities.ResetRequest.filter({ user_id: user.id }, "-created_date", 5),
    ]);
    await expireStalePending(sr, devices, now);
    const keys = uniqueVersions(keyRows);
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
      statements: keys.map(ownStatementOut),
      devices: devices.map((d: any) => ({ ...deviceOut(d, now), keys_waiting: waiting.has(d.device_id) })),
      recovery: recovery ? { keyring_version: recovery.keyring_version, recovery_pub: recovery.recovery_pub } : null,
      resets: resets.map(resetOut),
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
    requireRecoveryAnchor(statement);
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
      cert_has_kem: cert.has_kem,
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
    if (await deviceOf(sr, user.id, device.device_id)) throw new ApiError(409, "DEVICE_EXISTS", "This device is already registered.");
    const live = liveDevices(devices, now);
    if (live.length >= LIMITS.maxDevices) {
      throw new ApiError(409, "TOO_MANY_DEVICES", `You can have up to ${LIMITS.maxDevices} devices. Remove one first.`);
    }
    if (live.filter((d: any) => d.status === "pending").length >= LIMITS.maxPendingDevices) {
      throw new ApiError(429, "TOO_MANY_PENDING", "Too many devices are waiting for approval. Approve or deny them first.");
    }
    await enforceRate(sr, "Device", { user_id: user.id }, DAY, LIMITS.registrationsPerDay, now, "adding devices");
    const row = await sr.entities.Device.create({
      user_id: user.id,
      ...device,
      status: "pending",
      pending_expires_at: new Date(now.getTime() + LIMITS.pendingDeviceMinutes * 60_000).toISOString(),
    });
    if (!(await withinRate(sr, "Device", { user_id: user.id }, DAY, LIMITS.registrationsPerDay, now, row))) {
      await sr.entities.Device.delete(row.id);
      throw rateLimited("adding devices");
    }
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
      cert_has_kem: cert.has_kem,
      approved_by_device_id: approver.device_id,
      approved_via: "device_approval",
      approved_at: now.toISOString(),
    });
    const emailed = await tell(sr, user, newDeviceEmail(now));
    return { device: deviceOut({ ...target, ...updated }, now), emailed };
  },

  async deny_device(ctx) {
    const { sr, user, now } = ctx;
    const { data } = await signedByActiveDevice(ctx, "deny_device");
    const target = await deviceOf(sr, user.id, randomIdField(data.target_device_id, "device id"));
    if (!target || target.status !== "pending") throw new ApiError(409, "NOT_PENDING", "That device isn't waiting for approval.");
    await sr.entities.Device.update(target.id, { status: "revoked", revoked_reason: "denied", revoked_at: now.toISOString() });
    return { ok: true };
  },

  /** A device checks its own status and collects any keyring sealed to it. Reads with the member's own access. */
  async device_sync({ sr, own, user, body, now }) {
    const deviceId = randomIdField(body.device_id, "device id");
    const device = await deviceOf(own, user.id, deviceId);
    if (!device) throw new ApiError(404, "DEVICE_UNKNOWN", "This device isn't registered to your account.");
    const latest = latestKeyOf(await accountKeysOf(own, user.id));
    let envelope = null;
    if (device.status === "active" && latest) {
      const rows = await own.entities.KeyEnvelope.filter(
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

  /** The encrypted recovery backup. Useless without the 24-word phrase. Reads with the member's own access. */
  async get_recovery({ own, user }) {
    const keys = uniqueVersions(await accountKeysOf(own, user.id));
    const latest = latestKeyOf(keys);
    if (!latest) throw new ApiError(409, "NOT_INITIALISED", "Encryption isn't set up for this account yet.");
    const rows = await own.entities.KeyEnvelope.filter(
      { user_id: user.id, kind: "recovery", keyring_version: latest.version, key_sign_pub: latest.sign_pub },
      "-created_date",
      1,
    );
    if (!rows[0]) throw new ApiError(404, "NO_BACKUP", "No recovery backup was found for your current keys.");
    return {
      statements: keys.map(ownStatementOut),
      recovery: { keyring_version: rows[0].keyring_version, recovery_pub: rows[0].recovery_pub, sealed: JSON.parse(rows[0].sealed) },
    };
  },

  /** A device that opened the recovery backup certifies itself with the account key. It also stops any waiting reset. */
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
      cert_has_kem: cert.has_kem,
      approved_via: "recovery_phrase",
      approved_at: at,
      synced_key_version: latest.version,
      last_seen_at: at,
    };
    const existing = await deviceOf(sr, user.id, device.device_id);
    let row;
    if (existing) {
      // A pending link request from this same browser can be completed by recovery instead.
      const sameKeys = existing.sign_pub === device.sign_pub && existing.box_pub === device.box_pub && (existing.kem_pub || "") === (device.kem_pub || "");
      if (existing.status !== "pending" || !sameKeys) {
        throw new ApiError(409, "DEVICE_EXISTS", "This device is already registered.");
      }
      row = { ...existing, ...(await sr.entities.Device.update(existing.id, fields)) };
    } else {
      if (liveDevices(devices, now).length >= LIMITS.maxDevices) {
        throw new ApiError(409, "TOO_MANY_DEVICES", `You can have up to ${LIMITS.maxDevices} devices. Remove one first.`);
      }
      row = await sr.entities.Device.create({ user_id: user.id, ...device, ...fields });
    }
    // Whoever holds the phrase is the account's owner: a reset someone asked for stops here.
    await endResets(sr, await waitingResets(sr, user.id), "cancelled", "recovery", now);
    const emailed = await tell(sr, user, phraseUsedEmail(now));
    return { device: deviceOut(row, now), emailed };
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
    const revokedSelf = target.device_id === actor.device_id;
    if (!revokedSelf) {
      // A device taken off from elsewhere may be in someone else's hands. Every server key this
      // account holds is one it may have copied: each is renewed, and nothing new is sealed with
      // the old ones meanwhile (CV-04). Direct messages need nothing: each is sealed to the
      // account's current devices only.
      const held = await sr.entities.KeyGrant.filter({ user_id: user.id }, "created_date", 5000);
      const byServer = new Map<string, Set<string>>();
      for (const g of held) {
        if (!byServer.has(g.server_id)) byServer.set(g.server_id, new Set());
        byServer.get(g.server_id)!.add(g.chain_id);
      }
      for (const [serverId, chains] of byServer) await needRotation(sr, serverId, [...chains], "device");
      // And its sign-in session can't change how the account is protected any more.
      await bumpEpoch(sr, user.id);
    }
    return { remaining: remaining.map((d: any) => deviceOut(d, now)), revoked_self: revokedSelf };
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
    if (latest.version >= LIMITS.maxKeyVersions) throw new ApiError(409, "TOO_MANY_VERSIONS", "This account's keys have changed too many times. Contact support.");
    const statement = await parseStatement(data.statement, user.id);
    if (statement.version !== latest.version + 1 || statement.signed_by_version !== latest.version) {
      throw new ApiError(409, "STALE_KEYS", "Your keys changed on another device. Refresh and try again.");
    }
    if (!(await verifyStatement(statement, latest.sign_pub))) throw new ApiError(403, "STATEMENT_INVALID", "The new key wasn't signed by your current key.");
    // A new phrase is anchored with the phrase itself; an ordinary rotation carries no anchor, and
    // keeps the phrase's keys as they were (a post-quantum recovery key comes only with a new phrase).
    if (statement.recovery_pub !== latest.recovery_pub) requireRecoveryAnchor(statement);
    else {
      statement.recovery_mac = "";
      if (statement.kem_pub && statement.recovery_kem_pub !== (latest.recovery_kem_pub || "")) {
        throw new ApiError(400, "BAD_STATEMENT", "A recovery key can only change with a new recovery phrase.");
      }
    }
    if (latest.kem_pub && !statement.kem_pub) throw new ApiError(400, "BAD_STATEMENT", "New keys must include a post-quantum key.");

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
      const fields: any = { cert_key_version: statement.version, cert_issued_at: c.issued_at, cert_signature: c.signature, cert_has_kem: c.has_kem };
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
   * Lost every device and the phrase: ask to start a new, unlinked identity. Nothing
   * changes yet. The request waits LIMITS.resetDelayHours; the account's own devices
   * show it and can cancel it, so can the phrase, and the account's email is told.
   */
  async request_reset(ctx) {
    const { sr, user, now } = ctx;
    const { device, data } = await signedByNewDevice(ctx, "request_reset");
    if (data.confirm !== "RESET") throw new ApiError(400, "CONFIRM_REQUIRED", "Type RESET to confirm.");
    const latest = latestKeyOf(await accountKeysOf(sr, user.id));
    if (!latest) throw new ApiError(409, "NOT_INITIALISED", "Encryption isn't set up yet, so there's nothing to reset.");
    const statement = await parseStatement(data.statement, user.id);
    if (statement.version !== latest.version + 1 || statement.signed_by_version !== statement.version) {
      throw new ApiError(409, "STALE_KEYS", "Your keys changed. Refresh and try again.");
    }
    if (!(await verifyStatement(statement, statement.sign_pub))) throw new ApiError(403, "STATEMENT_INVALID", "The key statement failed its signature check.");
    requireRecoveryAnchor(statement);
    const cert = await verifyCert(data.cert, user.id, device, statement.version, statement.sign_pub);
    const recoverySealed = requireKeyringEnvelope(data.recovery, statement.version, statement.sign_pub, "recovery backup");
    const existing = await deviceOf(sr, user.id, device.device_id);
    if (existing && existing.status === "active") throw new ApiError(409, "DEVICE_EXISTS", "This browser is already set up, so there's nothing to reset.");

    const waiting = await waitingResets(sr, user.id);
    if (waiting.some((r: any) => r.device_id !== device.device_id)) {
      throw new ApiError(409, "RESET_PENDING", "A reset was already requested from another browser. It can be cancelled from one of your devices.");
    }
    await enforceRate(sr, "ResetRequest", { user_id: user.id }, DAY, LIMITS.resetsPerDay, now, "requesting resets");
    await endResets(sr, waiting, "withdrawn", "requester", now);
    const effective = new Date(now.getTime() + LIMITS.resetDelayHours * 3600_000);
    const row = await sr.entities.ResetRequest.create({
      user_id: user.id,
      device_id: device.device_id,
      device_label: device.label,
      device_sign_pub: device.sign_pub,
      device_box_pub: device.box_pub,
      device_kem_pub: device.kem_pub || "",
      statement: JSON.stringify(statement),
      cert: JSON.stringify(cert),
      recovery_sealed: recoverySealed,
      recovery_pub: statement.recovery_pub,
      key_sign_pub: statement.sign_pub,
      effective_at: effective.toISOString(),
      status: "waiting",
      ended_by: "",
      ended_at: "",
    });
    if (!(await withinRate(sr, "ResetRequest", { user_id: user.id }, DAY, LIMITS.resetsPerDay, now, row))) {
      await sr.entities.ResetRequest.delete(row.id);
      throw rateLimited("requesting resets");
    }
    const emailed = await tell(sr, user, resetRequestedEmail(effective));
    return { request: resetOut(row), emailed };
  },

  /** From the browser that asked: complete the reset once the waiting period is over. */
  async finish_reset(ctx) {
    const { sr, user, now } = ctx;
    const request = await signedByResetDevice(ctx, "finish_reset");
    if (request.status !== "waiting") {
      throw new ApiError(409, "RESET_ENDED", request.status === "done" ? "This reset is already complete." : "This reset was cancelled, so nothing changed.");
    }
    if (now.getTime() < Date.parse(request.effective_at)) {
      throw new ApiError(409, "RESET_WAITING", "The waiting period isn't over yet.");
    }
    const statement = JSON.parse(request.statement);
    const cert = JSON.parse(request.cert);
    const latest = latestKeyOf(await accountKeysOf(sr, user.id));
    if (!latest || statement.version !== latest.version + 1 || !(await verifyStatement(statement, statement.sign_pub))) {
      await endResets(sr, [request], "stale", "keys_changed", now);
      throw new ApiError(409, "RESET_STALE", "Your account's keys changed while the reset was waiting, so it was cancelled.");
    }
    const keys = await accountKeysOf(sr, user.id);
    const recentResets = keys.filter((k: any) => k.is_reset && now.getTime() - parsePlatformTime(k.created_date) < DAY).length;
    if (recentResets >= LIMITS.resetsPerDay) throw new ApiError(429, "RATE_LIMITED", "Too many resets today. Please try again tomorrow.");

    const key = await publishKey(sr, user.id, statement, true);
    if (!key) throw new ApiError(409, "STALE_KEYS", "Your keys changed at the same moment. Refresh and try again.");
    const at = now.toISOString();
    for (const d of await devicesOf(sr, user.id)) {
      if (d.status !== "revoked" && d.device_id !== request.device_id) {
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
      cert_has_kem: Boolean(cert.kem_pub),
      approved_via: "account_reset",
      approved_at: at,
      synced_key_version: statement.version,
      last_seen_at: at,
      pending_expires_at: "",
    };
    const keysOfRequest = { sign_pub: request.device_sign_pub, box_pub: request.device_box_pub, kem_pub: request.device_kem_pub || "", kem_sig: "" };
    const existing = await deviceOf(sr, user.id, request.device_id);
    if (existing) {
      await sr.entities.Device.update(existing.id, { ...fields, ...keysOfRequest });
    } else {
      await sr.entities.Device.create({
        user_id: user.id,
        device_id: request.device_id,
        label: request.device_label || "Device",
        ...keysOfRequest,
        ...fields,
      });
    }
    await sr.entities.KeyEnvelope.create({
      user_id: user.id, kind: "recovery", keyring_version: statement.version, recovery_pub: request.recovery_pub,
      key_sign_pub: request.key_sign_pub, sealed: request.recovery_sealed, created_by_device_id: request.device_id,
    });
    await endResets(sr, [request], "done", "requester", now);
    const emailed = await tell(sr, user, resetDoneEmail(now));
    return { ok: true, version: statement.version, emailed };
  },

  /** From the browser that asked: take the request back. */
  async withdraw_reset(ctx) {
    const { sr, now } = ctx;
    const request = await signedByResetDevice(ctx, "withdraw_reset");
    if (request.status === "waiting") await endResets(sr, [request], "withdrawn", "requester", now);
    return { ok: true };
  },

  /**
   * A device set up before post-quantum keys publishes one, signed with its own key. It's used
   * for keyrings sent to the device once the next key rotation certifies it. Set once.
   */
  async set_device_kem(ctx) {
    const { sr, user, now } = ctx;
    const { device, data } = await signedByActiveDevice(ctx, "set_device_kem");
    const kemPub = await requireKemKey(data.kem_pub, "post-quantum key");
    if (device.kem_pub) {
      if (device.kem_pub === kemPub) return { device: deviceOut(device, now) };
      throw new ApiError(409, "ALREADY_SET", "This device already has a post-quantum key.");
    }
    if (!(await verifyDeviceKemSig(user.id, device, kemPub, data.kem_sig))) {
      throw new ApiError(403, "SIGNATURE_INVALID", "The post-quantum key's signature didn't verify.");
    }
    const updated = await sr.entities.Device.update(device.id, { kem_pub: kemPub, kem_sig: data.kem_sig, cert_has_kem: false });
    return { device: deviceOut({ ...device, ...updated }, now) };
  },

  /** From any active device: stop every waiting reset. */
  async cancel_reset(ctx) {
    const { sr, user, now } = ctx;
    await signedByActiveDevice(ctx, "cancel_reset");
    const waiting = await waitingResets(sr, user.id);
    await endResets(sr, waiting, "cancelled", "device", now);
    return { ok: true, cancelled: waiting.length };
  },

  /**
   * Public keys and device certificates for people you share a conversation or a server with.
   * A few queries however many people (they come out of the app's shared allowance, see Ctx).
   */
  async peer_keys({ sr, own, user, body }) {
    const ids = idList(body.user_ids, "user ids", 50);
    const allowed = await contactsOf(own, user.id);
    for (const p of await serverPeersOf(sr, own, user.id, ids.filter((i) => !allowed.has(i)))) allowed.add(p);
    const wanted = ids.filter((i) => allowed.has(i));
    const out: Record<string, { statements: any[]; devices: any[] }> = {};
    if (!wanted.length) return { keys: out };
    const [keyRows, active, removed] = await Promise.all([
      forEveryone(sr, "AccountKey", {}, "version", 300, wanted),
      forEveryone(sr, "Device", { status: "active" }, "created_date", 50, wanted),
      // Devices removed after holding keys: needed to check what they sent before.
      forEveryone(sr, "Device", { status: "revoked", revoked_reason: { $in: ["removed", "account_reset"] } }, "-created_date", 100, wanted),
    ]);
    for (const uid of wanted) {
      out[uid] = {
        statements: uniqueVersions(keyRows.filter((k: any) => k.user_id === uid)).map(statementOut),
        devices: [...active, ...removed].filter((d: any) => d.user_id === uid && d.cert_signature).map(peerDeviceOut),
      };
    }
    return { keys: out };
  },
};
