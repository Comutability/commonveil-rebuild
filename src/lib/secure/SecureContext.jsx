// Holds this browser's encryption state for the signed-in account and runs the
// setup, linking, recovery, rotation and peer-verification flows.
//
// Nothing the server says about this account's own keys is used until it's been checked
// against something only the account can produce (see protocol.js): the keyring this
// browser holds, the history it showed in its link code, or the recovery phrase. And the
// server's word alone never deletes keys from this browser: the person decides that.
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { useAuth } from "@/lib/AuthContext";
import { callFn } from "@/lib/api";
import * as P from "./protocol.js";
import * as S from "./store.js";
import { createDeviceKeys, defaultDeviceLabel } from "../crypto/device.js";
import { anchorChain, assertKeyringMatchesChain, compareWithPin, headDigest, linkCode, pinFromChain, verifyAccountChain } from "../crypto/identity.js";
import { latestKey, parseKeyring, serializeKeyring } from "../crypto/keyring.js";
import { clearEnvelopeKeyCache } from "../crypto/envelope.js";

const SecureContext = createContext(null);

export function useSecure() {
  const ctx = useContext(SecureContext);
  if (!ctx) throw new Error("useSecure must be used inside SecureProvider");
  return ctx;
}

const PEER_TTL_MS = 60_000;

const RESET_ENDED = {
  device: "Your reset was cancelled from one of your devices, so nothing changed.",
  recovery: "Your reset was cancelled because your recovery phrase was used, so nothing changed.",
  keys_changed: "Your reset was cancelled because your keys changed in the meantime.",
  requester: "Your reset request was withdrawn.",
};

export function SecureProvider({ children }) {
  const { user: authUser, logout } = useAuth();
  const userId = authUser?.id;

  const [phase, setPhase] = useState("loading");
  const [error, setError] = useState(null);
  const [me, setMe] = useState(null);
  const [status, setStatus] = useState(null);
  const [chain, setChain] = useState(null);
  const [peers, setPeers] = useState({});
  const [notice, setNotice] = useState(null);
  const [linkPin, setLinkPinState] = useState(null);
  const [pendingReset, setPendingReset] = useState(null);
  const [removal, setRemoval] = useState(null);

  const deviceRef = useRef(null);
  const keyringRef = useRef(null);
  const pinsRef = useRef({});
  // Latest values for async flows: a callback created before keys loaded must still see them.
  const peersRef = useRef({});
  const chainRef = useRef(null);
  const statusRef = useRef(null);
  const linkPinRef = useRef(null);
  const pendingRef = useRef(null);
  const peerFetchedAt = useRef({});
  const repairAt = useRef(0);
  const pinsLock = useRef(Promise.resolve());

  const [device, setDeviceState] = useState(null);
  const [keyring, setKeyringState] = useState(null);

  const setDevice = useCallback(async (d, persist = true) => {
    deviceRef.current = d;
    setDeviceState(d);
    if (persist && userId && d) await S.saveDevice(userId, d);
  }, [userId]);

  const setKeyring = useCallback(async (k, persist = true) => {
    keyringRef.current = k;
    setKeyringState(k);
    clearEnvelopeKeyCache();
    if (persist && userId && k) await S.saveKeyring(userId, k);
  }, [userId]);

  const setLinkPin = useCallback(async (pin) => {
    linkPinRef.current = pin;
    setLinkPinState(pin);
    if (!userId) return;
    if (pin) await S.saveLinkPin(userId, pin);
    else await S.clearLinkPin(userId);
  }, [userId]);

  const forgetLocal = useCallback(async () => {
    if (userId) await S.wipeLocal(userId);
    deviceRef.current = null;
    keyringRef.current = null;
    linkPinRef.current = null;
    chainRef.current = null;
    setDeviceState(null);
    setKeyringState(null);
    setLinkPinState(null);
    setPendingReset(null);
    setChain(null);
    clearEnvelopeKeyCache();
  }, [userId]);

  // ---------- sync ----------

  /** Collect keys sent to this browser, accepting them only if they're really the account's. */
  const syncKeyring = useCallback(async (statusData) => {
    const d = deviceRef.current;
    const sync = await callFn("keys", { action: "device_sync", device_id: d.device_id });
    if (!sync.envelope) return false;
    const { keyring: received } = await P.acceptKeyringEnvelope({
      userId,
      device: d,
      envelope: sync.envelope,
      statements: statusData.statements,
      current: keyringRef.current,
      pin: keyringRef.current ? null : linkPinRef.current,
    });
    await setKeyring(received);
    if (linkPinRef.current) await setLinkPin(null);
    await callFn("keys", await P.prepareAck({ userId, device: d, keyringVersion: sync.envelope.keyring_version }));
    return true;
  }, [userId, setKeyring, setLinkPin]);

  /** Send current keys to any of my devices that missed a rotation. Best effort. */
  const repairDevices = useCallback(async (statusData, ownChain) => {
    if (Date.now() - repairAt.current < 60_000) return;
    repairAt.current = Date.now();
    const d = deviceRef.current;
    const k = keyringRef.current;
    if (!d || !k) return;
    const latest = latestKey(k).version;
    for (const other of statusData.devices) {
      if (other.status !== "active" || other.device_id === d.device_id || other.keys_waiting) continue;
      if ((other.synced_key_version || 0) >= latest) continue;
      // A device left on an older certificate was removed at a rotation: never send it keys.
      if (other.cert_key_version !== latest) continue;
      try {
        await callFn("keys", await P.prepareKeyringResend({ userId, device: d, keyring: k, target: other, chain: ownChain }));
      } catch {
        /* another device can try later */
      }
    }
  }, [userId]);

  /** A reset this browser asked for: wait, finish it, or learn that it was stopped. Returns true if it took over. */
  const settleReset = useCallback(async (saved, statusData) => {
    const mine = statusData.resets.find((r) => r.id === saved.request_id);
    if (mine?.status === "waiting" && Date.now() < Date.parse(mine.effective_at)) {
      setPhase("reset-waiting");
      return true;
    }
    if (mine?.status === "waiting") {
      try {
        await callFn("keys", await P.prepareFinishReset({ userId, device: saved.device, requestId: saved.request_id }));
      } catch (err) {
        if (err?.code !== "RESET_ENDED") throw err;
      }
    }
    if (mine?.status === "waiting" || mine?.status === "done") {
      await forgetLocal();
      await setDevice(saved.device);
      await setKeyring(parseKeyring(saved.keyring, userId));
      return false;
    }
    await S.clearPendingReset(userId);
    setPendingReset(null);
    setNotice(RESET_ENDED[mine?.ended_by] || "Your reset request has ended, so nothing changed.");
    return false;
  }, [userId, forgetLocal, setDevice, setKeyring]);

  /** Re-read everything. silent: a background check that shouldn't replace the screen on a network blip. */
  const refresh = useCallback(async ({ silent = false } = {}) => {
    if (!userId) return;
    if (!silent) setError(null);
    try {
      const meData = await callFn("profile", { action: "me" });
      setMe(meData);
      if (!meData.profile) {
        setPhase("needs-username");
        return;
      }
      if (!S.storageAvailable()) {
        setError("This browser can't store encryption keys (private browsing may block it). Try a normal window.");
        setPhase("error");
        return;
      }
      let statusData = await callFn("keys", { action: "status" });
      const savedReset = await S.loadPendingReset(userId);
      setPendingReset(savedReset);
      if (savedReset) {
        if (await settleReset(savedReset, statusData)) {
          statusRef.current = statusData;
          setStatus(statusData);
          return;
        }
        statusData = await callFn("keys", { action: "status" });
      }

      const [localDevice, localKeyring, pins, savedLinkPin] = await Promise.all([
        S.loadDevice(userId),
        S.loadKeyring(userId),
        S.loadPins(userId),
        S.loadLinkPin(userId),
      ]);
      pinsRef.current = pins;
      deviceRef.current = localDevice;
      keyringRef.current = localKeyring;
      linkPinRef.current = savedLinkPin;
      setDeviceState(localDevice);
      setKeyringState(localKeyring);
      setLinkPinState(savedLinkPin);
      statusRef.current = statusData;
      setStatus(statusData);
      // Until this browser's keys are checked against them, the server's keys are only a claim.
      chainRef.current = null;
      setChain(null);
      setRemoval(null);

      if (!statusData.statements.length) {
        setPhase("needs-keys");
        return;
      }
      const serverChain = await verifyAccountChain(userId, statusData.statements);

      if (!localDevice) {
        setPhase("needs-device");
        return;
      }
      const row = statusData.devices.find((x) => x.device_id === localDevice.device_id);
      if (!row || row.status === "revoked" || row.status === "expired") {
        if (!localKeyring) {
          // It never held keys, so there's nothing to keep.
          await forgetLocal();
          setPhase("needs-device");
          return;
        }
        setRemoval(row?.revoked_reason === "account_reset" ? "reset" : "removed");
        setPhase("removed");
        return;
      }
      if (row.status === "pending") {
        setPhase("awaiting-approval");
        return;
      }
      if (localKeyring) {
        try {
          anchorChain(serverChain, { keyring: localKeyring });
        } catch (err) {
          if (err?.code !== "ACCOUNT_RESET") throw err;
          setRemoval("reset");
          setPhase("removed");
          return;
        }
      }
      if (!localKeyring || latestKey(localKeyring).version < serverChain.latest.version) {
        const got = await syncKeyring(statusData);
        if (!got) {
          setPhase("awaiting-keys");
          return;
        }
      }
      assertKeyringMatchesChain(keyringRef.current, serverChain);
      chainRef.current = serverChain;
      setChain(serverChain);
      setPhase("ready");
      repairDevices(statusData, serverChain);
    } catch (err) {
      if (silent && err?.name !== "IdentityError") return;
      setError(err?.message || "Something went wrong.");
      setPhase("error");
    }
  }, [userId, forgetLocal, syncKeyring, repairDevices, settleReset]);

  useEffect(() => {
    setPhase("loading");
    refresh();
  }, [refresh]);

  // While waiting on another device, check every few seconds.
  useEffect(() => {
    if (phase !== "awaiting-approval" && phase !== "awaiting-keys") return undefined;
    const t = setInterval(() => refresh({ silent: true }), 4000);
    return () => clearInterval(t);
  }, [phase, refresh]);

  // ---------- username ----------

  const claimUsername = useCallback(async (username, displayName) => {
    await callFn("profile", { action: "claim_username", username, display_name: displayName });
    await refresh();
  }, [refresh]);

  const updateProfile = useCallback(async (changes) => {
    const res = await callFn("profile", { action: "update", ...changes });
    setMe((m) => ({ ...m, profile: res.profile }));
    return res.profile;
  }, []);

  // ---------- first device ----------

  /** Step 1: make keys locally and return the phrase to show. Nothing is sent yet. */
  const beginCreateAccount = useCallback(async () => {
    const d = await createDeviceKeys(defaultDeviceLabel());
    const prepared = await P.prepareNewAccount({ userId, device: d });
    pendingRef.current = { kind: "create", device: d, ...prepared };
    return prepared.phrase;
  }, [userId]);

  /** Step 2: after the phrase is confirmed, publish. */
  const finishCreateAccount = useCallback(async () => {
    const p = pendingRef.current;
    if (!p || p.kind !== "create") throw new Error("Start again: the setup was interrupted.");
    await callFn("keys", p.request);
    await setDevice(p.device);
    await setKeyring(p.keyring);
    pendingRef.current = null;
    await refresh();
  }, [setDevice, setKeyring, refresh]);

  // ---------- adding this device ----------

  /** Ask to join. The link code covers the account history this browser was shown, and the keys it gets must match it. */
  const startLinking = useCallback(async () => {
    let d = deviceRef.current;
    if (!d) {
      d = await createDeviceKeys(defaultDeviceLabel());
      await setDevice(d);
    }
    const statusData = await callFn("keys", { action: "status" });
    await setLinkPin(P.linkPinFor(await verifyAccountChain(userId, statusData.statements)));
    await callFn("keys", await P.prepareRegisterDevice({ userId, device: d }));
    setPhase("awaiting-approval");
  }, [userId, setDevice, setLinkPin]);

  /** Stop waiting. The pending request expires on its own after 15 minutes. */
  const cancelLinking = useCallback(async () => {
    await forgetLocal();
    setPhase("needs-device");
  }, [forgetLocal]);

  /** This browser is approved but can't get current keys: remove it and set it up again. */
  const startOver = useCallback(async () => {
    const d = deviceRef.current;
    if (d) {
      try {
        await callFn("keys", await P.prepareRevoke({ userId, device: d, targetDeviceId: d.device_id }));
      } catch {
        /* if it can't be revoked from here, it can be removed from another device */
      }
    }
    await forgetLocal();
    await refresh();
  }, [userId, forgetLocal, refresh]);

  /** The person has decided this browser's keys can go (after it was removed, or the account reset). */
  const discardKeys = useCallback(async () => {
    await forgetLocal();
    setRemoval(null);
    await refresh();
  }, [forgetLocal, refresh]);

  const myLinkCode = useMemo(() => {
    if (!device || !userId || !linkPin) return null;
    return linkCode({ userId, deviceId: device.device_id, signPub: device.sign_pub, boxPub: device.box_pub, accountDigest: linkPin.digest });
  }, [device, userId, linkPin]);

  /** Unlock the keys with the phrase. A pending link request from this browser is completed instead of duplicated. */
  const recoverWithPhrase = useCallback(async (phrase) => {
    const recoveryResponse = await callFn("keys", { action: "get_recovery" });
    const attempt = async (d) => {
      const { keyring: recovered, request } = await P.recoverWithPhrase({ userId, device: d, phrase, recoveryResponse });
      await callFn("keys", request);
      await setDevice(d);
      await setKeyring(recovered);
    };
    const existing = deviceRef.current;
    try {
      await attempt(existing || (await createDeviceKeys(defaultDeviceLabel())));
    } catch (err) {
      if (existing && err?.code === "DEVICE_EXISTS") await attempt(await createDeviceKeys(defaultDeviceLabel()));
      else throw err;
    }
    await setLinkPin(null);
    await refresh();
  }, [userId, setDevice, setKeyring, setLinkPin, refresh]);

  /** Step 1 of a reset: new keys and phrase, made here. Nothing is sent yet. */
  const beginReset = useCallback(async () => {
    const statusData = await callFn("keys", { action: "status" });
    const nextVersion = Math.max(...statusData.statements.map((s) => s.version)) + 1;
    const d = await createDeviceKeys(defaultDeviceLabel());
    const prepared = await P.prepareReset({ userId, device: d, nextVersion });
    pendingRef.current = { kind: "reset", device: d, ...prepared };
    return prepared.phrase;
  }, [userId]);

  /** Step 2: ask for the reset. It waits, and the new keys wait in this browser until it completes. */
  const finishReset = useCallback(async () => {
    const p = pendingRef.current;
    if (!p || p.kind !== "reset") throw new Error("Start again: the reset was interrupted.");
    const { request } = await callFn("keys", p.request);
    const saved = { request_id: request.id, effective_at: request.effective_at, device: p.device, keyring: serializeKeyring(p.keyring) };
    await S.savePendingReset(userId, saved);
    setPendingReset(saved);
    pendingRef.current = null;
    await refresh();
  }, [userId, refresh]);

  /** From the browser that asked: take the reset request back. */
  const withdrawReset = useCallback(async () => {
    const saved = await S.loadPendingReset(userId);
    if (saved) {
      try {
        await callFn("keys", await P.prepareWithdrawReset({ userId, device: saved.device, requestId: saved.request_id }));
      } catch {
        /* it may already have ended */
      }
      await S.clearPendingReset(userId);
    }
    setPendingReset(null);
    await refresh();
  }, [userId, refresh]);

  /** From one of the account's devices: stop a reset someone asked for. */
  const cancelReset = useCallback(async () => {
    await callFn("keys", await P.prepareCancelReset({ userId, device: deviceRef.current }));
    await refresh({ silent: true });
  }, [userId, refresh]);

  // ---------- managing devices ----------

  /** target: the snapshot of the device's keys the person compared codes for. */
  const approveDevice = useCallback(async (target) => {
    await callFn("keys", await P.prepareApproval({ userId, device: deviceRef.current, keyring: keyringRef.current, target }));
    await refresh();
  }, [userId, refresh]);

  const denyDevice = useCallback(async (targetId) => {
    await callFn("keys", await P.prepareDeny({ userId, device: deviceRef.current, targetDeviceId: targetId }));
    await refresh();
  }, [userId, refresh]);

  const rotate = useCallback(async ({ newPhrase = false, exclude = [] } = {}) => {
    const statusData = await callFn("keys", { action: "status" });
    const ownChain = await verifyAccountChain(userId, statusData.statements);
    const active = statusData.devices.filter((d) => d.status === "active");
    return P.prepareRotation({
      userId, device: deviceRef.current, keyring: keyringRef.current, chain: ownChain, activeDevices: active, excludeDeviceIds: exclude, newPhrase,
    });
  }, [userId]);

  /** Remove another device, then rotate keys so it can't read anything new. */
  const removeDevice = useCallback(async (targetId) => {
    const d = deviceRef.current;
    const res = await callFn("keys", await P.prepareRevoke({ userId, device: d, targetDeviceId: targetId }));
    if (res.revoked_self) {
      await forgetLocal();
      await refresh();
      return;
    }
    const rotation = await rotate({ exclude: [targetId] });
    await callFn("keys", rotation.request);
    await setKeyring(rotation.keyring);
    await refresh();
  }, [userId, forgetLocal, rotate, setKeyring, refresh]);

  const beginPhraseChange = useCallback(async () => {
    const rotation = await rotate({ newPhrase: true });
    pendingRef.current = { kind: "phrase", ...rotation };
    return rotation.phrase;
  }, [rotate]);

  const finishPhraseChange = useCallback(async () => {
    const p = pendingRef.current;
    if (!p || p.kind !== "phrase") throw new Error("Start again: the change was interrupted.");
    await callFn("keys", p.request);
    await setKeyring(p.keyring);
    pendingRef.current = null;
    await refresh();
  }, [setKeyring, refresh]);

  const cancelPending = useCallback(() => {
    pendingRef.current = null;
  }, []);

  /**
   * Delete the account. Signed by this device while the account has keys; the server works
   * in time-limited batches, so keep calling until it says it's done. Then wipe this browser.
   */
  const deleteAccount = useCallback(async () => {
    const d = deviceRef.current;
    for (let attempt = 0; attempt < 40; attempt += 1) {
      const body = d && phase === "ready"
        ? await P.signedRequest({ userId, device: d, action: "delete_account", payload: { confirm: "DELETE" } })
        : { action: "delete_account", confirm: "DELETE" };
      let res;
      try {
        res = await callFn("profile", body);
      } catch (err) {
        // A repeat call after the sign-in itself was removed means the previous call finished.
        if (attempt > 0 && err?.status === 401) res = { done: true };
        else throw err;
      }
      if (res.done) {
        await forgetLocal();
        logout(false);
        window.location.assign("/?account_deleted=1");
        return;
      }
    }
    throw new Error("Deletion is taking longer than expected. Try again: it carries on where it stopped.");
  }, [userId, phase, forgetLocal, logout]);

  /** Sign out. Optionally remove this browser from the account and delete its keys. */
  const signOut = useCallback(async ({ removeThisDevice = false } = {}) => {
    if (removeThisDevice) {
      const d = deviceRef.current;
      if (d && phase === "ready") {
        try {
          await callFn("keys", await P.prepareRevoke({ userId, device: d, targetDeviceId: d.device_id }));
        } catch {
          /* still wipe locally */
        }
      }
      await forgetLocal();
    }
    logout(true);
  }, [userId, phase, forgetLocal, logout]);

  // ---------- other members ----------

  /**
   * Change stored pins one update at a time, re-reading what's stored first, so overlapping
   * key checks can't undo each other (or a "verified" mark).
   */
  const updatePins = useCallback((change) => {
    const run = pinsLock.current.then(async () => {
      const current = (await S.loadPins(userId)) || {};
      const next = change(current);
      pinsRef.current = next;
      await S.savePins(userId, next);
      return next;
    });
    pinsLock.current = run.catch(() => {});
    return run;
  }, [userId]);

  const updatePeers = useCallback((change) => {
    peersRef.current = change(peersRef.current);
    setPeers(peersRef.current);
  }, []);

  /**
   * Fetch and verify keys for other members. Trust on first use; after that, any change to
   * history at or before what was pinned is flagged, and their items are checked against the
   * pinned history until the person accepts the change.
   */
  const loadPeers = useCallback(async (userIds, { force = false } = {}) => {
    const now = Date.now();
    const wanted = [...new Set(userIds)].filter((id) => id && id !== userId && (force || !peerFetchedAt.current[id] || now - peerFetchedAt.current[id] > PEER_TTL_MS));
    if (!wanted.length) return;
    const { keys } = await callFn("keys", { action: "peer_keys", user_ids: wanted });
    const updates = {};
    const pinChanges = {};
    for (const id of wanted) {
      peerFetchedAt.current[id] = now;
      const entry = keys[id];
      if (!entry || !entry.statements.length) {
        updates[id] = { ready: false };
        continue;
      }
      try {
        const peerChain = await verifyAccountChain(id, entry.statements);
        const pin = pinsRef.current[id];
        const relation = compareWithPin(peerChain, pin);
        if (relation === "new") pinChanges[id] = (prev) => prev || pinFromChain(peerChain, false);
        if (relation === "rotated") pinChanges[id] = (prev) => pinFromChain(peerChain, Boolean(prev?.verified));
        let pinnedChain = null;
        if (relation === "changed" && pin?.statements) pinnedChain = await verifyAccountChain(id, pin.statements).catch(() => null);
        updates[id] = {
          ready: true,
          chain: peerChain,
          pinnedChain,
          devices: entry.devices,
          changed: relation === "changed",
          verified: relation !== "changed" && Boolean(pin?.verified),
        };
      } catch (err) {
        updates[id] = { ready: false, broken: true, error: err?.message };
      }
    }
    if (Object.keys(pinChanges).length) {
      await updatePins((current) => {
        const next = { ...current };
        for (const [id, change] of Object.entries(pinChanges)) next[id] = change(current[id]);
        return next;
      });
    }
    updatePeers((prev) => ({ ...prev, ...updates }));
  }, [userId, updatePins, updatePeers]);

  const acceptKeyChange = useCallback(async (peerId) => {
    const p = peersRef.current[peerId];
    if (!p?.chain) return;
    await updatePins((current) => ({ ...current, [peerId]: pinFromChain(p.chain, false) }));
    updatePeers((prev) => ({ ...prev, [peerId]: { ...prev[peerId], changed: false, pinnedChain: null, verified: false } }));
  }, [updatePins, updatePeers]);

  const markVerified = useCallback(async (peerId, verified = true) => {
    const p = peersRef.current[peerId];
    if (!p?.chain || p.changed) return;
    await updatePins((current) => ({ ...current, [peerId]: pinFromChain(p.chain, verified) }));
    updatePeers((prev) => ({ ...prev, [peerId]: { ...prev[peerId], verified } }));
  }, [updatePins, updatePeers]);

  /** Verified chains for every member, ready for encrypting to a conversation. Always reads the latest keys. */
  const chainsFor = useCallback((memberIds) => {
    const map = new Map();
    for (const id of memberIds) {
      if (id === userId) {
        const own = chainRef.current;
        const k = keyringRef.current;
        if (!own || !k || own.latest.version !== latestKey(k).version || own.latest.ecdh_pub !== latestKey(k).ecdh_pub) {
          throw new Error("Your keys are being checked. Try again in a moment.");
        }
        map.set(id, own);
        continue;
      }
      const p = peersRef.current[id];
      if (!p?.ready) throw new Error("Still checking everyone's keys. Try again in a moment.");
      if (p.changed) throw new Error("Someone's security keys changed. Review it in the conversation details before sending.");
      map.set(id, p.chain);
    }
    return map;
  }, [userId]);

  // These read the refs too, but depend on the state so that effects using them re-run when keys change.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const devicesOf = useCallback((id) => (id === userId ? statusRef.current?.devices || [] : peersRef.current[id]?.devices || []), [userId, status, peers]);
  /** The chain to check someone's signatures against: while a key change waits for review, the one pinned before it. */
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const chainOf = useCallback((id) => {
    if (id === userId) return chainRef.current;
    const p = peersRef.current[id];
    if (!p?.chain) return null;
    return p.changed ? p.pinnedChain || null : p.chain;
  }, [userId, chain, peers]);
  /** Only certificates from keys this browser holds count for your own devices. */
  const ownMinCertVersion = keyring?.versions?.[0]?.version ?? 1;

  const waitingReset = phase === "ready" ? (status?.resets || []).find((r) => r.status === "waiting") || null : null;

  const value = {
    userId,
    phase,
    error,
    notice,
    clearNotice: () => setNotice(null),
    me,
    status,
    chain,
    chainDigest: chain ? headDigest(chain) : null,
    device,
    keyring,
    peers,
    removal,
    pendingReset,
    waitingReset,
    isAdmin: me?.user?.role === "admin",
    refresh,
    claimUsername,
    updateProfile,
    beginCreateAccount,
    finishCreateAccount,
    startLinking,
    cancelLinking,
    startOver,
    discardKeys,
    myLinkCode,
    recoverWithPhrase,
    beginReset,
    finishReset,
    withdrawReset,
    cancelReset,
    approveDevice,
    denyDevice,
    removeDevice,
    beginPhraseChange,
    finishPhraseChange,
    cancelPending,
    signOut,
    deleteAccount,
    loadPeers,
    acceptKeyChange,
    markVerified,
    chainsFor,
    devicesOf,
    chainOf,
    ownMinCertVersion,
  };

  return <SecureContext.Provider value={value}>{children}</SecureContext.Provider>;
}
