// Holds this browser's encryption state for the signed-in account and runs the
// setup, linking, recovery, rotation and peer-verification flows.
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { useAuth } from "@/lib/AuthContext";
import { callFn } from "@/lib/api";
import * as P from "./protocol.js";
import * as S from "./store.js";
import { createDeviceKeys, defaultDeviceLabel } from "../crypto/device.js";
import { compareWithPin, linkCode, pinFromChain, verifyAccountChain } from "../crypto/identity.js";
import { latestKey } from "../crypto/keyring.js";
import { clearEnvelopeKeyCache } from "../crypto/envelope.js";

const SecureContext = createContext(null);

export function useSecure() {
  const ctx = useContext(SecureContext);
  if (!ctx) throw new Error("useSecure must be used inside SecureProvider");
  return ctx;
}

const PEER_TTL_MS = 60_000;

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

  const deviceRef = useRef(null);
  const keyringRef = useRef(null);
  const pinsRef = useRef({});
  const pendingRef = useRef(null);
  const peerFetchedAt = useRef({});
  const repairAt = useRef(0);

  const [device, setDeviceState] = useState(null);
  const [keyring, setKeyringState] = useState(null);

  const setDevice = useCallback(async (d, persist = true) => {
    deviceRef.current = d;
    setDeviceState(d);
    if (persist && userId) {
      if (d) await S.saveDevice(userId, d);
    }
  }, [userId]);

  const setKeyring = useCallback(async (k, persist = true) => {
    keyringRef.current = k;
    setKeyringState(k);
    clearEnvelopeKeyCache();
    if (persist && userId && k) await S.saveKeyring(userId, k);
  }, [userId]);

  const forgetLocal = useCallback(async () => {
    if (userId) await S.wipeLocal(userId);
    deviceRef.current = null;
    keyringRef.current = null;
    setDeviceState(null);
    setKeyringState(null);
    clearEnvelopeKeyCache();
  }, [userId]);

  // ---------- sync ----------

  const syncKeyring = useCallback(async (statusData) => {
    const d = deviceRef.current;
    const sync = await callFn("keys", { action: "device_sync", device_id: d.device_id });
    if (!sync.envelope) return false;
    const { keyring: received } = await P.acceptKeyringEnvelope({ userId, device: d, envelope: sync.envelope, statements: statusData.statements });
    await setKeyring(received);
    await callFn("keys", await P.prepareAck({ userId, device: d, keyringVersion: sync.envelope.keyring_version }));
    return true;
  }, [userId, setKeyring]);

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
      try {
        await callFn("keys", await P.prepareKeyringResend({ userId, device: d, keyring: k, target: other, chain: ownChain }));
      } catch {
        /* another device can try later */
      }
    }
  }, [userId]);

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
      const [localDevice, localKeyring, pins] = await Promise.all([S.loadDevice(userId), S.loadKeyring(userId), S.loadPins(userId)]);
      pinsRef.current = pins;
      deviceRef.current = localDevice;
      keyringRef.current = localKeyring;
      setDeviceState(localDevice);
      setKeyringState(localKeyring);

      const statusData = await callFn("keys", { action: "status" });
      setStatus(statusData);
      if (!statusData.statements.length) {
        setPhase("needs-keys");
        return;
      }
      const ownChain = await verifyAccountChain(userId, statusData.statements);
      setChain(ownChain);

      if (!localDevice) {
        setPhase("needs-device");
        return;
      }
      const row = statusData.devices.find((x) => x.device_id === localDevice.device_id);
      if (!row || row.status === "revoked" || row.status === "expired") {
        if (localKeyring) setNotice("This browser was removed from your account, so its keys were deleted here.");
        await forgetLocal();
        setPhase("needs-device");
        return;
      }
      if (row.status === "pending") {
        setPhase("awaiting-approval");
        return;
      }
      const current = keyringRef.current;
      if (!current || latestKey(current).version < ownChain.latest.version) {
        const got = await syncKeyring(statusData);
        if (!got) {
          setPhase(current ? "awaiting-keys" : "awaiting-keys");
          return;
        }
      }
      setPhase("ready");
      repairDevices(statusData, ownChain);
    } catch (err) {
      if (silent && err?.code !== "BAD_SIGNATURE" && err?.name !== "IdentityError") return;
      setError(err?.message || "Something went wrong.");
      setPhase("error");
    }
  }, [userId, forgetLocal, syncKeyring, repairDevices]);

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

  const startLinking = useCallback(async () => {
    let d = deviceRef.current;
    if (!d) {
      d = await createDeviceKeys(defaultDeviceLabel());
      await setDevice(d);
    }
    await callFn("keys", await P.prepareRegisterDevice({ userId, device: d }));
    setPhase("awaiting-approval");
  }, [userId, setDevice]);

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

  const myLinkCode = useMemo(() => {
    if (!device || !userId) return null;
    return linkCode({ userId, deviceId: device.device_id, signPub: device.sign_pub, boxPub: device.box_pub });
  }, [device, userId]);

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
    await refresh();
  }, [userId, setDevice, setKeyring, refresh]);

  const beginReset = useCallback(async () => {
    const statusData = await callFn("keys", { action: "status" });
    const nextVersion = Math.max(...statusData.statements.map((s) => s.version)) + 1;
    const d = await createDeviceKeys(defaultDeviceLabel());
    const prepared = await P.prepareReset({ userId, device: d, nextVersion });
    pendingRef.current = { kind: "reset", device: d, ...prepared };
    return prepared.phrase;
  }, [userId]);

  const finishReset = useCallback(async () => {
    const p = pendingRef.current;
    if (!p || p.kind !== "reset") throw new Error("Start again: the reset was interrupted.");
    await callFn("keys", p.request);
    await forgetLocal();
    await setDevice(p.device);
    await setKeyring(p.keyring);
    pendingRef.current = null;
    await refresh();
  }, [forgetLocal, setDevice, setKeyring, refresh]);

  // ---------- managing devices ----------

  const approveDevice = useCallback(async (target) => {
    await callFn("keys", await P.prepareApproval({ userId, device: deviceRef.current, keyring: keyringRef.current, target }));
    await refresh();
  }, [userId, refresh]);

  const denyDevice = useCallback(async (targetId) => {
    await callFn("keys", await P.prepareDeny({ userId, device: deviceRef.current, targetDeviceId: targetId }));
    await refresh();
  }, [userId, refresh]);

  const rotate = useCallback(async ({ newPhrase = false } = {}) => {
    const statusData = await callFn("keys", { action: "status" });
    const ownChain = await verifyAccountChain(userId, statusData.statements);
    const active = statusData.devices.filter((d) => d.status === "active");
    return P.prepareRotation({ userId, device: deviceRef.current, keyring: keyringRef.current, chain: ownChain, activeDevices: active, newPhrase });
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
    const rotation = await rotate();
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

  const savePins = useCallback(async (next) => {
    pinsRef.current = next;
    await S.savePins(userId, next);
  }, [userId]);

  /** Fetch and verify keys for other members. TOFU-pins new ones; flags changes. */
  const loadPeers = useCallback(async (userIds, { force = false } = {}) => {
    const now = Date.now();
    const wanted = [...new Set(userIds)].filter((id) => id && id !== userId && (force || !peerFetchedAt.current[id] || now - peerFetchedAt.current[id] > PEER_TTL_MS));
    if (!wanted.length) return;
    const { keys } = await callFn("keys", { action: "peer_keys", user_ids: wanted });
    const pins = { ...pinsRef.current };
    const updates = {};
    for (const id of wanted) {
      peerFetchedAt.current[id] = now;
      const entry = keys[id];
      if (!entry || !entry.statements.length) {
        updates[id] = { ready: false };
        continue;
      }
      try {
        const peerChain = await verifyAccountChain(id, entry.statements);
        const relation = compareWithPin(peerChain, pins[id]);
        if (relation === "new") pins[id] = pinFromChain(peerChain, false);
        if (relation === "rotated") pins[id] = { ...pinFromChain(peerChain, pins[id].verified), verified: pins[id].verified };
        updates[id] = {
          ready: true,
          chain: peerChain,
          devices: entry.devices,
          changed: relation === "changed",
          verified: relation !== "changed" && Boolean(pins[id]?.verified),
        };
      } catch (err) {
        updates[id] = { ready: false, broken: true, error: err?.message };
      }
    }
    await savePins(pins);
    setPeers((prev) => ({ ...prev, ...updates }));
  }, [userId, savePins]);

  const acceptKeyChange = useCallback(async (peerId) => {
    const p = peers[peerId];
    if (!p?.chain) return;
    await savePins({ ...pinsRef.current, [peerId]: pinFromChain(p.chain, false) });
    setPeers((prev) => ({ ...prev, [peerId]: { ...prev[peerId], changed: false, verified: false } }));
  }, [peers, savePins]);

  const markVerified = useCallback(async (peerId, verified = true) => {
    const p = peers[peerId];
    if (!p?.chain) return;
    await savePins({ ...pinsRef.current, [peerId]: pinFromChain(p.chain, verified) });
    setPeers((prev) => ({ ...prev, [peerId]: { ...prev[peerId], verified } }));
  }, [peers, savePins]);

  /** Verified chains for every member, ready for encrypting to a conversation. */
  const chainsFor = useCallback((memberIds) => {
    const map = new Map();
    for (const id of memberIds) {
      if (id === userId) {
        map.set(id, chain);
        continue;
      }
      const p = peers[id];
      if (!p?.ready) throw new Error("Still checking everyone's keys. Try again in a moment.");
      if (p.changed) throw new Error("Someone's security keys changed. Review it in the conversation details before sending.");
      map.set(id, p.chain);
    }
    return map;
  }, [userId, chain, peers]);

  const devicesOf = useCallback((id) => (id === userId ? status?.devices || [] : peers[id]?.devices || []), [userId, status, peers]);
  const chainOf = useCallback((id) => (id === userId ? chain : peers[id]?.chain || null), [userId, chain, peers]);

  const value = {
    userId,
    phase,
    error,
    notice,
    clearNotice: () => setNotice(null),
    me,
    status,
    chain,
    device,
    keyring,
    peers,
    isAdmin: me?.user?.role === "admin",
    refresh,
    claimUsername,
    updateProfile,
    beginCreateAccount,
    finishCreateAccount,
    startLinking,
    cancelLinking,
    startOver,
    myLinkCode,
    recoverWithPhrase,
    beginReset,
    finishReset,
    approveDevice,
    denyDevice,
    removeDevice,
    beginPhraseChange,
    finishPhraseChange,
    cancelPending,
    signOut,
    loadPeers,
    acceptKeyChange,
    markVerified,
    chainsFor,
    devicesOf,
    chainOf,
  };

  return <SecureContext.Provider value={value}>{children}</SecureContext.Provider>;
}
