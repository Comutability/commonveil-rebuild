// A device's signed offer to join a call. It binds the WebRTC certificate fingerprint this
// device will use to its own signing key, so the relay in the middle can't swap in its own
// connection keys: everyone in the call checks the offer against that device's certificate
// for the member's account before connecting, and checks the fingerprint the connection
// actually uses against the signed one.
import { CONTEXTS, canonical, voiceHelloFields } from "../crypto/canonical.js";
import { utf8 } from "../crypto/encoding.js";
import { importSignPrivate, signBytes, verifyWithRaw } from "../crypto/primitives.js";
import { deviceIsCertified } from "../secure/protocol.js";

const HELLO_MAX_AGE_MS = 24 * 3600_000;

/** The SHA-256 certificate fingerprint an SDP commits to, upper case, or null. */
export function fingerprintOf(sdp) {
  const found = new Set();
  for (const m of String(sdp || "").matchAll(/^a=fingerprint:sha-256 ([0-9A-Fa-f:]+)\s*$/gm)) found.add(m[1].toUpperCase());
  return found.size === 1 ? [...found][0] : null;
}

export const helloText = ({ room, userId, deviceId, callId, fingerprint, issuedAt }) =>
  canonical(CONTEXTS.voiceHello, voiceHelloFields({ room, user_id: userId, device_id: deviceId, peer_id: callId, fingerprint, issued_at: issuedAt }));

export async function signHello({ device, room, userId, callId, fingerprint }) {
  const issuedAt = new Date().toISOString();
  const key = await importSignPrivate(device.sign_priv);
  const signature = await signBytes(key, utf8(helloText({ room, userId, deviceId: device.device_id, callId, fingerprint, issuedAt })));
  return { call_id: callId, fingerprint, issued_at: issuedAt, signature };
}

/**
 * True if a peer's offer was signed by a device certified for their account.
 * peer: { user_id, device_id, hello }, chain: their verified key chain, devices: their device rows.
 */
export async function verifyHello({ room, peer, chain, devices }) {
  const h = peer?.hello;
  if (!h || !chain) return false;
  const issued = Date.parse(h.issued_at);
  if (!Number.isFinite(issued) || Math.abs(Date.now() - issued) > HELLO_MAX_AGE_MS) return false;
  const device = (devices || []).find((d) => d.device_id === peer.device_id && d.status !== "revoked" && d.status !== "expired");
  if (!device || !(await deviceIsCertified(peer.user_id, device, chain))) return false;
  const text = helloText({ room, userId: peer.user_id, deviceId: peer.device_id, callId: h.call_id, fingerprint: h.fingerprint, issuedAt: h.issued_at });
  return verifyWithRaw(device.sign_pub, h.signature, text);
}
