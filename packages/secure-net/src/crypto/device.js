// Per-device keys. The signing and box private halves are generated non-extractable, so
// page script can use them but never export them. They stay in this browser.
//
// Each device also has a post-quantum key (ML-KEM-768 + P-256, kem.js) that keyrings are sealed
// to. Its 32-byte seed is stored as data, like the keyring: it only ever protects keyrings on
// their way to this device, which the keyring stored here exposes anyway.
import { randomId } from "./encoding.js";
import { exportRaw, generateEcdh, generateEcdsa } from "./primitives.js";
import { kemKeygen } from "./kem.js";

export async function createDeviceKeys(label) {
  const sign = await generateEcdsa(false);
  const box = await generateEcdh(false);
  const kem = kemKeygen();
  return {
    device_id: randomId(16),
    label: String(label || "This device").slice(0, 60),
    sign_priv: sign.privateKey,
    sign_pub: await exportRaw(sign.publicKey),
    box_priv: box.privateKey,
    box_pub: await exportRaw(box.publicKey),
    kem_priv: kem.kem_priv,
    kem_pub: kem.kem_pub,
    created_at: new Date().toISOString(),
  };
}

/** A device made before post-quantum keys, given one. Returns a new object; save it. */
export function withDeviceKem(device) {
  if (device.kem_pub && device.kem_priv) return device;
  return { ...device, ...kemKeygen() };
}

/** The public half of a device, as published to the server. */
export function publicDevice(device) {
  const out = { device_id: device.device_id, sign_pub: device.sign_pub, box_pub: device.box_pub, label: device.label };
  if (device.kem_pub) out.kem_pub = device.kem_pub;
  return out;
}

export function defaultDeviceLabel(userAgent = typeof navigator !== "undefined" ? navigator.userAgent : "") {
  const ua = String(userAgent);
  const browser = /Edg\//.test(ua)
    ? "Edge"
    : /Firefox\//.test(ua)
      ? "Firefox"
      : /Chrome\//.test(ua)
        ? "Chrome"
        : /Safari\//.test(ua)
          ? "Safari"
          : "Browser";
  const os = /iPhone|iPad/.test(ua)
    ? "iOS"
    : /Android/.test(ua)
      ? "Android"
      : /Mac OS X/.test(ua)
        ? "macOS"
        : /Windows/.test(ua)
          ? "Windows"
          : /Linux/.test(ua)
            ? "Linux"
            : "unknown system";
  return `${browser} on ${os}`;
}
