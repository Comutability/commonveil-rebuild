// Per-device keys. The private halves are generated non-extractable, so page
// script can use them but never export them. They stay in this browser.
import { randomId } from "./encoding.js";
import { exportRaw, generateEcdh, generateEcdsa } from "./primitives.js";

export async function createDeviceKeys(label) {
  const sign = await generateEcdsa(false);
  const box = await generateEcdh(false);
  return {
    device_id: randomId(16),
    label: String(label || "This device").slice(0, 60),
    sign_priv: sign.privateKey,
    sign_pub: await exportRaw(sign.publicKey),
    box_priv: box.privateKey,
    box_pub: await exportRaw(box.publicKey),
    created_at: new Date().toISOString(),
  };
}

/** The public half of a device, as published to the server. */
export function publicDevice(device) {
  return { device_id: device.device_id, sign_pub: device.sign_pub, box_pub: device.box_pub, label: device.label };
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
