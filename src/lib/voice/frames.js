// The second layer of encryption on call audio. WebRTC already encrypts media between devices
// (DTLS-SRTP), but its key exchange isn't post-quantum. So every audio frame is also sealed
// with AES-256-GCM under a key derived from the channel's key chain, which members receive
// through post-quantum hybrid (ML-KEM-768 + P-256) grants. Someone recording the traffic today
// would need to break both layers.
//
// Frame layout: [version 1][generation, 2 bytes][step, 4 bytes][IV, 12 bytes][ciphertext + tag]
// The first 7 bytes are authenticated as additional data. No imports: a worker loads this too.

export const FRAME_VERSION = 1;
const HEADER = 7;
const IV = 12;

export const epochId = (generation, step) => `${generation}:${step}`;

function header(generation, step) {
  const h = new Uint8Array(HEADER);
  const v = new DataView(h.buffer);
  v.setUint8(0, FRAME_VERSION);
  v.setUint16(1, generation);
  v.setUint32(3, step);
  return h;
}

export async function sealFrame(key, generation, step, data) {
  const h = header(generation, step);
  const iv = crypto.getRandomValues(new Uint8Array(IV));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: h }, key, data));
  const out = new Uint8Array(HEADER + IV + ct.length);
  out.set(h, 0);
  out.set(iv, HEADER);
  out.set(ct, HEADER + IV);
  return out;
}

/** Returns the plaintext, or null if the frame isn't ours or doesn't check out. */
export async function openFrame(keyFor, data) {
  if (data.length < HEADER + IV + 16) return null;
  const v = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (v.getUint8(0) !== FRAME_VERSION) return null;
  const key = await keyFor(v.getUint16(1), v.getUint32(3));
  if (!key) return null;
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: data.subarray(HEADER, HEADER + IV), additionalData: data.subarray(0, HEADER) },
      key,
      data.subarray(HEADER + IV),
    );
    return new Uint8Array(pt);
  } catch {
    return null;
  }
}

/**
 * A TransformStream for encoded audio frames. side "send" seals with the current epoch's key;
 * side "recv" opens with whichever epoch the sender used. Frames that can't be sealed or opened
 * are dropped, never passed on in the clear.
 * keys: { current(): { generation, step, key } | null, keyFor(generation, step): Promise<CryptoKey|null> }
 * stats: an object whose sealed/opened/dropped counts are updated.
 */
export function frameTransform(side, keys, stats = { sealed: 0, opened: 0, dropped: 0 }) {
  return new TransformStream({
    async transform(frame, controller) {
      const data = new Uint8Array(frame.data);
      if (side === "send") {
        const cur = keys.current();
        if (!cur) {
          stats.dropped += 1;
          return;
        }
        frame.data = (await sealFrame(cur.key, cur.generation, cur.step, data)).buffer;
        stats.sealed += 1;
        controller.enqueue(frame);
        return;
      }
      const pt = await openFrame(keys.keyFor, data);
      if (!pt) {
        stats.dropped += 1;
        return;
      }
      frame.data = pt.buffer;
      stats.opened += 1;
      controller.enqueue(frame);
    },
  });
}
