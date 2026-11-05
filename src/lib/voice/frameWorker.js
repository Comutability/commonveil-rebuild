// Runs the frame encryption off the main thread, for browsers with RTCRtpScriptTransform
// (Firefox, Safari). Chromium uses the same code on the main thread instead.
import { epochId, frameTransform } from "./frames.js";

const keys = new Map(); // "generation:step" -> CryptoKey
let current = null; // { generation, step }
const waiting = new Map(); // epoch id -> [resolve]
const stats = { sealed: 0, opened: 0, dropped: 0 };

const keySource = {
  current: () => (current && keys.has(epochId(current.generation, current.step)) ? { ...current, key: keys.get(epochId(current.generation, current.step)) } : null),
  keyFor(generation, step) {
    const id = epochId(generation, step);
    if (keys.has(id)) return Promise.resolve(keys.get(id));
    self.postMessage({ type: "need-key", generation, step });
    return new Promise((resolve) => {
      const list = waiting.get(id) || [];
      list.push(resolve);
      waiting.set(id, list);
      setTimeout(() => resolve(keys.get(id) || null), 3000);
    });
  },
};

self.onmessage = (event) => {
  const msg = event.data || {};
  if (msg.type === "key" && msg.key) {
    const id = epochId(msg.generation, msg.step);
    keys.set(id, msg.key);
    for (const resolve of waiting.get(id) || []) resolve(msg.key);
    waiting.delete(id);
  } else if (msg.type === "no-key") {
    const id = epochId(msg.generation, msg.step);
    for (const resolve of waiting.get(id) || []) resolve(null);
    waiting.delete(id);
  } else if (msg.type === "current") {
    current = { generation: msg.generation, step: msg.step };
  } else if (msg.type === "stats") {
    self.postMessage({ type: "stats", stats });
  }
};

self.onrtctransform = (event) => {
  const t = event.transformer;
  t.readable.pipeThrough(frameTransform(t.options.side, keySource, stats)).pipeTo(t.writable).catch(() => {});
};
