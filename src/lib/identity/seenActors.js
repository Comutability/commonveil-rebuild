// The highest seq this browser has accepted for each actor it checked.
//
// An actor document's seq only goes up, and Secure Net refuses an older one (ROLLBACK). That only
// works if something remembers what was seen, so this keeps it: nothing but an id, a number and
// the handle, on this device. It holds no keys and no content, and it is only ever raised.
const KEY = "cv.seen-actors.v1";
const memory = new Map();

const store = (storage) => {
  if (storage) return storage;
  try {
    return globalThis.localStorage || null;
  } catch {
    return null;
  }
};

function readAll(storage) {
  const s = store(storage);
  if (!s) return Object.fromEntries(memory);
  try {
    const value = JSON.parse(s.getItem(KEY) || "{}");
    return value && typeof value === "object" && !Array.isArray(value) ? value : {};
  } catch {
    return {};
  }
}

function writeAll(all, storage) {
  const s = store(storage);
  if (s) {
    try {
      s.setItem(KEY, JSON.stringify(all));
    } catch {
      // A full or blocked store only costs rollback memory, never a check.
    }
    return;
  }
  memory.clear();
  for (const [id, row] of Object.entries(all)) memory.set(id, row);
}

/** What this browser last accepted for an actor, or null. */
export function seenActor(id, storage) {
  if (!id) return null;
  const row = readAll(storage)[id];
  return row && Number.isSafeInteger(row.seq) ? row : null;
}

/** Raise the remembered seq for an actor. A lower or equal seq never wins. */
export function rememberActor(id, { seq, handle = "" } = {}, storage) {
  if (!id || !Number.isSafeInteger(seq) || seq < 1) return { raised: false, previous: null };
  const all = readAll(storage);
  const previous = all[id] && Number.isSafeInteger(all[id].seq) ? all[id] : null;
  if (previous && seq <= previous.seq) return { raised: false, previous };
  all[id] = { seq, handle: String(handle || ""), at: new Date().toISOString() };
  writeAll(all, storage);
  return { raised: true, previous };
}