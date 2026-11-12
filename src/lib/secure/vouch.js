// Remembering which signed records have already checked out (server key generations and grants),
// so they aren't verified again on every refresh.
//
// The memory is keyed by a digest of the whole record and everything it was checked against (the
// signer's key history and devices). Never by its signature alone: a backend could otherwise send
// a different record carrying a signature that was seen before, and skip the check (CV-01).

const stable = (v) => (Array.isArray(v) ? v.map(stable) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, stable(v[k])])) : v);

/** SHA-256 (hex) of a record and what it was checked against. */
export async function vouchDigest(record, against) {
  const bytes = new TextEncoder().encode(JSON.stringify(stable({ record, against })));
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(hash, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** check(kind, record, against, verify) -> true once verify() has passed for exactly this record and context. */
export function createVouchCache(limit = 5000) {
  const seen = new Set();
  return async function check(kind, record, against, verify) {
    const tag = `${kind}:${await vouchDigest(record, against)}`;
    if (seen.has(tag)) return true;
    const ok = await verify().catch(() => false);
    if (ok) {
      if (seen.size >= limit) seen.delete(seen.values().next().value);
      seen.add(tag);
    }
    return ok;
  };
}
