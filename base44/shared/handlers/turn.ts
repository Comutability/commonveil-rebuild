// Ephemeral TURN credentials using coturn's REST shared-secret authentication.
// The shared secret never reaches a browser. Credentials are scoped to a short
// lifespan and are issued only after the caller has passed voice permissions.
const env = (name: string): string => {
  const g = globalThis as any;
  return String(g.Deno?.env?.get?.(name) ?? g.process?.env?.[name] ?? "").trim();
};

export async function turnIceServers(userId: string): Promise<Array<{ urls: string[]; username: string; credential: string }>> {
  const secret = env("VOICE_TURN_SECRET");
  const urls = env("VOICE_TURN_URLS").split(",").map((url) => url.trim()).filter(Boolean);
  // All or nothing: never use a TURN URL with missing or malformed credentials.
  if (!secret || !urls.length || urls.some((url) => !/^turns?:[^\s/?#]+(?::\d{1,5})?(?:\?transport=(?:udp|tcp))?$/.test(url))) return [];
  const expires = Math.floor(Date.now() / 1000) + 6 * 60 * 60;
  // The user id is not secret and contains no name, email or IP address.
  const username = `${expires}:${userId}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(username)));
  const credential = btoa(String.fromCharCode(...signed));
  return [{ urls, username, credential }];
}
