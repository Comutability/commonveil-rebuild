// Stands in for @base44/sdk in a self-hosted build (see vite.config.js), so none of Base44's
// code ships with a self-hosted site. Only what the app imports from it is here.

/** The saved sign-in token, read the same way the SDK reads it. */
export function getAccessToken() {
  try {
    const fromUrl = new URLSearchParams(window.location.search).get("access_token");
    if (fromUrl) return fromUrl;
    return window.localStorage.getItem("base44_access_token") || window.localStorage.getItem("token") || null;
  } catch {
    return null;
  }
}

export function createClient() {
  throw new Error("This is a self-hosted build: it talks to its own server (src/api/selfhostClient.js).");
}
