// Settings for a self-hosted site, from environment variables. docs/SELF_HOSTING.md lists them all.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const list = (v) => String(v || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const bool = (v, fallback) => (v === undefined || v === "" ? fallback : /^(1|true|yes|on)$/i.test(String(v)));

export function loadConfig(env = process.env) {
  const dataDir = path.resolve(env.DATA_DIR || "./data");
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  // A secret for signing file links and site-to-site requests. Made once and kept with the data.
  const secretFile = path.join(dataDir, "secret");
  let secret = env.SECRET || "";
  if (!secret) {
    if (!fs.existsSync(secretFile)) fs.writeFileSync(secretFile, crypto.randomBytes(32).toString("base64url"), { mode: 0o600 });
    secret = fs.readFileSync(secretFile, "utf8").trim();
  }
  const siteUrl = String(env.SITE_URL || `http://localhost:${env.PORT || 8080}`).replace(/\/+$/, "");
  const host = new URL(siteUrl).hostname.toLowerCase();
  return {
    port: Number(env.PORT || 8080),
    bind: env.BIND || "0.0.0.0",
    siteUrl,
    host,
    secure: siteUrl.startsWith("https://"),
    dataDir,
    dbFile: path.join(dataDir, "commonveil.db"),
    filesDir: path.join(dataDir, "files"),
    distDir: path.resolve(env.DIST_DIR || new URL("../dist", import.meta.url).pathname),
    secret,
    siteName: env.SITE_NAME || "Commonveil",
    // PBKDF2 rounds for passwords. Only tests lower it.
    passwordRounds: Math.max(1000, Number(env.PASSWORD_ROUNDS || 600_000)),
    defaultServerAdmins: list(env.DEFAULT_SERVER_ADMINS),
    // The proposals forum in the community server: off unless asked for (docs/SNIP_FORUM.md).
    snipForum: { enabled: String(env.SNIP_FORUM || "").toLowerCase() === "on", repo: env.SNIP_REPO || "", token: env.GITHUB_TOKEN || "" },
    openRegistration: bool(env.OPEN_REGISTRATION, true),
    trustProxy: bool(env.TRUST_PROXY, false),
    // Updates: where releases are announced, and the updater container that applies them.
    updateFeed: env.UPDATE_FEED || "https://api.github.com/repos/Comutability/commonveil-rebuild/releases?per_page=20",
    updateCheckHours: Math.max(1, Number(env.UPDATE_CHECK_HOURS || 6)),
    updaterUrl: env.UPDATER_URL || "",
    updaterToken: env.UPDATER_TOKEN || "",
    // Federation (docs/FEDERATION.md): on unless turned off.
    federation: bool(env.FEDERATION, true),
    // For a site that can only be reached under a path (behind a gateway that owns the rest of the
    // address): its protocol endpoints move under this prefix, and its site document says so.
    federationPrefix: /^(\/[A-Za-z0-9._~-]+){1,4}$/.test(String(env.FEDERATION_PATH_PREFIX || "")) ? String(env.FEDERATION_PATH_PREFIX) : "",
    // People's handles are <username>.<handleDomain>; it defaults to the site's own name.
    handleDomain: String(env.HANDLE_DOMAIN || host).toLowerCase(),
    allowPrivateFederation: bool(env.FEDERATION_ALLOW_PRIVATE, false),
    version: env.COMMONVEIL_VERSION || JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")).version,
  };
}
