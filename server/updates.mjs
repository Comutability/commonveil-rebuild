// Updates for a self-hosted site: checks for new releases, tells admins, and asks the updater
// container (updater/) to install one, now or automatically. Before an update the database is
// copied to DATA_DIR/backups, so an update can always be undone.
//
// The check reads the project's public release list (UPDATE_FEED). It sends nothing about this
// site: GitHub sees an ordinary request from this server's address, a few times a day.
import fs from "node:fs";
import path from "node:path";
import { compareVersions, isNewer, isVersion } from "../src/lib/site/releases.js";
import { json, readBody } from "./http.mjs";

const SETTINGS_KEY = "updates:settings";
const STATUS_KEY = "updates:status";
const KEEP_BACKUPS = 5;

export class Updates {
  constructor({ config, store, log = console, fetchImpl = globalThis.fetch }) {
    this.config = config;
    this.store = store;
    this.log = log;
    this.fetch = fetchImpl;
    this.timer = null;
  }

  get settings() {
    return { auto: false, ...this.store.getSetting(SETTINGS_KEY, {}) };
  }

  get status() {
    return this.store.getSetting(STATUS_KEY, { checked_at: null, latest: null, error: null, applying: null });
  }

  #setStatus(changes) {
    this.store.setSetting(STATUS_KEY, { ...this.status, ...changes });
  }

  start() {
    if (this.timer) return;
    const hours = this.config.updateCheckHours;
    const tick = () => this.check().catch(() => {});
    setTimeout(tick, 60_000).unref?.();
    // Timers top out at about 24 days; checking less often than that isn't useful anyway.
    this.timer = setInterval(tick, Math.min(hours * 3600_000, 2 ** 31 - 1));
    this.timer.unref?.();
  }

  stop() {
    clearInterval(this.timer);
    this.timer = null;
  }

  /** Look for a newer release. Installs it straight away if automatic updates are on. */
  async check() {
    try {
      const res = await this.fetch(this.config.updateFeed, {
        headers: { Accept: "application/vnd.github+json", "User-Agent": "Commonveil-update-check" },
        signal: AbortSignal.timeout(15_000),
      });
      if (!res.ok) throw new Error(`The release list answered ${res.status}`);
      const list = await res.json();
      const releases = (Array.isArray(list) ? list : [])
        .filter((r) => r && !r.draft && !r.prerelease && isVersion(String(r.tag_name || "").replace(/^v/, "")))
        .map((r) => ({
          version: String(r.tag_name).replace(/^v/, ""),
          title: String(r.name || "").slice(0, 200),
          notes: String(r.body || "").slice(0, 20_000),
          url: /^https:\/\//.test(r.html_url || "") ? r.html_url : null,
          published_at: r.published_at || null,
        }))
        .sort((a, b) => compareVersions(b.version, a.version));
      const latest = releases[0] || null;
      const newer = releases.filter((r) => isNewer(r.version, this.config.version));
      this.#setStatus({ checked_at: new Date().toISOString(), latest, newer, error: null });
      if (latest && isNewer(latest.version, this.config.version) && this.settings.auto && this.canApply) {
        this.log.info?.(`[updates] installing ${latest.version} automatically`);
        await this.apply(latest.version).catch((e) => this.log.warn?.("[updates] automatic update failed:", e.message));
      }
      return this.status;
    } catch (err) {
      this.#setStatus({ checked_at: new Date().toISOString(), error: err.message });
      throw err;
    }
  }

  get canApply() {
    return Boolean(this.config.updaterUrl && this.config.updaterToken);
  }

  /** Copy the database with SQLite's own snapshot, keeping the last few. */
  backup(label) {
    const dir = path.join(this.config.dataDir, "backups");
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const file = path.join(dir, `commonveil-${this.config.version}-to-${label}-${new Date().toISOString().replace(/[:.]/g, "-")}.db`);
    this.store.db.exec(`VACUUM INTO '${file.replace(/'/g, "''")}'`);
    const old = fs.readdirSync(dir).filter((f) => f.endsWith(".db")).sort();
    for (const f of old.slice(0, Math.max(0, old.length - KEEP_BACKUPS))) fs.rmSync(path.join(dir, f), { force: true });
    return file;
  }

  async apply(version) {
    if (!isVersion(version)) throw new Error("Not a version");
    if (!this.canApply) throw new Error("This site has no updater. See docs/SELF_HOSTING.md to add one.");
    if (!isNewer(version, this.config.version)) throw new Error("That isn't newer than this site.");
    const backup = this.backup(version);
    this.#setStatus({ applying: { version, at: new Date().toISOString(), backup: path.basename(backup) } });
    const res = await this.fetch(`${this.config.updaterUrl.replace(/\/$/, "")}/update`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${this.config.updaterToken}` },
      body: JSON.stringify({ version }),
      signal: AbortSignal.timeout(20_000),
    });
    const out = await res.json().catch(() => ({}));
    if (!res.ok) {
      this.#setStatus({ applying: null, error: out.error || `The updater answered ${res.status}` });
      throw new Error(out.error || "The updater refused");
    }
    return { ok: true, version, backup: path.basename(backup) };
  }

  view() {
    const s = this.status;
    const latest = s.latest && isNewer(s.latest.version, this.config.version) ? s.latest : null;
    return {
      current: this.config.version,
      available: latest,
      newer: (s.newer || []).filter((r) => isNewer(r.version, this.config.version)),
      checked_at: s.checked_at,
      error: s.error,
      // An update in progress finishes when the site comes back on the new version.
      applying: s.applying && isNewer(s.applying.version, this.config.version) ? s.applying : null,
      auto: this.settings.auto,
      can_apply: this.canApply,
    };
  }

  /** /api/admin/updates: GET the status; POST { action: "check" | "apply" | "set_auto", auto }. Admins only. */
  async route(req, res, _url, user) {
    if (!user || user.role !== "admin") return json(res, 403, { error: "Admins only.", code: "FORBIDDEN" });
    try {
      if (req.method === "GET") return json(res, 200, this.view());
      if (req.method !== "POST") return json(res, 405, { error: "Use GET or POST.", code: "METHOD" });
      const body = JSON.parse((await readBody(req, 4096)) || "{}");
      if (body.action === "check") {
        await this.check().catch(() => {});
        return json(res, 200, this.view());
      }
      if (body.action === "set_auto") {
        this.store.setSetting(SETTINGS_KEY, { ...this.settings, auto: body.auto === true });
        return json(res, 200, this.view());
      }
      if (body.action === "apply") {
        const target = body.version || this.view().available?.version;
        await this.apply(String(target || ""));
        return json(res, 200, this.view());
      }
      return json(res, 400, { error: "Unknown action.", code: "UNKNOWN_ACTION" });
    } catch (err) {
      return json(res, 400, { error: err.message, code: "UPDATE_FAILED" });
    }
  }
}
