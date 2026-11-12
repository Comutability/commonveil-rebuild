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
/** An update that hasn't come back on its new version by then didn't work. */
const APPLY_DEADLINE_MS = 20 * 60_000;

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
    // The copy has to be there before anything else happens.
    const made = fs.statSync(file, { throwIfNoEntry: false });
    if (!made || made.size === 0) throw new Error("The backup couldn't be made, so nothing was changed.");
    // Keep the newest few by when they were made, never by name (version numbers don't sort as
    // text: 0.9 comes after 0.19), and never the one just made (CV-21).
    const old = fs
      .readdirSync(dir)
      .filter((f) => f.endsWith(".db") && path.join(dir, f) !== file)
      .map((f) => ({ f, at: fs.statSync(path.join(dir, f)).mtimeMs }))
      .sort((a, b) => b.at - a.at);
    for (const { f } of old.slice(KEEP_BACKUPS - 1)) fs.rmSync(path.join(dir, f), { force: true });
    return file;
  }

  async apply(version) {
    if (!isVersion(version)) throw new Error("Not a version");
    if (!this.canApply) throw new Error("This site has no updater. See docs/SELF_HOSTING.md to add one.");
    if (!isNewer(version, this.config.version)) throw new Error("That isn't newer than this site.");
    const backup = this.backup(version);
    this.#setStatus({ applying: { version, at: new Date().toISOString(), backup: path.basename(backup) }, error: null });
    let res;
    try {
      res = await this.fetch(`${this.updaterBase}/update`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${this.config.updaterToken}` },
        body: JSON.stringify({ version }),
        signal: AbortSignal.timeout(20_000),
      });
    } catch (err) {
      // Couldn't even ask: nothing is updating (CV-19).
      this.#setStatus({ applying: null, error: `Couldn't reach the updater: ${err.message}` });
      throw new Error("Couldn't reach the updater. Nothing was changed.");
    }
    const out = await res.json().catch(() => ({}));
    if (!res.ok) {
      this.#setStatus({ applying: null, error: out.error || `The updater answered ${res.status}` });
      throw new Error(out.error || "The updater refused");
    }
    // 202 means accepted, not installed: reconcile() follows the job to its end.
    return { ok: true, version, backup: path.basename(backup) };
  }

  get updaterBase() {
    return String(this.config.updaterUrl || "").replace(/\/$/, "");
  }

  /**
   * Follow an update the updater accepted. Success restarts this site on the new version (and
   * view() then shows nothing applying); failure or a rollback is reported here, and an update
   * that hasn't finished in time is treated as failed, so the admin can try again (CV-19).
   */
  async reconcile() {
    const a = this.status.applying;
    if (!a || !isNewer(a.version, this.config.version)) return;
    let job = null;
    try {
      const res = await this.fetch(`${this.updaterBase}/status`, { headers: { Authorization: `Bearer ${this.config.updaterToken}` }, signal: AbortSignal.timeout(5000) });
      if (res.ok) job = await res.json();
    } catch {
      job = null;
    }
    const last = job?.last;
    if (last && last.version === a.version && last.ok === false && Date.parse(last.at) >= Date.parse(a.at)) {
      this.#setStatus({ applying: null, error: `The update to ${a.version} didn't work${last.rolled_back === false ? " and going back failed too: check the server" : ", so the site went back to the version it had"}. ${last.error || ""}`.trim() });
      return;
    }
    if (!job?.busy && Date.now() - Date.parse(a.at) > APPLY_DEADLINE_MS) {
      this.#setStatus({ applying: null, error: `The update to ${a.version} didn't finish. You can try again.` });
    }
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
      if (req.method === "GET") {
        await this.reconcile().catch(() => {});
        return json(res, 200, this.view());
      }
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
