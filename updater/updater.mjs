// The Commonveil updater: a tiny service, reachable only from the app container, that installs a
// new release when the site's admin (or automatic updates) asks. It sets COMMONVEIL_VERSION in
// the deployment's .env, pulls that image and restarts the app with it. If the new version doesn't
// come up healthy, it goes back to the previous one.
//
// It needs the Docker socket, which is powerful: that's why it's a separate container that does
// this one thing, answers only requests carrying UPDATER_TOKEN, and only accepts version numbers.
import http from "node:http";
import fs from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import crypto from "node:crypto";

const run = promisify(execFile);
const PROJECT = process.env.PROJECT_DIR || "/project";
const ENV_FILE = `${PROJECT}/.env`;
const TOKEN = process.env.UPDATER_TOKEN || "";
const SERVICE = process.env.APP_SERVICE || "app";
const HEALTH_URL = process.env.APP_HEALTH_URL || `http://${SERVICE}:8080/api/health`;
const SEMVER = /^\d{1,4}\.\d{1,4}\.\d{1,6}$/;

let state = { busy: false, last: null };

if (!TOKEN || TOKEN.length < 24) {
  console.error("UPDATER_TOKEN must be set (at least 24 characters). See docs/SELF_HOSTING.md.");
  process.exit(1);
}

const compose = (...args) => run("docker", ["compose", "--project-directory", PROJECT, ...args], { cwd: PROJECT, env: { ...process.env, PWD: PROJECT }, timeout: 15 * 60_000, maxBuffer: 8 * 1024 * 1024 });

function readEnv() {
  return fs.existsSync(ENV_FILE) ? fs.readFileSync(ENV_FILE, "utf8") : "";
}

function setVersion(text, version) {
  const line = `COMMONVEIL_VERSION=${version}`;
  return /^COMMONVEIL_VERSION=.*$/m.test(text) ? text.replace(/^COMMONVEIL_VERSION=.*$/m, line) : `${text.replace(/\n?$/, "\n")}${line}\n`;
}

async function healthy(version, ms = 120_000) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try {
      const r = await fetch(HEALTH_URL, { signal: AbortSignal.timeout(4000) });
      const j = await r.json();
      if (r.ok && j.version === version) return true;
    } catch {
      // still starting
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
  return false;
}

async function update(version) {
  const before = readEnv();
  const previous = /^COMMONVEIL_VERSION=(.*)$/m.exec(before)?.[1] || "latest";
  fs.writeFileSync(ENV_FILE, setVersion(before, version));
  try {
    await compose("pull", SERVICE);
    await compose("up", "-d", "--no-deps", SERVICE);
    if (!(await healthy(version))) throw new Error(`${version} didn't start properly`);
    state.last = { ok: true, version, at: new Date().toISOString() };
    console.log(`Updated to ${version}`);
  } catch (err) {
    console.error(`Update to ${version} failed: ${err.message}. Going back to ${previous}.`);
    fs.writeFileSync(ENV_FILE, before);
    await compose("up", "-d", "--no-deps", SERVICE).catch(() => {});
    state.last = { ok: false, version, error: String(err.message).slice(0, 300), at: new Date().toISOString() };
  } finally {
    state.busy = false;
  }
}

const authorised = (req) => {
  const got = Buffer.from(String(req.headers.authorization || ""));
  const want = Buffer.from(`Bearer ${TOKEN}`);
  return got.length === want.length && crypto.timingSafeEqual(got, want);
};

const reply = (res, status, body) => {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
};

http
  .createServer((req, res) => {
    if (!authorised(req)) return reply(res, 401, { error: "Not allowed" });
    if (req.method === "GET" && req.url === "/status") return reply(res, 200, state);
    if (req.method !== "POST" || req.url !== "/update") return reply(res, 404, { error: "Not found" });
    let body = "";
    req.on("data", (c) => {
      body += c;
      if (body.length > 1024) req.destroy();
    });
    req.on("end", () => {
      let version = "";
      try {
        version = String(JSON.parse(body).version || "");
      } catch {
        version = "";
      }
      if (!SEMVER.test(version)) return reply(res, 400, { error: "Not a version number" });
      if (state.busy) return reply(res, 409, { error: "An update is already running" });
      state.busy = true;
      reply(res, 202, { ok: true, version });
      update(version);
    });
  })
  .listen(8090, "0.0.0.0", () => console.log("Commonveil updater ready"));
