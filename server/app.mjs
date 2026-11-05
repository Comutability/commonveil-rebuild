// The self-hosted Commonveil server: the site, its backend functions, sign-in, files, realtime
// rooms, scheduled tasks, updates and the Commonveil Protocol, in one process.
import http from "node:http";
import fs from "node:fs";
import { Store, loadSchemas } from "./store.mjs";
import { Auth, AuthError } from "./auth.mjs";
import { createMail } from "./mail.mjs";
import { FileStore } from "./files.mjs";
import { ActorHost } from "./actors.mjs";
import { functionTable, runAction, runMaintenance } from "./functions.mjs";
import { bearer, clientIp, json, readBody, send, serveStatic } from "./http.mjs";
import { Updates } from "./updates.mjs";
import { Federation } from "./federation/index.mjs";
import { selfHostCsp } from "./csp.mjs";
import VoiceRoom from "../base44/actors/VoiceRoom/entry.ts";
import Presence from "../base44/actors/Presence/entry.ts";

const MAX_JSON = 256 * 1024;
const ENTITY_OPS = new Set(["filter", "list", "get", "create", "update", "delete"]);

export async function createApp(config, { log = console } = {}) {
  const store = new Store({ file: config.dbFile, schemas: loadSchemas(new URL("../base44/entities/", import.meta.url)) });
  const mail = createMail({ smtpUrl: config.smtpUrl, from: config.mailFrom, log });
  const auth = new Auth({ store, mail, config });
  const files = new FileStore({ dir: config.filesDir, secret: config.secret, siteUrl: config.siteUrl });

  // Deleting an account's User row removes its sign-in too; deleting a file's row removes the file.
  store.onRemove = (entity, id, row) => {
    if (entity === "User") auth.removeAccount(id);
    if (entity === "Attachment" && row?.file_uri) files.remove(row.file_uri);
  };

  const integrations = {
    Core: {
      SendEmail: (args) => mail.send(args),
      UploadPrivateFile: ({ file }) => files.upload(file),
      CreateFileSignedUrl: ({ file_uri, expires_in }) => files.signedUrl(file_uri, expires_in),
    },
  };
  const serviceClient = { entities: store.entities, integrations };
  const clientFor = (user) => ({
    entities: store.asPerson(user),
    auth: {
      me: async () => {
        if (!user) throw Object.assign(new Error("Unauthorized"), { status: 401 });
        return structuredClone(user);
      },
    },
    asServiceRole: serviceClient,
  });

  const functions = functionTable({ defaultAdmins: config.defaultServerAdmins });
  const actors = new ActorHost({ classes: { VoiceRoom, Presence }, client: { asServiceRole: serviceClient }, store, auth, log });
  const updates = new Updates({ config, store, log });
  const federation = new Federation({ config, store, serviceClient, clientFor, auth, log });
  const csp = selfHostCsp();

  // ---------- scheduled tasks (on Base44 these are workflows) ----------
  const timers = [];
  const every = (task, ms) => {
    const run = () => runMaintenance(serviceClient, task, new Date()).catch((e) => log.warn?.(`[maintenance ${task}]`, e?.message));
    timers.push(setInterval(run, ms));
    setTimeout(run, 30_000 + Math.random() * 30_000).unref?.();
  };
  every("deliver", 60_000);
  every("expire", 30 * 60_000);
  every("inactive", 6 * 3600_000);
  updates.start();
  federation.start();

  const authRoutes = {
    register: (b, ip) => auth.register(b, ip),
    "verify-otp": (b) => auth.verifyOtp(b),
    "resend-otp": (b) => auth.resendOtp(b.email),
    login: (b, ip) => auth.login(b, ip),
    "reset-request": (b) => auth.resetPasswordRequest(b.email),
    reset: (b) => auth.resetPassword(b),
  };

  async function handle(req, res) {
    const url = new URL(req.url, config.siteUrl);
    const p = url.pathname;
    const ip = clientIp(req, config.trustProxy);

    if (await federation.route(req, res, url)) return;

    if (p === "/api/health") return json(res, 200, { ok: true, version: config.version });
    if (p === "/api/site") {
      return json(res, 200, {
        id: "self-hosted",
        public_settings: { auth_config: { enable_username_password: true, mfa_policy: "off" } },
        site: { name: config.siteName, version: config.version, federation: config.federation, handle_domain: config.handleDomain, email: mail.enabled },
      });
    }

    if (p.startsWith("/api/auth/")) {
      const what = p.slice("/api/auth/".length);
      try {
        if (what === "me" && req.method === "GET") {
          const user = await auth.userFor(bearer(req));
          return user ? json(res, 200, user) : json(res, 401, { error: "Please sign in again.", code: "SIGN_IN_REQUIRED" });
        }
        if (what === "logout" && req.method === "POST") {
          auth.logout(bearer(req));
          return json(res, 200, { ok: true });
        }
        if (req.method !== "POST" || !Object.hasOwn(authRoutes, what)) return json(res, 404, { error: "Not found", code: "NOT_FOUND" });
        const body = JSON.parse((await readBody(req, 16 * 1024)) || "{}");
        return json(res, 200, await authRoutes[what](body, ip));
      } catch (err) {
        const status = err instanceof AuthError ? err.status : err?.status === 413 ? 413 : err instanceof SyntaxError ? 400 : 500;
        if (status === 500) log.error?.("[auth]", err);
        return json(res, status, { error: status === 500 ? "Something went wrong." : err.message, code: err.code || "ERROR" });
      }
    }

    if (p.startsWith("/api/functions/")) {
      const name = p.slice("/api/functions/".length);
      if (req.method !== "POST" || !Object.hasOwn(functions, name)) return json(res, 404, { error: "Unknown function.", code: "NOT_FOUND" });
      const [actions, options = {}] = functions[name];
      let raw;
      try {
        raw = await readBody(req, (options.maxBodyBytes || MAX_JSON) + 1024);
      } catch {
        return json(res, 413, { error: "That request is too large.", code: "TOO_LARGE" });
      }
      const user = await auth.userFor(bearer(req));
      const response = await runAction(clientFor(user), raw, actions, options);
      return send(res, response.status, await response.text(), { "Content-Type": "application/json; charset=utf-8" });
    }

    if (p.startsWith("/api/entities/")) {
      const [name, op] = p.slice("/api/entities/".length).split("/");
      if (req.method !== "POST" || !ENTITY_OPS.has(op) || !store.schemas[name]) return json(res, 404, { error: "Not found", code: "NOT_FOUND" });
      try {
        const b = JSON.parse((await readBody(req, MAX_JSON)) || "{}");
        const user = await auth.userFor(bearer(req));
        const t = store.asPerson(user)[name];
        const limit = Math.min(Number(b.limit) || 200, 500);
        const out =
          op === "filter" ? await t.filter(b.query && typeof b.query === "object" ? b.query : {}, typeof b.sort === "string" ? b.sort : undefined, limit, Number(b.skip) || 0)
          : op === "list" ? await t.list(typeof b.sort === "string" ? b.sort : undefined, limit, Number(b.skip) || 0)
          : op === "get" ? await t.get(String(b.id))
          : op === "create" ? await t.create(b.data || {})
          : op === "update" ? await t.update(String(b.id), b.data || {})
          : await t.delete(String(b.id));
        return json(res, 200, out);
      } catch (err) {
        const status = [400, 403, 404].includes(err?.status) ? err.status : err instanceof SyntaxError ? 400 : 500;
        if (status === 500) log.error?.("[entities]", err);
        return json(res, status, { error: status === 500 ? "Something went wrong." : err.message, code: "ERROR" });
      }
    }

    if (p.startsWith("/api/files/") && (req.method === "GET" || req.method === "HEAD")) {
      const file = files.open(p.slice("/api/files/".length), url.searchParams.get("exp"), url.searchParams.get("sig"));
      if (!file) return json(res, 404, { error: "That link has expired.", code: "NOT_FOUND" });
      res.writeHead(200, { "Content-Type": "application/octet-stream", "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Content-Length": fs.statSync(file).size });
      if (req.method === "HEAD") return res.end();
      return fs.createReadStream(file).pipe(res);
    }

    if (p.startsWith("/api/admin/updates")) return updates.route(req, res, url, await auth.userFor(bearer(req)));

    if (p.startsWith("/api/")) return json(res, 404, { error: "Not found", code: "NOT_FOUND" });
    if (req.method !== "GET" && req.method !== "HEAD") return send(res, 405, "Method not allowed");
    return serveStatic(req, res, config.distDir, csp);
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      log.error?.("[http]", err);
      if (!res.headersSent) json(res, 500, { error: "Something went wrong.", code: "INTERNAL" });
      else res.end();
    });
  });
  server.on("upgrade", (req, socket, head) => {
    if (String(req.url || "").startsWith("/api/actors/")) actors.handleUpgrade(req, socket, head);
    else socket.destroy();
  });
  server.requestTimeout = 120_000;
  server.headersTimeout = 30_000;

  return {
    server,
    store,
    auth,
    files,
    updates,
    federation,
    clientFor,
    serviceClient,
    async close() {
      for (const t of timers) clearInterval(t);
      updates.stop();
      federation.stop();
      await new Promise((r) => server.close(r));
      actors.wss.close();
      store.close();
    },
  };
}
