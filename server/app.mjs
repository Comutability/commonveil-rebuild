// The self-hosted Commonveil server: the site, its backend functions, sign-in, files, realtime
// rooms, scheduled tasks, updates and the Commonveil Protocol, in one process.
import http from "node:http";
import fs from "node:fs";
import { Store, loadSchemas } from "./store.mjs";
import { userRecord, verifyAccess } from "../base44/shared/identity/sessions.ts";
import { configurePush } from "../base44/shared/handlers/notifications.ts";
import { FileStore } from "./files.mjs";
import { ActorHost } from "./actors.mjs";
import { functionTable, runAction, runMaintenance } from "./functions.mjs";
import { bearer, json, readBody, send, serveStatic } from "./http.mjs";
import { Updates } from "./updates.mjs";
import { Federation } from "./federation/index.mjs";
import { selfHostCsp } from "./csp.mjs";
import { createBootstrap } from "./bootstrap.mjs";
import VoiceRoom from "../base44/actors/VoiceRoom/entry.ts";
import Presence from "../base44/actors/Presence/entry.ts";

const MAX_JSON = 256 * 1024;
const ENTITY_OPS = new Set(["filter", "list", "get", "create", "update", "delete"]);
// Tables the app only ever reads through the backend functions, which also apply rules a row rule
// can't express (a channel's newcomer-history setting, CV-06). Direct reads of them are refused.
const FUNCTIONS_ONLY = new Set(["ServerMessage"]);

export async function createApp(config, options = {}) {
  const log = options.log || console;
  const store = new Store({ file: config.dbFile, schemas: loadSchemas(new URL("../base44/entities/", import.meta.url)) });
  const files = new FileStore({ dir: config.filesDir, secret: config.secret, siteUrl: config.siteUrl });

  // Deleting a file's row removes the file. (Deleting an account removes its sign-in in the
  // shared code, base44/shared/accountDeletion.ts, as on Base44.)
  store.onRemove = (entity, id, row) => {
    if (entity === "Attachment" && row?.file_uri) files.remove(row.file_uri);
  };

  const integrations = {
    Core: {
      UploadPrivateFile: ({ file }) => files.upload(file),
      CreateFileSignedUrl: ({ file_uri, expires_in }) => files.signedUrl(file_uri, expires_in),
    },
  };
  const serviceClient = { entities: store.entities, integrations };

  // Who's calling: Commonveil sign-in's access token, sent as the bearer token (docs/IDENTITY.md).
  const auth = {
    /** { user, session } for an access token, or null. */
    async sessionFor(token) {
      const session = await verifyAccess(serviceClient, token);
      const record = session ? await userRecord(serviceClient, session.userId) : null;
      return record ? { user: { ...record, id: record.id, email: record.email || "", role: record.role || "user" }, session } : null;
    },
    async userFor(token) {
      return (await this.sessionFor(token))?.user || null;
    },
  };
  const clientFor = (user, session = null) => ({
    entities: store.asPerson(user),
    auth: {
      me: async () => {
        if (!user) throw Object.assign(new Error("Unauthorized"), { status: 401 });
        return structuredClone(user);
      },
      session: async () => session,
    },
    asServiceRole: serviceClient,
  });

  configurePush(config.siteUrl);
  const bootstrap = createBootstrap({ dataDir: config.dataDir, log });
  await bootstrap.prepare(serviceClient);
  const functions = functionTable({
    defaultAdmins: config.defaultServerAdmins,
    snipForum: config.snipForum,
    identity: {
      realm: config.host,
      siteName: config.siteName,
      passkeyHost: (h) => h === config.host,
      // The first account needs the operator's one-time setup code (server/bootstrap.mjs).
      bootstrap,
      registrationOpen: () => config.openRegistration,
      passwordRounds: config.passwordRounds,
    },
  });
  const updates = new Updates({ config, store, log });
  const federation = new Federation({ config, store, serviceClient, clientFor, auth, log, transport: options.transport });
  const actors = new ActorHost({ classes: { VoiceRoom, Presence }, client: { asServiceRole: serviceClient }, store, auth, log, federation });
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

  async function handle(req, res) {
    const url = new URL(req.url, config.siteUrl);
    const p = url.pathname;

    if (await federation.route(req, res, url)) return;

    if (p === "/api/health") return json(res, 200, { ok: true, version: config.version });
    if (p === "/api/site") {
      return json(res, 200, {
        id: "self-hosted",
        public_settings: { auth_config: { enable_username_password: true, mfa_policy: "off" } },
        site: { name: config.siteName, version: config.version, federation: config.federation, handle_domain: config.handleDomain, email: false },
      });
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
      const who = await auth.sessionFor(bearer(req));
      const user = who?.user || null;
      const fedOptions = { ...options, trustPlatformUser: true, federation: federation.enabled ? federation.handlers : undefined };
      const runLocal = async (bodyText) => {
        const r = await runAction(clientFor(user, who?.session), bodyText, actions, fedOptions);
        const text = await r.text();
        let data = null;
        try {
          data = JSON.parse(text);
        } catch {
          data = null;
        }
        return { status: r.status, data };
      };
      // Something on another site, or "all of mine" across sites: the protocol relays it.
      const relayed = await federation.relayFunction(name, raw, user, runLocal);
      if (relayed) return json(res, relayed.status, relayed.data ?? {});
      const response = await runAction(clientFor(user, who?.session), raw, actions, fedOptions);
      return send(res, response.status, await response.text(), { "Content-Type": "application/json; charset=utf-8" });
    }

    if (p.startsWith("/api/entities/")) {
      const [name, op] = p.slice("/api/entities/".length).split("/");
      if (req.method !== "POST" || !ENTITY_OPS.has(op) || !store.schemas[name] || FUNCTIONS_ONLY.has(name)) return json(res, 404, { error: "Not found", code: "NOT_FOUND" });
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
    return serveStatic(req, res, config.distDir, csp, { siteUrl: config.siteUrl });
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      log.error?.("[http]", err);
      if (!res.headersSent) json(res, 500, { error: "Something went wrong.", code: "INTERNAL" });
      else res.end();
    });
  });
  server.on("upgrade", (req, socket, head) => {
    const u = String(req.url || "");
    if (u.startsWith("/api/actors/")) actors.handleUpgrade(req, socket, head);
    else if (u.startsWith("/cvp/v1/actors/") || (config.federationPrefix && u.startsWith(`${config.federationPrefix}/cvp/v1/actors/`))) federation.acceptActor(req, socket, head, actors);
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
    bootstrap,
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
