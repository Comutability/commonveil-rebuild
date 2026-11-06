// Run real self-hosted Commonveil servers (server/) in this process, for tests: each with its own
// data folder and port, all reachable by name through a transport that maps names to ports.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { register } from "node:module";

register("../../server/loader.mjs", import.meta.url);
const { createApp } = await import("../../server/app.mjs");
const { loadConfig } = await import("../../server/config.mjs");
const { Transport } = await import("../../server/federation/net.mjs");

const quiet = { info() {}, warn() {}, error: (...a) => console.error(...a) };

/** Start sites by name ("alpha.test", ...). Answers { sites: { name: { app, port, url } }, close() }. */
export async function startSites(names, env = {}) {
  const ports = {};
  const portFor = (host) => {
    const h = host.replace(/:\d+$/, "");
    const site = names.find((n) => h === n || h.endsWith(`.${n}`));
    if (!site) throw new Error(`unknown test site ${host}`);
    return ports[site];
  };
  const transport = new Transport({
    allowPrivate: true,
    hostHeader: true,
    urlFor: (host, p, ws) => `${ws ? "ws" : "http"}://127.0.0.1:${portFor(host)}${p}`,
  });
  const sites = {};
  for (const name of names) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), `cv-${name}-`));
    const config = loadConfig({ DATA_DIR: dir, SITE_URL: `http://${name}`, TRUST_PROXY: "true", FEDERATION_ALLOW_PRIVATE: "true", UPDATE_CHECK_HOURS: "1000", ...env });
    const app = await createApp(config, { log: quiet, transport });
    await new Promise((r) => app.server.listen(0, "127.0.0.1", r));
    ports[name] = app.server.address().port;
    sites[name] = { app, config, dir, port: ports[name], url: `http://127.0.0.1:${ports[name]}` };
  }
  return {
    sites,
    transport,
    async close() {
      for (const s of Object.values(sites)) {
        await s.app.close().catch(() => {});
        fs.rmSync(s.dir, { recursive: true, force: true });
      }
    },
  };
}

/** HTTP to a site, as if from a browser on it. */
export async function http(site, p, { method = "GET", body, token, host } = {}) {
  const res = await fetch(`${site.url}${p}`, {
    method,
    headers: { ...(body !== undefined ? { "Content-Type": "application/json" } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}), "X-Forwarded-Host": host || site.config.host },
    body: body !== undefined ? JSON.stringify(body) : undefined,
    redirect: "manual",
  });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  return { status: res.status, data, headers: res.headers };
}
