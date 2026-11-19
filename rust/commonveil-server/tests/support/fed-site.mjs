// A Node.js Commonveil site for the Rust tests that run sites side by side: the same server as
// server/index.mjs, reaching the other test sites by name through CV_SITE_PORTS
// ({ "alpha.test": 41001, ... }), all on 127.0.0.1 (as tests/support/selfhost.mjs does in-process).
import { register } from "node:module";

register(new URL("../../../../server/loader.mjs", import.meta.url).href);

const { loadConfig } = await import(new URL("../../../../server/config.mjs", import.meta.url).href);
const { createApp } = await import(new URL("../../../../server/app.mjs", import.meta.url).href);
const { Transport } = await import(new URL("../../../../server/federation/net.mjs", import.meta.url).href);

const ports = JSON.parse(process.env.CV_SITE_PORTS || "{}");
const portFor = (host) => {
  const h = host.replace(/:\d+$/, "");
  const site = Object.keys(ports).find((n) => h === n || h.endsWith(`.${n}`));
  if (!site) throw new Error(`unknown test site ${host}`);
  return ports[site];
};
const transport = new Transport({ allowPrivate: true, hostHeader: true, urlFor: (host, p, ws) => `${ws ? "ws" : "http"}://127.0.0.1:${portFor(host)}${p}` });
const quiet = { info() {}, warn() {}, error: (...a) => console.error(...a) };
const config = loadConfig(process.env);
const app = await createApp(config, { log: quiet, transport });
app.server.listen(config.port, "127.0.0.1", () => console.log("ready"));
const stop = async () => {
  await app.close().catch(() => {});
  process.exit(0);
};
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
