// Start a self-hosted Commonveil server.   node server/index.mjs
// Settings come from environment variables: see docs/SELF_HOSTING.md.
import { register } from "node:module";

register("./loader.mjs", import.meta.url);

const { loadConfig } = await import("./config.mjs");
const { createApp } = await import("./app.mjs");
const { runCli } = await import("./cli.mjs");

const config = loadConfig();

if (process.argv[2]) {
  // Admin commands, for example: node server/index.mjs reset-password someone@example.com
  process.exitCode = await runCli(config, process.argv.slice(2));
} else {
  const app = await createApp(config);
  app.server.listen(config.port, config.bind, () => {
    console.log(`Commonveil ${config.version} is running at ${config.siteUrl} (listening on ${config.bind}:${config.port})`);
  });
  const stop = async (signal) => {
    console.log(`${signal}: stopping`);
    await app.close().catch(() => {});
    process.exit(0);
  };
  process.on("SIGTERM", () => stop("SIGTERM"));
  process.on("SIGINT", () => stop("SIGINT"));
}
