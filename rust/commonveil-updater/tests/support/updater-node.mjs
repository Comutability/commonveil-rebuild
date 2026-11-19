// Runs the Node.js updater (updater/updater.mjs), unchanged, on the port the test chose: it always
// listens on 8090, and tests that run side by side would collide there.
import http from "node:http";

const listen = http.Server.prototype.listen;
http.Server.prototype.listen = function (_port, ...rest) {
  return listen.call(this, Number(process.env.UPDATER_TEST_PORT), ...rest);
};
await import(new URL("../../../../updater/updater.mjs", import.meta.url));
