// Serve a production build (dist/) locally and pass /api through to Base44, so the site can be
// checked under its real Content Security Policy before it's published. The policy only exists
// in production builds: the editor preview runs Vite's dev server, which has none.
//
//   npm run build
//   CV_API_HOST=preview-sandbox--<app-id>.base44.app node tests/e2e/serve-dist.mjs 4173
//   # then run the scripts with CV_BASE_URL=http://localhost:4173
//
// Until the app is published, Base44 only answers visitors through the preview's host, so pass
// that as CV_API_HOST. The build calls the functions version it was built for
// (VITE_BASE44_FUNCTIONS_VERSION, "preview" in the editor's sandbox).
import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import path from "node:path";

const DIST = path.resolve(process.env.CV_DIST || "dist");
const PORT = Number(process.argv[2] || 4173);
const API_HOST = process.env.CV_API_HOST || "base44.app";
const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
  ".json": "application/json",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

http
  .createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    if (url.pathname.startsWith("/api/")) {
      const headers = { ...req.headers, host: API_HOST };
      delete headers.origin;
      delete headers.referer;
      const upstream = https.request({ host: API_HOST, path: req.url, method: req.method, headers }, (r) => {
        res.writeHead(r.statusCode || 502, r.headers);
        r.pipe(res);
      });
      upstream.on("error", (e) => {
        res.writeHead(502, { "content-type": "text/plain" });
        res.end(`proxy error: ${e.message}`);
      });
      req.pipe(upstream);
      return;
    }
    let file = path.join(DIST, decodeURIComponent(url.pathname));
    if (!file.startsWith(DIST + path.sep) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) file = path.join(DIST, "index.html");
    res.writeHead(200, { "content-type": TYPES[path.extname(file)] || "application/octet-stream", "cache-control": "no-store" });
    fs.createReadStream(file).pipe(res);
  })
  .listen(PORT, () => console.log(`Serving ${DIST} on http://localhost:${PORT}, API via ${API_HOST}`));
