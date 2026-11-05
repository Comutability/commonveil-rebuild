// Small HTTP helpers for the self-hosted server.
import fs from "node:fs";
import path from "node:path";

export const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(self), microphone=(self), display-capture=(self), geolocation=(), payment=(), usb=(), interest-cohort=()",
};

export function send(res, status, body, headers = {}) {
  const isJson = body !== null && typeof body === "object" && !Buffer.isBuffer(body);
  const data = isJson ? JSON.stringify(body) : body ?? "";
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    "Cache-Control": "no-store",
    ...(isJson ? { "Content-Type": "application/json; charset=utf-8" } : {}),
    ...headers,
  });
  res.end(data);
}

export const json = (res, status, body, headers) => send(res, status, body, headers);

/** The request body as text, refusing anything longer than max bytes. */
export function readBody(req, max) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > max) {
        reject(Object.assign(new Error("too large"), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

export function bearer(req) {
  const h = String(req.headers.authorization || "");
  return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
}

export function clientIp(req, trustProxy) {
  if (trustProxy) {
    const f = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    if (f) return f;
  }
  return req.socket.remoteAddress || "";
}

const TYPES = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp",
  ".ico": "image/x-icon", ".woff2": "font/woff2", ".woff": "font/woff", ".txt": "text/plain; charset=utf-8", ".webmanifest": "application/manifest+json", ".wasm": "application/wasm",
};

/** Serve the built site, falling back to index.html for the app's own routes. */
export function serveStatic(req, res, distDir, csp) {
  const url = new URL(req.url, "http://local");
  let rel = decodeURIComponent(url.pathname);
  if (rel.includes("\0")) return send(res, 400, "Bad path");
  let file = path.join(distDir, path.normalize(rel).replace(/^(\.\.[/\\])+/, ""));
  if (!file.startsWith(distDir)) return send(res, 404, "Not found");
  let isIndex = false;
  if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    // A missing asset is a 404; anything else is a page of the app.
    if (/^\/assets\//.test(rel) || path.extname(rel)) return send(res, 404, "Not found", { "Content-Type": "text/plain" });
    file = path.join(distDir, "index.html");
    isIndex = true;
  }
  const ext = path.extname(file).toLowerCase();
  const headers = {
    ...SECURITY_HEADERS,
    "Content-Type": TYPES[ext] || "application/octet-stream",
    "Cache-Control": isIndex || ext === ".html" ? "no-cache" : /\/assets\//.test(file) ? "public, max-age=31536000, immutable" : "public, max-age=3600",
  };
  if (ext === ".html") {
    headers["Content-Security-Policy"] = csp;
    headers["X-Frame-Options"] = "DENY";
  }
  if (req.method === "HEAD") {
    res.writeHead(200, headers);
    return res.end();
  }
  res.writeHead(200, headers);
  fs.createReadStream(file).pipe(res);
}
