// Small HTTP helpers for the self-hosted server.
import fs from "node:fs";
import path from "node:path";
import { DEFAULT_SITE_URL, headHtml, seoFor } from "../src/lib/site/seo.js";

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
    // The last address is the one our own proxy added; earlier ones are whatever the client sent.
    const f = String(req.headers["x-forwarded-for"] || "").split(",").map((x) => x.trim()).filter(Boolean).pop();
    if (f) return f;
  }
  return req.socket.remoteAddress || "";
}

const TYPES = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp",
  ".ico": "image/x-icon", ".woff2": "font/woff2", ".woff": "font/woff", ".txt": "text/plain; charset=utf-8", ".xml": "application/xml; charset=utf-8", ".webmanifest": "application/manifest+json", ".wasm": "application/wasm",
};

// Each page's own title, description and link-preview tags, written into the HTML it's sent with,
// so search engines and link previews needn't run any script (src/lib/site/seo.js).
const seoCache = new Map();
function seoAssets(distDir) {
  if (!seoCache.has(distDir)) {
    let articles = [];
    try {
      articles = JSON.parse(fs.readFileSync(path.join(distDir, "help-index.json"), "utf8"));
    } catch {
      articles = [];
    }
    seoCache.set(distDir, { html: fs.readFileSync(path.join(distDir, "index.html"), "utf8"), articles });
  }
  return seoCache.get(distDir);
}

/** The page for a path, with its own tags, and whether it exists. */
export function pageFor(distDir, pathname, siteUrl) {
  const { html, articles } = seoAssets(distDir);
  const meta = seoFor(pathname, { articles, siteUrl });
  const block = /<!-- seo:[^>]*-->[\s\S]*?<!-- \/seo -->/;
  return { body: block.test(html) ? html.replace(block, headHtml(meta, siteUrl)) : html, notFound: meta.notFound, noindex: meta.noindex, movedTo: meta.movedTo || "" };
}

/** Serve the built site, falling back to index.html for the app's own routes. */
export function serveStatic(req, res, distDir, csp, { siteUrl = "" } = {}) {
  const url = new URL(req.url, "http://local");
  let rel;
  try {
    rel = decodeURIComponent(url.pathname);
  } catch {
    return send(res, 400, "Bad path");
  }
  if (rel.includes("\0")) return send(res, 400, "Bad path");
  const root = path.resolve(distDir);
  let file = path.resolve(root, `.${path.posix.normalize(`/${rel}`)}`);
  if (file !== root && !file.startsWith(root + path.sep)) return send(res, 404, "Not found");
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
    // The service worker and manifest must be checked every time, or new versions wouldn't arrive.
    "Cache-Control": isIndex || ext === ".html" || /[\\/](sw\.js|manifest\.webmanifest)$/.test(file) ? "no-cache" : /\/assets\//.test(file) ? "public, max-age=31536000, immutable" : "public, max-age=3600",
  };
  if (ext === ".html") {
    headers["Content-Security-Policy"] = csp;
    headers["X-Frame-Options"] = "DENY";
  }
  if (isIndex && siteUrl) {
    const page = pageFor(distDir, rel, siteUrl);
    if (page.movedTo) {
      res.writeHead(301, { ...SECURITY_HEADERS, Location: page.movedTo, "Cache-Control": "public, max-age=86400" });
      return res.end();
    }
    if (page.noindex) headers["X-Robots-Tag"] = "noindex, nofollow";
    // An unknown address is a real "not found", so it isn't indexed as a page of the site.
    res.writeHead(page.notFound ? 404 : 200, headers);
    return res.end(req.method === "HEAD" ? undefined : page.body);
  }
  // The sitemap and robots file are written for the usual address; this site's own goes in.
  if (siteUrl && /[\\/](sitemap\.xml|robots\.txt)$/.test(file)) {
    const text = fs.readFileSync(file, "utf8").split(DEFAULT_SITE_URL).join(siteUrl.replace(/\/+$/, ""));
    headers["Content-Type"] = file.endsWith(".xml") ? "application/xml; charset=utf-8" : headers["Content-Type"];
    res.writeHead(200, headers);
    return res.end(req.method === "HEAD" ? undefined : text);
  }
  if (req.method === "HEAD") {
    res.writeHead(200, headers);
    return res.end();
  }
  res.writeHead(200, headers);
  fs.createReadStream(file).pipe(res);
}
