import { useEffect } from "react";
import { useLocation } from "react-router-dom";
import { HELP_ARTICLES } from "@/lib/site/helpContent";
import { SHARE_IMAGE, SHARE_IMAGE_ALT, SITE_NAME, jsonLdText, seoFor } from "@/lib/site/seo";

// Keeps the page's <head> right for search engines and link previews as you move around the
// site (src/lib/site/seo.js says what each page tells them). Renders nothing.

// Structured data goes in <script type="application/ld+json">. Under Trusted Types, setting a
// script's text needs a policy; this one only ever wraps JSON this file has just made.
let policy = null;
function trustedJson(text) {
  if (!policy && typeof window !== "undefined" && window.trustedTypes) {
    try {
      policy = window.trustedTypes.createPolicy("json-ld", { createScript: (s) => s });
    } catch {
      policy = { createScript: () => null };
    }
  }
  return policy ? policy.createScript(text) : text;
}

function setMeta(attr, key, content) {
  let el = document.head.querySelector(`meta[${attr}="${key}"]`);
  if (content == null) {
    el?.remove();
    return;
  }
  if (!el) {
    el = document.createElement("meta");
    el.setAttribute(attr, key);
    document.head.appendChild(el);
  }
  el.setAttribute("content", content);
}

function setCanonical(href) {
  let el = document.head.querySelector('link[rel="canonical"]');
  if (!href) {
    el?.remove();
    return;
  }
  if (!el) {
    el = document.createElement("link");
    el.setAttribute("rel", "canonical");
    document.head.appendChild(el);
  }
  el.setAttribute("href", href);
}

function setJsonLd(items) {
  for (const old of document.head.querySelectorAll("script[data-seo]")) old.remove();
  for (const data of items) {
    const text = trustedJson(jsonLdText(data));
    if (text == null) continue;
    const s = document.createElement("script");
    s.type = "application/ld+json";
    s.setAttribute("data-seo", "");
    s.text = text;
    document.head.appendChild(s);
  }
}

export default function Seo() {
  const { pathname } = useLocation();
  useEffect(() => {
    const siteUrl = window.location.origin;
    const m = seoFor(pathname, { articles: HELP_ARTICLES, siteUrl });
    document.title = m.title;
    setMeta("name", "description", m.description);
    setMeta("name", "robots", m.noindex ? "noindex, nofollow" : "index, follow, max-image-preview:large");
    const open = !m.noindex;
    setCanonical(open ? m.url : null);
    const image = `${siteUrl}${SHARE_IMAGE}`;
    for (const [k, v] of [
      ["og:type", m.ogType],
      ["og:site_name", SITE_NAME],
      ["og:locale", "en_GB"],
      ["og:title", m.title],
      ["og:description", m.description],
      ["og:url", m.url],
      ["og:image", image],
      ["og:image:width", "1200"],
      ["og:image:height", "630"],
      ["og:image:alt", SHARE_IMAGE_ALT],
    ]) setMeta("property", k, open ? v : null);
    for (const [k, v] of [
      ["twitter:card", "summary_large_image"],
      ["twitter:title", m.title],
      ["twitter:description", m.description],
      ["twitter:image", image],
      ["twitter:image:alt", SHARE_IMAGE_ALT],
    ]) setMeta("name", k, open ? v : null);
    setJsonLd(open ? m.jsonLd : []);
  }, [pathname]);
  return null;
}
