// Saved pages and guide progress on the public site. Kept in this browser's local storage
// only: nothing about what you read, save or finish is sent anywhere, and no account is
// involved. Clearing site data (or "Clear everything" on the Saved page) removes it.
import { useCallback, useEffect, useState } from "react";

const SAVED_KEY = "commonveil:saved";
const DONE_KEY = "commonveil:done";
const CHANGED = "commonveil:saved-changed";
const MAX_SAVED = 500;

export const KIND_PATHS = Object.freeze({ guide: "/guides/", wiki: "/wiki/", blog: "/blog/", path: "/paths/" });
export const KIND_LABELS = Object.freeze({ guide: "Guide", wiki: "Wiki", blog: "Blog post", path: "Learning path" });
const SLUG_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,159}$/;
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

const today = () => new Date().toISOString().slice(0, 10);

/** Only well-formed entries survive, whatever is in storage. */
export function cleanSaved(value) {
  if (!Array.isArray(value)) return [];
  const seen = new Set();
  const out = [];
  for (const s of value) {
    if (!s || !KIND_PATHS[s.kind] || typeof s.slug !== "string" || !SLUG_RE.test(s.slug) || typeof s.title !== "string") continue;
    const id = `${s.kind}:${s.slug}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({ kind: s.kind, slug: s.slug, title: s.title.slice(0, 200), saved_on: DAY_RE.test(s.saved_on) ? s.saved_on : null });
    if (out.length >= MAX_SAVED) break;
  }
  return out;
}

/** { [guide slug]: day it was marked done } */
export function cleanDone(value) {
  const out = {};
  if (!value || typeof value !== "object" || Array.isArray(value)) return out;
  for (const [slug, day] of Object.entries(value)) {
    if (SLUG_RE.test(slug) && DAY_RE.test(day)) out[slug] = day;
  }
  return out;
}

export const hrefOf = (item) => `${KIND_PATHS[item.kind]}${item.slug}`;

function read(key) {
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function write(key, value) {
  try {
    if (value === null) window.localStorage.removeItem(key);
    else window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* storage may be off (private windows, blocked site data): the page still works, it just won't remember */
  }
  window.dispatchEvent(new Event(CHANGED));
}

export function useSaved() {
  const [saved, setSaved] = useState(() => cleanSaved(read(SAVED_KEY)));
  const [done, setDone] = useState(() => cleanDone(read(DONE_KEY)));

  useEffect(() => {
    const sync = () => {
      setSaved(cleanSaved(read(SAVED_KEY)));
      setDone(cleanDone(read(DONE_KEY)));
    };
    window.addEventListener("storage", sync);
    window.addEventListener(CHANGED, sync);
    return () => {
      window.removeEventListener("storage", sync);
      window.removeEventListener(CHANGED, sync);
    };
  }, []);

  const isSaved = useCallback((kind, slug) => saved.some((s) => s.kind === kind && s.slug === slug), [saved]);

  const toggleSaved = useCallback(({ kind, slug, title }) => {
    const current = cleanSaved(read(SAVED_KEY));
    const exists = current.some((s) => s.kind === kind && s.slug === slug);
    write(SAVED_KEY, exists ? current.filter((s) => !(s.kind === kind && s.slug === slug)) : cleanSaved([{ kind, slug, title, saved_on: today() }, ...current]));
  }, []);

  const isDone = useCallback((slug) => Boolean(done[slug]), [done]);

  const toggleDone = useCallback((slug) => {
    const current = cleanDone(read(DONE_KEY));
    if (current[slug]) delete current[slug];
    else current[slug] = today();
    write(DONE_KEY, current);
  }, []);

  const clearAll = useCallback(() => {
    write(SAVED_KEY, null);
    write(DONE_KEY, null);
  }, []);

  return { saved, done, isSaved, toggleSaved, isDone, toggleDone, clearAll };
}
