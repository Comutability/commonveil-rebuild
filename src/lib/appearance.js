// How the app looks on this browser: theme, message density, text size, motion. Kept in this
// browser's local storage only; it says nothing about you and never leaves the device.
import { useEffect, useState } from "react";

const KEY = "commonveil:appearance";

export const DEFAULT_APPEARANCE = Object.freeze({ theme: "system", density: "cozy", textSize: 100, reduceMotion: false });
export const TEXT_SIZES = [90, 100, 112, 125];

function read() {
  try {
    const saved = JSON.parse(window.localStorage.getItem(KEY) || "{}");
    return clean(saved);
  } catch {
    return { ...DEFAULT_APPEARANCE };
  }
}

function clean(a) {
  return {
    theme: ["system", "light", "dark"].includes(a?.theme) ? a.theme : "system",
    density: a?.density === "compact" ? "compact" : "cozy",
    textSize: TEXT_SIZES.includes(a?.textSize) ? a.textSize : 100,
    reduceMotion: a?.reduceMotion === true,
  };
}

const listeners = new Set();
let current = typeof window === "undefined" ? { ...DEFAULT_APPEARANCE } : read();
let media = null;

function systemDark() {
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-color-scheme: dark)").matches;
}

/** Put the settings on <html>: data-theme for the colours, .dark for components that use it. */
export function applyAppearance(a = current) {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  if (a.theme === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", a.theme);
  root.classList.toggle("dark", a.theme === "dark" || (a.theme === "system" && systemDark()));
  root.dataset.density = a.density;
  root.style.fontSize = a.textSize === 100 ? "" : `${a.textSize}%`;
  root.classList.toggle("reduce-motion", a.reduceMotion);
  if (!media && typeof window !== "undefined" && window.matchMedia) {
    media = window.matchMedia("(prefers-color-scheme: dark)");
    media.addEventListener?.("change", () => applyAppearance(current));
  }
}

export function getAppearance() {
  return current;
}

export function setAppearance(changes) {
  current = clean({ ...current, ...changes });
  try {
    window.localStorage.setItem(KEY, JSON.stringify(current));
  } catch {
    /* private windows can refuse storage: the choice still applies until the page closes */
  }
  applyAppearance(current);
  for (const fn of listeners) fn(current);
  return current;
}

/** The current appearance, kept up to date. */
export function useAppearance() {
  const [value, setValue] = useState(current);
  useEffect(() => {
    listeners.add(setValue);
    return () => listeners.delete(setValue);
  }, []);
  return value;
}
