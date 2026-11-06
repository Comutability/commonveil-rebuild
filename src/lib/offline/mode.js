// Offline mode (docs/OFFLINE.md): whether this browser is reaching the server at all.
//
//   - Chosen offline: you turned offline mode on. Nothing is fetched; messages you send wait.
//   - Cut off: the connection dropped (or the server can't be reached). Messages you send wait,
//     and the app keeps checking quietly.
//
// Either way, waiting messages go out as soon as you're back (see outbox.js).
import { useEffect, useState } from "react";

const KEY = "commonveil_offline_mode";
const listeners = new Set();
let chosen = read();
let cutOff = typeof navigator !== "undefined" && navigator.onLine === false;

function read() {
  try {
    return window.localStorage.getItem(KEY) === "1";
  } catch {
    return false;
  }
}

const emit = () => listeners.forEach((fn) => fn({ chosen, cutOff }));

export function offlineChosen() {
  return chosen;
}

/** Offline mode, or no connection: don't try the network for sends. */
export function isOffline() {
  return chosen || cutOff;
}

export function setOfflineMode(on) {
  chosen = Boolean(on);
  try {
    if (chosen) window.localStorage.setItem(KEY, "1");
    else window.localStorage.removeItem(KEY);
  } catch {
    // Not remembered after a reload; still on for now.
  }
  emit();
}

/** Called when a request couldn't reach the server (true) or just did (false). */
export function reportReachable(ok) {
  const next = !ok;
  if (next !== cutOff) {
    cutOff = next;
    emit();
  }
}

export function onOfflineChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

if (typeof window !== "undefined") {
  window.addEventListener("offline", () => reportReachable(false));
  window.addEventListener("online", () => reportReachable(true));
}

/** { chosen, cutOff } for components. */
export function useOffline() {
  const [state, setState] = useState({ chosen, cutOff });
  useEffect(() => onOfflineChange(setState), []);
  return state;
}
