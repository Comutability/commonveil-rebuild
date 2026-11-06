// The installable app (docs/INSTALLING.md): the service worker, installing, and updates.
import { useEffect, useState } from "react";

let policy = null;
/** Trusted Types (see csp.config.mjs): this policy only ever returns the service worker's address. */
function workerUrl() {
  if (window.trustedTypes && !policy) {
    policy = window.trustedTypes.createPolicy("service-worker", {
      createScriptURL: (u) => {
        if (u !== "/sw.js") throw new TypeError("Not the service worker");
        return u;
      },
    });
  }
  return policy ? policy.createScriptURL("/sw.js") : "/sw.js";
}

const listeners = new Set();
const state = { installPrompt: null, installed: false, updateReady: null };
const emit = () => listeners.forEach((fn) => fn({ ...state }));

export const isStandalone = () =>
  typeof window !== "undefined" && (window.matchMedia?.("(display-mode: standalone)").matches || window.navigator.standalone === true);

export const isIos = () => typeof navigator !== "undefined" && /iPhone|iPad|iPod/.test(navigator.userAgent) && !window.MSStream;

/** Start the service worker. Called once, from main.jsx. */
export function startApp() {
  if (typeof window === "undefined") return;
  state.installed = isStandalone();
  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    state.installPrompt = e;
    emit();
  });
  window.addEventListener("appinstalled", () => {
    state.installPrompt = null;
    state.installed = true;
    emit();
  });
  if (!("serviceWorker" in navigator) || import.meta.env.DEV) return;
  window.addEventListener("load", async () => {
    try {
      const reg = await navigator.serviceWorker.register(workerUrl(), { scope: "/" });
      const watch = (worker) => {
        if (!worker) return;
        worker.addEventListener("statechange", () => {
          if (worker.state === "installed" && navigator.serviceWorker.controller) {
            state.updateReady = worker;
            emit();
          }
        });
      };
      if (reg.waiting && navigator.serviceWorker.controller) {
        state.updateReady = reg.waiting;
        emit();
      }
      reg.addEventListener("updatefound", () => watch(reg.installing));
      // Look for a new version now and then.
      setInterval(() => reg.update().catch(() => {}), 60 * 60_000);
    } catch {
      // No service worker (a private window, or blocked): the site works as an ordinary page.
    }
  });
  let reloading = false;
  navigator.serviceWorker?.addEventListener("controllerchange", () => {
    if (reloading || !state.updating) return;
    reloading = true;
    window.location.reload();
  });
}

/** Show the browser's install dialog. Answers "accepted", "dismissed" or "unavailable". */
export async function install() {
  const p = state.installPrompt;
  if (!p) return "unavailable";
  p.prompt();
  const { outcome } = await p.userChoice;
  state.installPrompt = null;
  emit();
  return outcome;
}

/** Switch to the new version that's waiting. */
export function applyUpdate() {
  if (!state.updateReady) return;
  state.updating = true;
  state.updateReady.postMessage({ type: "skip-waiting" });
}

/** { installPrompt, installed, updateReady } */
export function useApp() {
  const [s, setS] = useState({ ...state });
  useEffect(() => {
    listeners.add(setS);
    return () => listeners.delete(setS);
  }, []);
  return s;
}
