// The service worker (public/sw.js), run with stand-ins for the browser: what a notification shows,
// where tapping it leads, quiet hours, and what it does (and doesn't) keep.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const SOURCE = readFileSync(new URL("../public/sw.js", import.meta.url), "utf8");

function worker({ prefs = {}, windows = [] } = {}) {
  const handlers = {};
  const shown = [];
  const opened = [];
  const fakeIdb = {
    open() {
      const req = {};
      setTimeout(() => {
        req.result = { createObjectStore() {}, transaction: () => ({ objectStore: () => ({ get() { const g = {}; setTimeout(() => { g.result = prefs; g.onsuccess?.(); }); return g; } }) }) };
        req.onsuccess?.();
      });
      return req;
    },
  };
  const self = {
    location: { origin: "https://commonveil.online" },
    addEventListener: (type, fn) => (handlers[type] = fn),
    registration: {
      showNotification: async (title, options) => shown.push({ title, ...options }),
      getNotifications: async () => [],
    },
    clients: { matchAll: async () => windows, openWindow: async (url) => opened.push(url), claim: async () => {} },
    skipWaiting() {},
  };
  const context = vm.createContext({ self, indexedDB: fakeIdb, caches: { open: async () => ({ addAll: async () => {}, put: async () => {}, keys: async () => [] }), keys: async () => [], match: async () => new Response("kept") }, navigator: {}, URL, Response, fetch: async () => new Response("") , setTimeout, console });
  vm.runInContext(SOURCE, context);
  const fire = async (type, event) => {
    let work = null;
    handlers[type]({ ...event, waitUntil: (p) => (work = p), respondWith: (p) => (event.responded = p) });
    await work;
  };
  return { handlers, shown, opened, fire };
}

const pushOf = (payload) => ({ data: { json: () => payload } });

test("a notification says only that there's something new", async () => {
  const w = worker();
  await w.fire("push", pushOf({ v: 1, k: "message", c: "one-time-code", m: "" }));
  assert.equal(w.shown.length, 1);
  const n = w.shown[0];
  assert.equal(n.title, "Commonveil");
  assert.equal(n.body, "New message");
  assert.equal(n.tag, "commonveil", "each replaces the last, so fewer are kept on the device");
  assert.equal(JSON.stringify(n.data), JSON.stringify({ c: "one-time-code" }), "nothing but the one-time code");
  assert.equal(n.silent, false);
  // Whatever a push might carry, only known words are ever shown.
  await w.fire("push", pushOf({ k: "message", body: "Meet at six", title: "From Ann" }));
  assert.equal(w.shown[1].body, "New message");
  assert.equal(w.shown[1].title, "Commonveil");
  await w.fire("push", { data: { json: () => { throw new Error("not JSON"); } } });
  assert.equal(w.shown[2].body, "New activity", "something unreadable still shows nothing in particular");
});

test("quiet hours and focus keep notifications silent", async () => {
  const always = worker({ prefs: { quiet: true, quietFrom: 0, quietTo: 1439 } });
  await always.fire("push", pushOf({ k: "message", c: "x" }));
  assert.equal(always.shown[0].silent, true);
  const focus = worker({ prefs: { focusUntil: Date.now() + 3600_000 } });
  await focus.fire("push", pushOf({ k: "message", c: "x" }));
  assert.equal(focus.shown[0].silent, true);
});

test("tapping a notification opens the app with its code, or focuses an open window", async () => {
  const w = worker();
  let closed = false;
  await w.fire("notificationclick", { notification: { data: { c: "abc" }, close: () => (closed = true) } });
  assert.ok(closed);
  assert.equal(JSON.stringify(w.opened), JSON.stringify(["/app?push=abc"]));

  const posted = [];
  const open = { url: "https://commonveil.online/app/s/1", focus: async () => {}, postMessage: (m) => posted.push(m) };
  const w2 = worker({ windows: [open] });
  await w2.fire("notificationclick", { notification: { data: { c: "def" }, close() {} } });
  assert.equal(JSON.stringify(posted), JSON.stringify([{ type: "push-open", code: "def" }]));
  assert.equal(w2.opened.length, 0);
});

test("the worker never handles anything from the backend", () => {
  const w = worker();
  for (const path of ["/api/functions/messages", "/api/apps/1/functions/keys", "/cvp/v1/act", "/.well-known/commonveil", "/sw.js"]) {
    const event = { request: { method: "GET", url: `https://commonveil.online${path}`, mode: "cors" } };
    w.handlers.fetch({ ...event, respondWith: () => (event.responded = true) });
    assert.equal(event.responded, undefined, `${path} goes straight to the network, never kept`);
  }
  const post = { request: { method: "POST", url: "https://commonveil.online/assets/x.js", mode: "cors" } };
  w.handlers.fetch({ ...post, respondWith: () => (post.responded = true) });
  assert.equal(post.responded, undefined);
  const asset = { request: { method: "GET", url: "https://commonveil.online/assets/index-abc.js", mode: "cors" } };
  w.handlers.fetch({ ...asset, respondWith: () => (asset.responded = true) });
  assert.equal(asset.responded, true, "the app's own files are kept");
});
