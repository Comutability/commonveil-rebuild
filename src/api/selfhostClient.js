// The app's connection to a self-hosted Commonveil server (server/), with the same shape as the
// parts of the Base44 SDK the app uses: sign-in, backend functions, a few tables, and realtime
// rooms. Used when the site is built with VITE_COMMONVEIL_BACKEND=selfhost.
import { WebSocket as ReconnectingWebSocket } from "partysocket";

const TOKEN_KEY = "base44_access_token"; // the same key app-params.js reads
const PING_MS = 1000;
const DEAD_MS = 3000;

const readToken = () => {
  try {
    return window.localStorage.getItem(TOKEN_KEY) || "";
  } catch {
    return "";
  }
};

function writeToken(t) {
  try {
    if (t) window.localStorage.setItem(TOKEN_KEY, t);
    else window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    // Private windows may refuse storage; the session then lasts as long as the page.
  }
}

class HttpError extends Error {
  constructor(status, data) {
    super(data?.error || `Request failed (${status})`);
    this.status = status;
    this.data = data;
    this.response = { status, data };
  }
}

export function createSelfHostClient() {
  let token = readToken();

  async function request(path, body, method = "POST") {
    let res;
    try {
      res = await fetch(path, {
        method,
        headers: { ...(body !== undefined ? { "Content-Type": "application/json" } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        credentials: "omit",
        cache: "no-store",
      });
    } catch {
      throw new HttpError(0, { error: "Can't reach the server." });
    }
    const text = await res.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = { error: text };
    }
    if (!res.ok) throw new HttpError(res.status, data || {});
    return data;
  }

  const setToken = (t) => {
    token = t || "";
    writeToken(token);
  };

  const auth = {
    setToken,
    async me() {
      if (!token) throw new HttpError(401, { error: "Please sign in." });
      return request("/api/auth/me", undefined, "GET");
    },
    async isAuthenticated() {
      try {
        await auth.me();
        return true;
      } catch {
        return false;
      }
    },
    async loginViaEmailPassword(email, password) {
      const r = await request("/api/auth/login", { email, password });
      if (r?.access_token) setToken(r.access_token);
      return r;
    },
    async register({ email, password }) {
      return request("/api/auth/register", { email, password });
    },
    async verifyOtp({ email, otpCode }) {
      return request("/api/auth/verify-otp", { email, otpCode });
    },
    async resendOtp(email) {
      return request("/api/auth/resend-otp", { email });
    },
    async resetPasswordRequest(email) {
      return request("/api/auth/reset-request", { email });
    },
    async resetPassword({ resetToken, newPassword }) {
      return request("/api/auth/reset", { resetToken, newPassword });
    },
    logout(redirectTo) {
      const t = token;
      setToken("");
      if (t) fetch("/api/auth/logout", { method: "POST", headers: { Authorization: `Bearer ${t}` }, keepalive: true }).catch(() => {});
      if (redirectTo) window.location.href = "/";
    },
    redirectToLogin(returnTo) {
      const back = returnTo ? new URL(returnTo, window.location.origin) : null;
      const path = back && back.origin === window.location.origin ? back.pathname + back.search : "/app";
      window.location.href = `/login?returnTo=${encodeURIComponent(path)}`;
    },
    async loginWithProvider() {
      throw new HttpError(400, { error: "This site signs in with email and password." });
    },
  };

  const functions = {
    async invoke(name, body) {
      return { data: await request(`/api/functions/${encodeURIComponent(name)}`, body ?? {}) };
    },
  };

  const entities = new Proxy({}, {
    get(_t, name) {
      if (typeof name !== "string") return undefined;
      const call = (op, body) => request(`/api/entities/${encodeURIComponent(name)}/${op}`, body);
      return {
        filter: (query = {}, sort, limit, skip) => call("filter", { query, sort, limit, skip }),
        list: (sort, limit, skip) => call("list", { sort, limit, skip }),
        get: (id) => call("get", { id }),
        create: (data) => call("create", { data }),
        update: (id, data) => call("update", { id, data }),
        delete: (id) => call("delete", { id }),
      };
    },
  });

  /** A realtime room connection, like the SDK's: reconnects by itself and keeps its id. */
  function connectActor(name, instanceId, options = {}) {
    const id = options.id || crypto.randomUUID().replace(/-/g, "");
    const listeners = new Set();
    let closed = false;
    const scheme = window.location.protocol === "https:" ? "wss" : "ws";
    const ws = new ReconnectingWebSocket(() => `${scheme}://${window.location.host}/api/actors/${encodeURIComponent(name)}/${encodeURIComponent(instanceId)}?id=${encodeURIComponent(id)}&token=${encodeURIComponent(token)}`);
    let lastMsg = Date.now();
    ws.addEventListener("open", () => { lastMsg = Date.now(); });
    ws.addEventListener("message", (ev) => {
      lastMsg = Date.now();
      let data;
      try {
        data = JSON.parse(ev.data);
      } catch {
        return;
      }
      if (data?.type === "__pong") return;
      for (const l of listeners) l(data);
    });
    const heartbeat = setInterval(() => {
      if (Date.now() - lastMsg > DEAD_MS) {
        lastMsg = Date.now();
        if (ws.readyState === ws.OPEN) ws.reconnect();
        return;
      }
      try {
        ws.send(JSON.stringify({ type: "__ping" }));
      } catch {
        // Not open yet; the reconnecting socket sends nothing until it is.
      }
    }, PING_MS);
    return {
      id,
      subscribe(cb) {
        listeners.add(cb);
        return { unsubscribe: () => listeners.delete(cb) };
      },
      send(data) {
        if (!closed) ws.send(JSON.stringify(data));
      },
      close() {
        if (closed) return;
        closed = true;
        clearInterval(heartbeat);
        listeners.clear();
        ws.close();
      },
    };
  }

  const actors = new Proxy({}, {
    get(_t, name) {
      if (typeof name !== "string") return undefined;
      return (instanceId) => {
        let conn = null;
        return {
          connect(options) {
            if (!conn) {
              conn = connectActor(name, instanceId, options);
              const close = conn.close;
              conn.close = () => {
                close();
                conn = null;
              };
            }
            return conn;
          },
        };
      };
    },
  });

  const app = {
    async getPublicSettings() {
      return request("/api/site", undefined, "GET");
    },
  };

  return { auth, functions, entities, actors, app, selfHosted: true };
}
