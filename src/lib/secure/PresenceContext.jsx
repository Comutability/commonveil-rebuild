// Online status and typing, off unless you turn them on, and mutual: you see other people's only
// while you share your own. They go through a live room (base44/actors/Presence) that keeps them
// in memory and writes nothing down. Rooms are opened only for the server or conversation on
// screen, and typing is never sent for private channels.
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { base44 } from "@/api/base44Client";
import { randomId } from "@/lib/crypto/encoding";
import { useSecure } from "./SecureContext.jsx";

const PresenceContext = createContext(null);
const HELLO_MS = 20_000;
const IDLE_MS = 5 * 60_000;
const TYPING_SHOWN_MS = 8000;

function readSettings(userId) {
  try {
    const raw = localStorage.getItem(`cv.presence.${userId}`);
    const v = raw ? JSON.parse(raw) : {};
    return { presence: v.presence === true, typing: v.typing === true };
  } catch {
    return { presence: false, typing: false };
  }
}

export function PresenceProvider({ children }) {
  const { userId } = useSecure();
  const [settings, setSettingsState] = useState(() => readSettings(userId));
  const rooms = useRef(new Map()); // key -> { conn, sub, refs, people: Map, typing: Map }
  const [tick, setTick] = useState(0);
  const bump = useCallback(() => setTick((t) => t + 1), []);
  const lastActive = useRef(Date.now());
  const status = useRef("online");

  const setSettings = useCallback((changes) => {
    setSettingsState((cur) => {
      const next = { ...cur, ...changes };
      if (!next.presence) next.typing = false;
      try {
        localStorage.setItem(`cv.presence.${userId}`, JSON.stringify(next));
      } catch {
        // Remembered for this tab only.
      }
      return next;
    });
  }, [userId]);

  const close = useCallback((key) => {
    const r = rooms.current.get(key);
    if (!r) return;
    clearInterval(r.timer);
    r.sub?.unsubscribe?.();
    r.conn?.close?.();
    rooms.current.delete(key);
    bump();
  }, [bump]);

  const open = useCallback((key) => {
    const r = { refs: 1, people: new Map(), typing: new Map() };
    rooms.current.set(key, r);
    try {
      r.conn = base44.actors.Presence(key).connect({ id: randomId(16) });
      r.sub = r.conn.subscribe((msg) => {
        if (!msg || typeof msg !== "object") return;
        if (msg.type === "here" && Array.isArray(msg.people)) {
          r.people = new Map(msg.people.filter((p) => typeof p?.user_id === "string").map((p) => [p.user_id, p.status === "idle" ? "idle" : "online"]));
          bump();
        } else if (msg.type === "typing" && typeof msg.user_id === "string") {
          r.typing.set(`${msg.user_id}|${msg.channel_id || ""}|${msg.thread_id || ""}`, Date.now());
          bump();
          setTimeout(bump, TYPING_SHOWN_MS + 100);
        }
      });
      const hello = () => r.conn?.send?.({ type: "hello", status: status.current });
      hello();
      r.timer = setInterval(hello, HELLO_MS);
    } catch {
      // Presence is a nicety: if the room can't be reached, nothing else depends on it.
    }
  }, [bump]);

  // Turning sharing off closes every room straight away.
  useEffect(() => {
    if (!settings.presence) for (const key of [...rooms.current.keys()]) close(key);
  }, [settings.presence, close]);

  useEffect(() => () => {
    for (const key of [...rooms.current.keys()]) close(key);
  }, [close]);

  // Idle after a while without input; back to online on the next.
  useEffect(() => {
    const active = () => {
      lastActive.current = Date.now();
      if (status.current !== "online") {
        status.current = "online";
        for (const r of rooms.current.values()) r.conn?.send?.({ type: "hello", status: "online" });
      }
    };
    const check = setInterval(() => {
      if (status.current === "online" && Date.now() - lastActive.current > IDLE_MS) {
        status.current = "idle";
        for (const r of rooms.current.values()) r.conn?.send?.({ type: "hello", status: "idle" });
      }
    }, 30_000);
    window.addEventListener("pointerdown", active);
    window.addEventListener("keydown", active);
    return () => {
      clearInterval(check);
      window.removeEventListener("pointerdown", active);
      window.removeEventListener("keydown", active);
    };
  }, []);

  /** Keep a room open while a component that needs it is on screen. */
  const useRoom = (kind, id) => {
    const key = id ? `${kind}.${id}` : null;
    useEffect(() => {
      if (!key || !settings.presence) return undefined;
      const r = rooms.current.get(key);
      if (r) r.refs += 1;
      else open(key);
      return () => {
        const cur = rooms.current.get(key);
        if (!cur) return;
        cur.refs -= 1;
        if (cur.refs <= 0) close(key);
      };
    }, [key]);
  };

  const value = useMemo(() => {
    const statusIn = (kind, id, uid) => (settings.presence ? rooms.current.get(`${kind}.${id}`)?.people.get(uid) || null : null);
    const typingIn = (kind, id, channelId = "", threadId = "") => {
      if (!settings.typing) return [];
      const r = rooms.current.get(`${kind}.${id}`);
      if (!r) return [];
      const now = Date.now();
      const out = [];
      for (const [k, at] of r.typing) {
        if (now - at > TYPING_SHOWN_MS) {
          r.typing.delete(k);
          continue;
        }
        const [uid, ch, th] = k.split("|");
        if (uid !== userId && ch === channelId && th === threadId) out.push(uid);
      }
      return out;
    };
    const sendTyping = (kind, id, { channelId = "", threadId = "", isPrivate = false } = {}) => {
      if (!settings.typing || isPrivate) return;
      rooms.current.get(`${kind}.${id}`)?.conn?.send?.({ type: "typing", ...(channelId ? { channel_id: channelId } : {}), ...(threadId ? { thread_id: threadId } : {}) });
    };
    return { settings, setSettings, statusIn, typingIn, sendTyping, tick };
  }, [settings, setSettings, tick, userId]);

  return <PresenceContext.Provider value={{ ...value, useRoom }}>{children}</PresenceContext.Provider>;
}

const OFF = { settings: { presence: false, typing: false }, setSettings: () => {}, statusIn: () => null, typingIn: () => [], sendTyping: () => {}, useRoom: () => {} };

export function usePresence() {
  return useContext(PresenceContext) || OFF;
}

/** Keep the presence room for a server ("s") or conversation ("c") open while mounted. */
export function usePresenceRoom(kind, id) {
  const ctx = useContext(PresenceContext);
  (ctx?.useRoom || OFF.useRoom)(kind, id);
}

export function typingText(names) {
  if (!names.length) return null;
  if (names.length === 1) return `${names[0]} is typing…`;
  if (names.length === 2) return `${names[0]} and ${names[1]} are typing…`;
  return "Several people are typing…";
}
