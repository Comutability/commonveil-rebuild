import { useEffect, useRef, useState } from "react";
import { ApiError, callFn } from "@/lib/api";
import { useSecure } from "@/lib/secure/SecureContext";
import { useServers } from "@/lib/secure/ServerContext";
import { P } from "@/lib/secure/permissions.js";
import { serverRequest } from "@/lib/secure/serverProtocol.js";
import { isOffline } from "@/lib/offline/mode.js";
import { planSnipSync, runSnipSync } from "@/lib/secure/snipForum.js";

const FIRST_MS = 5_000;
const NEXT_STEP_MS = 75_000;
const BUSY_PAUSE_MS = [90_000, 180_000, 300_000, 300_000];
const EVERY_MS = 5 * 60_000;

/**
 * Keeps the proposals forum in step with GitHub (docs/SNIP_FORUM.md). Shows nothing. It only
 * does anything in the app of someone who can manage channels and threads in the community
 * server: everyone else's app never asks.
 */
export default function SnipForumSync() {
  const { userId, device } = useSecure();
  const ctx = useServers();
  const latest = useRef(ctx);
  latest.current = ctx;
  const busy = useRef(false);
  const passRef = useRef(null);
  const nextAllowed = useRef(0);
  const busyFailures = useRef(0);
  const [pending, setPending] = useState(null);
  const [lastError, setLastError] = useState("");
  const [working, setWorking] = useState(false);
  const [cooldownUntil, setCooldownUntil] = useState(0);
  const [stale, setStale] = useState(false);

  const defaultId = Object.keys(ctx.servers || {}).find((sid) => ctx.servers[sid]?.server?.is_default) || "";
  const manager = Boolean(defaultId) && ctx.can(defaultId, P.MANAGE_CHANNELS) && ctx.can(defaultId, P.MANAGE_THREADS);

  useEffect(() => {
    if (!manager || !userId || !device) return undefined;
    let stopped = false;
    let scheduled = null;
    const later = (run, delay) => {
      if (scheduled !== null) clearTimeout(scheduled);
      scheduled = setTimeout(run, delay);
    };
    const pass = async () => {
      // Do not let focus/online events or repeated clicks exhaust the same
      // shared Base44 request budget. A rate-limited partial operation will
      // resume against fixed SNIP IDs rather than creating duplicates.
      if (stopped || busy.current || isOffline() || document.visibilityState !== "visible") return;
      const now = Date.now();
      if (now < nextAllowed.current) return;
      busy.current = true;
      setWorking(true);
      let backlog = null;
      try {
        const c = () => latest.current;
        const result = await runSnipSync({
          status: async () => {
            const report = await callFn("snips", { action: "status" });
            setStale(Boolean(report.stale));
            backlog = planSnipSync(report, Number.MAX_SAFE_INTEGER).length;
            setPending(backlog);
            return report;
          },
          ensureForum: async () => {
            await callFn("snips", await serverRequest({ userId, device, action: "ensure_forum", payload: {} }));
            await c().reloadServer(defaultId);
          },
          channelOf: async (channelId) => {
            const find = () => (c().servers[defaultId]?.channels || []).find((ch) => ch.id === channelId) || null;
            if (!find()) await c().reloadServer(defaultId);
            return find();
          },
          post: (channel, payload, opts) => c().sendWithId(defaultId, channel, payload, opts),
          lock: (channel, msgId) => c().lockThread(defaultId, { m: { channel_id: channel.id, msg_id: msgId } }, true),
        });
        busyFailures.current = 0;
        setCooldownUntil(0);
        setLastError("");
        // A newly posted, immediately locked proposal counts once.
        const completed = result.posted.length + result.closed.filter((id) => !result.posted.includes(id)).length;
        const left = Math.max(0, (backlog ?? 0) - completed);
        setPending(left);
        if (result.posted.length || result.closed.length) {
          console.info("[snips] authorised device reconciled proposal", {
            posted: result.posted.length, closed: result.closed.length,
          });
        }
        if (left > 0 && !stopped) {
          nextAllowed.current = Date.now() + NEXT_STEP_MS;
          later(pass, NEXT_STEP_MS);
        }
      } catch (err) {
        if (stopped) return;
        const rateLimited = err instanceof ApiError &&
          (err.code === "UPSTREAM_BUSY" || err.status === 429 || err.code === "NETWORK");
        if (rateLimited) {
          const attempt = Math.min(busyFailures.current++, BUSY_PAUSE_MS.length - 1);
          const pause = BUSY_PAUSE_MS[attempt];
          nextAllowed.current = Date.now() + pause;
          setCooldownUntil(nextAllowed.current);
          setLastError("Commonveil is limiting requests. Sync has paused safely and will retry automatically. Already signed posts are kept.");
          later(pass, pause + 1_000);
        } else {
          setLastError(err?.message || "Could not sync the proposals.");
          // Another transient failure should not cause a rapid retry loop.
          nextAllowed.current = Date.now() + NEXT_STEP_MS;
        }
      } finally {
        busy.current = false;
        if (!stopped) setWorking(false);
      }
    };
    passRef.current = pass;
    const first = setTimeout(pass, FIRST_MS);
    const timer = setInterval(pass, EVERY_MS);
    document.addEventListener("visibilitychange", pass);
    window.addEventListener("focus", pass);
    window.addEventListener("online", pass);
    return () => {
      stopped = true;
      passRef.current = null;
      clearTimeout(first);
      clearInterval(timer);
      if (scheduled !== null) clearTimeout(scheduled);
      document.removeEventListener("visibilitychange", pass);
      window.removeEventListener("focus", pass);
      window.removeEventListener("online", pass);
    };
  }, [manager, userId, device, defaultId]);

  if (!manager || !userId || !device) return null;
  return <div className="fixed bottom-4 right-4 z-[70] max-w-[min(21rem,calc(100vw-2rem))] rounded-xl border border-border bg-card p-3 text-xs shadow-lg" role="region" aria-label="Secure Net proposal forum synchronisation">
    <div className="flex items-center gap-3">
      <span className="min-w-0 flex-1 font-semibold">
        Secure Net proposals {typeof pending==="number" && pending>0 ? "("+pending+" pending)" : ""}
      </span>
      <button type="button" onClick={() => passRef.current?.()}
        disabled={working || (cooldownUntil > Date.now())}
        className="rounded-md border border-border px-3 py-2 font-medium hover:bg-muted disabled:opacity-50">
        {working ? "Checking…" : cooldownUntil > Date.now() ? "Retry queued" : "Sync now"}
      </button>
    </div>
    {lastError ? <p role={cooldownUntil ? "status" : "alert"} className="mt-2 text-muted-foreground">{lastError}</p> :
      <p className="mt-1 text-muted-foreground">
        {stale ? "GitHub is temporarily unavailable; no changes will be made from an old snapshot." :
          typeof pending === "number" && pending > 0 ?
          "Continuing in small, spaced-out steps while this tab stays open." :
          "Only this authorised device can sign and encrypt forum updates."}
      </p>}
  </div>;
}
