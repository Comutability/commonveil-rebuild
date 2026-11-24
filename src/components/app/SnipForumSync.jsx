import { useEffect, useRef, useState } from "react";
import { callFn } from "@/lib/api";
import { useSecure } from "@/lib/secure/SecureContext";
import { useServers } from "@/lib/secure/ServerContext";
import { P } from "@/lib/secure/permissions.js";
import { serverRequest } from "@/lib/secure/serverProtocol.js";
import { isOffline } from "@/lib/offline/mode.js";
import { planSnipSync, runSnipSync } from "@/lib/secure/snipForum.js";

const FIRST_MS = 3_000;
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
  const [pending, setPending] = useState(null);
  const [lastError, setLastError] = useState("");
  const [working, setWorking] = useState(false);

  const defaultId = Object.keys(ctx.servers || {}).find((sid) => ctx.servers[sid]?.server?.is_default) || "";
  const manager = Boolean(defaultId) && ctx.can(defaultId, P.MANAGE_CHANNELS) && ctx.can(defaultId, P.MANAGE_THREADS);

  useEffect(() => {
    if (!manager || !userId || !device) return undefined;
    let stopped = false;
    const pass = async () => {
      if (stopped || busy.current || isOffline() || document.visibilityState !== "visible") return;
      busy.current = true;
      setWorking(true);
      try {
        const c = () => latest.current;
        const result=await runSnipSync({
          status: async () => {
            const report=await callFn("snips", { action: "status" });
            setPending(planSnipSync(report).length);
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
        if (!stopped) {
          const report = await callFn("snips", { action: "status" });
          setPending(planSnipSync(report).length);
          setLastError("");
          if (result.posted.length || result.closed.length) {
            console.info("[snips] authorised admin device reconciled forum", {
              posted: result.posted.length, closed: result.closed.length,
            });
          }
        }
      } catch (err) {
        // Errors are shown to the authorised admin; never bypass the encryption.
        if (!stopped) setLastError(err?.message || "Could not sync the proposals.");
      } finally {
        busy.current = false;
        if (!stopped) setWorking(false);
      }
    };
    passRef.current=pass;
    const first = setTimeout(pass, FIRST_MS);
    const timer = setInterval(pass, EVERY_MS);
    document.addEventListener("visibilitychange", pass);
    window.addEventListener("focus", pass);
    window.addEventListener("online", pass);
    return () => {
      stopped = true;
      clearTimeout(first);
      clearInterval(timer);
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
      <button type="button" onClick={() => passRef.current?.()} disabled={working}
        className="rounded-md border border-border px-3 py-2 font-medium hover:bg-muted disabled:opacity-50">
        {working?"Checking…":"Sync now"}
      </button>
    </div>
    {lastError?<p role="alert" className="mt-2 text-destructive">{lastError}</p>:
      <p className="mt-1 text-muted-foreground">Only this authorised device can sign and encrypt forum updates.</p>}
  </div>;
}
