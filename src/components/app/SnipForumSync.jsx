import { useEffect, useRef } from "react";
import { callFn } from "@/lib/api";
import { useSecure } from "@/lib/secure/SecureContext";
import { useServers } from "@/lib/secure/ServerContext";
import { P } from "@/lib/secure/permissions.js";
import { serverRequest } from "@/lib/secure/serverProtocol.js";
import { isOffline } from "@/lib/offline/mode.js";
import { runSnipSync } from "@/lib/secure/snipForum.js";

const FIRST_MS = 20_000;
const EVERY_MS = 10 * 60_000;

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

  const defaultId = Object.keys(ctx.servers || {}).find((sid) => ctx.servers[sid]?.server?.is_default) || "";
  const manager = Boolean(defaultId) && ctx.can(defaultId, P.MANAGE_CHANNELS) && ctx.can(defaultId, P.MANAGE_THREADS);

  useEffect(() => {
    if (!manager || !userId || !device) return undefined;
    let stopped = false;
    const pass = async () => {
      if (stopped || busy.current || isOffline() || document.visibilityState !== "visible") return;
      busy.current = true;
      try {
        const c = () => latest.current;
        await runSnipSync({
          status: () => callFn("snips", { action: "status" }),
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
      } catch {
        // Not reachable, keys still loading, or GitHub unavailable: the next pass tries again.
      } finally {
        busy.current = false;
      }
    };
    const first = setTimeout(pass, FIRST_MS);
    const timer = setInterval(pass, EVERY_MS);
    return () => {
      stopped = true;
      clearTimeout(first);
      clearInterval(timer);
    };
  }, [manager, userId, device, defaultId]);

  return null;
}
