import React, { useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { applyUpdate, useApp } from "@/lib/pwa/app";
import { openFromPush } from "@/lib/pwa/push";

/**
 * Following a tapped notification: it carries only a one-time code, which the app (signed in)
 * swaps for where to go. Also clears the app icon's badge whenever Commonveil is looked at.
 */
export function PushLanding() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  useEffect(() => {
    const go = async (code) => navigate(await openFromPush(code), { replace: true });
    const code = params.get("push");
    if (code) {
      setParams({}, { replace: true });
      go(code);
    }
    const onMessage = (e) => {
      if (e.data?.type === "push-open") e.data.code ? go(e.data.code) : navigate("/app");
    };
    navigator.serviceWorker?.addEventListener("message", onMessage);
    return () => navigator.serviceWorker?.removeEventListener("message", onMessage);
  }, [params, setParams, navigate]);
  useEffect(() => {
    const clear = () => {
      if (document.visibilityState === "visible") navigator.clearAppBadge?.().catch(() => {});
    };
    clear();
    document.addEventListener("visibilitychange", clear);
    return () => document.removeEventListener("visibilitychange", clear);
  }, []);
  return null;
}

/** A new version of the app has arrived: offer to switch now. */
export function UpdateBar() {
  const { updateReady } = useApp();
  if (!updateReady) return null;
  return (
    <div role="status" className="border-b border-border bg-muted">
      <div className="mx-auto flex max-w-5xl flex-wrap items-center gap-3 px-4 py-2 text-sm">
        <RefreshCw className="h-4 w-4 text-primary" aria-hidden="true" />
        <p className="min-w-0 flex-1">A new version of Commonveil is ready.</p>
        <Button size="sm" onClick={applyUpdate}>Update now</Button>
      </div>
    </div>
  );
}
