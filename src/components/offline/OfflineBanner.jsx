import React from "react";
import { Link } from "react-router-dom";
import { CloudOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { setOfflineMode, useOffline } from "@/lib/offline/mode";

/** At the top of the app while you're offline, by choice or not (docs/OFFLINE.md). */
export default function OfflineBanner() {
  const { chosen, cutOff } = useOffline();
  if (!chosen && !cutOff) return null;
  return (
    <div role="status" className="border-b border-border bg-muted">
      <div className="mx-auto flex max-w-5xl flex-wrap items-center gap-3 px-4 py-2 text-sm">
        <CloudOff className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
        <p className="min-w-0 flex-1">
          {chosen
            ? "Offline mode is on. Messages you send are sealed now and wait on this device until you turn it off."
            : "You're offline. Messages you send are sealed now and go out when you're back."}
        </p>
        {chosen ? (
          <Button size="sm" variant="outline" onClick={() => setOfflineMode(false)}>Go back online</Button>
        ) : (
          <Link to="/help/offline-mode" className="text-xs font-medium text-primary hover:underline">How this works</Link>
        )}
      </div>
    </div>
  );
}
