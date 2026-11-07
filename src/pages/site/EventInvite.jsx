import React from "react";
import { Link, Navigate, useParams } from "react-router-dom";
import { CalendarCheck, Lock, LogIn } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/lib/AuthContext";

/**
 * The link someone is sent. Signed in, it opens the event itself; otherwise it asks them to sign
 * in or create an account first, and sends them on to the event afterwards.
 */
export default function EventInvite() {
  const { eventId } = useParams();
  const { isAuthenticated } = useAuth();
  const next = `/app/e/${encodeURIComponent(eventId)}`;
  const back = `?returnTo=${encodeURIComponent(next)}`;
  if (isAuthenticated) return <Navigate to={next} replace />;
  return (
    <div className="container-cv py-16 sm:py-24">
      <div className="card-cv mx-auto max-w-lg px-6 py-10 text-center">
        <CalendarCheck className="mx-auto h-9 w-9 text-primary" aria-hidden="true" />
        <p className="eyebrow mt-4">You're invited</p>
        <h1 className="mt-2 text-3xl font-semibold leading-tight">Someone shared an event with you</h1>
        <p className="mt-3 text-muted-foreground">
          Sign in, or create an account, to see what it is and say whether you're coming.
        </p>
        <div className="mt-6 flex flex-wrap justify-center gap-2">
          <Button asChild size="lg">
            <Link to={`/login${back}`}><LogIn className="mr-1.5 h-4 w-4" aria-hidden="true" /> Sign in</Link>
          </Button>
          <Button asChild size="lg" variant="outline">
            <Link to={`/register${back}`}>Create an account</Link>
          </Button>
        </div>
        <p className="mt-5 flex items-center justify-center gap-1.5 text-xs text-muted-foreground">
          <Lock className="h-3.5 w-3.5" aria-hidden="true" /> Events are end-to-end encrypted, so nothing about this one is shown until you're signed in.
        </p>
      </div>
    </div>
  );
}