import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Button } from "@/components/ui/button";
import Avatar, { ACCENT_HUES } from "@/components/chat/Avatar";
import { SELF_HOSTED } from "@/api/base44Client";

// Where someone's address leads in a browser (name.example.org → /u/name). It shows only what they
// chose to share, and a way to message them; there's no directory, posts or activity here.

export default function PublicProfile() {
  const { username } = useParams();
  const [state, setState] = useState({ loading: true });

  useEffect(() => {
    let live = true;
    if (!SELF_HOSTED) {
      setState({ missing: true });
      return undefined;
    }
    fetch(`/api/fed/profile/${encodeURIComponent(username)}`, { cache: "no-store" })
      .then(async (r) => (r.ok ? r.json() : null))
      .then((p) => live && setState(p ? { profile: p } : { missing: true }))
      .catch(() => live && setState({ missing: true }));
    return () => {
      live = false;
    };
  }, [username]);

  if (state.loading) return <div className="container-cv min-h-[50vh] py-16" aria-busy="true" />;
  if (state.missing) {
    return (
      <div className="container-cv flex min-h-[50vh] flex-col items-start justify-center py-16">
        <h1 className="text-3xl font-semibold">Nobody here by that name</h1>
        <p className="mt-3 max-w-md text-muted-foreground">Check the address. Usernames are exact, and there's no directory to search.</p>
      </div>
    );
  }

  const p = state.profile;
  const address = p.handle || p.username;
  const hue = ACCENT_HUES[p.accent_color];
  return (
    <div className="container-cv py-16">
      <div className="flex max-w-xl flex-col items-start gap-5 rounded-2xl border p-6" style={hue !== undefined ? { borderColor: `hsl(${hue} 60% 50% / 0.4)` } : undefined}>
        <Avatar id={p.username} name={p.display_name || p.username} emoji={p.avatar_emoji} image={p.avatar_image} accent={p.accent_color} size="h-20 w-20" />
        <div>
          <h1 className="text-3xl font-semibold">{p.display_name || p.username}</h1>
          <p className="mt-1 break-all font-mono text-sm text-muted-foreground">@{address}</p>
        </div>
        {p.accepts_new ? (
          <div className="space-y-2">
            <Button asChild>
              <Link to={`/app?to=${encodeURIComponent(address)}`}>Send a message</Link>
            </Button>
            <p className="text-sm text-muted-foreground">Have an account on another Commonveil site? Start a conversation there with <span className="font-mono">@{address}</span>.</p>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">{p.display_name || p.username} only takes new conversations from people they share a server with.</p>
        )}
        <p className="text-xs text-muted-foreground">Messages are end-to-end encrypted. This page shows only what they chose to share.</p>
      </div>
    </div>
  );
}
