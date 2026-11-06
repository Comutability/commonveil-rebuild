import React, { useEffect, useMemo, useState } from "react";
import { useSiteInfo } from "@/lib/site/siteInfo";
import { useNavigate } from "react-router-dom";
import { Compass, Loader2, Lock, Search, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ErrorNote } from "@/components/site/bits";
import Shell, { NavButton } from "@/components/shell/Shell";
import ServerIcon from "@/components/shell/ServerIcon";
import { useServers } from "@/lib/secure/ServerContext";

const TAG_LABELS = {
  privacy: "Privacy",
  security: "Security",
  "open-source": "Open source",
  learning: "Learning",
  support: "Support",
  community: "Community",
  friends: "Friends",
  study: "Study",
  gaming: "Gaming",
  creative: "Creative",
  technology: "Technology",
  local: "Local",
  activism: "Activism",
  health: "Health",
  music: "Music",
  books: "Books",
};
export const tagLabel = (t) => TAG_LABELS[t] || t;
export const ALL_TAGS = Object.keys(TAG_LABELS);

function DiscoverPanel({ tag, setTag }) {
  return (
    <nav aria-label="Discover" className="flex h-full min-h-0 flex-col">
      <div className="flex h-12 shrink-0 items-center border-b border-border/70 px-4 shadow-sm">
        <h2 className="font-heading text-[1.05rem] font-semibold">Discover</h2>
      </div>
      <ul className="scroll-thin min-h-0 flex-1 space-y-0.5 overflow-y-auto px-2 py-3">
        <li>
          <button type="button" onClick={() => setTag(null)} aria-current={!tag ? "page" : undefined} className="panel-item">
            <Compass className="h-4 w-4" aria-hidden="true" /> All servers
          </button>
        </li>
        {ALL_TAGS.map((t) => (
          <li key={t}>
            <button type="button" onClick={() => setTag(t)} aria-current={tag === t ? "page" : undefined} className="panel-item">
              <span className="w-4 text-center text-muted-foreground" aria-hidden="true">#</span> {tagLabel(t)}
            </button>
          </li>
        ))}
      </ul>
    </nav>
  );
}

/** Servers whose admins chose to list them. Their public card is all anyone sees until they join. */
export default function Discover() {
  const navigate = useNavigate();
  const { discover, joinServer, servers } = useServers();
  const [tag, setTag] = useState(null);
  const [list, setList] = useState(null);
  const [q, setQ] = useState("");
  const [error, setError] = useState("");
  const [joining, setJoining] = useState("");
  // Self-hosted sites can browse servers listed on another Commonveil site.
  const siteInfo = useSiteInfo();
  const [site, setSite] = useState("");
  const [siteInput, setSiteInput] = useState("");

  useEffect(() => {
    let alive = true;
    setList(null);
    setError("");
    discover(tag, site)
      .then((r) => alive && setList(r.servers))
      .catch((err) => alive && setError(err.message));
    return () => {
      alive = false;
    };
  }, [tag, site, discover]);

  const shown = useMemo(() => {
    const query = q.trim().toLowerCase();
    return (list || []).filter((s) => !query || s.name.toLowerCase().includes(query) || s.description.toLowerCase().includes(query));
  }, [list, q]);

  const join = async (s) => {
    if (servers[s.id]) {
      navigate(`/app/s/${s.id}`);
      return;
    }
    setJoining(s.id);
    setError("");
    try {
      const sid = await joinServer({ serverId: s.id, site });
      navigate(`/app/s/${sid}`);
    } catch (err) {
      setError(err.message);
      setJoining("");
    }
  };

  return (
    <Shell panel={<DiscoverPanel tag={tag} setTag={setTag} />} mainOpen>
      <div className="flex min-h-0 flex-1 flex-col">
        <header className="flex h-12 shrink-0 items-center gap-2 border-b border-border/70 px-3 shadow-sm sm:px-4">
          <NavButton />
          <Compass className="h-5 w-5 text-muted-foreground" aria-hidden="true" />
          <h1 className="font-heading text-[1.05rem] font-semibold">{tag ? tagLabel(tag) : "Discover servers"}</h1>
        </header>
        <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-5xl px-4 py-8 sm:px-8">
            <h2 className="text-4xl font-semibold leading-tight">Find your people</h2>
            <p className="mt-2 max-w-prose text-muted-foreground">
              These servers chose to publish a public name and description. Inside, everything is still end-to-end encrypted. Server admins don't learn who browses.
            </p>
            <div className="relative mt-6 max-w-md">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Filter by name or description"
                aria-label="Filter servers"
                className="h-10 w-full rounded-lg border border-border bg-card pl-9 pr-3 text-sm outline-none focus:ring-2 focus:ring-ring/40"
              />
            </div>
            {siteInfo?.federation && (
              <form
                className="mt-4 flex max-w-md flex-wrap items-center gap-2 text-sm"
                onSubmit={(e) => {
                  e.preventDefault();
                  setSite(siteInput.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, ""));
                }}
              >
                <label htmlFor="discover-site" className="text-muted-foreground">Showing servers on</label>
                <input
                  id="discover-site"
                  value={siteInput}
                  onChange={(e) => setSiteInput(e.target.value)}
                  placeholder="this site, or another like example.org"
                  maxLength={253}
                  className="h-9 min-w-[12rem] flex-1 rounded-lg border border-border bg-card px-3 outline-none focus:ring-2 focus:ring-ring/40"
                />
                <Button type="submit" size="sm" variant="outline">Browse</Button>
                {site && <Button type="button" size="sm" variant="ghost" onClick={() => { setSite(""); setSiteInput(""); }}>Back to this site</Button>}
              </form>
            )}
            <ErrorNote>{error}</ErrorNote>
            {!list && !error && <p className="mt-10 flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Loading…</p>}
            {list && shown.length === 0 && <p className="mt-10 text-sm text-muted-foreground">No listed servers match{tag ? ` in ${tagLabel(tag)}` : ""}.</p>}
            <ul className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {shown.map((s) => {
                const member = Boolean(servers[s.id]);
                return (
                  <li key={s.id} className="flex flex-col overflow-hidden rounded-xl border border-border bg-card">
                    <div className="h-16" style={{ backgroundColor: s.color ? `${s.color}33` : "hsl(var(--muted))" }} aria-hidden="true" />
                    <div className="-mt-8 flex flex-1 flex-col px-4 pb-4">
                      <span className="rounded-2xl ring-4 ring-[hsl(var(--card))]">
                        <ServerIcon look={{ name: s.name, icon: s.icon, color: s.color }} size="h-14 w-14" rounded />
                      </span>
                      <h3 className="mt-2 font-heading text-lg font-semibold leading-snug">{s.name}</h3>
                      <p className="mt-1 line-clamp-3 flex-1 text-sm text-muted-foreground">{s.description}</p>
                      {s.tags.length > 0 && (
                        <ul className="mt-3 flex flex-wrap gap-1">
                          {s.tags.map((t) => <li key={t} className="rounded-md bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">{tagLabel(t)}</li>)}
                        </ul>
                      )}
                      <div className="mt-4 flex items-center justify-between gap-2">
                        <span className="flex items-center gap-1 text-xs text-muted-foreground">
                          <Users className="h-3.5 w-3.5" aria-hidden="true" /> About {s.member_count} {s.member_count === 1 ? "member" : "members"}
                        </span>
                        {s.join_mode === "open" || member ? (
                          <Button size="sm" variant={member ? "outline" : "default"} disabled={joining === s.id} onClick={() => join(s)}>
                            {member ? "Open" : joining === s.id ? "Joining…" : "Join"}
                          </Button>
                        ) : (
                          <span className="flex items-center gap-1 text-xs text-muted-foreground"><Lock className="h-3.5 w-3.5" aria-hidden="true" /> Invite only</span>
                        )}
                      </div>
                    </div>
                  </li>
                );
              })}
            </ul>
          </div>
        </div>
      </div>
    </Shell>
  );
}
