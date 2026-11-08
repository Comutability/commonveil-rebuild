import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useSiteInfo } from "@/lib/site/siteInfo";
import { useNavigate } from "react-router-dom";
import { Compass, Loader2, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ErrorNote } from "@/components/site/bits";
import Shell, { NavButton } from "@/components/shell/Shell";
import DiscoverCard from "@/components/discover/DiscoverCard";
import { ALL_TAGS, tagLabel } from "@/lib/site/discoverTags";
import { useServers } from "@/lib/secure/ServerContext";

export { ALL_TAGS, tagLabel };

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
  const { discover, joinServer, servers, serverLook } = useServers();
  const [tag, setTag] = useState(null);
  const [list, setList] = useState(null);
  const [q, setQ] = useState("");
  const [error, setError] = useState("");
  const [joining, setJoining] = useState("");
  // Self-hosted sites can browse servers listed on another Commonveil site.
  const siteInfo = useSiteInfo();
  const [site, setSite] = useState("");
  const [siteInput, setSiteInput] = useState("");

  const load = useCallback(() => discover(tag, site), [discover, tag, site]);

  useEffect(() => {
    let alive = true;
    setList(null);
    setError("");
    load()
      .then((r) => alive && setList(r.servers))
      .catch((err) => alive && setError(err.message));
    // A server changes its public card in its own settings: pick that up without a reload.
    const refresh = () => {
      if (document.visibilityState !== "visible") return;
      load()
        .then((r) => alive && setList(r.servers))
        .catch(() => {});
    };
    const timer = setInterval(refresh, 30000);
    window.addEventListener("focus", refresh);
    return () => {
      alive = false;
      clearInterval(timer);
      window.removeEventListener("focus", refresh);
    };
  }, [load]);

  const shown = useMemo(() => {
    const query = q.trim().toLowerCase();
    if (!query) return list || [];
    return (list || []).filter((s) =>
      s.name.toLowerCase().includes(query) ||
      s.description.toLowerCase().includes(query) ||
      (s.tags || []).some((t) => tagLabel(t).toLowerCase().includes(query))
    );
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
              These servers chose to publish a public card: a name, a description and tags. Inside, everything is still end-to-end encrypted. Server admins don't learn who browses.
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
                  <DiscoverCard
                    key={s.id}
                    server={s}
                    member={member}
                    look={member ? serverLook(s.id) : null}
                    joining={joining}
                    onOpen={() => join(s)}
                  />
                );
              })}
            </ul>
          </div>
        </div>
      </div>
    </Shell>
  );
}