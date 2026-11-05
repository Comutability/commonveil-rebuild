import React, { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";
import { listContent } from "@/lib/api";
import { Loading, PageHeader, Pill } from "@/components/site/bits";

function useList(entity, sort) {
  return useQuery({ queryKey: ["content", entity, sort], queryFn: () => listContent(entity, sort) });
}

function CategoryFilter({ items, value, onChange }) {
  const cats = useMemo(() => [...new Set(items.map((i) => i.category).filter(Boolean))].sort(), [items]);
  if (cats.length < 2) return null;
  return (
    <div className="mb-8 flex flex-wrap gap-2" role="group" aria-label="Filter by topic">
      {["All", ...cats].map((c) => {
        const active = (value || "All") === c;
        return (
          <button
            key={c}
            type="button"
            onClick={() => onChange(c === "All" ? null : c)}
            aria-pressed={active}
            className={`rounded-full border px-3 py-1 text-sm transition-colors ${active ? "border-primary bg-primary text-primary-foreground" : "border-border hover:bg-muted"}`}
          >
            {c}
          </button>
        );
      })}
    </div>
  );
}

// ---------- Resources ----------

export default function ResourcesIndex() {
  const { data = [], isLoading } = useList("Resource", "name");
  const [cat, setCat] = useState(null);
  const shown = data.filter((r) => !cat || r.category === cat);
  return (
    <>
      <PageHeader eyebrow="Resources" title="Tools worth knowing about" intro="A short, opinionated list. Nobody pays to be here, and nothing is an affiliate link." />
      <div className="container-cv py-10">
        {isLoading ? <Loading /> : (
          <>
            <CategoryFilter items={data} value={cat} onChange={setCat} />
            <ul className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {shown.map((r) => (
                <li key={r.id} className="card-cv flex flex-col p-5">
                  <p className="eyebrow">{r.category}</p>
                  <h2 className="mt-2 text-lg font-semibold">{r.name}</h2>
                  <p className="mt-2 flex-1 text-sm text-muted-foreground">{r.description}</p>
                  <div className="mt-4 flex flex-wrap gap-1.5">
                    {r.open_source === "Yes" && <Pill tone="accent">Open source</Pill>}
                    {r.open_source === "Partly" && <Pill>Partly open source</Pill>}
                    {r.self_hostable && <Pill tone="accent">Self-hostable</Pill>}
                    {r.pricing_summary && <Pill>{r.pricing_summary}</Pill>}
                  </div>
                  {r.website && (
                    <a href={/^https?:\/\//i.test(r.website || "") ? r.website : undefined} target="_blank" rel="noopener noreferrer nofollow" className="mt-4 inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline">
                      Visit site <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
                    </a>
                  )}
                </li>
              ))}
            </ul>
          </>
        )}
      </div>
    </>
  );
}
