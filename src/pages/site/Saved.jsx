import React, { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { BookmarkX, CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { listContent } from "@/lib/api";
import { KIND_LABELS, hrefOf, useSaved } from "@/lib/site/saved.js";
import { EmptyState, PageHeader, formatDate } from "@/components/site/bits";

export default function Saved() {
  const { saved, done, toggleSaved, toggleDone, clearAll } = useSaved();
  const [confirming, setConfirming] = useState(false);
  const guides = useQuery({ queryKey: ["content", "Guide", "title"], queryFn: () => listContent("Guide", "title") });
  const doneSlugs = Object.keys(done);
  const titleOf = (slug) => (guides.data || []).find((g) => g.slug === slug)?.title || slug;

  return (
    <>
      <PageHeader
        eyebrow="Saved"
        title="Saved on this browser"
        intro="Pages you've saved and guides you've finished. They're kept in this browser only: nothing about what you read is sent to us, and there's no account involved."
      />
      <div className="container-cv space-y-12 py-10">
        <section aria-labelledby="saved-pages">
          <h2 id="saved-pages" className="text-2xl font-semibold">Saved pages</h2>
          {saved.length === 0 ? (
            <div className="mt-4"><EmptyState title="Nothing saved yet">Use the Save button on any guide, wiki page, blog post or learning path.</EmptyState></div>
          ) : (
            <ul className="mt-4 divide-y divide-border rounded-xl border border-border">
              {saved.map((s) => (
                <li key={`${s.kind}:${s.slug}`} className="flex items-center gap-3 px-4 py-3">
                  <div className="min-w-0 flex-1">
                    <Link to={hrefOf(s)} className="font-medium hover:text-primary hover:underline">{s.title}</Link>
                    <p className="text-xs text-muted-foreground">{KIND_LABELS[s.kind]}{s.saved_on ? ` · saved ${formatDate(s.saved_on)}` : ""}</p>
                  </div>
                  <Button variant="ghost" size="sm" onClick={() => toggleSaved(s)} aria-label={`Remove ${s.title} from saved`}>
                    <BookmarkX className="h-4 w-4" aria-hidden="true" />
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section aria-labelledby="finished-guides">
          <h2 id="finished-guides" className="text-2xl font-semibold">Guides you've finished</h2>
          {doneSlugs.length === 0 ? (
            <p className="mt-4 text-sm text-muted-foreground">None yet. Mark a guide as done when you've followed it; learning paths then show how far along you are.</p>
          ) : (
            <ul className="mt-4 divide-y divide-border rounded-xl border border-border">
              {doneSlugs.map((slug) => (
                <li key={slug} className="flex items-center gap-3 px-4 py-3">
                  <CheckCircle2 className="h-5 w-5 shrink-0 text-primary" aria-hidden="true" />
                  <div className="min-w-0 flex-1">
                    <Link to={`/guides/${slug}`} className="font-medium hover:text-primary hover:underline">{titleOf(slug)}</Link>
                    <p className="text-xs text-muted-foreground">Done {formatDate(done[slug])}</p>
                  </div>
                  <Button variant="ghost" size="sm" onClick={() => toggleDone(slug)}>Not done</Button>
                </li>
              ))}
            </ul>
          )}
        </section>

        {(saved.length > 0 || doneSlugs.length > 0) && (
          <section className="rounded-xl border border-border p-5 text-sm">
            <p className="text-muted-foreground">Clearing removes your saved pages and finished guides from this browser. It can't be undone.</p>
            {confirming ? (
              <div className="mt-3 flex flex-wrap gap-2">
                <Button variant="destructive" size="sm" onClick={() => { clearAll(); setConfirming(false); }}>Clear everything</Button>
                <Button variant="ghost" size="sm" onClick={() => setConfirming(false)}>Cancel</Button>
              </div>
            ) : (
              <Button variant="outline" size="sm" className="mt-3" onClick={() => setConfirming(true)}>Clear everything on this browser</Button>
            )}
          </section>
        )}
      </div>
    </>
  );
}
