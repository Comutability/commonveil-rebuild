import React, { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ExternalLink, Search as SearchIcon } from "lucide-react";
import { Input } from "@/components/ui/input";
import { listContent } from "@/lib/api";
import { searchContent, toDocs } from "@/lib/site/search.js";
import { Loading, PageHeader, Pill } from "@/components/site/bits";

const KIND = { guide: "Guide", wiki: "Wiki", blog: "Blog", path: "Learning path", resource: "Resource" };

/** The same queries the section pages use, so what's already loaded is reused. */
function useAllContent() {
  const guides = useQuery({ queryKey: ["content", "Guide", "title"], queryFn: () => listContent("Guide", "title") });
  const wiki = useQuery({ queryKey: ["content", "WikiPage", "title"], queryFn: () => listContent("WikiPage", "title") });
  const blog = useQuery({ queryKey: ["content", "BlogPost", "-published_at"], queryFn: () => listContent("BlogPost", "-published_at") });
  const paths = useQuery({ queryKey: ["content", "LearningPath", "title"], queryFn: () => listContent("LearningPath", "title") });
  const resources = useQuery({ queryKey: ["content", "Resource", "name"], queryFn: () => listContent("Resource", "name") });
  const all = [guides, wiki, blog, paths, resources];
  const docs = useMemo(
    () => toDocs({ guides: guides.data, wiki: wiki.data, blog: blog.data, paths: paths.data, resources: resources.data }),
    [guides.data, wiki.data, blog.data, paths.data, resources.data],
  );
  return { docs, loading: all.some((q) => q.isLoading), failed: all.some((q) => q.isError) };
}

export default function Search() {
  // Kept in this page only: never in the address bar, so it isn't in your history or sent anywhere.
  const [q, setQ] = useState("");
  const { docs, loading, failed } = useAllContent();
  const results = useMemo(() => searchContent(docs, q), [docs, q]);
  const searching = q.trim().length >= 2;

  return (
    <>
      <PageHeader eyebrow="Search" title="Search guides, the wiki and the blog" intro="The search runs in your browser. What you type isn't sent anywhere, put in the address bar or kept." />
      <div className="container-cv max-w-3xl py-10">
        <form role="search" onSubmit={(e) => e.preventDefault()}>
          <div className="relative">
            <SearchIcon className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input
              type="search"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="For example: passwords, backups, two-factor"
              className="h-12 pl-10 text-base"
              aria-label="Search the site"
              autoComplete="off"
              autoFocus
            />
          </div>
        </form>
        <div className="mt-8" aria-live="polite">
          {loading && !docs.length ? (
            <Loading label="Loading pages to search" />
          ) : failed && !docs.length ? (
            <p className="text-sm text-destructive">The pages couldn't be loaded. Try again in a moment.</p>
          ) : !searching ? (
            <p className="text-sm text-muted-foreground">Type at least two letters. Every word has to appear somewhere on a page for it to show.</p>
          ) : results.length === 0 ? (
            <p className="text-sm text-muted-foreground">Nothing matches &ldquo;{q.trim()}&rdquo;. Try fewer or different words.</p>
          ) : (
            <>
              <p className="text-sm text-muted-foreground">{results.length === 1 ? "1 page" : `${results.length} pages`}</p>
              <ul className="mt-4 space-y-3">
                {results.map(({ doc, snippet }) => (
                  <li key={`${doc.kind}:${doc.url}:${doc.title}`}>
                    <div className="card-cv p-5">
                      <div className="flex flex-wrap items-center gap-2">
                        <Pill tone="accent">{KIND[doc.kind]}</Pill>
                        {doc.category && <Pill>{doc.category}</Pill>}
                      </div>
                      <h2 className="mt-2 text-lg font-semibold">
                        <Link to={doc.url} className="hover:text-primary hover:underline">{doc.title}</Link>
                      </h2>
                      {snippet && <p className="mt-1 text-sm text-muted-foreground">{snippet}</p>}
                      {doc.external && (
                        <a href={doc.external} target="_blank" rel="noopener noreferrer nofollow" className="mt-2 inline-flex items-center gap-1 text-sm text-primary hover:underline">
                          Visit site <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
                        </a>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      </div>
    </>
  );
}
