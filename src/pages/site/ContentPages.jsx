import React, { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, ArrowRight, CheckCircle2, Clock, ExternalLink } from "lucide-react";
import { contentBySlug, listContent } from "@/lib/api";
import Markdown from "@/components/site/Markdown";
import { DoneButton, SaveButton } from "@/components/site/SaveButton";
import { useSaved } from "@/lib/site/saved.js";
import { EmptyState, Loading, PageHeader, Pill, formatDate } from "@/components/site/bits";

function useList(entity, sort) {
  return useQuery({ queryKey: ["content", entity, sort], queryFn: () => listContent(entity, sort) });
}

function useOne(entity, slug) {
  return useQuery({ queryKey: ["content", entity, "slug", slug], queryFn: () => contentBySlug(entity, slug), enabled: Boolean(slug) });
}

function NotFoundBlock({ backTo, backLabel }) {
  return (
    <div className="container-cv py-16">
      <EmptyState title="That page isn't here">
        <Link className="text-primary underline" to={backTo}>{backLabel}</Link>
      </EmptyState>
    </div>
  );
}

function BackLink({ to, children }) {
  return (
    <Link to={to} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground">
      <ArrowLeft className="h-4 w-4" aria-hidden="true" /> {children}
    </Link>
  );
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

// ---------- Blog ----------

export function BlogIndex() {
  const { data = [], isLoading } = useList("BlogPost", "-published_at");
  const [cat, setCat] = useState(null);
  const posts = data.filter((p) => !cat || p.category === cat);
  return (
    <>
      <PageHeader eyebrow="Blog" title="Notes on privacy, self-hosting and the open web" intro="Written by hand, at the pace things actually change." />
      <div className="container-cv py-10">
        {isLoading ? <Loading /> : (
          <>
            <CategoryFilter items={data} value={cat} onChange={setCat} />
            {posts.length === 0 ? <EmptyState title="No posts yet" /> : (
              <ul className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
                {posts.map((p) => (
                  <li key={p.id} className="card-cv group overflow-hidden transition-shadow hover:shadow-md">
                    <Link to={`/blog/${p.slug}`} className="block h-full">
                      {p.cover_image && <img src={p.cover_image} alt="" loading="lazy" referrerPolicy="no-referrer" className="aspect-[16/9] w-full object-cover" />}
                      <div className="p-5">
                        <p className="eyebrow">{p.category}</p>
                        <h2 className="mt-2 text-xl font-semibold leading-snug group-hover:text-primary">{p.title}</h2>
                        {p.excerpt && <p className="mt-2 line-clamp-3 text-sm text-muted-foreground">{p.excerpt}</p>}
                        <p className="mt-4 text-xs text-muted-foreground">{[formatDate(p.published_at || p.created_date), p.reading_time].filter(Boolean).join(" · ")}</p>
                      </div>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </div>
    </>
  );
}

export function BlogArticle() {
  const { slug } = useParams();
  const { data: post, isLoading } = useOne("BlogPost", slug);
  if (isLoading) return <Loading />;
  if (!post) return <NotFoundBlock backTo="/blog" backLabel="Back to the blog" />;
  return (
    <article className="container-cv py-10">
      <BackLink to="/blog">All posts</BackLink>
      <header className="mt-6 max-w-3xl">
        <p className="eyebrow">{post.category}</p>
        <h1 className="mt-3 text-4xl font-semibold leading-tight sm:text-5xl">{post.title}</h1>
        {post.excerpt && <p className="mt-4 text-lg text-muted-foreground">{post.excerpt}</p>}
        <p className="mt-4 text-sm text-muted-foreground">
          {[post.author_name, formatDate(post.published_at || post.created_date), post.reading_time].filter(Boolean).join(" · ")}
        </p>
        <SaveButton kind="blog" slug={post.slug} title={post.title} className="mt-4" />
      </header>
      {post.cover_image && <img src={post.cover_image} alt="" referrerPolicy="no-referrer" className="mt-8 aspect-[16/8] w-full max-w-4xl rounded-xl border border-border object-cover" />}
      <div className="mt-10"><Markdown>{post.body}</Markdown></div>
      {post.tags?.length > 0 && (
        <div className="mt-10 flex flex-wrap gap-2">{post.tags.map((t) => <Pill key={t}>#{t}</Pill>)}</div>
      )}
    </article>
  );
}

// ---------- Guides ----------

export function GuidesIndex() {
  const { data = [], isLoading } = useList("Guide", "title");
  const { isDone } = useSaved();
  const [cat, setCat] = useState(null);
  const guides = data.filter((g) => !cat || g.category === cat);
  return (
    <>
      <PageHeader eyebrow="Guides" title="Step-by-step guides you can follow this afternoon" intro="Each guide says what it needs, how long it takes and when it was last tested." />
      <div className="container-cv py-10">
        {isLoading ? <Loading /> : (
          <>
            <CategoryFilter items={data} value={cat} onChange={setCat} />
            {guides.length === 0 ? <EmptyState title="No guides yet" /> : (
              <ul className="grid gap-4 sm:grid-cols-2">
                {guides.map((g) => (
                  <li key={g.id}>
                    <Link to={`/guides/${g.slug}`} className="card-cv group block h-full p-5 transition-shadow hover:shadow-md">
                      <div className="flex flex-wrap items-center gap-2">
                        <Pill tone="accent">{g.difficulty || "Beginner"}</Pill>
                        <Pill>{g.category}</Pill>
                        {g.estimated_time && <span className="inline-flex items-center gap-1 text-xs text-muted-foreground"><Clock className="h-3.5 w-3.5" aria-hidden="true" />{g.estimated_time}</span>}
                        {isDone(g.slug) && <span className="inline-flex items-center gap-1 text-xs font-medium text-primary"><CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />Done</span>}
                      </div>
                      <h2 className="mt-3 text-xl font-semibold group-hover:text-primary">{g.title}</h2>
                      {g.summary && <p className="mt-2 text-sm text-muted-foreground">{g.summary}</p>}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </div>
    </>
  );
}

function FactList({ title, items }) {
  if (!items?.length) return null;
  return (
    <div>
      <p className="text-sm font-semibold">{title}</p>
      <ul className="mt-1 list-disc pl-5 text-sm text-muted-foreground">{items.map((i) => <li key={i}>{i}</li>)}</ul>
    </div>
  );
}

export function GuideArticle() {
  const { slug } = useParams();
  const { data: guide, isLoading } = useOne("Guide", slug);
  if (isLoading) return <Loading />;
  if (!guide) return <NotFoundBlock backTo="/guides" backLabel="Back to guides" />;
  return (
    <article className="container-cv py-10">
      <BackLink to="/guides">All guides</BackLink>
      <div className="mt-6 grid gap-10 lg:grid-cols-[1fr_280px]">
        <div>
          <p className="eyebrow">{guide.category}</p>
          <h1 className="mt-3 text-4xl font-semibold leading-tight">{guide.title}</h1>
          {guide.summary && <p className="mt-4 max-w-2xl text-lg text-muted-foreground">{guide.summary}</p>}
          <div className="mt-10"><Markdown>{guide.body}</Markdown></div>
        </div>
        <aside className="card-cv h-fit space-y-4 p-5 lg:sticky lg:top-24">
          <div className="flex flex-wrap gap-2">
            <Pill tone="accent">{guide.difficulty || "Beginner"}</Pill>
            {guide.estimated_time && <Pill>{guide.estimated_time}</Pill>}
            {guide.os_version && <Pill>{guide.os_version}</Pill>}
          </div>
          <FactList title="You'll need" items={guide.requirements} />
          <FactList title="Before you start" items={guide.prerequisites} />
          {guide.last_tested && <p className="text-xs text-muted-foreground">Last tested {formatDate(guide.last_tested)}</p>}
          <div className="flex flex-wrap gap-2 border-t border-border pt-4">
            <DoneButton slug={guide.slug} />
            <SaveButton kind="guide" slug={guide.slug} title={guide.title} />
          </div>
          <p className="text-xs text-muted-foreground">Kept on this browser only. <Link to="/saved" className="underline hover:text-foreground">See what's saved</Link>.</p>
        </aside>
      </div>
    </article>
  );
}

// ---------- Learning paths ----------

export function PathsIndex() {
  const { data = [], isLoading } = useList("LearningPath", "title");
  const { isDone } = useSaved();
  return (
    <>
      <PageHeader eyebrow="Learning paths" title="A sensible order to learn things in" intro="Short sequences of guides, for when you don't know where to start." />
      <div className="container-cv py-10">
        {isLoading ? <Loading /> : data.length === 0 ? <EmptyState title="No paths yet" /> : (
          <ul className="grid gap-4 md:grid-cols-3">
            {data.map((p) => (
              <li key={p.id}>
                <Link to={`/paths/${p.slug}`} className="card-cv group flex h-full flex-col p-6 transition-shadow hover:shadow-md">
                  <div className="flex gap-2"><Pill tone="accent">{p.difficulty || "Beginner"}</Pill>{p.estimated_time && <Pill>{p.estimated_time}</Pill>}</div>
                  <h2 className="mt-3 text-2xl font-semibold group-hover:text-primary">{p.title}</h2>
                  <p className="mt-2 flex-1 text-sm text-muted-foreground">{p.summary}</p>
                  <p className="mt-4 inline-flex items-center gap-1 text-sm font-medium text-primary">
                    {(p.guide_slugs || []).length} guides
                    {(p.guide_slugs || []).some(isDone) && ` · ${(p.guide_slugs || []).filter(isDone).length} done`}
                    <ArrowRight className="h-4 w-4" aria-hidden="true" />
                  </p>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
    </>
  );
}

export function PathDetail() {
  const { slug } = useParams();
  const { data: path, isLoading } = useOne("LearningPath", slug);
  const { data: guides = [] } = useList("Guide", "title");
  const { isDone } = useSaved();
  if (isLoading) return <Loading />;
  if (!path) return <NotFoundBlock backTo="/paths" backLabel="Back to paths" />;
  const steps = (path.guide_slugs || []).map((s) => guides.find((g) => g.slug === s)).filter(Boolean);
  const finished = steps.filter((g) => isDone(g.slug)).length;
  return (
    <div className="container-cv py-10">
      <BackLink to="/paths">All paths</BackLink>
      <header className="mt-6 max-w-3xl">
        <p className="eyebrow">{path.category}</p>
        <h1 className="mt-3 text-4xl font-semibold">{path.title}</h1>
        <p className="mt-4 text-lg text-muted-foreground">{path.description || path.summary}</p>
        <SaveButton kind="path" slug={path.slug} title={path.title} className="mt-4" />
      </header>
      {steps.length > 0 && (
        <div className="mt-8 max-w-3xl">
          <div className="flex items-center justify-between text-sm">
            <span className="font-medium">{finished === steps.length ? "All done. Nicely done." : `${finished} of ${steps.length} done`}</span>
            <span className="text-xs text-muted-foreground">Progress is kept on this browser only.</span>
          </div>
          <div className="mt-2 h-2 overflow-hidden rounded-full bg-muted" role="progressbar" aria-label="Guides done" aria-valuemin={0} aria-valuemax={steps.length} aria-valuenow={finished}>
            <div className="h-full rounded-full bg-primary transition-all" style={{ width: `${(finished / steps.length) * 100}%` }} />
          </div>
        </div>
      )}
      <ol className="mt-8 max-w-3xl space-y-3">
        {steps.map((g, i) => {
          const done = isDone(g.slug);
          return (
            <li key={g.id}>
              <Link to={`/guides/${g.slug}`} className="card-cv group flex items-start gap-4 p-5 hover:shadow-md">
                <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-full font-heading text-lg ${done ? "bg-primary/15 text-primary" : "bg-primary text-primary-foreground"}`}>
                  {done ? <CheckCircle2 className="h-5 w-5" aria-label="Done" /> : i + 1}
                </span>
                <span>
                  <span className="block text-lg font-semibold group-hover:text-primary">{g.title}</span>
                  <span className="mt-1 block text-sm text-muted-foreground">{g.summary}</span>
                </span>
              </Link>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

// ---------- Resources ----------

export function ResourcesIndex() {
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
                    <a href={r.website} target="_blank" rel="noopener noreferrer nofollow" className="mt-4 inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline">
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

// ---------- Wiki ----------

export function WikiIndex() {
  const { data = [], isLoading } = useList("WikiPage", "title");
  return (
    <>
      <PageHeader eyebrow="Wiki" title="Plain-language explanations" intro="Short reference pages for the ideas behind private technology." />
      <div className="container-cv py-10">
        {isLoading ? <Loading /> : data.length === 0 ? <EmptyState title="No pages yet" /> : (
          <ul className="grid gap-4 sm:grid-cols-2">
            {data.map((p) => (
              <li key={p.id}>
                <Link to={`/wiki/${p.slug}`} className="card-cv group block p-5 hover:shadow-md">
                  <p className="eyebrow">{p.category}</p>
                  <h2 className="mt-2 text-xl font-semibold group-hover:text-primary">{p.title}</h2>
                  {p.summary && <p className="mt-2 text-sm text-muted-foreground">{p.summary}</p>}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
    </>
  );
}

export function WikiArticle() {
  const { slug } = useParams();
  const { data: page, isLoading } = useOne("WikiPage", slug);
  if (isLoading) return <Loading />;
  if (!page) return <NotFoundBlock backTo="/wiki" backLabel="Back to the wiki" />;
  return (
    <article className="container-cv py-10">
      <BackLink to="/wiki">Wiki</BackLink>
      <p className="eyebrow mt-6">{page.category}</p>
      <h1 className="mt-3 text-4xl font-semibold">{page.title}</h1>
      {page.summary && <p className="mt-4 max-w-2xl text-lg text-muted-foreground">{page.summary}</p>}
      <SaveButton kind="wiki" slug={page.slug} title={page.title} className="mt-4" />
      <div className="mt-10"><Markdown>{page.body}</Markdown></div>
      <p className="mt-10 text-xs text-muted-foreground">Last updated {formatDate(page.updated_date)}</p>
    </article>
  );
}
