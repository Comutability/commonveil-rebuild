import React, { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, ArrowRight, BookOpen, Download, Printer, Search as SearchIcon } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import Markdown from "@/components/site/Markdown";
import { EmptyState, PageHeader } from "@/components/site/bits";
import { buildGuide, groupBySection, headingsOf, neighbours, searchHelp } from "@/lib/site/help.js";
import { HELP_ARTICLES, helpBySlug } from "@/lib/site/helpContent.js";

const START_HERE = ["create-account", "conversations", "safety-numbers", "privacy-report"];

function useTitle(title) {
  useEffect(() => {
    const before = document.title;
    document.title = `${title} · Commonveil help`;
    return () => {
      document.title = before;
    };
  }, [title]);
}

function ArticleLink({ a }) {
  return (
    <Link to={`/help/${a.slug}`} className="group block rounded-lg px-3 py-3 -mx-3 hover:bg-muted">
      <span className="block font-medium group-hover:text-primary">{a.title}</span>
      <span className="mt-0.5 block text-sm text-muted-foreground">{a.summary}</span>
    </Link>
  );
}

function downloadGuide() {
  const md = buildGuide(HELP_ARTICLES, { links: "anchors", siteUrl: window.location.origin });
  const url = URL.createObjectURL(new Blob([md], { type: "text/markdown;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = "commonveil-guide.md";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ---------- /help ----------

export function HelpIndex() {
  useTitle("Help Centre");
  // Kept in this page only: never in the address bar, so it isn't in your history or sent anywhere.
  const [q, setQ] = useState("");
  const results = useMemo(() => searchHelp(HELP_ARTICLES, q), [q]);
  const searching = q.trim().length >= 2;
  const groups = useMemo(() => groupBySection(HELP_ARTICLES), []);
  const start = START_HERE.map(helpBySlug).filter(Boolean);

  return (
    <>
      <PageHeader
        eyebrow="Help Centre"
        title="How to use Commonveil"
        intro="Every feature, what it's for, and exactly what it shares. Start with the basics, or search for what you need."
      >
        <form role="search" onSubmit={(e) => e.preventDefault()} className="mt-8 max-w-xl">
          <div className="relative">
            <SearchIcon className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input
              type="search"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="For example: recovery phrase, check-in, roles"
              className="h-12 bg-background pl-10 text-base"
              aria-label="Search the help"
              autoComplete="off"
            />
          </div>
          <p className="mt-2 text-xs text-muted-foreground">Searched in your browser. What you type isn't sent anywhere.</p>
        </form>
      </PageHeader>

      <div className="container-cv py-10">
        {searching ? (
          <section aria-live="polite" aria-label="Search results" className="max-w-3xl">
            <h2 className="text-xl font-semibold">{results.length ? `${results.length} ${results.length === 1 ? "article" : "articles"}` : "Nothing matches"}</h2>
            {results.length ? (
              <ul className="mt-4 divide-y divide-border">
                {results.map((a) => (
                  <li key={a.slug}>
                    <ArticleLink a={a} />
                    <span className="sr-only">In {a.section}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-2 text-sm text-muted-foreground">Every word has to appear in an article. Try fewer words, or browse the sections below.</p>
            )}
          </section>
        ) : (
          <>
            <section aria-labelledby="start-here">
              <h2 id="start-here" className="text-xl font-semibold">New here? Start with these</h2>
              <ol className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                {start.map((a, i) => (
                  <li key={a.slug}>
                    <Link to={`/help/${a.slug}`} className="card-cv group flex h-full gap-3 p-4 hover:border-primary/50">
                      <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary text-sm font-semibold text-primary-foreground" aria-hidden="true">{i + 1}</span>
                      <span>
                        <span className="block font-medium group-hover:text-primary">{a.title}</span>
                        <span className="mt-1 block text-sm text-muted-foreground">{a.summary}</span>
                      </span>
                    </Link>
                  </li>
                ))}
              </ol>
            </section>

            <div className="mt-14 grid gap-x-12 gap-y-12 md:grid-cols-2">
              {groups.map((g) => (
                <section key={g.section} aria-labelledby={`sec-${g.section}`}>
                  <h2 id={`sec-${g.section}`} className="border-b border-border pb-2 text-lg font-semibold">{g.section}</h2>
                  <ul className="mt-2">
                    {g.articles.map((a) => <li key={a.slug}><ArticleLink a={a} /></li>)}
                  </ul>
                </section>
              ))}
            </div>
          </>
        )}

        <aside className="card-cv mt-14 flex flex-col gap-4 p-6 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="flex items-center gap-2 font-semibold"><BookOpen className="h-5 w-5 text-primary" aria-hidden="true" /> The complete guide</h2>
            <p className="mt-1 text-sm text-muted-foreground">Every article on one page, to read through, print or keep.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button asChild><Link to="/help/guide">Read the complete guide</Link></Button>
            <Button variant="outline" onClick={downloadGuide}><Download className="mr-2 h-4 w-4" aria-hidden="true" /> Download</Button>
          </div>
        </aside>
      </div>
    </>
  );
}

// ---------- /help/:slug ----------

export function HelpArticle() {
  const { slug } = useParams();
  const article = helpBySlug(slug);
  useTitle(article ? article.title : "Not found");
  if (!article) {
    return (
      <div className="container-cv py-16">
        <EmptyState title="That help article isn't here">
          <Link className="text-primary underline" to="/help">Back to the Help Centre</Link>
        </EmptyState>
      </div>
    );
  }
  const toc = headingsOf(article.body);
  const { previous, next } = neighbours(HELP_ARTICLES, article.slug);
  const sameSection = HELP_ARTICLES.filter((a) => a.section === article.section);

  return (
    <article className="container-cv py-10">
      <Link to="/help" className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="h-4 w-4" aria-hidden="true" /> Help Centre
      </Link>
      <div className="mt-6 grid gap-10 lg:grid-cols-[1fr_260px]">
        <div className="min-w-0">
          <p className="eyebrow">{article.section}</p>
          <h1 className="mt-3 text-4xl font-semibold leading-tight">{article.title}</h1>
          <p className="mt-4 max-w-2xl text-lg text-muted-foreground">{article.summary}</p>
          <div className="mt-10"><Markdown>{article.body}</Markdown></div>

          <nav aria-label="More help" className="mt-14 grid gap-3 border-t border-border pt-6 sm:grid-cols-2">
            {previous ? (
              <Link to={`/help/${previous.slug}`} className="card-cv group p-4 hover:border-primary/50">
                <span className="flex items-center gap-1 text-xs text-muted-foreground"><ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" /> Previous</span>
                <span className="mt-1 block font-medium group-hover:text-primary">{previous.title}</span>
              </Link>
            ) : <span />}
            {next && (
              <Link to={`/help/${next.slug}`} className="card-cv group p-4 text-right hover:border-primary/50">
                <span className="flex items-center justify-end gap-1 text-xs text-muted-foreground">Next <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" /></span>
                <span className="mt-1 block font-medium group-hover:text-primary">{next.title}</span>
              </Link>
            )}
          </nav>
        </div>

        <aside className="h-fit space-y-8 lg:sticky lg:top-24">
          {toc.length > 1 && (
            <nav aria-label="On this page">
              <p className="text-sm font-semibold">On this page</p>
              <ul className="mt-2 space-y-1.5 border-l border-border text-sm">
                {toc.map((h) => (
                  <li key={h.id}><a href={`#${h.id}`} className="-ml-px block border-l border-transparent pl-3 text-muted-foreground hover:border-primary hover:text-foreground">{h.text}</a></li>
                ))}
              </ul>
            </nav>
          )}
          {sameSection.length > 1 && (
            <nav aria-label={`More in ${article.section}`}>
              <p className="text-sm font-semibold">More in {article.section}</p>
              <ul className="mt-2 space-y-1.5 text-sm">
                {sameSection.map((a) => (
                  <li key={a.slug}>
                    {a.slug === article.slug
                      ? <span className="font-medium text-foreground" aria-current="page">{a.title}</span>
                      : <Link to={`/help/${a.slug}`} className="text-muted-foreground hover:text-foreground">{a.title}</Link>}
                  </li>
                ))}
              </ul>
            </nav>
          )}
          <div className="card-cv p-4 text-sm">
            <p className="font-medium">Try it now</p>
            <p className="mt-1 text-muted-foreground">Everything here is in the app.</p>
            <Button asChild size="sm" className="mt-3"><Link to="/app">Open Commonveil</Link></Button>
          </div>
        </aside>
      </div>
    </article>
  );
}

// ---------- /help/guide ----------

export function HelpGuide() {
  useTitle("The complete guide");
  // Links between articles jump within this page.
  const md = useMemo(() => buildGuide(HELP_ARTICLES, { links: "anchors", title: "" }).replace(/^# *\n+/, ""), []);
  return (
    <>
      <PageHeader eyebrow="Help Centre" title="The complete guide" intro="Every Commonveil feature, what it's for and how to use it, on one page.">
        <div className="mt-6 flex flex-wrap gap-2 print:hidden">
          <Button variant="outline" onClick={() => window.print()}><Printer className="mr-2 h-4 w-4" aria-hidden="true" /> Print or save as PDF</Button>
          <Button variant="outline" onClick={downloadGuide}><Download className="mr-2 h-4 w-4" aria-hidden="true" /> Download</Button>
          <Button asChild variant="ghost"><Link to="/help">Back to the Help Centre</Link></Button>
        </div>
      </PageHeader>
      <div className="container-cv py-10">
        <Markdown>{md}</Markdown>
      </div>
    </>
  );
}
