import React from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, BookOpen, KeyRound, Lock, MessagesSquare, ShieldCheck, Wrench } from "lucide-react";
import { Button } from "@/components/ui/button";
import { listContent } from "@/lib/api";
import { formatDate } from "@/components/site/bits";

const PROTECTIONS = [
  [Lock, "Content stays between you", "Messages and group names are encrypted on your device. Our servers store ciphertext they can't read."],
  [KeyRound, "Your keys, your devices", "Private keys never leave your devices. New devices join only with approval from one you already have, or your recovery phrase."],
  [ShieldCheck, "Check who you're talking to", "Every message is signed. Compare a safety number in person and you'll know nobody swapped the keys."],
  [MessagesSquare, "No directory to browse", "People find you only by your exact username. There's no member list and no public profile page."],
];

export default function Home() {
  const posts = useQuery({ queryKey: ["content", "BlogPost", "home"], queryFn: () => listContent("BlogPost", "-published_at", 3) });
  const guides = useQuery({ queryKey: ["content", "Guide", "home"], queryFn: () => listContent("Guide", "title", 4) });

  return (
    <>
      <section className="relative overflow-hidden border-b border-border">
        <div aria-hidden="true" className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_left,hsl(var(--primary)/0.14),transparent_55%),radial-gradient(ellipse_at_bottom_right,hsl(var(--warning)/0.10),transparent_50%)]" />
        <div className="container-cv relative py-20 sm:py-28">
          <p className="eyebrow">Be it me, not you</p>
          <h1 className="mt-4 max-w-3xl text-5xl font-semibold leading-[1.05] sm:text-6xl">
            Own your digital life. Talk without being overheard.
          </h1>
          <p className="mt-6 max-w-2xl text-lg text-muted-foreground sm:text-xl">
            Commonveil is a place to learn practical privacy, one sensible step at a time, and to message people with end-to-end encryption
            that doesn't depend on trusting us.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Button asChild size="lg">
              <Link to="/guides">
                <BookOpen className="mr-2 h-5 w-5" aria-hidden="true" /> Start learning
              </Link>
            </Button>
            <Button asChild size="lg" variant="outline">
              <Link to="/app">
                <Lock className="mr-2 h-5 w-5" aria-hidden="true" /> Open encrypted messages
              </Link>
            </Button>
          </div>
        </div>
      </section>

      <section className="container-cv py-16">
        <div className="grid gap-10 lg:grid-cols-[1fr_1.4fr]">
          <div>
            <p className="eyebrow">Messaging</p>
            <h2 className="mt-3 text-3xl font-semibold">Private by construction, not by promise</h2>
            <p className="mt-4 text-muted-foreground">
              Direct messages and small groups, encrypted on your device. Our servers check who's allowed to post and store what they're given,
              but they never hold anything that would let them read it.
            </p>
            <Link to="/security" className="mt-4 inline-flex items-center gap-1 font-medium text-primary hover:underline">
              How it works, and what it doesn't protect <ArrowRight className="h-4 w-4" aria-hidden="true" />
            </Link>
          </div>
          <ul className="grid gap-4 sm:grid-cols-2">
            {PROTECTIONS.map(([Icon, title, text]) => (
              <li key={title} className="card-cv p-5">
                <Icon className="h-6 w-6 text-primary" aria-hidden="true" />
                <h3 className="mt-3 text-lg font-semibold">{title}</h3>
                <p className="mt-1.5 text-sm text-muted-foreground">{text}</p>
              </li>
            ))}
          </ul>
        </div>
        <div className="mt-8 rounded-xl border border-[hsl(var(--warning)/0.4)] bg-[hsl(var(--warning)/0.08)] p-5 text-sm">
          <strong>Honest status:</strong> the protocol is small, documented and tested, but it hasn't had an independent security audit yet.
          It's a good fit for everyday privacy. If your safety depends on it, use an audited tool such as Signal until an audit is published here.
        </div>
      </section>

      <section className="border-y border-border bg-muted/40">
        <div className="container-cv py-16">
          <div className="flex items-end justify-between gap-4">
            <div>
              <p className="eyebrow">Guides</p>
              <h2 className="mt-3 text-3xl font-semibold">Start with one thing that would hurt to lose</h2>
            </div>
            <Link to="/paths" className="hidden shrink-0 items-center gap-1 font-medium text-primary hover:underline sm:inline-flex">
              Learning paths <ArrowRight className="h-4 w-4" aria-hidden="true" />
            </Link>
          </div>
          <ul className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {(guides.data || []).map((g) => (
              <li key={g.id}>
                <Link to={`/guides/${g.slug}`} className="card-cv group flex h-full flex-col p-5 hover:shadow-md">
                  <Wrench className="h-5 w-5 text-primary" aria-hidden="true" />
                  <h3 className="mt-3 font-semibold group-hover:text-primary">{g.title}</h3>
                  <p className="mt-1.5 line-clamp-3 flex-1 text-sm text-muted-foreground">{g.summary}</p>
                  <p className="mt-3 text-xs text-muted-foreground">{[g.difficulty, g.estimated_time].filter(Boolean).join(" · ")}</p>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section className="container-cv py-16">
        <div className="flex items-end justify-between gap-4">
          <div>
            <p className="eyebrow">From the blog</p>
            <h2 className="mt-3 text-3xl font-semibold">Recent writing</h2>
          </div>
          <Link to="/blog" className="inline-flex shrink-0 items-center gap-1 font-medium text-primary hover:underline">
            All posts <ArrowRight className="h-4 w-4" aria-hidden="true" />
          </Link>
        </div>
        <ul className="mt-8 grid gap-6 md:grid-cols-3">
          {(posts.data || []).map((p) => (
            <li key={p.id}>
              <Link to={`/blog/${p.slug}`} className="group block">
                <p className="eyebrow">{p.category}</p>
                <h3 className="mt-2 text-xl font-semibold leading-snug group-hover:text-primary">{p.title}</h3>
                <p className="mt-2 line-clamp-2 text-sm text-muted-foreground">{p.excerpt}</p>
                <p className="mt-2 text-xs text-muted-foreground">{formatDate(p.published_at || p.created_date)}</p>
              </Link>
            </li>
          ))}
        </ul>
      </section>
    </>
  );
}
