import React from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowRight, BookOpen, CalendarClock, KeyRound, Lock, MessagesSquare, Phone, ShieldCheck, Users } from "lucide-react";
import { Button } from "@/components/ui/button";

const PROTECTIONS = [
  [Lock, "Content stays between you", "Messages and group names are encrypted on your device. Our servers store ciphertext they can't read."],
  [KeyRound, "Your keys, your devices", "Private keys never leave your devices. New devices join only with approval from one you already have, or your recovery phrase."],
  [ShieldCheck, "Check who you're talking to", "Every message is signed. Compare a safety number in person and you'll know nobody swapped the keys."],
  [MessagesSquare, "No directory to browse", "People find you only by your exact username. There's no member list and no public profile page."],
];

const FEATURES = [
  [MessagesSquare, "Messages and groups", "Direct messages and groups of up to 32, with replies, reactions, files, voice notes and polls.", "/help/messages"],
  [Users, "Communities", "Servers with channels, roles, threads, events and built-in moderation, all encrypted.", "/help/servers"],
  [Phone, "Calls", "Voice, video and screen sharing, straight between devices and encrypted twice over.", "/help/calls"],
  [CalendarClock, "Safety check-ins", "A message that sends itself if you don't say you're OK in time. Plus send later and self-destructing chats.", "/help/send-later-and-check-ins"],
];

export default function Home() {
  const [params] = useSearchParams();
  const deleted = params.get("account_deleted") === "1";

  return (
    <>
      {deleted && (
        <div className="border-b border-border bg-accent/50" role="status">
          <p className="container-cv py-3 text-sm">Your account has been deleted, and this browser's keys with it.</p>
        </div>
      )}
      <section className="relative overflow-hidden border-b border-border">
        <div aria-hidden="true" className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_left,hsl(var(--primary)/0.14),transparent_55%),radial-gradient(ellipse_at_bottom_right,hsl(var(--warning)/0.10),transparent_50%)]" />
        <div className="container-cv relative py-20 sm:py-28">
          <p className="eyebrow">Be it me, not you</p>
          <h1 className="mt-4 max-w-3xl text-5xl font-semibold leading-[1.05] sm:text-6xl">
            Own your digital life. Talk without being overheard.
          </h1>
          <p className="mt-6 max-w-2xl text-lg text-muted-foreground sm:text-xl">
            Commonveil is a place to talk, one to one, in groups and in whole communities, with end-to-end encryption that doesn't
            depend on trusting us.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Button asChild size="lg">
              <Link to="/app">
                <Lock className="mr-2 h-5 w-5" aria-hidden="true" /> Open Commonveil
              </Link>
            </Button>
            <Button asChild size="lg" variant="outline">
              <Link to="/help">
                <BookOpen className="mr-2 h-5 w-5" aria-hidden="true" /> How it works
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
              Messages, groups, communities and calls, encrypted on your device. Our servers check who's allowed to post and store what they're given,
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
          <p className="eyebrow">What you can do</p>
          <h2 className="mt-3 max-w-2xl text-3xl font-semibold">Everything you'd expect from a chat app, without handing it your life</h2>
          <ul className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {FEATURES.map(([Icon, title, text, to]) => (
              <li key={title}>
                <Link to={to} className="card-cv group flex h-full flex-col p-5 hover:shadow-md">
                  <Icon className="h-5 w-5 text-primary" aria-hidden="true" />
                  <h3 className="mt-3 font-semibold group-hover:text-primary">{title}</h3>
                  <p className="mt-1.5 flex-1 text-sm text-muted-foreground">{text}</p>
                </Link>
              </li>
            ))}
          </ul>
          <Link to="/help" className="mt-8 inline-flex items-center gap-1 font-medium text-primary hover:underline">
            See how everything works <ArrowRight className="h-4 w-4" aria-hidden="true" />
          </Link>
        </div>
      </section>
    </>
  );
}
