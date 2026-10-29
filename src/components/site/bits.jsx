import React from "react";
import { Loader2 } from "lucide-react";

export function PageHeader({ eyebrow, title, intro, children }) {
  return (
    <header className="border-b border-border bg-gradient-to-b from-accent/40 to-transparent">
      <div className="container-cv py-12 sm:py-16">
        {eyebrow && <p className="eyebrow mb-3">{eyebrow}</p>}
        <h1 className="max-w-3xl text-4xl font-semibold leading-tight sm:text-5xl">{title}</h1>
        {intro && <p className="mt-4 max-w-2xl text-lg text-muted-foreground">{intro}</p>}
        {children}
      </div>
    </header>
  );
}

export function Loading({ label = "Loading" }) {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-muted-foreground" role="status">
      <Loader2 className="h-5 w-5 animate-spin" aria-hidden="true" />
      <span>{label}…</span>
    </div>
  );
}

export function FullScreenLoading({ label = "Loading" }) {
  return (
    <div className="fixed inset-0 flex items-center justify-center">
      <Loading label={label} />
    </div>
  );
}

export function EmptyState({ title, children }) {
  return (
    <div className="card-cv px-6 py-12 text-center">
      <p className="font-heading text-xl">{title}</p>
      {children && <div className="mt-2 text-muted-foreground">{children}</div>}
    </div>
  );
}

export function ErrorNote({ children }) {
  if (!children) return null;
  return (
    <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive" role="alert">
      {children}
    </div>
  );
}

export function Pill({ children, tone = "muted" }) {
  const tones = {
    muted: "bg-muted text-muted-foreground",
    accent: "bg-accent text-accent-foreground",
    warn: "bg-[hsl(var(--warning)/0.15)] text-[hsl(var(--warning))]",
  };
  return <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${tones[tone]}`}>{children}</span>;
}

export function formatDate(value) {
  if (!value) return "";
  const s = /Z$|[+-]\d{2}:\d{2}$/.test(value) ? value : `${value}Z`;
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" });
}

export function formatTime(value) {
  if (!value) return "";
  const s = /Z$|[+-]\d{2}:\d{2}$/.test(value) ? value : `${value}Z`;
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return "";
  const today = new Date();
  const sameDay = d.toDateString() === today.toDateString();
  return sameDay
    ? d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })
    : d.toLocaleDateString("en-GB", { day: "numeric", month: "short" }) + " " + d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
}
