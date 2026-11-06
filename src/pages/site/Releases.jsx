import React from "react";
import { PageHeader } from "@/components/site/bits";
import { APP_VERSION, RELEASES } from "@/lib/site/version.js";

const longDate = (d) => new Date(`${d}T12:00:00Z`).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" });

export default function Releases() {
  return (
    <>
      <PageHeader
        eyebrow="Releases"
        title="What's changed"
        intro={`Every version of Commonveil, newest first. This site is running ${APP_VERSION}. A new minor version (0.x.0) adds features; a patch (0.x.y) fixes things.`}
      />
      <div className="container-cv py-10">
        <ol className="max-w-3xl">
          {RELEASES.map((r, i) => (
            <li key={r.version} id={`v${r.version}`} className="relative scroll-mt-24 border-l border-border pb-10 pl-6 last:pb-0">
              <span
                className={`absolute -left-[5px] top-2 h-2.5 w-2.5 rounded-full ${i === 0 ? "bg-primary" : "bg-border"}`}
                aria-hidden="true"
              />
              <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                <h2 className="text-xl font-semibold">
                  <a href={`#v${r.version}`} className="hover:text-primary">{r.version}</a>
                </h2>
                <p className="text-sm text-muted-foreground">
                  <time dateTime={r.date}>{longDate(r.date)}</time>
                  {i === 0 && <span className="ml-2 rounded-full bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary">This site</span>}
                </p>
              </div>
              <p className="mt-1 font-medium">{r.title}</p>
              <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-muted-foreground">
                {r.notes.map((n) => <li key={n}>{n}</li>)}
              </ul>
            </li>
          ))}
        </ol>
      </div>
    </>
  );
}
