import React from "react";
import { Check, Minus, X } from "lucide-react";

// How Commonveil compares with other chat apps, from each project's public documentation as of
// November 2026. Keep it honest and dated: other apps change, and so does this.

const APPS = ["Commonveil", "Signal", "Matrix (Element)", "Session", "SimpleX", "Discord", "Telegram"];

// yes / no / part, with a short note where "part" needs one.
const ROWS = [
  {
    label: "Sign up without a phone number",
    values: [["yes"], ["no", "Number-free sign-up is still in beta"], ["yes"], ["yes"], ["yes"], ["part", "Email, and sometimes a phone"], ["no"]],
  },
  {
    label: "Messages end-to-end encrypted by default",
    values: [["yes"], ["yes"], ["part", "Private rooms; public rooms aren't"], ["yes"], ["yes"], ["no", "Only calls are"], ["no", "Only one-to-one secret chats"]],
  },
  {
    label: "Encrypted communities with channels and roles",
    values: [["yes"], ["no", "Groups only"], ["yes", "Spaces"], ["no", "Communities aren't encrypted"], ["part", "Groups"], ["no", "Not encrypted"], ["no", "Not encrypted"]],
  },
  {
    label: "Run it on your own server",
    values: [["yes", "Docker"], ["no"], ["yes"], ["part", "Community servers"], ["yes", "Relays"], ["no"], ["no"]],
  },
  {
    label: "Talk with people on other servers",
    values: [["yes", "Commonveil Protocol"], ["no"], ["yes"], ["part", "One shared network"], ["yes"], ["no"], ["no"]],
  },
  {
    label: "Built-in moderation tools for communities",
    values: [["yes"], ["no"], ["part", "Mostly through bots"], ["part"], ["part"], ["yes"], ["part"]],
  },
  {
    label: "Safety check-ins (a message that sends itself unless you're OK)",
    values: [["yes"], ["no"], ["no"], ["no"], ["no"], ["no"], ["no"]],
  },
];

const ICON = {
  yes: [Check, "text-[hsl(var(--success,142_60%_40%))]", "Yes"],
  part: [Minus, "text-[hsl(var(--warning,38_90%_45%))]", "Partly"],
  no: [X, "text-muted-foreground", "No"],
};

function Cell({ value: [kind, note], first }) {
  const [Icon, tone, word] = ICON[kind];
  return (
    <td className={`px-3 py-3 align-top ${first ? "bg-[hsl(var(--primary)/0.05)]" : ""}`}>
      <span className="flex flex-col items-center gap-1 text-center">
        <Icon className={`h-4 w-4 ${tone}`} aria-hidden="true" />
        <span className="sr-only">{word}{note ? `: ${note}` : ""}</span>
        {note && <span className="text-[0.7rem] leading-tight text-muted-foreground" aria-hidden="true">{note}</span>}
      </span>
    </td>
  );
}

export default function Comparison() {
  return (
    <section className="container-cv py-16" aria-labelledby="compare-title">
      <p className="eyebrow">How it compares</p>
      <h2 id="compare-title" className="mt-3 max-w-2xl text-3xl font-semibold">Private chat apps, side by side</h2>
      <p className="mt-3 max-w-2xl text-muted-foreground">
        Each of these does some things well. Commonveil is for when you want Discord-style communities with the privacy of Signal, on a server you can run yourself.
      </p>
      <div className="mt-8 overflow-x-auto rounded-xl border border-border" tabIndex={0} role="region" aria-label="Comparison table, scrolls sideways">
        <table className="w-full min-w-[760px] border-collapse text-sm">
          <caption className="sr-only">Commonveil compared with other chat apps</caption>
          <thead>
            <tr className="border-b border-border bg-muted/40">
              <th scope="col" className="px-3 py-3 text-left font-medium text-muted-foreground"><span className="sr-only">Feature</span></th>
              {APPS.map((a, i) => (
                <th key={a} scope="col" className={`px-3 py-3 text-center font-semibold ${i === 0 ? "bg-[hsl(var(--primary)/0.08)] text-primary" : ""}`}>{a}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {ROWS.map((r) => (
              <tr key={r.label} className="border-b border-border last:border-0">
                <th scope="row" className="max-w-[16rem] px-3 py-3 text-left font-medium">{r.label}</th>
                {r.values.map((v, i) => <Cell key={APPS[i]} value={v} first={i === 0} />)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-3 text-xs text-muted-foreground">
        Compared in November 2026 from each project's own documentation. Apps change: if something here is out of date, tell us through the Commonveil Community server.
        Commonveil's encryption hasn't had an independent audit yet; Signal's has.
      </p>
    </section>
  );
}

