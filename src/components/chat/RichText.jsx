import React, { useState } from "react";
import { Link } from "react-router-dom";

// Message formatting, done here as React elements (never HTML strings): code blocks, inline
// code, headings, lists, small text, bold, italics, underline, strikethrough, spoilers, quotes,
// links, @mentions and #channels.
// Links aren't previewed: nothing is fetched until you choose to open one.

const INLINE = new RegExp(
  [
    "(`[^`\\n]+`)", // 1 code
    "(\\*\\*[^*\\n]+\\*\\*)", // 2 bold
    "(\\|\\|[^|\\n]+\\|\\|)", // 3 spoiler
    "(~~[^~\\n]+~~)", // 4 strike
    "(https?:\\/\\/[^\\s<>\"]+[^\\s<>\".,:;'!?)\\]])", // 5 link
    "(@[A-Za-z0-9_]{3,20}(?:\\.[A-Za-z0-9-]+)*\\b)", // 6 mention (a handle on another site has dots)
    "(#[\\p{L}\\p{N}][\\p{L}\\p{N}-]{0,99})", // 7 channel
    "(__[^_\\n]+__)", // 8 underline
    "(\\*[^*\\s][^*\\n]*\\*)", // 9 italic
    "(\\b_[^_\\n]+_\\b)", // 10 italic
    "(<:[a-z0-9_]{2,32}:[a-z0-9]{8}>)", // 11 a server's own emoji
  ].join("|"),
  "gu",
);

function Spoiler({ children }) {
  const [shown, setShown] = useState(false);
  return (
    <button
      type="button"
      onClick={() => setShown(true)}
      className={`rounded px-0.5 ${shown ? "bg-muted" : "bg-foreground/80 text-transparent hover:bg-foreground/70"}`}
      aria-label={shown ? undefined : "Spoiler: select to show"}
    >
      {children}
    </button>
  );
}

function inline(text, ctx, keyBase) {
  const out = [];
  let last = 0;
  let i = 0;
  for (const m of text.matchAll(INLINE)) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const k = `${keyBase}-${i++}`;
    const [token] = m;
    if (m[1]) out.push(<code key={k} className="rounded bg-muted px-1 py-0.5 font-mono text-[0.88em]">{token.slice(1, -1)}</code>);
    else if (m[2]) out.push(<strong key={k}>{inline(token.slice(2, -2), ctx, k)}</strong>);
    else if (m[3]) out.push(<Spoiler key={k}>{inline(token.slice(2, -2), ctx, k)}</Spoiler>);
    else if (m[4]) out.push(<s key={k}>{inline(token.slice(2, -2), ctx, k)}</s>);
    else if (m[5]) {
      out.push(
        <a key={k} href={token} target="_blank" rel="noopener noreferrer nofollow" className="break-all text-primary underline decoration-primary/40 underline-offset-2 hover:decoration-primary">
          {token}
        </a>,
      );
    } else if (m[6]) {
      const name = token.slice(1);
      const everyone = name === "everyone" || name === "here";
      const who = everyone ? null : ctx.resolveUser?.(name);
      if (everyone || who) {
        const mine = everyone || who?.self;
        out.push(
          <span key={k} className={`rounded px-0.5 font-medium ${mine ? "bg-[hsl(var(--warning)/0.18)] text-[hsl(var(--warning))]" : "bg-primary/15 text-primary"}`}>
            @{who?.name || name}
          </span>,
        );
      } else out.push(token);
    } else if (m[7]) {
      const ch = ctx.resolveChannel?.(token.slice(1));
      if (ch) {
        out.push(
          <Link key={k} to={ch.to} className="rounded bg-primary/15 px-0.5 font-medium text-primary hover:underline">
            #{ch.name}
          </Link>,
        );
      } else out.push(token);
    } else if (m[8]) out.push(<u key={k}>{inline(token.slice(2, -2), ctx, k)}</u>);
    else if (m[9] || m[10]) out.push(<em key={k}>{inline(token.slice(1, -1), ctx, k)}</em>);
    else if (m[11]) {
      const [, name, id] = token.slice(1, -1).split(":");
      const found = ctx.resolveEmoji?.(id);
      out.push(found ? <img key={k} src={found.img} alt={`:${found.name}:`} title={`:${found.name}:`} className="inline-block h-[1.375em] w-[1.375em] align-[-0.3em] object-contain" draggable={false} /> : `:${name}:`);
    }
    last = m.index + token.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

/**
 * ctx: { resolveUser(username) -> { name, self } | null, resolveChannel(name) -> { name, to } | null,
 *   resolveEmoji(id) -> { name, img } | null }.
 */
export default function RichText({ text, ctx = {} }) {
  const parts = String(text || "").split(/```(?:[a-z0-9+-]*\n)?([\s\S]*?)```/i);
  return (
    <>
      {parts.map((part, pi) => {
        if (pi % 2 === 1) {
          return (
            <pre key={pi} className="my-1 max-w-full overflow-x-auto rounded-md border border-border bg-muted px-3 py-2 font-mono text-[0.85em] leading-relaxed">
              <code>{part.replace(/\n$/, "")}</code>
            </pre>
          );
        }
        const lines = part.split("\n");
        const blocks = [];
        let quote = [];
        const flush = (key) => {
          if (!quote.length) return;
          blocks.push(
            <blockquote key={`q${key}`} className="my-0.5 border-l-4 border-border pl-2.5 text-foreground/90">
              {quote.map((l, li) => (
                <React.Fragment key={li}>
                  {li > 0 && <br />}
                  {inline(l, ctx, `${pi}q${key}${li}`)}
                </React.Fragment>
              ))}
            </blockquote>,
          );
          quote = [];
        };
        lines.forEach((line, li) => {
          if (/^> ?/.test(line)) {
            quote.push(line.replace(/^> ?/, ""));
            return;
          }
          flush(li);
          const heading = /^(#{1,3}) (\S.*)$/.exec(line);
          if (heading) {
            const size = ["text-xl", "text-lg", "text-base"][heading[1].length - 1];
            blocks.push(<span key={li} className={`mt-1 block font-heading font-semibold leading-snug ${size}`}>{inline(heading[2], ctx, `${pi}h${li}`)}</span>);
            return;
          }
          const small = /^-# (\S.*)$/.exec(line);
          if (small) {
            blocks.push(<span key={li} className="block text-xs text-muted-foreground">{inline(small[1], ctx, `${pi}s${li}`)}</span>);
            return;
          }
          const bullet = /^\s*[-*] (\S.*)$/.exec(line);
          if (bullet) {
            blocks.push(<span key={li} className="flex gap-2 pl-1"><span aria-hidden="true">•</span><span className="min-w-0">{inline(bullet[1], ctx, `${pi}b${li}`)}</span></span>);
            return;
          }
          blocks.push(
            <React.Fragment key={li}>
              {blocks.length > 0 && !(lines[li - 1] !== undefined && /^(> ?|#{1,3} \S|-# \S|\s*[-*] \S)/.test(lines[li - 1])) && <br />}
              {inline(line, ctx, `${pi}l${li}`)}
            </React.Fragment>,
          );
        });
        flush("end");
        return <React.Fragment key={pi}>{blocks}</React.Fragment>;
      })}
    </>
  );
}
