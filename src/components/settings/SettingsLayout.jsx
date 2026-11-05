import React, { useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowLeft, ChevronRight, X } from "lucide-react";

/** Leave settings: back to wherever you were, or a fallback. */
export function useCloseSettings(fallback) {
  const navigate = useNavigate();
  return () => {
    if ((window.history.state?.idx ?? 0) > 0) navigate(-1);
    else navigate(fallback, { replace: true });
  };
}

/**
 * Settings, full screen: sections down the left, the open one on the right, Escape to leave.
 * On a phone: the list of sections first, then one section with a way back.
 * groups: [{ label, items: [{ id, label, icon, to, tone }] }].
 */
export default function SettingsLayout({ groups, active, base, title, onClose, children, footer = null }) {
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape" && !document.querySelector("[role='dialog'],[role='alertdialog']")) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const nav = (
    <nav aria-label={`${title} sections`} className="space-y-5">
      {groups.map((g) => (
        <div key={g.label}>
          <h2 className="px-2.5 pb-1 text-xs font-semibold text-muted-foreground">{g.label}</h2>
          <ul className="space-y-0.5">
            {g.items.map((it) => (
              <li key={it.id}>
                <Link
                  to={it.to || `${base}/${it.id}`}
                  replace
                  aria-current={active === it.id ? "page" : undefined}
                  className={`panel-item justify-between ${it.tone === "danger" ? "!text-destructive" : ""}`}
                >
                  <span className="flex min-w-0 items-center gap-2">
                    {it.icon && <it.icon className="h-4 w-4 shrink-0" aria-hidden="true" />}
                    <span className="truncate">{it.label}</span>
                  </span>
                  <ChevronRight className="h-4 w-4 shrink-0 opacity-50 md:hidden" aria-hidden="true" />
                </Link>
              </li>
            ))}
          </ul>
        </div>
      ))}
      {footer}
    </nav>
  );

  return (
    <div className="flex h-full w-full overflow-hidden bg-chat">
      <aside className={`${active ? "hidden md:flex" : "flex"} scroll-thin w-full shrink-0 justify-end overflow-y-auto bg-panel md:w-[min(20rem,32vw)]`}>
        <div className="w-full max-w-[14rem] px-3 py-8 md:max-w-[15rem]">
          <div className="mb-6 flex items-center justify-between gap-2 px-2.5 md:block">
            <p className="truncate font-heading text-lg font-semibold">{title}</p>
            <button type="button" onClick={onClose} className="rounded-full border border-border p-1.5 text-muted-foreground hover:text-foreground md:hidden" aria-label="Close settings">
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
          {nav}
        </div>
      </aside>
      <main className={`${active ? "flex" : "hidden md:flex"} scroll-thin min-w-0 flex-1 overflow-y-auto`}>
        <div className="w-full max-w-3xl px-4 py-6 sm:px-8 md:py-10">
          <div className="mb-4 flex items-center gap-2 md:hidden">
            <Link to={base} replace className="flex items-center gap-1 rounded-md px-1.5 py-1 text-sm text-muted-foreground hover:bg-muted hover:text-foreground">
              <ArrowLeft className="h-4 w-4" aria-hidden="true" /> {title}
            </Link>
          </div>
          {children}
        </div>
        <div className="sticky top-0 hidden shrink-0 pr-6 pt-10 md:block">
          <button type="button" onClick={onClose} className="flex flex-col items-center gap-1 text-xs text-muted-foreground hover:text-foreground" aria-label="Close settings">
            <span className="flex h-9 w-9 items-center justify-center rounded-full border-2 border-current"><X className="h-4 w-4" aria-hidden="true" /></span>
            Esc
          </button>
        </div>
      </main>
    </div>
  );
}

/** A section's title and what it's for. */
/** help: a Help Centre article's slug, linked as "How this works". */
export function SettingsTitle({ children, intro, help }) {
  return (
    <div className="mb-6">
      <h1 className="text-3xl font-semibold">{children}</h1>
      {intro && <p className="mt-1.5 max-w-prose text-sm text-muted-foreground">{intro}</p>}
      {help && (
        <Link to={`/help/${help}`} className="mt-2 inline-block text-sm text-primary underline-offset-4 hover:underline">
          How this works
        </Link>
      )}
    </div>
  );
}

/** One group of settings: a heading, then its controls. Groups are divided by a rule, not boxed. */
export function SettingsGroup({ title, children, description }) {
  return (
    <section className="border-b border-border py-6 first:pt-0 last:border-b-0">
      {title && <h2 className="font-heading text-lg font-semibold">{title}</h2>}
      {description && <p className="mt-1 max-w-prose text-sm text-muted-foreground">{description}</p>}
      <div className={title || description ? "mt-4" : ""}>{children}</div>
    </section>
  );
}

/** A choice between a few options, as radio rows with a line of explanation each. */
export function ChoiceList({ name, value, onChange, options, disabled = false }) {
  return (
    <div role="radiogroup" className="space-y-2">
      {options.map((o) => (
        <label key={o.value} className={`flex cursor-pointer items-start gap-3 rounded-lg border px-3 py-2.5 transition-colors ${value === o.value ? "border-primary bg-primary/5" : "border-border hover:bg-muted/60"} ${disabled ? "cursor-not-allowed opacity-60" : ""}`}>
          <input type="radio" name={name} value={o.value} checked={value === o.value} disabled={disabled} onChange={() => onChange(o.value)} className="mt-1 accent-[hsl(var(--primary))]" />
          <span>
            <span className="block text-sm font-medium">{o.label}</span>
            {o.help && <span className="block text-xs text-muted-foreground">{o.help}</span>}
          </span>
        </label>
      ))}
    </div>
  );
}
