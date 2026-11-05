import React, { useMemo, useState } from "react";
import { Search } from "lucide-react";
import { EMOJI, EMOJI_GROUPS, QUICK_REACTIONS, emojiName, searchEmoji } from "@/lib/emoji";

/**
 * The fixed emoji list, searchable by name. Nothing is fetched: it's all part of the app.
 * selected: emoji to show as already chosen (your reactions).
 * custom: the server's own emoji ({ id, name, img }), offered first when onPickCustom is given.
 */
export default function EmojiPicker({ onPick, selected = [], label = "Choose an emoji", custom = [], onPickCustom = null }) {
  const [query, setQuery] = useState("");
  const chosen = useMemo(() => new Set(selected), [selected]);
  const found = useMemo(() => searchEmoji(query), [query]);
  const own = useMemo(() => {
    if (!onPickCustom) return [];
    const q = query.trim().toLowerCase().replace(/^:|:$/g, "");
    return q ? custom.filter((x) => x.name.includes(q)) : custom;
  }, [custom, onPickCustom, query]);
  const groups = useMemo(() => {
    if (query.trim()) return [{ name: "Results", items: found }];
    return [{ name: "Quick", items: QUICK_REACTIONS.map((e) => EMOJI.find((x) => x.e === e)) }, ...EMOJI_GROUPS.map((g) => ({ name: g, items: EMOJI.filter((x) => x.group === g) }))];
  }, [query, found]);

  return (
    <div className="w-72" role="dialog" aria-label={label}>
      <label className="flex items-center gap-2 border-b border-border px-3 py-2">
        <Search className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <input
          autoFocus
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search emoji"
          aria-label="Search emoji"
          className="min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
        />
      </label>
      <div className="scroll-thin max-h-64 overflow-y-auto p-2">
        {own.length > 0 && (
          <section aria-label="This server" className="mb-2">
            <h3 className="px-1 pb-1 text-xs font-semibold text-muted-foreground">This server</h3>
            <div className="grid grid-cols-8 gap-0.5">
              {own.map((x) => (
                <button
                  key={x.id}
                  type="button"
                  onClick={() => onPickCustom(x)}
                  title={`:${x.name}:`}
                  aria-label={`${chosen.has(`c:${x.id}`) ? "Remove " : ""}${x.name}`}
                  aria-pressed={chosen.has(`c:${x.id}`) || undefined}
                  className={`flex h-8 w-8 items-center justify-center rounded-md transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${chosen.has(`c:${x.id}`) ? "bg-primary/15" : ""}`}
                >
                  <img src={x.img} alt="" className="h-6 w-6 object-contain" />
                </button>
              ))}
            </div>
          </section>
        )}
        {groups.map((g) => (
          <section key={g.name} aria-label={g.name} className="mb-2">
            <h3 className="px-1 pb-1 text-xs font-semibold text-muted-foreground">{g.name}</h3>
            {g.items.length === 0 ? (
              <p className="px-1 text-sm text-muted-foreground">No emoji called that.</p>
            ) : (
              <div className="grid grid-cols-8 gap-0.5">
                {g.items.map((x) => (
                  <button
                    key={`${g.name}-${x.e}`}
                    type="button"
                    onClick={() => onPick(x.e)}
                    title={x.name}
                    aria-label={`${chosen.has(x.e) ? "Remove" : ""} ${emojiName(x.e)}`.trim()}
                    aria-pressed={chosen.has(x.e) || undefined}
                    className={`flex h-8 w-8 items-center justify-center rounded-md text-lg transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${chosen.has(x.e) ? "bg-primary/15" : ""}`}
                  >
                    <span aria-hidden="true">{x.e}</span>
                  </button>
                ))}
              </div>
            )}
          </section>
        ))}
      </div>
    </div>
  );
}
