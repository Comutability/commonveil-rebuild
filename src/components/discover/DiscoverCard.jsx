import React from "react";
import { Lock, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import ServerIcon from "@/components/shell/ServerIcon";
import { tagLabel } from "@/lib/site/discoverTags";

/**
 * One listed server. What visitors see comes from the server's public card; members also get the
 * picture and banner they can decrypt, so the server they're in looks like itself here too.
 */
export default function DiscoverCard({ server, member, look, joining, onOpen }) {
  const color = look?.color || server.color || "";
  const banner = member ? look?.banner_image : "";
  const name = (look?.name || server.name || "").trim();
  const description = (look?.description || server.description || "").trim();
  const tags = member && look?.traits?.length ? look.traits : server.tags || [];
  const open = server.join_mode === "open" || member;
  const tint = color ? `${color}2e` : "hsl(var(--muted))";
  const wash = color ? `linear-gradient(120deg, ${color}55, ${color}0d)` : undefined;

  return (
    <li className="group flex flex-col overflow-hidden rounded-xl border border-border bg-card transition-shadow hover:shadow-md focus-within:shadow-md">
      <div className="relative h-24 shrink-0 overflow-hidden" style={{ backgroundColor: tint, backgroundImage: wash }} aria-hidden="true">
        {banner && <img src={banner} alt="" className="h-full w-full object-cover" />}
      </div>
      <div className="relative -mt-9 flex flex-1 flex-col px-4 pb-4">
        <span className="w-fit rounded-2xl ring-4 ring-[hsl(var(--card))]">
          <ServerIcon look={{ name, icon: member ? look?.icon || server.icon : server.icon, color, picture: member ? look?.picture : "" }} size="h-16 w-16" rounded className="!text-2xl" />
        </span>
        <div className="mt-2 flex items-start justify-between gap-2">
          <h3 className="font-heading text-lg font-semibold leading-snug">{name}</h3>
          {member && <span className="mt-1 shrink-0 rounded-full bg-primary/10 px-2 py-0.5 text-[11px] font-medium text-primary">Joined</span>}
        </div>
        <p className="mt-1 line-clamp-4 flex-1 text-sm text-muted-foreground">{description || "No description yet."}</p>
        {tags.length > 0 && (
          <ul className="mt-3 flex flex-wrap gap-1.5">
            {tags.map((t) => (
              <li key={t} className="rounded-full border border-border bg-[hsl(var(--chat-hover))] px-2.5 py-0.5 text-xs text-foreground/80">
                {member && look?.traits?.length ? t : tagLabel(t)}
              </li>
            ))}
          </ul>
        )}
        <div className="mt-4 flex items-center justify-between gap-2 border-t border-border/70 pt-3">
          <span className="flex items-center gap-1 text-xs text-muted-foreground">
            <Users className="h-3.5 w-3.5" aria-hidden="true" /> About {server.member_count} {server.member_count === 1 ? "member" : "members"}
          </span>
          {open ? (
            <Button size="sm" variant={member ? "outline" : "default"} disabled={joining === server.id} onClick={onOpen}>
              {member ? "Open" : joining === server.id ? "Joining…" : "Join"}
            </Button>
          ) : (
            <span className="flex items-center gap-1 text-xs text-muted-foreground">
              <Lock className="h-3.5 w-3.5" aria-hidden="true" /> Invite only
            </span>
          )}
        </div>
      </div>
    </li>
  );
}