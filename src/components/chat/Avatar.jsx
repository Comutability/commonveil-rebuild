import React from "react";
import { Users } from "lucide-react";

function hueFor(id = "") {
  let h = 0;
  for (let i = 0; i < id.length; i += 1) h = (h * 31 + id.charCodeAt(i)) % 360;
  return h;
}

/** Profile colours on offer (base44/shared/handlers/profile.ts), as hues. */
export const ACCENT_HUES = { teal: 172, sky: 199, indigo: 234, violet: 262, rose: 350, amber: 38, lime: 84, slate: 215 };

/**
 * Someone's avatar: the emoji they chose, or their initials, on their colour (or one worked out
 * from their id). There are no uploaded pictures, so showing an avatar never fetches anything.
 */
export default function Avatar({ id, name, group = false, size = "h-10 w-10", emoji = "", accent = "", className = "" }) {
  if (group) {
    return (
      <span className={`flex shrink-0 items-center justify-center rounded-full bg-accent text-accent-foreground ${size} ${className}`} aria-hidden="true">
        <Users className="h-5 w-5" />
      </span>
    );
  }
  const hue = ACCENT_HUES[accent] ?? hueFor(id);
  const initials = String(name || "?").replace(/^@/, "").slice(0, 2).toUpperCase();
  // Colours come from .avatar-cv in index.css, which adjusts them for dark mode.
  return (
    <span className={`avatar-cv flex shrink-0 items-center justify-center rounded-full font-semibold ${emoji ? "text-[1.15em]" : "text-sm"} ${size} ${className}`} style={{ "--h": hue }} aria-hidden="true">
      {emoji || initials}
    </span>
  );
}
