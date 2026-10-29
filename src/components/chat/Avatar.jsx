import React from "react";
import { Users } from "lucide-react";

function hueFor(id = "") {
  let h = 0;
  for (let i = 0; i < id.length; i += 1) h = (h * 31 + id.charCodeAt(i)) % 360;
  return h;
}

export default function Avatar({ id, name, group = false, size = "h-10 w-10" }) {
  if (group) {
    return (
      <span className={`flex shrink-0 items-center justify-center rounded-full bg-accent text-accent-foreground ${size}`} aria-hidden="true">
        <Users className="h-5 w-5" />
      </span>
    );
  }
  const initials = String(name || "?").replace(/^@/, "").slice(0, 2).toUpperCase();
  // Colours come from .avatar-cv in index.css, which adjusts them for dark mode.
  return (
    <span className={`avatar-cv flex shrink-0 items-center justify-center rounded-full text-sm font-semibold ${size}`} style={{ "--h": hueFor(id) }} aria-hidden="true">
      {initials}
    </span>
  );
}
