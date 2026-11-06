import React from "react";
import { initialsOf } from "@/lib/secure/serverTemplates";

const EMOJI_RE = /\p{Extended_Pictographic}/u;

/**
 * A server's icon: the picture its members uploaded (decrypted on this device), or its emoji, or
 * up to two letters on its colour. Nothing is fetched, so opening a server never asks another
 * site for an image.
 */
export default function ServerIcon({ look, active = false, size = "h-12 w-12", className = "", rounded = false }) {
  const text = look.icon || initialsOf(look.name);
  const emoji = EMOJI_RE.test(text);
  const style = look.color && !emoji ? { backgroundColor: look.color, color: "#fff" } : undefined;
  return (
    <span
      className={`server-icon ${size} ${rounded ? "!rounded-2xl" : ""} ${style || look.picture ? "" : "bg-panel text-foreground"} ${emoji ? "text-2xl" : ""} ${className}`}
      data-active={active ? "true" : "false"}
      style={style}
      aria-hidden="true"
    >
      {look.picture ? <img src={look.picture} alt="" className="h-full w-full object-cover" /> : text}
    </span>
  );
}