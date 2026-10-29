import React from "react";
import { Link } from "react-router-dom";

export function LogoMark({ className = "h-7 w-7" }) {
  return (
    <svg viewBox="0 0 64 64" className={className} aria-hidden="true">
      <rect width="64" height="64" rx="14" className="fill-primary" />
      <path d="M14 40c6-14 12-21 18-21s12 7 18 21" fill="none" className="stroke-primary-foreground" strokeWidth="4" strokeLinecap="round" />
      <path d="M20 44c4-8 8-12 12-12s8 4 12 12" fill="none" stroke="currentColor" strokeOpacity="0.55" strokeWidth="3.5" strokeLinecap="round" />
      <circle cx="32" cy="47" r="3" className="fill-primary-foreground" />
    </svg>
  );
}

export default function Logo({ to = "/" }) {
  return (
    <Link to={to} className="flex items-center gap-2.5 rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
      <LogoMark className="h-8 w-8 text-primary-foreground" />
      <span className="font-heading text-xl font-semibold tracking-tight">Commonveil</span>
    </Link>
  );
}
