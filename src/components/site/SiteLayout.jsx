import React, { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import { Lock, Menu, Search, X } from "lucide-react";
import { useAuth } from "@/lib/AuthContext";
import { Button } from "@/components/ui/button";
import Logo from "./Logo";
import { APP_VERSION } from "@/lib/site/version.js";

const NAV = [
  ["/help", "Help"],
  ["/resources", "Resources"],
  ["/security", "Security"],
];

const linkClass = ({ isActive }) =>
  `rounded-md px-3 py-2 text-sm font-medium transition-colors hover:bg-muted ${isActive ? "text-foreground" : "text-muted-foreground"}`;

export default function SiteLayout() {
  const { isAuthenticated } = useAuth();
  const [open, setOpen] = useState(false);
  const location = useLocation();

  useEffect(() => setOpen(false), [location.pathname]);

  return (
    <div className="flex min-h-screen flex-col">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-card focus:px-3 focus:py-2">
        Skip to content
      </a>
      <header className="sticky top-0 z-30 border-b border-border bg-background/85 backdrop-blur supports-[backdrop-filter]:bg-background/70">
        <div className="container-cv flex h-16 items-center justify-between gap-2 sm:gap-4">
          <Logo />
          <nav className="hidden items-center gap-1 md:flex" aria-label="Main">
            {NAV.map(([to, label]) => (
              <NavLink key={to} to={to} className={linkClass}>
                {label}
              </NavLink>
            ))}
          </nav>
          <div className="flex items-center gap-1 sm:gap-2">
            <Link to="/search" className="rounded-md p-2 text-muted-foreground hover:bg-muted hover:text-foreground" aria-label="Search the site" title="Search">
              <Search className="h-5 w-5" aria-hidden="true" />
            </Link>
            <Button asChild size="sm">
              <Link to="/app">
                <Lock className="mr-1.5 h-4 w-4" aria-hidden="true" />
                {isAuthenticated ? "Messages" : "Sign in"}
              </Link>
            </Button>
            <button
              type="button"
              className="rounded-md p-2 text-muted-foreground hover:bg-muted md:hidden"
              onClick={() => setOpen((v) => !v)}
              aria-expanded={open}
              aria-controls="mobile-nav"
              aria-label={open ? "Close menu" : "Open menu"}
            >
              {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>
          </div>
        </div>
        {open && (
          <nav id="mobile-nav" className="border-t border-border md:hidden" aria-label="Main">
            <div className="container-cv flex flex-col py-2">
              {[...NAV, ["/search", "Search"], ["/privacy", "Privacy"], ["/terms", "Terms"], ["/security", "Security"]].map(([to, label]) => (
                <NavLink key={to} to={to} className={linkClass}>
                  {label}
                </NavLink>
              ))}
            </div>
          </nav>
        )}
      </header>

      <main id="main" className="flex-1">
        <Outlet />
      </main>

      <footer className="mt-16 border-t border-border">
        <div className="container-cv grid gap-8 py-10 sm:grid-cols-3">
          <div>
            <Logo />
            <p className="mt-3 max-w-xs text-sm text-muted-foreground">
              A private place to talk, end-to-end encrypted, that you can run yourself.
            </p>
          </div>
          <div className="text-sm">
            <p className="mb-2 font-semibold">Explore</p>
            <ul className="space-y-1.5 text-muted-foreground">
              {NAV.map(([to, label]) => (
                <li key={to}>
                  <Link className="hover:text-foreground" to={to}>
                    {label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
          <div className="text-sm">
            <p className="mb-2 font-semibold">Commonveil</p>
            <ul className="space-y-1.5 text-muted-foreground">
              <li><Link className="hover:text-foreground" to="/app">Encrypted messages</Link></li>
              <li><Link className="hover:text-foreground" to="/help/guide">The complete guide</Link></li>
              <li><Link className="hover:text-foreground" to="/releases">Releases</Link></li>
              <li><Link className="hover:text-foreground" to="/privacy">Privacy: what we hold</Link></li>
              <li><Link className="hover:text-foreground" to="/terms">Terms of Use</Link></li>
              <li><Link className="hover:text-foreground" to="/security">Security and status</Link></li>
              <li><Link className="hover:text-foreground" to="/security/report">Report a security problem</Link></li>
            </ul>
          </div>
        </div>
        <div className="border-t border-border">
          <p className="container-cv py-5 text-xs text-muted-foreground">
            No ads, no analytics and no third-party trackers in this site's code. Commonveil's encryption has not yet had an
            independent audit; see <Link className="underline hover:text-foreground" to="/security">Security</Link>.{" "}
            <Link className="underline hover:text-foreground" to="/releases">Version {APP_VERSION}</Link>.
          </p>
        </div>
      </footer>
    </div>
  );
}
