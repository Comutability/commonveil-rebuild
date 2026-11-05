import React, { createContext, useContext, useEffect, useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import { Menu } from "lucide-react";
import ServerRail from "./ServerRail";
import UserPanel from "./UserPanel";

const ShellContext = createContext({ openNav: () => {}, closeNav: () => {}, mainOpen: true });
export const useShell = () => useContext(ShellContext);

/** The button that brings back the server list and channels on a phone. */
export function NavButton({ className = "" }) {
  const { openNav } = useShell();
  return (
    <button
      type="button"
      onClick={openNav}
      className={`-ml-1 flex h-9 w-9 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-muted md:hidden ${className}`}
      aria-label="Servers and channels"
    >
      <Menu className="h-5 w-5" aria-hidden="true" />
    </button>
  );
}

/**
 * The app's frame: the server rail, a panel (your direct messages, or a server's channels) with
 * you at its foot, and the main view. On a phone only one shows at a time: the panel when nothing
 * is open, otherwise the main view, with the panel a tap away.
 */
export default function Shell({ panel, children, mainOpen = true, banner = null }) {
  const [navOpen, setNavOpen] = useState(false);
  const location = useLocation();
  useEffect(() => setNavOpen(false), [location.pathname]);
  useEffect(() => {
    if (!navOpen) return undefined;
    const onKey = (e) => e.key === "Escape" && setNavOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [navOpen]);
  const ctx = useMemo(() => ({ openNav: () => setNavOpen(true), closeNav: () => setNavOpen(false), mainOpen }), [mainOpen]);
  const overlay = mainOpen && navOpen;

  return (
    <ShellContext.Provider value={ctx}>
      <div className="flex h-full w-full flex-col overflow-hidden bg-chat text-foreground">
        {banner}
        <div className="relative flex min-h-0 flex-1">
          {overlay && <button type="button" className="fixed inset-0 z-30 bg-black/45 md:hidden" onClick={() => setNavOpen(false)} aria-label="Close menu" />}
          <div
            className={[
              "min-h-0 md:flex md:static md:z-auto md:w-auto md:shadow-none",
              mainOpen ? (overlay ? "fixed inset-y-0 left-0 z-40 flex w-[min(22rem,90vw)] shadow-2xl" : "hidden") : "flex w-full",
            ].join(" ")}
          >
            <ServerRail />
            <div className="flex min-h-0 min-w-0 flex-1 flex-col bg-panel md:w-60 md:flex-none">
              <div className="min-h-0 flex-1">{panel}</div>
              <UserPanel />
            </div>
          </div>
          <main className={`${mainOpen ? "flex" : "hidden md:flex"} min-h-0 min-w-0 flex-1 flex-col bg-chat`}>{children}</main>
        </div>
      </div>
    </ShellContext.Provider>
  );
}
