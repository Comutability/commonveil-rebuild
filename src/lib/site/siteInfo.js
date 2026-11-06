import { useEffect, useState } from "react";
import { SELF_HOSTED } from "@/api/base44Client";

// What a self-hosted site says about itself (/api/site): its name, version and whether it talks to
// other sites. Null on Base44, and while loading.
let cached = null;

export function useSiteInfo() {
  const [info, setInfo] = useState(cached);
  useEffect(() => {
    if (!SELF_HOSTED || cached) return undefined;
    let live = true;
    fetch("/api/site", { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        cached = d?.site || null;
        if (live) setInfo(cached);
      })
      .catch(() => {});
    return () => {
      live = false;
    };
  }, []);
  return info;
}

/** Someone's address on this site, if it talks to other sites ("ann-lee.example.org"). */
export function handleOf(username, info) {
  if (!username || !info?.federation || !info.handle_domain) return "";
  return `${String(username).toLowerCase().replace(/_/g, "-")}.${info.handle_domain}`;
}
