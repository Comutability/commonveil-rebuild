// Shared code revision: 2026-11-14b. Bump this line when files in base44/shared change, so the platform redeploys this function with them.
import { createClientFromRequest } from "npm:@base44/sdk@0.8.57";
import { serve } from "../../shared/http.ts";
import { snipActions } from "../../shared/handlers/snips.ts";

// The proposals forum in the community server (docs/SNIP_FORUM.md). On the hosted site it is on
// unless the SNIP_FORUM secret is "off". GITHUB_TOKEN (optional, read-only access to public
// repositories) lets it check GitHub every 3 minutes instead of every 20.
const actions = snipActions({
  enabled: () => String(Deno.env.get("SNIP_FORUM") || "").toLowerCase() !== "off",
  repo: () => Deno.env.get("SNIP_REPO") || "",
  token: () => Deno.env.get("GITHUB_TOKEN") || "",
});

export default async function (req: Request): Promise<Response> {
  return serve(req, createClientFromRequest, actions);
}
