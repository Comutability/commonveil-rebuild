// Shared code revision: 2026-11-12a. Bump this line when files in base44/shared change, so the platform redeploys this function with them.
import { createClientFromRequest } from "npm:@base44/sdk@0.8.57";
import { serve } from "../../shared/http.ts";
import { inviteActions } from "../../shared/handlers/servers.ts";

// Open to visitors who aren't signed in, so an invite link can show what it's for before they
// sign in. It answers only from the invite code, never says who made it, and the server's name
// on a private server's invite stays encrypted under the link's secret.
export default async function (req: Request): Promise<Response> {
  return serve(req, createClientFromRequest, inviteActions, { allowAnonymous: true });
}
