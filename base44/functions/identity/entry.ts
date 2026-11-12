// Shared code revision: 2026-11-12d. Bump this line when files in base44/shared change, so the platform redeploys this function with them.
// Commonveil sign-in (docs/IDENTITY.md): accounts, devices, passkeys, recovery and sessions.
import { createClientFromRequest } from "npm:@base44/sdk@0.8.57";
import { serve } from "../../shared/http.ts";
import { identityActions } from "../../shared/handlers/identity.ts";

const actions = identityActions();

export default async function (req: Request): Promise<Response> {
  return serve(req, createClientFromRequest, actions, { allowAnonymous: true, allowPlatformUser: true });
}
