// Shared code revision: 2026-11-05d. Bump this line when files in base44/shared change, so the platform redeploys this function with them.
import { createClientFromRequest } from "npm:@base44/sdk@0.8.57";
import { serve } from "../../shared/http.ts";
import { keysActions } from "../../shared/handlers/keys.ts";

const actions = { ...keysActions, async deploy_marker() { return { marker: "2026-11-05d", actions: Object.keys(keysActions).length }; } };

export default async function (req: Request): Promise<Response> {
  return serve(req, createClientFromRequest, actions);
}
