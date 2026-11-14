// Shared code revision: 2026-11-14b. Bump this line when files in base44/shared change, so the platform redeploys this function with them.
// The Commonveil Protocol's "inbox" endpoint for the hosted site (docs/FEDERATION.md).
import { createClientFromRequest } from "npm:@base44/sdk@0.8.57";
import { serveFederation } from "../../shared/federation/inbound.ts";

export default async function (req: Request): Promise<Response> {
  return serveFederation(req, createClientFromRequest, "inbox");
}
