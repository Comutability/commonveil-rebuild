// Shared code revision: 2026-11-05i. Bump this line when files in base44/shared change, so the platform redeploys this function with them.
import { createClientFromRequest } from "npm:@base44/sdk@0.8.57";
import { serve } from "../../shared/http.ts";
import { FILES_MAX_BODY, fileActions } from "../../shared/handlers/files.ts";

export default async function (req: Request): Promise<Response> {
  return serve(req, createClientFromRequest, fileActions, { maxBodyBytes: FILES_MAX_BODY });
}
