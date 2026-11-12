// Shared code revision: 2026-11-12a. Bump this line when files in base44/shared change, so the platform redeploys this function with them.
// Push notifications that say only that there's something new (docs/NOTIFICATIONS.md).
import { createClientFromRequest } from "npm:@base44/sdk@0.8.57";
import { serve } from "../../shared/http.ts";
import { notificationActions } from "../../shared/handlers/notifications.ts";

export default async function (req: Request): Promise<Response> {
  return serve(req, createClientFromRequest, notificationActions);
}
