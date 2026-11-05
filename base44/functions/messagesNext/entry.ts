// Temporary copy of `messages` for testing the preview against the current backend. Deleted after testing.
import { createClientFromRequest } from "npm:@base44/sdk@0.8.57";
import { serve } from "../../shared/http.ts";
import { messageActions } from "../../shared/handlers/messages.ts";

export default async function (req: Request): Promise<Response> {
  return serve(req, createClientFromRequest, messageActions);
}
