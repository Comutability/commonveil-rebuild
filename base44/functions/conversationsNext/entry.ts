// Temporary copy of `conversations` for testing the preview against the current backend. Deleted after testing.
import { createClientFromRequest } from "npm:@base44/sdk@0.8.57";
import { serve } from "../../shared/http.ts";
import { conversationActions } from "../../shared/handlers/conversations.ts";

export default async function (req: Request): Promise<Response> {
  return serve(req, createClientFromRequest, conversationActions);
}
