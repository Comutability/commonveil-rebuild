// Temporary copy of `profile` for testing the preview against the current backend. Deleted after testing.
import { createClientFromRequest } from "npm:@base44/sdk@0.8.57";
import { serve } from "../../shared/http.ts";
import { profileActions } from "../../shared/handlers/profile.ts";

export default async function (req: Request): Promise<Response> {
  return serve(req, createClientFromRequest, profileActions);
}
