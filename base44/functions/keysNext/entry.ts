// Temporary copy of `keys` for testing the preview against the current backend (Base44 keeps
// serving the published version of the original there). Deleted after testing.
import { createClientFromRequest } from "npm:@base44/sdk@0.8.57";
import { serve } from "../../shared/http.ts";
import { keysActions } from "../../shared/handlers/keys.ts";

export default async function (req: Request): Promise<Response> {
  return serve(req, createClientFromRequest, keysActions);
}
