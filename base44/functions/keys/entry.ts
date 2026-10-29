import { createClientFromRequest } from "npm:@base44/sdk@0.8.54";
import { serve } from "../../shared/http.ts";
import { keysActions } from "../../shared/handlers/keys.ts";

export default async function (req: Request): Promise<Response> {
  return serve(req, createClientFromRequest, keysActions);
}
