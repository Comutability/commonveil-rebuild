// Temporary: the keys function under another name, to see whether it deploys. Deleted after checking.
import { createClientFromRequest } from "npm:@base44/sdk@0.8.57";
import { serve } from "../../shared/http.ts";
import { keysActions } from "../../shared/handlers/keys.ts";

export default async function (req: Request): Promise<Response> {
  return serve(req, createClientFromRequest, keysActions);
}
