import { createClientFromRequest } from "npm:@base44/sdk@0.8.57";
import { serve } from "../../shared/http.ts";
import { safetyActions } from "../../shared/handlers/safety.ts";

export default async function (req: Request): Promise<Response> {
  return serve(req, createClientFromRequest, safetyActions);
}
