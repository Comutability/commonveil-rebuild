// Shared code revision: 2026-11-05i. Bump this line when files in base44/shared change, so the platform redeploys this function with them.
import { createClientFromRequest } from "npm:@base44/sdk@0.8.57";
import { json } from "../../shared/http.ts";
import { runMaintenance } from "../../shared/maintenance.ts";

// Started by the scheduled automations in function.jsonc, which send { args: { task } }.
// There's no signed-in user here, so it works as the service role. Its address is public like
// every function's; see maintenance.ts for why that's safe.
export default async function (req: Request): Promise<Response> {
  if (req.method !== "POST") return json(405, { error: "Use POST.", code: "METHOD_NOT_ALLOWED" });
  const raw = await req.text();
  let task: unknown = "";
  if (raw.length <= 4096) {
    try {
      task = JSON.parse(raw)?.args?.task;
    } catch {
      task = "";
    }
  }
  return runMaintenance(createClientFromRequest(req).asServiceRole, task, new Date());
}
