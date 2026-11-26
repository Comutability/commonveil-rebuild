// Shared code revision: 2026-11-26d. Bump this line when files in base44/shared change, so the platform redeploys this function with them.
import { createClientFromRequest } from "npm:@base44/sdk@0.8.57";
import { json } from "../../shared/http.ts";
import { claimRun, runMaintenance } from "../../shared/maintenance.ts";

// Started by the scheduled workflows in base44/workflows, which send { task } (older
// automations sent { args: { task } }; both are accepted).
// There's no signed-in user here, so it works as the service role. Its address is public like
// every function's; see maintenance.ts for why that's safe, and why repeat calls are cheap.
export default async function (req: Request): Promise<Response> {
  if (req.method !== "POST") return json(405, { error: "Use POST.", code: "METHOD_NOT_ALLOWED" });
  const raw = await req.text();
  let task: unknown = "";
  if (raw.length <= 4096) {
    try {
      const parsed = JSON.parse(raw);
      task = parsed?.args?.task ?? parsed?.task;
    } catch {
      task = "";
    }
  }
  const sr = createClientFromRequest(req).asServiceRole;
  if (!(await claimRun(sr, task))) return json(200, { task, skipped: "ran recently" });
  return runMaintenance(sr, task, new Date());
}
