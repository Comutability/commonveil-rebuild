import { createClientFromRequest } from "npm:@base44/sdk@0.8.57";
import { serve } from "../../shared/http.ts";
import { serverActions } from "../../shared/handlers/servers.ts";

// DEFAULT_SERVER_ADMINS: comma-separated sign-in addresses that become the community server's
// admins when they join (the first becomes its owner). An app secret, so it isn't in the code.
const actions = serverActions({
  defaultAdmins: () => String(Deno.env.get("DEFAULT_SERVER_ADMINS") || "").split(","),
});

export default async function (req: Request): Promise<Response> {
  return serve(req, createClientFromRequest, actions);
}
