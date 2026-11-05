// Temporary: checks how secrets reach functions. Reports only whether one is set. Deleted after checking. r3
import { secrets } from "base44:runtime";

export default async function (req: Request): Promise<Response> {
  let fromRuntime = false;
  let fromEnv = false;
  try {
    fromRuntime = Boolean(secrets.get("DEFAULT_SERVER_ADMINS"));
  } catch {
    fromRuntime = false;
  }
  try {
    fromEnv = Boolean(Deno.env.get("DEFAULT_SERVER_ADMINS"));
  } catch {
    fromEnv = false;
  }
  return Response.json({ fromRuntime, fromEnv });
}
