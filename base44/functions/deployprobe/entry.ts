// Temporary: reports which actions the deployed shared code has. Deleted after checking.
import { keysActions } from "../../shared/handlers/keys.ts";
import { messageActions } from "../../shared/handlers/messages.ts";

export default async function (req: Request): Promise<Response> {
  return Response.json({ keys: Object.keys(keysActions), messages: Object.keys(messageActions), at: "2026-11-05b" });
}
