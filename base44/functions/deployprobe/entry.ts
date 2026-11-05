// Temporary: reports which actions the deployed shared code has. Deleted after checking. r1
import { keysActions } from "../../shared/handlers/keys.ts";
import { messageActions } from "../../shared/handlers/messages.ts";
import { PROBE } from "../../shared/deployprobe.ts";

export default async function (req: Request): Promise<Response> {
  return Response.json({ keys: Object.keys(keysActions).length, messages: Object.keys(messageActions), probe: PROBE });
}
