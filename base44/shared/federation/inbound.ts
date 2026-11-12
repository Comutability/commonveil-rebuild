// The hosted site's protocol endpoints (docs/FEDERATION.md): one function each, all served here.
// Kept apart from hosted.ts because only these functions need every handler loaded.
import { runAction } from "../http.ts";
import { profileActions } from "../handlers/profile.ts";
import { keysActions } from "../handlers/keys.ts";
import { conversationActions } from "../handlers/conversations.ts";
import { messageActions } from "../handlers/messages.ts";
import { safetyActions } from "../handlers/safety.ts";
import { serverActions } from "../handlers/servers.ts";
import { serverMessageActions } from "../handlers/serverMessages.ts";
import { eventActions } from "../handlers/events.ts";
import { moderationActions } from "../handlers/moderation.ts";
import { FederationError, HostedFederation } from "./hosted.ts";

const MAX_BODY = 9 * 1024 * 1024;
/** What a person's own site does for them, and nobody else's: only these reads are open to other sites. */
const HOME_ONLY: Record<string, string[]> = { keys: ["peer_keys"], profile: ["get_many", "find"], safety: [] };

const json = (status: number, body: unknown, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extra } });

/** What people from other sites can do here: everything about conversations and servers, nothing about accounts. */
export function inboundTable({ defaultAdmins = () => [] as string[] } = {}): Record<string, any> {
  return {
    profile: profileActions,
    keys: keysActions,
    conversations: conversationActions,
    messages: messageActions,
    safety: safetyActions,
    servers: serverActions({ defaultAdmins }),
    channels: serverMessageActions,
    events: eventActions,
    moderation: moderationActions,
  };
}

async function inboundAct(fed: HostedFederation, base44: any, table: Record<string, any>, from: string, payload: any, signedUser: string) {
  const card = payload?.user;
  if (!card || card.id !== signedUser) throw new FederationError(400, "BAD_PERSON", "The request's person doesn't match its signature.");
  const fn = String(payload.function || "");
  if (!Object.hasOwn(table, fn)) throw new FederationError(404, "NOT_FOUND", "That isn't something another site can ask for here.");
  const raw = String(payload.request || "{}");
  let parsed: any = {};
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = {};
  }
  if (HOME_ONLY[fn] && !HOME_ONLY[fn].includes(parsed?.action)) throw new FederationError(403, "HOME_ONLY", "That's done on the person's own site.");
  await fed.mirror(from, card);
  // No sign-in session: the person's own site vouched for them, and its signature was checked.
  return runAction(base44, raw, table[fn], { actAs: { id: card.id, email: "", role: "user", remote: true, home: from }, federation: fed.handlers });
}

/**
 * Serve one protocol endpoint. endpoint: act, directory, inbox, identity or discover.
 * options.federation: for tests; otherwise made from the request's client.
 */
export async function serveFederation(req: Request, makeClient: (req: Request) => any, endpoint: string, options: { federation?: HostedFederation; defaultAdmins?: () => string[] } = {}): Promise<Response> {
  const base44 = makeClient(req);
  const fed = options.federation || new HostedFederation({ sr: base44.asServiceRole });
  const url = new URL(req.url);
  try {
    // Setting up: the site's public key, for whoever runs the site to publish (federation/site.ts).
    if (endpoint === "identity" && url.searchParams.get("site") === "1") return json(200, { host: fed.host, enabled: fed.enabled, public_key: (await fed.key()).public });
    if (!fed.enabled) return json(404, { error: "This site doesn't talk to other sites.", code: "FEDERATION_OFF" });
    if (endpoint === "identity") return json(200, await fed.identity(url.searchParams.get("handle") || ""), { "Access-Control-Allow-Origin": "*" });
    if (endpoint === "discover") return json(200, await fed.discover(url.searchParams.get("tag") || ""), { "Access-Control-Allow-Origin": "*", "Cache-Control": "public, max-age=120" });
    if (req.method !== "POST") return json(405, { error: "Use POST.", code: "METHOD_NOT_ALLOWED" });
    const body = await req.text();
    if (body.length > MAX_BODY) return json(413, { error: "That request is too large.", code: "TOO_LARGE" });
    const { from, user } = await fed.verify(req, body);
    const payload = JSON.parse(body || "{}");
    if (endpoint === "act") return await inboundAct(fed, base44, inboundTable({ defaultAdmins: options.defaultAdmins }), from, payload, user);
    if (endpoint === "directory") return json(200, await fed.inboundDirectory(from, payload));
    if (endpoint === "inbox") return json(200, await fed.inboundInbox(from, payload));
    return json(404, { error: "Not found", code: "NOT_FOUND" });
  } catch (err: any) {
    if (err instanceof FederationError) return json(err.status, { error: err.message, code: err.code });
    console.error("commonveil federation failure", { name: err?.name || "Error" });
    return json(500, { error: "Something went wrong.", code: "INTERNAL" });
  }
}
