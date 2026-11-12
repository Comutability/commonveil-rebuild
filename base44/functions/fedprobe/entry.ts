// TEMPORARY probe (remove after use): answers what a function sees of a request, and whether a
// record can be made with a chosen id. Needs the token; touches one throwaway CvChallenge row,
// which it deletes again.
import { createClientFromRequest } from "npm:@base44/sdk@0.8.57";

const TOKEN = "QnRw_xUi0QiqIT9ziSlUOK4A";
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });

export default async function (req: Request): Promise<Response> {
  const url = new URL(req.url);
  if (url.searchParams.get("t") !== TOKEN) return json({ error: "Not found" }, 404);
  const seen = { method: req.method, url: req.url, path: url.pathname, host: req.headers.get("host"), forwarded_host: req.headers.get("x-forwarded-host"), original: req.headers.get("x-original-url") || req.headers.get("x-forwarded-uri") || null, header_names: [...req.headers.keys()].sort() };
  if (url.searchParams.get("ids") !== "1") return json({ seen });
  const out: Record<string, unknown> = {};
  try {
    const sr = createClientFromRequest(req).asServiceRole;
    const want = "6af0" + Array.from(crypto.getRandomValues(new Uint8Array(10)), (b) => b.toString(16).padStart(2, "0")).join("");
    const row = { purpose: "probe", token_hash: "probe", expires_at: new Date(Date.now() + 60_000).toISOString() };
    for (const key of ["id", "_id"]) {
      try {
        const made = await sr.entities.CvChallenge.create({ ...row, [key]: want });
        out[key] = { asked: want, got: made?.id, kept: made?.id === want };
        if (made?.id) await sr.entities.CvChallenge.delete(made.id);
      } catch (e) {
        out[key] = { error: String((e as Error)?.message || e).slice(0, 200) };
      }
    }
  } catch (e) {
    out.error = String((e as Error)?.message || e).slice(0, 200);
  }
  return json({ seen, ids: out });
}
