import { createClientFromRequest } from "npm:@base44/sdk@0.8.57";

// TEMPORARY: checks row rules that follow a locked per-user list. Deleted after the check.
export default async function (req: Request): Promise<Response> {
  const base44 = createClientFromRequest(req);
  const me = await base44.auth.me().catch(() => null);
  if (!me?.id) return Response.json({ error: "sign in" }, { status: 401 });
  const body = await req.json().catch(() => ({}));
  const sr = base44.asServiceRole;
  const out: any = { me: me.id, step: body.step };
  try {
    if (body.step === "setup") {
      await sr.entities.User.update(me.id, { cv_access: ["aud_a_" + me.id] });
      const existing = await sr.entities.RlsProbe.filter({ note: me.id }, "created_date", 10);
      if (!existing.length) {
        await sr.entities.RlsProbe.bulkCreate([
          { audience_id: "aud_a_" + me.id, note: me.id },
          { audience_id: "aud_b_" + me.id, note: me.id },
        ]);
      }
      out.user_after = (await sr.entities.User.get(me.id))?.cv_access;
    }
    if (body.step === "add_b") {
      await sr.entities.User.update(me.id, { cv_access: ["aud_a_" + me.id, "aud_b_" + me.id] });
    }
    if (body.step === "clear") {
      await sr.entities.User.update(me.id, { cv_access: [] });
    }
    if (body.step === "cleanup") {
      for (const r of await sr.entities.RlsProbe.filter({ note: me.id }, "created_date", 10)) await sr.entities.RlsProbe.delete(r.id);
      await sr.entities.User.update(me.id, { cv_access: [] });
    }
    out.own = (await base44.entities.RlsProbe.filter({}, "created_date", 50)).map((r: any) => r.audience_id);
    out.me_access = (await base44.auth.me())?.cv_access ?? null;
    // Can the member change the locked field themselves?
    if (body.step === "tamper") {
      try {
        await base44.auth.updateMe({ cv_access: ["aud_a_" + me.id, "aud_b_" + me.id, "evil"] });
        out.tamper = "allowed";
      } catch (e) {
        out.tamper = "refused: " + String((e as any)?.message || e).slice(0, 120);
      }
      out.after_tamper = (await sr.entities.User.get(me.id))?.cv_access;
    }
  } catch (e) {
    out.error = String((e as any)?.message || e).slice(0, 300);
  }
  return Response.json(out);
}
