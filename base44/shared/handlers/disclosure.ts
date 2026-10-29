// Reporting a security problem in Commonveil. Open to anyone, signed in or not, because
// researchers shouldn't need an account. Anonymous reports share a small hourly and daily
// allowance so the channel can't be used to fill the database; signed-in reporters get
// their own allowance, so a flood of anonymous reports can't shut them out.
import { ApiError, cleanText, type Actions } from "../http.ts";
import { countSince } from "../store.ts";

export const DISCLOSURE_LIMITS = Object.freeze({
  anonymousPerHour: 10,
  anonymousPerDay: 40,
  perUserPerDay: 5,
});

const HOUR = 3600_000;
const DAY = 24 * HOUR;

export const disclosureActions: Actions = {
  async submit({ sr, user, body, now }) {
    const summary = cleanText(body.summary, 200);
    const details = cleanText(body.details, 8000);
    const contact = cleanText(body.contact, 300);
    if (summary.length < 5) throw new ApiError(400, "BAD_FIELD", "Give the problem a short title.");
    if (details.length < 20) throw new ApiError(400, "BAD_FIELD", "Please describe the problem in a little more detail.");

    const busy = () => new ApiError(429, "RATE_LIMITED", "We've had a lot of reports just now. Please try again later.");
    if (user) {
      const today = await countSince(sr, "SecurityReport", { reporter_user_id: user.id }, new Date(now.getTime() - DAY), DISCLOSURE_LIMITS.perUserPerDay);
      if (today >= DISCLOSURE_LIMITS.perUserPerDay) throw busy();
    } else {
      const anonymous = { reporter_user_id: "" };
      const hour = await countSince(sr, "SecurityReport", anonymous, new Date(now.getTime() - HOUR), DISCLOSURE_LIMITS.anonymousPerHour);
      if (hour >= DISCLOSURE_LIMITS.anonymousPerHour) throw busy();
      const day = await countSince(sr, "SecurityReport", anonymous, new Date(now.getTime() - DAY), DISCLOSURE_LIMITS.anonymousPerDay);
      if (day >= DISCLOSURE_LIMITS.anonymousPerDay) throw busy();
    }

    await sr.entities.SecurityReport.create({
      summary,
      details,
      contact,
      reporter_user_id: user ? user.id : "",
      status: "new",
      staff_note: "",
    });
    return { ok: true };
  },
};
