// Quiet hours and focus: worked out on the device, never sent anywhere.
import test from "node:test";
import assert from "node:assert/strict";
import { cleanAlerts, isQuiet, minutesToTime, timeToMinutes } from "../src/lib/secure/alerts.js";

const at = (h, m = 0) => { const d = new Date(2026, 10, 5, h, m); return d; };

test("quiet hours across midnight, within a day, and off", () => {
  const night = cleanAlerts({ quiet: true, quietFrom: 22 * 60, quietTo: 7 * 60 });
  assert.equal(isQuiet(night, at(23)), true);
  assert.equal(isQuiet(night, at(3)), true);
  assert.equal(isQuiet(night, at(7)), false);
  assert.equal(isQuiet(night, at(12)), false);
  const lunch = cleanAlerts({ quiet: true, quietFrom: 12 * 60, quietTo: 13 * 60 });
  assert.equal(isQuiet(lunch, at(12, 30)), true);
  assert.equal(isQuiet(lunch, at(13)), false);
  assert.equal(isQuiet(cleanAlerts({ quiet: false }), at(23)), false);
});

test("focus silences until it ends, and odd values are dropped", () => {
  const now = new Date();
  assert.equal(isQuiet(cleanAlerts({ focusUntil: now.getTime() + 60_000 }), now), true);
  assert.equal(isQuiet(cleanAlerts({ focusUntil: now.getTime() - 1 }), now), false);
  assert.equal(cleanAlerts({ focusUntil: now.getTime() + 30 * 86_400_000 }).focusUntil, 0, "at most a day");
  const c = cleanAlerts({ quietFrom: 99999, quietTo: "x", extra: "dropped" });
  assert.deepEqual(Object.keys(c).sort(), ["focusUntil", "notify", "quiet", "quietFrom", "quietTo", "showSender", "titleCount"]);
  assert.equal(c.quietFrom, 22 * 60);
  assert.equal(minutesToTime(timeToMinutes("06:45")), "06:45");
  assert.equal(timeToMinutes("25:00"), null);
});
