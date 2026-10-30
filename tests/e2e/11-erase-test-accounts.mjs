// Cleaning up, and a check of Admin → Accounts: erases what deprovisioned test people left behind.
// Run it after deprovisioning them. Only accounts whose username starts with e2e_ are touched.
// Args: [admin embed url] (omit if the admin's browser profile is already signed in)
import { check, goto, open, shot } from "./lib.mjs";

const [adminUrl] = process.argv.slice(2);
const M = await open("admin1", adminUrl);
await goto(M.page, "/admin");
await M.page.waitForSelector('h1:has-text("Admin")', { timeout: 60000 });
await M.page.getByRole("tab", { name: /Accounts/ }).click();
await M.page.waitForSelector("text=/No removed sign-ins|Type ERASE to confirm|Couldn't check/", { timeout: 90000 });
const failure = M.page.locator('[role="tabpanel"] [role="alert"]');
if (await failure.count()) throw new Error(`FAILED: the list didn't load: ${await failure.first().innerText()}`);
await shot(M.page, "11-removed-accounts");

const rows = M.page.locator('li:has(strong:text-matches("^@e2e_"))');
let erased = 0;
while ((await rows.count()) > 0) {
  if (erased >= 50) throw new Error("FAILED: more rows than expected; stopping");
  const row = rows.first();
  const name = (await row.locator("strong").first().innerText()).trim();
  await row.getByLabel("Type ERASE to confirm").fill("ERASE");
  await row.getByRole("button", { name: "Erase what they left" }).click();
  const gone = M.page.locator(`li:has(strong:text-is("${name}"))`).waitFor({ state: "detached", timeout: 300000 });
  const error = row.locator('[role="alert"]').waitFor({ timeout: 300000 });
  await Promise.race([gone, error]).catch(() => {});
  if (await M.page.locator(`li:has(strong:text-is("${name}")) [role="alert"]`).count()) {
    throw new Error(`FAILED: erasing ${name}: ${await M.page.locator(`li:has(strong:text-is("${name}")) [role="alert"]`).first().innerText()}`);
  }
  console.log(`ok - erased what ${name} left`);
  erased += 1;
}
check(true, `${erased} removed test account(s) erased`);
await M.ctx.close();
