// The admin area works without encryption setup; non-admins are turned away.
// Args: <admin embed url>
import { PEOPLE, check, goto, open, shot } from "./lib.mjs";

const [adminUrl] = process.argv.slice(2);
const M = await open("admin1", adminUrl);
await goto(M.page, "/admin");
await M.page.waitForSelector('h1:has-text("Admin")', { timeout: 60000 });
const report = M.page.locator(`li:has-text("@${PEOPLE.ben.username} reported")`).first();
await report.waitFor({ timeout: 60000 });
check(true, "the report from 05-reset-warning is listed");
await report.getByRole("combobox", { name: "Status" }).click();
await M.page.getByRole("option", { name: "resolved" }).click();
await report.getByRole("textbox", { name: "Resolution note" }).fill("Test only");
await report.getByRole("button", { name: "Save" }).click();
await M.page.waitForTimeout(3000);
check((await M.page.locator(`li:has-text("@${PEOPLE.ben.username} reported")`).count()) === 0, "resolved reports leave the open list");

await M.page.getByRole("tab", { name: /Content/ }).click();
await M.page.getByRole("combobox", { name: "Content type" }).click();
await M.page.getByRole("option", { name: "Guides" }).click();
await M.page.waitForSelector('button:has-text("Docker for beginners")', { timeout: 60000 });
await M.page.locator('button:has-text("Docker for beginners")').click();
await M.page.getByRole("button", { name: "Preview" }).click();
await M.page.waitForSelector(".prose-cv h2", { timeout: 30000 });
check(true, "content editor opens with a Markdown preview");
await shot(M.page, "07-admin");

const A = await open("ann1");
await goto(A.page, "/admin");
await A.page.waitForTimeout(2000);
check(!A.page.url().includes("/admin"), "a non-admin is sent away from /admin");
await M.ctx.close();
await A.ctx.close();
