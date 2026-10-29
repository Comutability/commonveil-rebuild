// Ann adds a second browser by approving it from her first, after comparing link codes.
// Args: <ann embed url, for the new browser>
import { PEOPLE, check, countLocked, countUnverified, goto, open, openConversation, sendText, shot } from "./lib.mjs";

const [ann2Url] = process.argv.slice(2);
const A1 = await open("ann1");
const A2 = await open("ann2", ann2Url);
await goto(A2.page);
await A2.page.getByRole("button", { name: /Approve it from another device/ }).click({ timeout: 60000 });
await A2.page.waitForFunction(() => /\d{4}/.test(document.querySelector('p[aria-label="Device link code"]')?.textContent || ""), null, { timeout: 60000 });
const newCode = (await A2.page.locator('p[aria-label="Device link code"]').innerText()).replace(/\s/g, "");
check(newCode.length === 20, "new browser shows a 20-digit link code");

await goto(A1.page, "/app/settings");
const pending = A1.page.locator('li:has-text("wants to join")');
await pending.waitFor({ timeout: 60000 });
const shownCode = (await pending.locator("p.mono").innerText()).replace(/\s/g, "");
check(shownCode === newCode, "the existing device shows the same code");
await pending.getByRole("checkbox").click();
await pending.getByRole("button", { name: "Approve" }).click();
await A1.page.waitForSelector('li:has-text("wants to join")', { state: "detached", timeout: 60000 });

await A2.page.waitForSelector('h1:has-text("Messages")', { timeout: 90000 });
await openConversation(A2.page, PEOPLE.ben.display);
await A2.page.waitForSelector("text=Hi Ann! Got it.", { timeout: 60000 });
check((await countUnverified(A2.page)) === 0 && (await countLocked(A2.page)) === 0, "new browser reads and verifies the full history");
await sendText(A2.page, "Sent from Ann's second browser");

const B = await open("ben1");
await goto(B.page);
await openConversation(B.page, PEOPLE.ann.display);
await B.page.waitForSelector("text=Sent from Ann's second browser", { timeout: 60000 });
await B.page.waitForTimeout(4000);
check((await countUnverified(B.page)) === 0, "Ben verifies the message from Ann's new device");
await shot(A2.page, "02-linked");
await A1.ctx.close();
await A2.ctx.close();
await B.ctx.close();
