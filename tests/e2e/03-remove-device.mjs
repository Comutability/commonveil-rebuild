// Ann removes her second browser. Keys rotate, Ben sees no false alarm, the removed browser is locked out.
import { PEOPLE, check, countUnverified, goto, open, openConversation, sendText, shot } from "./lib.mjs";

const A1 = await open("ann1");
await goto(A1.page, "/app/settings");
const fingerprint = () => A1.page.locator("p.mono").last().innerText();
const before = await fingerprint();
const other = A1.page.locator('li:has(button:has-text("Remove")):not(:has-text("This browser"))').first();
await other.waitFor({ timeout: 60000 });
await other.getByRole("button", { name: "Remove" }).click();
await A1.page.getByRole("alertdialog").getByRole("button", { name: "Remove" }).click();
await A1.page.getByRole("alertdialog").waitFor({ state: "detached", timeout: 90000 });
await goto(A1.page, "/app/settings");
check(before !== (await fingerprint()), "removing a device rotated the account key");
check((await A1.page.locator('li:has(button:has-text("Remove"))').count()) === 1, "one active device left");

await goto(A1.page);
await openConversation(A1.page, PEOPLE.ben.display);
await sendText(A1.page, "After removing the second browser");

const B = await open("ben1");
await goto(B.page);
await openConversation(B.page, PEOPLE.ann.display);
await B.page.waitForSelector("text=After removing the second browser", { timeout: 60000 });
await B.page.waitForTimeout(3000);
check((await countUnverified(B.page)) === 0, "Ben verifies messages under Ann's rotated key");
check((await B.page.locator("text=new security keys").count()) === 0, "a chained rotation raises no key-change warning");

const A2 = await open("ann2");
await goto(A2.page);
await A2.page.waitForSelector("text=This browser was removed from your account", { timeout: 60000 });
check(true, "the removed browser is locked out and told why");
check((await A2.page.getByRole("button", { name: /Delete this browser's keys/ }).count()) === 1, "its keys stay until the person chooses to delete them");
await A2.page.getByRole("button", { name: /Delete this browser's keys/ }).click();
await A2.page.waitForSelector("text=Set up encryption on this device", { timeout: 60000 });
check(true, "after deleting them it can be set up again");
await shot(A1.page, "03-after-removal");
await A1.ctx.close();
await A2.ctx.close();
await B.ctx.close();
