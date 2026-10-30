// Ann restores her keys on a fresh browser with the 24-word phrase. A wrong phrase is refused.
// Args: <ann embed url, for the fresh browser>
import { PEOPLE, check, countLocked, countUnverified, goto, loadPhrase, open, openConversation, shot } from "./lib.mjs";

const [ann3Url] = process.argv.slice(2);
const A3 = await open("ann3", ann3Url);
await goto(A3.page);
await A3.page.getByRole("button", { name: /Use your 24-word recovery phrase/ }).click({ timeout: 60000 });
await A3.page.fill("#phrase", `${"abandon ".repeat(23)}art`);
await A3.page.getByRole("button", { name: "Unlock my keys" }).click();
await A3.page.waitForSelector("text=isn't the current recovery phrase for this account", { timeout: 60000 });
check(true, "a valid but wrong phrase is refused");
await A3.page.fill("#phrase", loadPhrase("ann"));
await A3.page.getByRole("button", { name: "Unlock my keys" }).click();
await A3.page.waitForSelector('h1:has-text("Messages")', { timeout: 90000 });
await openConversation(A3.page, PEOPLE.ben.display);
for (const t of ["Hello Ben, this is end-to-end encrypted.", "Sent from Ann's second browser", "After removing the second browser"]) {
  await A3.page.waitForSelector(`text=${t}`, { timeout: 60000 });
}
await A3.page.waitForTimeout(3000);
check((await countLocked(A3.page)) === 0 && (await countUnverified(A3.page)) === 0, "everything, before and after rotation, is readable and verified");
await shot(A3.page, "04-recovered");
await A3.ctx.close();
