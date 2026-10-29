// Ben loses everything and resets. Ann is warned and her sending pauses until she reviews.
// Ben also files a report, used by 07-admin.mjs.
// Args: <ben embed url, for a fresh browser>
import { PEOPLE, check, confirmPhrase, countLocked, countUnverified, goto, open, openConversation, sendText, shot } from "./lib.mjs";

const [ben2Url] = process.argv.slice(2);
const B2 = await open("ben2", ben2Url);
await goto(B2.page);
await B2.page.getByRole("button", { name: /lost every device and my phrase/ }).click({ timeout: 60000 });
await B2.page.fill("#confirm-reset", "RESET");
await B2.page.getByRole("button", { name: "Reset my encryption" }).click();
await confirmPhrase(B2.page, "Reset and finish");
await B2.page.waitForSelector('h1:has-text("Messages")', { timeout: 90000 });
await openConversation(B2.page, PEOPLE.ann.display);
await B2.page.waitForTimeout(5000);
check((await countLocked(B2.page)) > 0, "messages to Ben's old identity can't be read by the new one");

const A1 = await open("ann1");
await goto(A1.page);
await openConversation(A1.page, PEOPLE.ben.display);
await A1.page.waitForSelector("text=new security keys", { timeout: 90000 });
const composer = A1.page.getByRole("textbox", { name: "Message" });
check(await composer.isDisabled(), "Ann is warned and sending is paused");
await shot(A1.page, "05-key-change");
await A1.page.getByRole("button", { name: "Review" }).click();
await A1.page.getByRole("button", { name: "I understand, continue" }).click();
await A1.page.keyboard.press("Escape");
await A1.page.waitForSelector("text=new security keys", { state: "detached", timeout: 30000 });
await sendText(A1.page, "Welcome back, Ben");
await B2.page.waitForSelector("text=Welcome back, Ben", { timeout: 60000 });
await B2.page.waitForTimeout(3000);
check((await countUnverified(B2.page)) === 0, "after review, messages flow and verify again");

await B2.page.getByRole("button", { name: /Conversation details/ }).click();
await B2.page.getByRole("button", { name: "Report" }).click();
await B2.page.getByRole("combobox", { name: "Reason" }).click();
await B2.page.getByRole("option", { name: "Spam" }).click();
await B2.page.getByRole("textbox", { name: "Details" }).fill("Test report from the browser suite.");
await B2.page.getByRole("button", { name: "Send report" }).click();
await B2.page.waitForSelector("text=Report sent", { timeout: 30000 });
check(true, "report sent");
await B2.page.keyboard.press("Escape");

const B1 = await open("ben1");
await goto(B1.page);
await B1.page.waitForSelector("text=Set up encryption on this device", { timeout: 60000 });
check((await B1.page.locator("text=was removed from your account").count()) > 0, "Ben's old browser is locked out");
await A1.ctx.close();
await B1.ctx.close();
await B2.ctx.close();
