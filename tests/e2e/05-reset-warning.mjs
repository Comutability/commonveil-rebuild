// Ben loses everything and asks to reset. The reset waits a week: his old browser shows the
// request and can cancel it. Once a reset completes, Ann is warned and her sending pauses until
// she reviews. Ben also files a report, used by 07-admin.mjs.
//
// Run it twice:
//   node 05-reset-warning.mjs "<ben embed url, for a fresh browser>"    asks, cancels, asks again
//   (move the waiting ResetRequest's effective_at into the past: see README)
//   node 05-reset-warning.mjs --finish                                   completes the reset
import { PEOPLE, check, confirmPhrase, countLocked, countUnverified, goto, open, openConversation, sendText, shot } from "./lib.mjs";

const args = process.argv.slice(2);
const REQUESTED = "text=Someone asked to reset your encryption keys";

async function askForReset(page) {
  await page.getByRole("button", { name: /lost every device and my phrase/ }).click({ timeout: 60000 });
  await page.fill("#confirm-reset", "RESET");
  await page.getByRole("button", { name: "Reset my encryption" }).click();
  await confirmPhrase(page, "Ask for the reset");
  await page.waitForSelector("text=Your reset is waiting", { timeout: 90000 });
}

if (args[0] !== "--finish") {
  const B2 = await open("ben2", args[0]);
  // What the server said about emailing the account's address.
  const emailed = [];
  B2.page.on("response", async (res) => {
    if (!/\/functions\/keys/.test(res.url()) || res.request().method() !== "POST") return;
    try {
      if (JSON.parse(res.request().postData() || "{}").action !== "request_reset") return;
      emailed.push((await res.json()).emailed);
    } catch {
      /* not JSON */
    }
  });

  await goto(B2.page);
  await askForReset(B2.page);
  check(true, "a reset waits instead of happening at once");
  check(emailed[0] === true, "the account's email address is sent a notice");

  const B1 = await open("ben1");
  await goto(B1.page);
  await B1.page.waitForSelector(REQUESTED, { timeout: 90000 });
  check(true, "Ben's existing browser shows the request");
  await shot(B1.page, "05-reset-requested");
  await B1.page.getByRole("button", { name: "Cancel the reset" }).click();
  await B1.page.waitForSelector(REQUESTED, { state: "detached", timeout: 60000 });
  check(true, "and can cancel it");

  await B2.page.getByRole("button", { name: "Check again" }).click();
  await B2.page.waitForSelector("text=Your reset was cancelled from one of your devices", { timeout: 60000 });
  check(true, "the browser that asked is told it was cancelled, and nothing changed");

  // Ask again, and this time leave it waiting.
  await askForReset(B2.page);
  await goto(B1.page);
  await B1.page.waitForSelector(REQUESTED, { timeout: 90000 });
  check(true, "a new request shows again");
  await B1.ctx.close();
  await B2.ctx.close();
  console.log("Next: move the waiting ResetRequest's effective_at into the past, then run this script again with --finish.");
} else {
  const B2 = await open("ben2");
  await goto(B2.page);
  await B2.page.waitForSelector('h1:has-text("Messages")', { timeout: 90000 });
  check(true, "after the wait, the browser that asked finishes the reset");
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
  await B2.page.getByRole("combobox", { name: "Reason" }).selectOption("spam");
  await B2.page.getByRole("textbox", { name: "Details" }).fill("Test report from the browser suite.");
  await B2.page.getByRole("button", { name: "Send report" }).click();
  await B2.page.waitForSelector("text=Report sent", { timeout: 30000 });
  check(true, "report sent");
  await B2.page.keyboard.press("Escape");

  const B1 = await open("ben1");
  await goto(B1.page);
  await B1.page.waitForSelector("text=Your encryption was reset elsewhere", { timeout: 60000 });
  check(true, "Ben's old browser is locked out and told why, with its keys left for him to delete");
  await A1.ctx.close();
  await B1.ctx.close();
  await B2.ctx.close();
}
