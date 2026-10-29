// Two new people set up keys and exchange messages; signatures verify; safety numbers match.
// Args: <ann embed url> <ben embed url>
import { PEOPLE, check, countUnverified, goto, open, openConversation, savePhrase, sendText, setUp, shot } from "./lib.mjs";

const [annUrl, benUrl] = process.argv.slice(2);
const A = await open("ann1", annUrl);
const B = await open("ben1", benUrl);
await goto(A.page);
await goto(B.page);
savePhrase("ann", await setUp(A.page, PEOPLE.ann));
await setUp(B.page, PEOPLE.ben);
check(true, "both accounts set up encryption");

await A.page.getByRole("button", { name: "New" }).click();
await A.page.fill("#dm-username", PEOPLE.ben.username);
await A.page.getByRole("button", { name: "Start conversation" }).click();
await A.page.waitForURL(/\/app\/c\//, { timeout: 60000 });
await sendText(A.page, "Hello Ben, this is end-to-end encrypted.");

await openConversation(B.page, PEOPLE.ann.display);
await B.page.waitForSelector("text=Hello Ben, this is end-to-end encrypted.", { timeout: 60000 });
check((await countUnverified(B.page)) === 0, "Ben's copy decrypts and its signature verifies");
await sendText(B.page, "Hi Ann! Got it.");
await A.page.waitForSelector("text=Hi Ann! Got it.", { timeout: 60000 });
check((await countUnverified(A.page)) === 0, "Ann's copy of the reply verifies");

const safety = async (page) => {
  await page.getByRole("button", { name: /Conversation details/ }).click();
  await page.getByRole("button", { name: "Show safety number" }).click();
  const n = (await page.locator("p.mono").first().innerText()).replace(/\s/g, "");
  await page.keyboard.press("Escape");
  return n;
};
const sa = await safety(A.page);
const sb = await safety(B.page);
check(sa.length === 60 && sa === sb, "60-digit safety numbers match on both sides");
await shot(A.page, "01-dm");
await A.ctx.close();
await B.ctx.close();
