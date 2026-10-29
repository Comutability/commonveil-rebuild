// Groups: encrypted name, a device-signed add, the "someone new" pause for other members,
// newcomers can't read earlier messages, device-signed delete and leave.
// Args: [cat embed url] (omit if Cat's browser profile is already signed in)
import { PEOPLE, check, countLocked, countUnverified, expectText, goto, open, openConversation, sendText, setUp, shot } from "./lib.mjs";

const GROUP = `Book club ${Math.floor(Date.now() / 1000) % 100000}`;
const [catUrl] = process.argv.slice(2);
const C = await open("cat1", catUrl);
await goto(C.page);
await setUp(C.page, PEOPLE.cat);

const A = await open("ann1");
await goto(A.page);
await A.page.getByRole("button", { name: "New" }).click();
await A.page.getByRole("tab", { name: "Group" }).click();
await A.page.fill("#group-name", GROUP);
await A.page.fill("#group-member", PEOPLE.ben.username);
await A.page.getByRole("button", { name: "Add", exact: true }).click();
await A.page.waitForSelector(`li:has-text("${PEOPLE.ben.display}")`, { timeout: 30000 });
await A.page.getByRole("button", { name: "Create group" }).click();
await A.page.waitForURL(/\/app\/c\//, { timeout: 60000 });
await A.page.waitForSelector(`h2:has-text("${GROUP}")`, { timeout: 60000 });
await sendText(A.page, "First group message");

const B = await open("ben2");
await goto(B.page);
await openConversation(B.page, GROUP);
await B.page.waitForSelector("text=First group message", { timeout: 60000 });
check((await countUnverified(B.page)) === 0, "Ben sees the encrypted group name and a verified message");

// Ann adds Cat (device-signed). The group name is re-encrypted so Cat can read it.
await A.page.getByRole("button", { name: /Conversation details/ }).click();
await A.page.fill("#add-person", PEOPLE.cat.username);
await A.page.getByRole("button", { name: "Add", exact: true }).click();
await expectText(A.page, "They'll see messages from now on");
await A.page.keyboard.press("Escape");
check((await A.page.locator("text=New in this conversation").count()) === 0, "the person who added Cat isn't asked to confirm it");
await sendText(A.page, "Cat is here now");

// Ben didn't add anyone, so he must see who's new before he can send.
await goto(B.page);
await openConversation(B.page, GROUP);
await B.page.waitForSelector("text=New in this conversation", { timeout: 60000 });
check(await B.page.getByRole("textbox", { name: "Message" }).isDisabled(), "Ben's sending pauses until he has seen that Cat joined");
await shot(B.page, "06-new-member");
await B.page.getByRole("button", { name: "OK, continue" }).click();
await sendText(B.page, "Hi Cat");

await goto(C.page);
await openConversation(C.page, GROUP);
await C.page.waitForSelector("text=Hi Cat", { timeout: 60000 });
await C.page.waitForTimeout(3000);
check((await C.page.locator(`h2:has-text("${GROUP}")`).count()) === 1, "Cat can read the group name");
check((await countLocked(C.page)) === 1, "Cat can't read the message sent before she joined");
check((await countUnverified(C.page)) === 0, "Cat verifies everything she can read");
check((await C.page.locator("text=New in this conversation").count()) === 0, "a newcomer isn't asked about members on first sight");

// Device-signed delete.
const bubble = A.page.locator('div.group:has-text("Cat is here now")').last();
await bubble.hover();
await bubble.getByRole("button", { name: "Message options" }).click();
await A.page.getByRole("menuitem", { name: "Delete for everyone" }).click();
await B.page.waitForSelector("text=Message deleted", { timeout: 60000 });
check(true, "Ann's deletion reaches Ben");

// Device-signed leave.
await C.page.getByRole("button", { name: /Conversation details/ }).click();
await C.page.getByRole("button", { name: "Leave group" }).click();
await C.page.waitForURL(/\/app$/, { timeout: 60000 });
check((await C.page.locator(`a:has-text("${GROUP}")`).count()) === 0, "Cat left the group");

await A.ctx.close();
await B.ctx.close();
await C.ctx.close();
