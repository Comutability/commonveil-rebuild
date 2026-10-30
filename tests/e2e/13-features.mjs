// The newer features, live: replies, reactions and edits; disappearing messages; group admins;
// message search; notifications and the unread count; the passcode lock; the data download;
// auto-delete; and on the public site, search, saved pages and guide progress.
//
// Uses Ann's browser from 01 and Ben's (from 05 if that ran, otherwise set CV_BEN_PROFILE=ben1).
//   node tests/e2e/13-features.mjs
// It prints a message to make disappear. Move that message's expires_at into the past (Base44 entity
// tools: Message where expires_at is set, newest first), then check it's gone everywhere:
//   node tests/e2e/13-features.mjs --expired "<that message>"
import fs from "node:fs";
import { BASE, PEOPLE, check, expectText, goto, loadPhrase, open, openConversation, sendText, shot } from "./lib.mjs";

const BEN = process.env.CV_BEN_PROFILE || "ben2";
const RUN = String(Math.floor(Date.now() / 1000) % 100000);
const args = process.argv.slice(2);

const bubble = (page, text) => page.locator("div.group", { hasText: text }).last();

async function menu(page, text, item) {
  const b = bubble(page, text);
  await b.hover();
  await b.getByRole("button", { name: "Message options" }).click();
  await page.getByRole("menuitem", { name: item }).click();
}

async function details(page) {
  await page.getByRole("button", { name: /Conversation details/ }).click();
  await page.getByRole("dialog").waitFor({ timeout: 30000 });
}

if (args[0] === "--expired") {
  const gone = args[1];
  const A = await open("ann1");
  const B = await open(BEN);
  for (const [who, page, other] of [["Ann", A.page, PEOPLE.ben.display], ["Ben", B.page, PEOPLE.ann.display]]) {
    await goto(page);
    await openConversation(page, other);
    await page.waitForTimeout(8000);
    check((await page.locator(`text=${gone}`).count()) === 0, `${who} no longer sees the message whose time is up`);
  }
  await A.ctx.close();
  await B.ctx.close();
  process.exit(0);
}

const A = await open("ann1");
const B = await open(BEN);
// Record what notifications say, without changing what they do.
await A.ctx.grantPermissions(["notifications"], { origin: BASE });
await A.ctx.addInitScript(() => {
  const Original = window.Notification;
  if (!Original) return;
  window.__alerts = [];
  window.Notification = class extends Original {
    constructor(title, options) {
      super(title, options);
      window.__alerts.push({ title, body: options?.body || "" });
    }
  };
});

// ---------- replies, reactions, edits ----------
await goto(A.page);
await openConversation(A.page, PEOPLE.ben.display);
await goto(B.page);
await openConversation(B.page, PEOPLE.ann.display);
const lunch = `Lunch tomorrow? ${RUN}`;
await sendText(A.page, lunch);
await bubble(B.page, lunch).waitFor({ timeout: 60000 });
await menu(B.page, lunch, "Reply");
await B.page.waitForSelector("text=Replying to Ann Test", { timeout: 10000 });
const reply = `Yes, at one ${RUN}`;
await sendText(B.page, reply);
await bubble(A.page, reply).waitFor({ timeout: 60000 });
await A.page.waitForTimeout(1500);
check((await bubble(A.page, reply).getByRole("button", { name: new RegExp(`Lunch tomorrow\\? ${RUN}`) }).count()) === 1, "Ann sees Ben's reply with a quote of what it answers");

await menu(A.page, reply, "React with Thumbs up");
await B.page.getByRole("button", { name: /^Thumbs up, 1/ }).waitFor({ timeout: 60000 });
check(true, "Ann's reaction reaches Ben, as a count under his message");

await menu(B.page, reply, "Edit");
await B.page.waitForSelector("text=Editing your message", { timeout: 10000 });
const edited = `Yes, at half past one ${RUN}`;
await sendText(B.page, edited);
await bubble(A.page, edited).waitFor({ timeout: 60000 });
await A.page.waitForTimeout(1500);
check((await bubble(A.page, edited).locator("text=· edited").count()) === 1, "Ann sees the new text, marked as edited");
check((await A.page.locator("div.group", { hasText: reply }).count()) === 0, "the old text is gone from Ann's screen");
check((await bubble(A.page, edited).getByRole("button", { name: /^Thumbs up, 1/ }).count()) === 1, "the reaction stays with the edited message");
await shot(A.page, "13-reply-reaction-edit");

// ---------- message search, on the device ----------
await goto(A.page);
await A.page.waitForSelector('h1:has-text("Messages")', { timeout: 90000 });
await openConversation(A.page, PEOPLE.ben.display);
await bubble(A.page, edited).waitFor({ timeout: 60000 });
await A.page.getByRole("textbox", { name: "Search conversations and messages" }).fill(`half past one ${RUN}`);
await A.page.locator('section[aria-label="Messages found"] a', { hasText: `half past one ${RUN}` }).first().waitFor({ timeout: 30000 });
check(true, "searching on the device finds the message as edited");
await A.page.getByRole("textbox", { name: "Search conversations and messages" }).fill("");

// ---------- disappearing messages ----------
await details(A.page);
await A.page.selectOption("#disappearing", "86400");
await expectText(A.page, "New messages will disappear after a day.");
await A.page.keyboard.press("Escape");
await A.page.locator("header >> text=1 day").first().waitFor({ timeout: 30000 });
const fleeting = `This one disappears ${RUN}`;
await sendText(A.page, fleeting);
check((await bubble(A.page, fleeting).locator("text=/^Disappears /").count()) === 1, "a message sent with the timer on shows when it disappears");
await goto(B.page);
await openConversation(B.page, PEOPLE.ann.display);
await B.page.waitForSelector("text=Ann Test set messages to disappear after a day.", { timeout: 90000 });
await bubble(B.page, fleeting).waitFor({ timeout: 60000 });
check(true, "Ben sees who set the timer, and the timed message");
await shot(B.page, "13-disappearing");

// ---------- group admins ----------
const GROUP = `Admins test ${RUN}`;
await goto(A.page);
await A.page.getByRole("button", { name: "New" }).click();
await A.page.getByRole("tab", { name: "Group" }).click();
await A.page.fill("#group-name", GROUP);
await A.page.fill("#group-member", PEOPLE.ben.username);
await A.page.getByRole("button", { name: "Add", exact: true }).click();
await A.page.waitForSelector(`li:has-text("${PEOPLE.ben.display}")`, { timeout: 30000 });
await A.page.getByRole("button", { name: "Create group" }).click();
await A.page.waitForSelector(`h2:has-text("${GROUP}")`, { timeout: 60000 });

await goto(B.page);
await openConversation(B.page, GROUP);
await B.page.getByRole("button", { name: "OK, continue" }).click({ timeout: 60000 });
await details(B.page);
await B.page.waitForSelector("text=Admins: Ann Test", { timeout: 30000 });
check((await B.page.locator("#rename, #add-person").count()) === 0 && (await B.page.locator("#disappearing").isDisabled()), "Ben isn't an admin: he can't rename, add people or change the timer");
await B.page.keyboard.press("Escape");

await details(A.page);
await A.page.getByRole("button", { name: `Manage ${PEOPLE.ben.display}` }).click();
await A.page.getByRole("menuitem", { name: "Make admin" }).click();
await expectText(A.page, `${PEOPLE.ben.display} is now an admin.`);
await A.page.keyboard.press("Escape");

let promoted = false;
for (let i = 0; i < 12 && !promoted; i += 1) {
  await B.page.waitForTimeout(10000);
  await details(B.page);
  promoted = (await B.page.locator("#rename").count()) === 1;
  await B.page.keyboard.press("Escape");
}
check(promoted, "once Ann makes him an admin, Ben can rename the group and add people");

// ---------- notifications and the unread count (Ann) ----------
await goto(A.page, "/app/settings");
await A.page.locator("#alert-notify").click();
await A.page.locator("#alert-title").click();
await A.page.waitForTimeout(1000);
check((await A.page.locator("#alert-notify").getAttribute("data-state")) === "checked", "notifications switch on once the browser allows them");
await goto(A.page);
await A.page.waitForSelector('h1:has-text("Messages")', { timeout: 90000 });
await A.page.waitForTimeout(3000);
const ping = `Ping ${RUN}`;
await goto(B.page);
await openConversation(B.page, PEOPLE.ann.display);
await sendText(B.page, ping);
await A.page.waitForFunction(() => /^\(\d+\) Commonveil$/.test(document.title), null, { timeout: 90000 });
check(true, `the tab title counts unread conversations: ${await A.page.title()}`);
const alerts = await A.page.evaluate(() => window.__alerts || []);
check(alerts.length >= 1 && alerts.every((n) => n.body === "New message"), `a notification said only "New message" (${JSON.stringify(alerts)})`);
await goto(A.page, "/app/settings");
await A.page.locator("#alert-notify").click();
await A.page.locator("#alert-title").click();

// ---------- passcode lock (Ann) ----------
const passcode = `correct horse battery ${RUN}`;
await A.page.fill("#passcode-new", passcode);
await A.page.fill("#passcode-again", passcode);
await A.page.getByRole("button", { name: "Turn on" }).click();
await expectText(A.page, "This browser is now locked with your passcode.");
await A.page.reload({ waitUntil: "networkidle" });
await A.page.waitForSelector('h1:has-text("Commonveil is locked")', { timeout: 60000 });
check(true, "after a reload the keys stay locked until the passcode is entered");
await A.page.fill("#passcode", "not the passcode");
await A.page.getByRole("button", { name: "Unlock" }).click();
await expectText(A.page, "That passcode isn't right.");
await A.page.fill("#passcode", passcode);
await A.page.getByRole("button", { name: "Unlock" }).click();
await A.page.waitForSelector('h1:has-text("Settings")', { timeout: 90000 });
await A.page.getByRole("button", { name: "Lock now" }).first().click();
await A.page.waitForSelector('h1:has-text("Commonveil is locked")', { timeout: 30000 });
check((await A.page.locator(`text=${edited}`).count()) === 0, "\"Lock now\" hides everything");
await A.page.fill("#passcode", passcode);
await A.page.getByRole("button", { name: "Unlock" }).click();
await A.page.waitForSelector('h1:has-text("Settings")', { timeout: 90000 });

// ---------- download my data (Ann, while the lock is on) ----------
const [download] = await Promise.all([
  A.page.waitForEvent("download", { timeout: 180000 }),
  A.page.getByRole("button", { name: "Download my data" }).click(),
]);
const file = await download.path();
const text = fs.readFileSync(file, "utf8");
const data = JSON.parse(text);
const dm = data.conversations.find((c) => c.kind === "direct message" && c.members.some((m) => m.username === PEOPLE.ben.username));
const editedRow = dm?.messages.find((m) => m.text === edited);
check(data.format === "commonveil-export-1" && data.account.username === PEOPLE.ann.username, "the download is Ann's");
check(Boolean(editedRow?.edited) && editedRow.reactions?.[0]?.from?.includes("You"), "it has her messages decrypted, with edits and reactions");
check(!/priv|pkcs8|sealed/i.test(text) && !text.includes(loadPhrase("ann").split(" ").slice(0, 4).join(" ")), "it holds no keys and no recovery phrase");
await A.page.getByRole("button", { name: "Turn off" }).click();
await expectText(A.page, "The lock is off.");

// ---------- auto-delete (Ben) ----------
await goto(B.page, "/app/settings");
await B.page.selectOption("#auto-delete", "183");
await expectText(B.page, "Saved.");
await B.page.waitForSelector("text=Last used:", { timeout: 10000 });
await B.page.selectOption("#auto-delete", "0");
await expectText(B.page, "The day you last used Commonveil is no longer kept.");
check(true, "auto-delete turns on and off, and off forgets the date");

// ---------- public site: search, saved pages, progress ----------
await goto(A.page, "/search");
await A.page.getByRole("searchbox", { name: "Search the site" }).fill("password");
await A.page.waitForSelector("main h2 a", { timeout: 60000 });
check(!A.page.url().includes("password"), "site search finds pages, and the query never goes in the address bar");
await goto(A.page, "/guides");
await A.page.locator('main a[href^="/guides/"]').first().click();
await A.page.waitForSelector("main h1", { timeout: 60000 });
const guideTitle = (await A.page.locator("main h1").first().innerText()).trim();
await A.page.getByRole("button", { name: "Save", exact: true }).click();
await A.page.getByRole("button", { name: "Mark as done" }).click();
await goto(A.page, "/saved");
await A.page.waitForSelector(`section[aria-labelledby="saved-pages"] a:has-text("${guideTitle}")`, { timeout: 10000 });
await A.page.waitForSelector(`section[aria-labelledby="finished-guides"] a:has-text("${guideTitle}")`, { timeout: 10000 });
check(true, "a saved, finished guide shows on the Saved page");
await A.page.getByRole("button", { name: "Clear everything on this browser" }).click();
await A.page.getByRole("button", { name: "Clear everything", exact: true }).click();
await A.page.waitForSelector("text=Nothing saved yet", { timeout: 10000 });
check(true, "clearing removes it all from the browser");
await shot(A.page, "13-saved");

console.log(`\nNext: move the expires_at of "${fleeting}" into the past, then run:\n  node tests/e2e/13-features.mjs --expired "${fleeting}"`);
await A.ctx.close();
await B.ctx.close();
