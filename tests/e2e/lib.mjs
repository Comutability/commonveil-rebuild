// Shared helpers for the live browser tests. See tests/e2e/README.md.
import { chromium } from "playwright";
import fs from "node:fs";
import path from "node:path";

export const BASE = (process.env.CV_BASE_URL || "").replace(/\/$/, "");
if (!BASE) throw new Error("Set CV_BASE_URL to the preview or published site URL.");

const ROOT = process.env.CV_E2E_DIR || "/tmp/cv-e2e";
export const SHOTS = path.join(ROOT, "shots");
fs.mkdirSync(SHOTS, { recursive: true });

/** Test people. Usernames must match the accounts you provisioned and signed in. */
export const PEOPLE = {
  ann: { username: "e2e_ann", display: "Ann Test" },
  ben: { username: "e2e_ben", display: "Ben Test" },
  cat: { username: "e2e_cat", display: "Cat Test" },
};

/** Open a browser profile that persists between scripts (one per device). */
export async function open(profile, embedUrl) {
  const ctx = await chromium.launchPersistentContext(path.join(ROOT, "profiles", profile), { viewport: { width: 1280, height: 860 } });
  const page = ctx.pages()[0] || (await ctx.newPage());
  page.on("pageerror", (e) => console.log(`[${profile}] page error:`, e.message));
  if (embedUrl) {
    await page.goto(embedUrl, { waitUntil: "networkidle", timeout: 90000 });
    await page.waitForTimeout(1500);
  }
  return { ctx, page };
}

export async function goto(page, p = "/app") {
  await page.goto(BASE + p, { waitUntil: "networkidle", timeout: 90000 });
}

export async function shot(page, name) {
  await page.screenshot({ path: path.join(SHOTS, `${name}.png`) });
}

export function savePhrase(name, phrase) {
  fs.writeFileSync(path.join(ROOT, `${name}.phrase`), phrase, { mode: 0o600 });
}

export function loadPhrase(name) {
  return fs.readFileSync(path.join(ROOT, `${name}.phrase`), "utf8").trim();
}

export function check(condition, message) {
  if (!condition) throw new Error(`FAILED: ${message}`);
  console.log(`ok - ${message}`);
}

/** Read the 24 words shown on screen and complete the three-word confirmation. */
export async function confirmPhrase(page, finishLabel) {
  await page.waitForSelector('ol[aria-label^="Recovery phrase"] li', { timeout: 60000 });
  const words = await page.locator('ol[aria-label^="Recovery phrase"] li span.mono').allInnerTexts();
  check(words.length === 24, "recovery phrase has 24 words");
  await page.getByRole("checkbox").click();
  await page.getByRole("button", { name: "Continue" }).click();
  const inputs = page.locator('input[id^="w"]');
  for (let i = 0; i < (await inputs.count()); i += 1) {
    const id = await inputs.nth(i).getAttribute("id");
    await inputs.nth(i).fill(words[Number(id.slice(1))]);
  }
  await page.getByRole("button", { name: finishLabel }).click();
  return words.join(" ");
}

/** Username, then keys, then phrase confirmation. Returns the phrase. */
export async function setUp(page, person) {
  await page.waitForSelector('#username, h1:has-text("Set up encryption"), h1:has-text("Messages")', { timeout: 60000 });
  if (await page.locator("#username").count()) {
    await page.fill("#username", person.username);
    await page.fill("#display", person.display);
    await page.getByRole("button", { name: "Continue" }).click();
  }
  await page.getByRole("button", { name: "Create my keys" }).click({ timeout: 60000 });
  const phrase = await confirmPhrase(page, "Finish setup");
  await page.waitForSelector('h1:has-text("Messages")', { timeout: 60000 });
  return phrase;
}

export async function openConversation(page, name) {
  // Wait for the app to finish its key checks first; a cold preview can take a while.
  await page.waitForSelector('h1:has-text("Messages")', { timeout: 90000 });
  await page.locator(`a:has-text("${name}")`).first().click({ timeout: 90000 });
}

export async function sendText(page, text) {
  const box = page.getByRole("textbox", { name: "Message" });
  await box.fill(text);
  await box.press("Enter");
  await page.waitForSelector(`text=${text}`, { timeout: 60000 });
}

export const countUnverified = (page) => page.locator("text=unverified").count();
export const countLocked = (page) => page.locator("text=Can't be read on this device").count();
