// Shared helpers for the live browser tests. See tests/e2e/README.md.
import { chromium } from "playwright";
import fs from "node:fs";
import path from "node:path";

export const BASE = (process.env.CV_BASE_URL || "").replace(/\/$/, "");
if (!BASE) throw new Error("Set CV_BASE_URL to the preview or published site URL.");

const ROOT = process.env.CV_E2E_DIR || "/tmp/cv-e2e";
export const SHOTS = path.join(ROOT, "shots");
fs.mkdirSync(SHOTS, { recursive: true });

/**
 * Test people. Deleted and erased accounts retire their usernames for good, so give each run its
 * own with CV_E2E_TAG (letters and numbers, up to 8): e2e_ann_<tag> and so on.
 */
const TAG = (process.env.CV_E2E_TAG || "").replace(/[^A-Za-z0-9]/g, "").slice(0, 8);
const handle = (name) => (TAG ? `e2e_${name}_${TAG}` : `e2e_${name}`);
export const PEOPLE = {
  ann: { username: handle("ann"), display: "Ann Test" },
  ben: { username: handle("ben"), display: "Ben Test" },
  cat: { username: handle("cat"), display: "Cat Test" },
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

/** Username, then keys, then phrase confirmation. Returns the phrase, or null if already set up. */
export async function setUp(page, person) {
  await page.waitForSelector('#username, h1:has-text("Set up encryption"), h1:has-text("Messages")', { timeout: 60000 });
  if (await page.locator('h1:has-text("Messages")').count()) return null;
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

/**
 * Send a message and make sure it went: the composer empties only once the server has it. (The
 * text alone isn't proof: the composer itself still holds it if sending failed.)
 */
export async function sendText(page, text) {
  const box = page.getByRole("textbox", { name: "Message" });
  await box.fill(text);
  await box.press("Enter");
  const deadline = Date.now() + 60000;
  while ((await box.inputValue()) !== "") {
    const alert = page.locator('form [role="alert"]');
    if ((await alert.count()) && !(await box.isDisabled())) throw new Error(`FAILED: sending "${text}": ${await alert.first().innerText()}`);
    if (Date.now() > deadline) throw new Error(`FAILED: "${text}" wasn't sent within a minute`);
    await page.waitForTimeout(250);
  }
  await page.locator("div.group", { hasText: text }).first().waitFor({ timeout: 30000 });
}

/** Wait for a success text; if an error appears on screen instead, fail with its wording. */
export async function expectText(page, text, timeout = 60000) {
  const ok = page.locator(`text=${text}`).first();
  const alert = page.locator('[role="alert"]').first();
  await Promise.race([ok.waitFor({ timeout }), alert.waitFor({ timeout })]).catch(() => {});
  if (await ok.count()) return;
  const shown = (await alert.count()) ? await alert.innerText() : "(nothing)";
  throw new Error(`FAILED: expected "${text}", the page showed: ${shown}`);
}

export const countUnverified = (page) => page.locator("text=unverified").count();
export const countLocked = (page) => page.locator("text=Can't be read on this device").count();
