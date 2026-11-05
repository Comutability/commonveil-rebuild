// node onboard.mjs <profile> <embedUrl> <username>
import { HOST, open, shot, sleep } from "./lib.mjs";

const [profile, url, username] = process.argv.slice(2);
const { ctx, page } = await open(profile);
try {
  await page.goto(url, { waitUntil: "domcontentloaded" });
  await sleep(6000);
  console.log("after ott:", page.url());
  await page.goto(`${HOST}/app`, { waitUntil: "domcontentloaded" });
  await sleep(5000);
  console.log("at:", page.url());
  if (await page.locator("#username").count()) {
    await page.fill("#username", username);
    await page.getByRole("button", { name: "Continue" }).click();
    await sleep(4000);
  }
  if (await page.getByRole("button", { name: "Create my keys" }).count()) {
    await page.getByRole("button", { name: "Create my keys" }).click();
    await page.waitForSelector('ol[aria-label="Recovery phrase, 24 words"]', { timeout: 30000 });
    const words = await page.$$eval('ol[aria-label="Recovery phrase, 24 words"] li span.mono', (els) => els.map((e) => e.textContent.trim()));
    console.log("phrase words:", words.length);
    await page.getByText("I've written down all 24 words, in order.").click();
    await page.getByRole("button", { name: "Continue" }).click();
    await sleep(500);
    for (let i = 0; i < 24; i += 1) {
      const input = page.locator(`#w${i}`);
      if (await input.count()) await input.fill(words[i]);
    }
    await page.getByRole("button", { name: "Finish setup" }).click();
  }
  await page.waitForSelector('nav[aria-label="Servers"]', { timeout: 60000 });
  await sleep(8000);
  await shot(page, `${profile}-home`);
  console.log("final:", page.url());
} catch (err) {
  console.log("ERROR", err.message);
  await shot(page, `${profile}-error`).catch(() => {});
} finally {
  await ctx.close();
}
