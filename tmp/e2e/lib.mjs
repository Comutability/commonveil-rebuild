import { chromium } from "playwright";
import fs from "node:fs";

export const HOST = "https://preview-sandbox--6ae32bdd1ba2418571d823fd.base44.app";
export const SHOTS = "/tmp/e2e/shots";
fs.mkdirSync(SHOTS, { recursive: true });

export async function open(profile, { width = 1280, height = 800, scale = 1 } = {}) {
  const ctx = await chromium.launchPersistentContext(`/tmp/e2e/profiles/${profile}`, {
    headless: true,
    viewport: { width, height },
    deviceScaleFactor: scale,
    colorScheme: process.env.SCHEME || "dark",
  });
  const page = ctx.pages()[0] || (await ctx.newPage());
  page.on("console", (m) => {
    if (m.type() === "error" || m.type() === "warning") console.log(`[${profile} ${m.type()}]`, m.text().slice(0, 300));
  });
  page.on("pageerror", (e) => console.log(`[${profile} pageerror]`, e.message));
  return { ctx, page };
}

export async function shot(page, name) {
  await page.screenshot({ path: `${SHOTS}/${name}.png` });
  console.log("shot", name);
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
