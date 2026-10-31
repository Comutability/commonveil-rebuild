// The production build under its Content Security Policy: public pages, the anonymous
// security-report form, a new member setting up and then deleting their account, and staff
// handling the report. Run it against a production build: the published site, or dist/ served by
// serve-dist.mjs. (The editor preview has no policy, so a pass there would prove nothing.)
//
// Args: <new member embed url> <admin embed url>
// The member must be a freshly provisioned account: this script deletes it.
// Links minted for another surface (such as the preview) are swapped for a sign-in here.
import { chromium } from "playwright";
import { BASE, SHOTS, check, expectText, setUp } from "./lib.mjs";

const [memberUrl, adminUrl] = process.argv.slice(2);
if (!memberUrl || !adminUrl) throw new Error("Usage: node 10-policy-report-delete.mjs <new member embed url> <admin embed url>");

const stamp = Date.now().toString(36).slice(-6);
const browser = await chromium.launch();
const violations = [];
const errors = [];

/** Sign-in links last 60 seconds, so turn both into sessions before anything else. */
async function tokenFrom(embedUrl) {
  if (new URL(embedUrl).origin === new URL(BASE).origin) return { embedUrl };
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto(embedUrl, { waitUntil: "networkidle", timeout: 120000 });
  let token = null;
  for (let i = 0; i < 90 && !token; i += 1) {
    token = await page.evaluate(() => localStorage.getItem("base44_access_token")).catch(() => null);
    if (!token) await page.waitForTimeout(1000);
  }
  await ctx.close();
  if (!token) throw new Error("FAILED: the sign-in link never produced a session");
  return { token };
}
const [memberSession, adminSession] = await Promise.all([tokenFrom(memberUrl), tokenFrom(adminUrl)]);

async function watched(name) {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  await ctx.exposeBinding("__cvViolation", (_source, v) => violations.push({ who: name, ...v }));
  await ctx.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) => {
      window.__cvViolation({ directive: e.violatedDirective, blocked: e.blockedURI || "inline", sample: e.sample || "", where: `${e.sourceFile || "?"}:${e.lineNumber || "?"}` });
    });
  });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(`[${name}] ${e.message}`));
  page.on("console", (m) => {
    if (m.type() === "error" && /content security|trusted|refused to/i.test(m.text())) errors.push(`[${name}] ${m.text()}`);
  });
  return { ctx, page };
}

async function signIn(name, session) {
  const w = await watched(name);
  const target = session.token ? `${BASE}/app?access_token=${encodeURIComponent(session.token)}` : session.embedUrl;
  await w.page.goto(target, { waitUntil: "networkidle", timeout: 120000 });
  return w;
}

// ---- The policy is in the page, and security.txt is served ----
const html = await (await fetch(`${BASE}/`)).text();
check(/http-equiv="Content-Security-Policy"[^>]*script-src 'self'/.test(html), "the page carries the Content Security Policy");
check(html.includes("require-trusted-types-for 'script'"), "the policy requires Trusted Types");
const securityTxt = await (await fetch(`${BASE}/.well-known/security.txt`)).text();
check(/^Contact: https:\/\/commonveil\.online\/security\/report$/m.test(securityTxt) && /^Expires: 20\d\d-/m.test(securityTxt), "security.txt is served");

// ---- Public pages ----
const PAGES = [
  "/", "/blog", "/blog/nostr-in-plain-english", "/guides", "/guides/docker-for-beginners", "/paths", "/paths/self-host-your-data",
  "/resources", "/wiki", "/wiki/what-is-end-to-end-encryption", "/privacy", "/security", "/security/report", "/search", "/saved", "/login", "/register", "/no-such-page",
];
const V = await watched("visitor");
for (const p of PAGES) {
  await V.page.goto(BASE + p, { waitUntil: "networkidle", timeout: 90000 });
  const h1 = await V.page.locator("h1").first().innerText({ timeout: 30000 }).catch(() => "");
  check(h1.length > 0, `${p} renders ("${h1.slice(0, 40)}")`);
}
await V.page.goto(`${BASE}/guides/docker-for-beginners`, { waitUntil: "networkidle", timeout: 90000 });
check((await V.page.locator(".prose-cv h2").count()) > 0, "Markdown articles render");

// ---- Anonymous security report ----
const reportTitle = `Policy check ${stamp}`;
await V.page.goto(`${BASE}/security/report`, { waitUntil: "networkidle", timeout: 90000 });
await V.page.fill("#sr-summary", reportTitle);
await V.page.fill("#sr-details", "An automated report from the browser checks. Nothing is wrong: please close it.");
await V.page.getByRole("button", { name: "Send report" }).click();
await expectText(V.page, "Thank you. Your report is with our staff.");
check(true, "a visitor who isn't signed in can send a security report");
await V.ctx.close();

// ---- A new member sets up, then deletes their account ----
const M = await signIn("member", memberSession);
await setUp(M.page, { username: `e2e_del_${stamp}`, display: "Deletion Test" });
check(true, "a new member sets up encryption under the policy");
await M.page.goto(`${BASE}/app/settings`, { waitUntil: "networkidle", timeout: 90000 });
await M.page.waitForSelector("#confirm-delete", { timeout: 60000 });
const deleteButton = M.page.getByRole("button", { name: "Delete my account" });
check(await deleteButton.isDisabled(), "deletion stays disabled until DELETE is typed");
await M.page.fill("#confirm-delete", "DELETE");
await deleteButton.click();
await M.page.waitForURL(/account_deleted=1/, { timeout: 240000 }).catch(() => {});
if (!M.page.url().includes("account_deleted=1")) {
  const shown = await M.page.locator('[role="alert"]').first().innerText().catch(() => "(nothing)");
  throw new Error(`FAILED: deletion didn't finish; the page showed: ${shown}`);
}
await expectText(M.page, "Your account has been deleted");
check(await M.page.evaluate(() => !localStorage.getItem("base44_access_token")), "the session is gone from the browser");
await M.page.screenshot({ path: `${SHOTS}/10-deleted.png` });
await M.ctx.close();

// ---- Staff see and close the report; the Markdown preview decodes entities ----
const A = await signIn("admin", adminSession);
await A.page.goto(`${BASE}/admin`, { waitUntil: "networkidle", timeout: 90000 });
await A.page.waitForSelector('h1:has-text("Admin")', { timeout: 90000 });
await A.page.getByRole("tab", { name: /Security/ }).click();
const item = A.page.locator(`li:has-text("${reportTitle}")`).first();
await item.waitFor({ timeout: 60000 });
check((await item.locator("text=Sent without signing in").count()) === 1, "staff see the anonymous report, marked as such");
await item.getByRole("combobox", { name: "Status" }).selectOption("closed");
await item.getByRole("textbox", { name: "Staff note" }).fill("Automated test");
await item.getByRole("button", { name: "Save" }).click();
await A.page.waitForTimeout(3000);
check((await A.page.locator(`li:has-text("${reportTitle}")`).count()) === 0, "a closed report leaves the new list");

await A.page.getByRole("tab", { name: /Accounts/ }).click();
await A.page.waitForSelector("text=/No removed sign-ins|Type ERASE to confirm/", { timeout: 90000 });
check(true, "the removed-accounts list loads");

await A.page.getByRole("tab", { name: /Content/ }).click();
await A.page.getByRole("button", { name: /New/ }).click();
await A.page.fill("#f-body", "## Fish &amp; chips\n\nCopyright &copy; 2026 &mdash; a test.");
await A.page.getByRole("button", { name: "Preview" }).click();
const preview = A.page.locator(".prose-cv").first();
await preview.waitFor({ timeout: 30000 });
const text = await preview.innerText();
check(text.includes("Fish & chips") && text.includes("©") && text.includes("—"), "the Markdown preview decodes character references");
await A.page.getByRole("button", { name: "← Back" }).click();
await A.page.screenshot({ path: `${SHOTS}/10-admin.png` });
await A.ctx.close();
await browser.close();

// ---- Verdict ----
// Base44 adds a few inline <script> elements to published pages; the policy blocks them by design.
// The app's own HTML has none, so any other violation is ours.
const ours = violations.filter((v) => !(v.blocked === "inline" && v.directive === "script-src-elem"));
const platform = violations.length - ours.length;
if (platform) console.log(`note - ${platform} platform-injected inline script(s) blocked, as intended`);
for (const v of ours) console.log(`violation [${v.who}] ${v.directive} blocked ${v.blocked} ${v.sample} at ${v.where}`);
for (const e of errors) console.log(`error ${e}`);
check(ours.length === 0, "nothing of the app's own was blocked by the policy");
check(errors.length === 0, "no page errors and no Trusted Types failures");
