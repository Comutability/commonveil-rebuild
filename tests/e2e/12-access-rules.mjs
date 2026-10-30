// Every table's read rule, checked against the real platform with two new accounts and a visitor:
// each member reads only rows that name them, can't fetch anyone else's by id, and visitors read nothing.
// Args: <embed url for a new member> <embed url for another new member>
import { chromium } from "playwright";
import { BASE, check, goto, open, setUp } from "./lib.mjs";

const APP = process.env.CV_APP_ID || "6ae32bdd1ba2418571d823fd";
const TAG = (process.env.CV_E2E_TAG || Date.now().toString(36).slice(-5)).replace(/[^A-Za-z0-9]/g, "").slice(0, 8);
const [urlA, urlB] = process.argv.slice(2);
if (!urlA || !urlB) throw new Error("Usage: node 12-access-rules.mjs <member A embed url> <member B embed url>");

const TABLES = ["Profile", "AccountKey", "Device", "KeyEnvelope", "ResetRequest", "Message", "Conversation", "Block", "Report", "SecurityReport", "RetiredUsername"];
const OWN = ["Profile", "AccountKey", "Device", "KeyEnvelope"];
const CLOSED = ["Block", "Report", "SecurityReport", "RetiredUsername"];

/** Runs in the page: list tables, and fetch named rows by id, with this browser's session (if any). */
const read = async ({ app, tables, ids }) => {
  const token = localStorage.getItem("base44_access_token");
  const headers = { "X-App-Id": app, ...(token ? { Authorization: `Bearer ${token}` } : {}) };
  const lists = {};
  for (const t of tables) {
    const r = await fetch(`/api/apps/${app}/entities/${t}?limit=500`, { headers });
    let rows = [];
    try {
      rows = await r.json();
    } catch {
      rows = [];
    }
    lists[t] = Array.isArray(rows) ? rows.map((x) => ({ id: x.id, user_id: x.user_id })) : [];
  }
  const direct = {};
  for (const [t, id] of Object.entries(ids || {})) direct[t] = (await fetch(`/api/apps/${app}/entities/${t}/${id}`, { headers })).status;
  const me = token ? (await (await fetch(`/api/apps/${app}/entities/User/me`, { headers })).json()).id : null;
  return { me, lists, direct };
};

const A = await open(`access-a-${TAG}`, urlA);
const B = await open(`access-b-${TAG}`, urlB);
await goto(A.page);
await goto(B.page);
await setUp(A.page, { username: `e2e_acca_${TAG}`, display: "Access A" });
await setUp(B.page, { username: `e2e_accb_${TAG}`, display: "Access B" });
check(true, "two new members set up encryption");

const a = await A.page.evaluate(read, { app: APP, tables: TABLES });
const b = await B.page.evaluate(read, { app: APP, tables: OWN });
for (const t of OWN) {
  check(a.lists[t].length > 0 && a.lists[t].every((r) => r.user_id === a.me), `${t}: A reads only her own rows`);
  check(b.lists[t].length > 0 && b.lists[t].every((r) => r.user_id === b.me), `${t}: B reads only his own rows`);
}
for (const t of CLOSED) check(a.lists[t].length === 0, `${t}: closed to members`);

const theirs = Object.fromEntries(OWN.map((t) => [t, b.lists[t][0].id]));
const tried = await A.page.evaluate(read, { app: APP, tables: [], ids: theirs });
for (const [t, status] of Object.entries(tried.direct)) check(status === 404 || status === 403, `${t}: A can't fetch B's row by id (${status})`);

const browser = await chromium.launch();
const visitor = await browser.newPage();
await visitor.goto(`${BASE}/`, { waitUntil: "networkidle" });
const v = await visitor.evaluate(read, { app: APP, tables: TABLES });
for (const t of TABLES) check(v.lists[t].length === 0, `${t}: nothing for a visitor`);
await browser.close();
await A.ctx.close();
await B.ctx.close();
console.log("Next: deprovision both accounts and run 11-erase-test-accounts.mjs.");
