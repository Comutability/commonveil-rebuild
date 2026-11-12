// Offline mode (docs/OFFLINE.md): messages sealed while offline and sent later, and a site holding
// messages for another site it can't reach, then passing them on.
import test, { after, before, mock } from "node:test";
import assert from "node:assert/strict";
import { startSites } from "./support/selfhost.mjs";
import { Person } from "./support/person.mjs";

let net;
before(async () => {
  net = await startSites(["home.test", "away.test"]);
});
after(async () => {
  await net?.close();
});

const DAY = 86_400_000;

/** Seal a message as if the device's clock said `offset` ms from now. */
async function sealedAt(person, conversation, text, offset) {
  mock.timers.enable({ apis: ["Date"], now: Date.now() + offset });
  try {
    return await person.build(conversation, text);
  } finally {
    mock.timers.reset();
  }
}

test("a message written offline goes out later, with the time it was written", async () => {
  const a = net.sites["home.test"];
  const pia = await new Person(a, "pia").setup();
  const raf = await new Person(a, "raf").setup();
  const dm = (await pia.ok("conversations", await pia.signed("create_dm", { username: "raf" }))).conversation;

  // Sealed two days ago (the app's outbox keeps the finished request, not the text).
  const body = await sealedAt(pia, dm, "Written on the train with no signal", -2 * DAY);
  const plain = await pia.call("messages", body);
  assert.equal(plain.status, 400, "an old send time is still refused without the offline flag");
  const sent = await pia.ok("messages", { ...body, queued: true });
  assert.equal(sent.message.sent_at, body.sent_at, "it keeps the time it was written");
  const again = await pia.ok("messages", { ...body, queued: true });
  assert.equal(again.duplicate, true, "sending the same one twice stores it once");

  const list = await raf.ok("messages", { action: "list", conversation_id: dm.id });
  const [opened] = await raf.read(list.messages, dm.member_ids);
  assert.equal(opened.text, "Written on the train with no signal");
  assert.equal(opened.status, "ok");

  const stale = await sealedAt(pia, dm, "Too old", -8 * DAY);
  const r = await pia.call("messages", { ...stale, queued: true });
  assert.equal(r.data.code, "TOO_OLD", "a week is the limit");
  // And never from the future.
  const ahead = await sealedAt(pia, dm, "From tomorrow", DAY);
  assert.equal((await pia.call("messages", { ...ahead, queued: true })).data.code, "CLOCK_SKEW");
});

test("your site holds a message for a site it can't reach, and passes it on when it can", async () => {
  const home = net.sites["home.test"];
  const away = net.sites["away.test"];
  const sol = await new Person(home, "sol").setup();
  const tam = await new Person(away, "tam").setup();
  // Tam starts it, so the conversation lives on Tam's site.
  const dm = (await tam.ok("conversations", await tam.signed("create_dm", { username: "sol.home.test" }))).conversation;
  await tam.send(dm, "Are you there?");
  // Sol's app has seen the conversation (Tam's site tells Sol's within a couple of seconds).
  await new Promise((r) => setTimeout(r, 2000));
  const seen = await sol.ok("messages", { action: "poll" });
  assert.ok(seen);
  const first = await sol.ok("messages", { action: "list", conversation_id: dm.id });
  assert.equal((await sol.read(first.messages, dm.member_ids))[0].text, "Are you there?");

  net.setDown("away.test", true);
  const body = await sol.build(dm, "Yes, but our link is down");
  const held = await sol.call("messages", body);
  assert.equal(held.status, 202);
  assert.deepEqual([held.data.queued, held.data.site, held.data.msg_id], [true, "away.test", body.msg_id]);
  // The app tries again now and then; it's held once.
  assert.equal((await sol.call("messages", { ...body, queued: true })).status, 202);
  const rows = home.app.store.db.prepare("SELECT * FROM fed_outbox").all();
  assert.equal(rows.length, 1);
  assert.ok(!rows[0].body.includes("our link is down"), "held as ciphertext");
  assert.equal(await home.app.federation.deliverHeld(Date.now() + 60_000), 0, "still down: it waits");

  net.setDown("away.test", false);
  assert.equal(await home.app.federation.deliverHeld(Date.now() + 10 * 60_000), 1);
  assert.equal(home.app.store.db.prepare("SELECT COUNT(*) AS n FROM fed_outbox").get().n, 0);
  const list = await tam.ok("messages", { action: "list", conversation_id: dm.id });
  const texts = (await tam.read(list.messages, dm.member_ids)).map((m) => m.text);
  assert.deepEqual(texts, ["Are you there?", "Yes, but our link is down"]);

  // The app's own retry now finds it there already.
  const after = await sol.ok("messages", { ...body, queued: true });
  assert.equal(after.duplicate, true);
});

test("only message sends are held; anything else says the site can't be reached", async () => {
  const home = net.sites["home.test"];
  const away = net.sites["away.test"];
  const uma = await new Person(home, "uma").setup();
  const vic = await new Person(away, "vic").setup();
  const dm = (await vic.ok("conversations", await vic.signed("create_dm", { username: "uma.home.test" }))).conversation;
  // Uma's site hears where the conversation lives a moment after it's made.
  for (let i = 0; i < 100 && !(await uma.ok("conversations", { action: "list" })).conversations.some((c) => c.id === dm.id); i += 1) await new Promise((r) => setTimeout(r, 30));
  net.setDown("away.test", true);
  try {
    const r = await uma.call("messages", { action: "list", conversation_id: dm.id });
    assert.equal(r.status, 502, JSON.stringify(r.data));
    assert.equal(r.data.code, "SITE_UNREACHABLE");
  } finally {
    net.setDown("away.test", false);
  }
});
