import test from "node:test";
import assert from "node:assert/strict";
import { automodReason, cleanAutomod } from "../src/lib/secure/automod.js";
import { cleanSet } from "../src/lib/customEmoji.js";
import { serverMessageContent } from "../src/lib/secure/serverProtocol.js";

test("AutoMod: words (with *), links, invites and mention limits", () => {
  const rules = cleanAutomod({ enabled: true, words: ["Spam*", "x", "bad word"], block_links: true, block_invites: true, mention_limit: 3 });
  assert.deepEqual(rules.words, ["spam*", "bad word"]);
  assert.ok(automodReason(rules, "buy SPAMMY things"));
  assert.equal(automodReason(rules, "antispam is fine"), null);
  assert.ok(automodReason(rules, "a bad word here"));
  assert.ok(automodReason(rules, "see https://example.com"));
  assert.ok(automodReason(rules, "join discord.gg/abc"));
  assert.ok(automodReason(rules, "hi", { users: ["a", "b", "c"], roles: ["d"] }));
  assert.equal(automodReason(rules, "hi", { users: ["a"] }), null);
  assert.equal(automodReason({ ...rules, enabled: false }, "spam"), null);
  assert.deepEqual(cleanAutomod({ mention_limit: 7 }).mention_limit, 0);
});

test("emoji sets drop bad entries; messages accept custom reactions and stickers by id only", () => {
  const ok = { id: "abcd1234", name: "ok_hand", img: "data:image/png;base64,AAAA" };
  const set = cleanSet("emoji", { items: [ok, { ...ok }, { id: "BAD", name: "x", img: ok.img }, { id: "zzzz9999", name: "evil", img: "javascript:alert(1)" }, { id: "yyyy8888", name: "svg", img: "data:image/svg+xml;base64,AAAA" }] });
  assert.deepEqual(set.items.map((x) => x.id), ["abcd1234"]);
  assert.ok(serverMessageContent({ type: "reaction", target: "a".repeat(22), emoji: "c:abcd1234" }, "reaction"));
  assert.equal(serverMessageContent({ type: "reaction", target: "a".repeat(22), emoji: "c:../x" }, "reaction"), null);
  const sticker = serverMessageContent({ type: "text", text: "", sticker: "abcd1234" }, "message");
  assert.equal(sticker.sticker, "abcd1234");
  assert.equal(serverMessageContent({ type: "text", text: "", sticker: "<img>" }, "message"), null);
});
