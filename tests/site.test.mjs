// The public site's on-browser search, over the help articles and resources.
import test from "node:test";
import assert from "node:assert/strict";
import { plainText, searchContent, toDocs } from "../src/lib/site/search.js";

test("site search: every word must appear, titles count most, and markdown doesn't get in the way", () => {
  const docs = toDocs({
    help: [
      { slug: "password-manager", title: "Set up a password manager", summary: "One strong password to remember.", section: "Getting started", body: "## Why\nA **password manager** remembers the rest. Use [Bitwarden](https://bitwarden.com) or similar." },
      { slug: "backups", title: "Back up your phone", summary: "Before you lose it.", section: "Your account", body: "Keep an end-to-end encrypted backup." },
      { slug: "e2ee", title: "End-to-end encryption", summary: "Only the people talking can read it.", section: "Privacy and safety", body: "No one in between, including the server." },
      { slug: "note", title: "A note on passwords", summary: "Short.", section: "Help", body: "Managers help." },
    ],
    resources: [{ name: "Bitwarden", description: "An open-source password manager.", category: "Passwords", website: "https://bitwarden.com" }],
  });
  assert.equal(docs.length, 5);
  const hits = searchContent(docs, "password manager");
  assert.deepEqual(hits.map((h) => h.doc.title), ["Set up a password manager", "A note on passwords", "Bitwarden"], "words match inside longer words too");
  assert.equal(hits[0].doc.url, "/help/password-manager");
  assert.equal(hits[2].doc.external, "https://bitwarden.com");
  assert.ok(!hits[0].snippet.includes("**") && !hits[0].snippet.includes("https://"), "snippets are plain text");
  assert.deepEqual(searchContent(docs, "END-TO-END").map((h) => h.doc.title), ["End-to-end encryption", "Back up your phone"]);
  assert.deepEqual(searchContent(docs, "x"), [], "two letters at least");
  assert.deepEqual(searchContent(docs, "password zebra"), []);
  assert.equal(plainText("- one\n- two\n\n```js\ncode()\n```\n[link](https://example.com)"), "one two link");
});
