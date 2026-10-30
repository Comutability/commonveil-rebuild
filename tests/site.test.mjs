// The public site's on-browser features: saved pages, guide progress and search.
import test from "node:test";
import assert from "node:assert/strict";
import { cleanDone, cleanSaved, hrefOf } from "../src/lib/site/saved.js";
import { plainText, searchContent, toDocs } from "../src/lib/site/search.js";

test("saved pages: only well-formed entries are kept, whatever ends up in storage", () => {
  const stored = [
    { kind: "guide", slug: "password-manager", title: "Set up a password manager", saved_on: "2026-10-30", extra: "dropped" },
    { kind: "guide", slug: "password-manager", title: "duplicate" },
    { kind: "script", slug: "x", title: "unknown kind" },
    { kind: "wiki", slug: "../../etc", title: "bad slug" },
    { kind: "blog", slug: "why-backups", title: 42 },
    { kind: "path", slug: "start-here", title: "Start here", saved_on: "yesterday" },
    null,
  ];
  assert.deepEqual(cleanSaved(stored), [
    { kind: "guide", slug: "password-manager", title: "Set up a password manager", saved_on: "2026-10-30" },
    { kind: "path", slug: "start-here", title: "Start here", saved_on: null },
  ]);
  assert.deepEqual(cleanSaved("not a list"), []);
  assert.equal(hrefOf({ kind: "wiki", slug: "end-to-end" }), "/wiki/end-to-end");
  assert.deepEqual(cleanDone({ "password-manager": "2026-10-30", "bad slug!": "2026-10-30", other: "soon" }), { "password-manager": "2026-10-30" });
  assert.deepEqual(cleanDone(["password-manager"]), {});
});

test("site search: every word must appear, titles count most, and markdown doesn't get in the way", () => {
  const docs = toDocs({
    guides: [
      { slug: "password-manager", title: "Set up a password manager", summary: "One strong password to remember.", category: "Accounts", body: "## Why\nA **password manager** remembers the rest. Use [Bitwarden](https://bitwarden.com) or similar." },
      { slug: "backups", title: "Back up your phone", summary: "Before you lose it.", category: "Devices", body: "Keep an end-to-end encrypted backup." },
    ],
    wiki: [{ slug: "e2ee", title: "End-to-end encryption", summary: "Only the people talking can read it.", category: "Ideas", body: "No one in between, including the server." }],
    blog: [{ slug: "note", title: "A note on passwords", excerpt: "Short.", category: "Notes", tags: ["passwords"], body: "Managers help." }],
    resources: [{ name: "Bitwarden", description: "An open-source password manager.", category: "Passwords", website: "https://bitwarden.com" }],
  });
  assert.equal(docs.length, 5);
  const hits = searchContent(docs, "password manager");
  assert.deepEqual(hits.map((h) => h.doc.title), ["Set up a password manager", "Bitwarden"]);
  assert.equal(hits[0].doc.url, "/guides/password-manager");
  assert.equal(hits[1].doc.external, "https://bitwarden.com");
  assert.ok(!hits[0].snippet.includes("**") && !hits[0].snippet.includes("https://"), "snippets are plain text");
  assert.deepEqual(searchContent(docs, "END-TO-END").map((h) => h.doc.title), ["End-to-end encryption", "Back up your phone"]);
  assert.deepEqual(searchContent(docs, "x"), [], "two letters at least");
  assert.deepEqual(searchContent(docs, "password zebra"), []);
  assert.equal(plainText("- one\n- two\n\n```js\ncode()\n```\n[link](https://example.com)"), "one two link");
});
