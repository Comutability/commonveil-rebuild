// Asking for a file's download links: the request names where the file was posted, so it reaches
// the site that holds it, and that site's answer is only trusted for what was asked.
import test from "node:test";
import assert from "node:assert/strict";
import { register } from "node:module";

register("./support/apiStubLoader.mjs", import.meta.url);
const { ApiError } = await import("./support/apiStub.mjs");
const { clearLinks, forwardedCopy, linksFor } = await import("../src/lib/secure/fileTransfer.js");

const C = "c".repeat(24);
const S = "s".repeat(24);
const H = "h".repeat(24);

/** Answer the next calls with reply(body); returns the bodies sent. */
function server(reply) {
  const sent = [];
  globalThis.__commonveilCallFn = async (fn, body) => {
    assert.equal(fn, "files");
    sent.push(body);
    return reply(body);
  };
  return sent;
}

test("the request names the place, and only its ids", async () => {
  clearLinks();
  const sent = server((b) => ({ links: Object.fromEntries(b.file_ids.map((id) => [id, `/api/files/${id}`])) }));
  const place = { server_id: S, channel_id: H, conversation_id: 5, note: "not an id" };
  assert.deepEqual(await linksFor(["p1", "p2"], place), ["/api/files/p1", "/api/files/p2"]);
  assert.deepEqual(sent, [{ action: "download_links", file_ids: ["p1", "p2"], server_id: S, channel_id: H }]);
  assert.deepEqual(await linksFor(["p1"], place), ["/api/files/p1"], "asked once, then kept a while");
  assert.equal(sent.length, 1);
});

test("links are kept only for the ids asked for, and only for the place asked about", async () => {
  clearLinks();
  // A site answering about its own conversation adds a link for a file posted elsewhere.
  const sent = server((b) => ({ links: { elsewhere1: "/planted", ...Object.fromEntries(b.file_ids.map((id) => [id, `/from-answer/${id}`])) } }));
  await linksFor(["mine1"], { conversation_id: C });
  assert.deepEqual(await linksFor(["elsewhere1"], { server_id: S, channel_id: H }), ["/from-answer/elsewhere1"], "the planted link wasn't kept");
  assert.equal(sent.length, 2);
  // The same part ids named under another place are asked about again, not taken from the first answer.
  assert.deepEqual(await linksFor(["mine1"], { server_id: S, channel_id: H }), ["/from-answer/mine1"]);
  assert.equal(sent.length, 3);
  assert.deepEqual(sent[2], { action: "download_links", file_ids: ["mine1"], server_id: S, channel_id: H });
});

test("a missing link is null, and a site that doesn't share files says so plainly", async () => {
  clearLinks();
  server(() => ({ links: {} }));
  assert.deepEqual(await linksFor(["gone"], { conversation_id: C }), [null]);
  server(() => {
    throw new ApiError(404, "NOT_FOUND", "That isn't something another site can ask for here.");
  });
  await assert.rejects(linksFor(["far"], { conversation_id: C }), /doesn't share files with other sites yet/);
  server(() => {
    throw new ApiError(403, "FORBIDDEN", "Not allowed.");
  });
  await assert.rejects(linksFor(["far"], { conversation_id: C }), { status: 403 }, "other errors go through as they are");
});

test("a forwarded copy leaves where the original was posted behind", () => {
  const original = { name: "a.txt", size: 3, key: "k", ivp: "i", ids: ["old"], place: { conversation_id: C } };
  assert.deepEqual(forwardedCopy(original, ["new"]), { name: "a.txt", size: 3, key: "k", ivp: "i", ids: ["new"] });
  assert.deepEqual(original.place, { conversation_id: C }, "the original is left as it was");
});
