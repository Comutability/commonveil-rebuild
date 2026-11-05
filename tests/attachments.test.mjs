import test from "node:test";
import assert from "node:assert/strict";
import { cleanAttachment, openFile, PART_PLAIN, previewKind, sealFile } from "../src/lib/secure/attachments.js";

const fileOf = (bytes, name = "a.bin", type = "application/octet-stream") => new File([bytes], name, { type });

test("a file seals into parts and opens back to the same bytes", async () => {
  const bytes = crypto.getRandomValues(new Uint8Array(PART_PLAIN + 1234));
  const { meta, parts } = await sealFile(fileOf(bytes));
  assert.equal(parts.length, 2);
  assert.equal(meta.parts, 2);
  const blob = await openFile(meta, parts);
  assert.deepEqual(new Uint8Array(await blob.arrayBuffer()), bytes);
  assert.equal(blob.type, "application/octet-stream");
});

test("swapped, altered or missing parts are refused", async () => {
  const bytes = crypto.getRandomValues(new Uint8Array(PART_PLAIN * 2 + 10));
  const { meta, parts } = await sealFile(fileOf(bytes));
  await assert.rejects(openFile(meta, [parts[1], parts[0], parts[2]]), /integrity/);
  await assert.rejects(openFile(meta, parts.slice(0, 2)), /missing/);
  const bad = parts.map((p) => p.slice());
  bad[2][5] ^= 1;
  await assert.rejects(openFile(meta, bad), /integrity/);
  await assert.rejects(openFile({ ...meta, size: meta.size - 1 }, parts), /integrity/);
});

test("only plain image, video and audio types get previews", () => {
  assert.equal(previewKind("image/png"), "image");
  assert.equal(previewKind("image/svg+xml"), "file");
  assert.equal(previewKind("text/html"), "file");
  assert.equal(previewKind("video/mp4"), "video");
  assert.equal(previewKind("audio/webm"), "audio");
});

test("attachments from messages are checked field by field", async () => {
  const { meta } = await sealFile(fileOf(new Uint8Array([1, 2, 3]), "../../evil\n.txt"));
  const good = cleanAttachment({ ...meta, ids: ["abc"] });
  assert.ok(good);
  assert.equal(good.name.includes("/"), false);
  assert.equal(cleanAttachment({ ...meta, ids: [] }), null);
  assert.equal(cleanAttachment({ ...meta, ids: ["abc"], parts: 2 }), null);
  assert.equal(cleanAttachment({ ...meta, ids: ["a b"] }), null);
  assert.equal(cleanAttachment({ ...meta, ids: ["abc"], size: 11 * 1024 * 1024 }), null);
  assert.equal(cleanAttachment({ ...meta, ids: ["abc"], extra: "x" }).extra, undefined);
});
