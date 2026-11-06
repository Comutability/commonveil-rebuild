// A server's picture and banner. They're shrunk here, on the device that uploads them, and then
// travel inside one encrypted server item: the service stores the envelope without seeing the
// picture, only members' apps can open it, and showing one never fetches an image from anywhere.
//
// A stored field holds about 20,000 characters and an envelope costs about a third more than its
// contents, so each picture gets its own item with the budget below.

export const PICTURE_LIMITS = Object.freeze({
  icon: { width: 256, height: 256, maxChars: 5000 },
  banner: { width: 800, height: 200, maxChars: 13000 },
});

const IMG_RE = /^data:image\/(webp|png);base64,[A-Za-z0-9+/]+=*$/;

/** The picture inside a decrypted item, or null (a picture that isn't one is dropped). */
export function cleanPicture(kind, payload) {
  const max = PICTURE_LIMITS[kind]?.maxChars || 0;
  const img = typeof payload?.img === "string" ? payload.img : "";
  if (!img || img.length > max || !IMG_RE.test(img)) return null;
  return { img };
}

function shrinkToFit(canvas, maxChars) {
  for (let quality = 0.82; quality >= 0.3; quality -= 0.08) {
    const url = canvas.toDataURL("image/webp", quality);
    if (url.startsWith("data:image/webp") && url.length <= maxChars) return url;
  }
  return "";
}

/**
 * Shrink a picture to its slot's size (cropped to fill it, centred) and to a size that fits the
 * item, lowering quality until it does. Done on this device: the original never leaves it.
 */
export async function shrinkPicture(file, kind) {
  const lim = PICTURE_LIMITS[kind];
  if (!lim) throw new Error("Unknown picture.");
  if (!/^image\/(png|jpeg|webp)$/.test(file.type)) throw new Error("Use a PNG, JPEG or WebP picture.");
  if (file.size > 8 * 1024 * 1024) throw new Error("That picture is over 8 MB.");
  let bmp;
  try {
    bmp = await createImageBitmap(file);
  } catch {
    throw new Error("That picture couldn't be read.");
  }
  const canvas = document.createElement("canvas");
  canvas.width = lim.width;
  canvas.height = lim.height;
  const g = canvas.getContext("2d");
  const scale = Math.max(lim.width / bmp.width, lim.height / bmp.height);
  const w = bmp.width * scale;
  const h = bmp.height * scale;
  g.drawImage(bmp, (lim.width - w) / 2, (lim.height - h) / 2, w, h);
  bmp.close?.();
  const url = shrinkToFit(canvas, lim.maxChars);
  if (!url) throw new Error("That picture is too detailed to shrink. Try a simpler one.");
  return url;
}