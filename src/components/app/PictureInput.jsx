import React, { useRef, useState } from "react";
import { ImagePlus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";

// The picture is kept inline with the profile, and a stored field holds at most 20,000
// characters: stay under that or the whole profile can't be saved.
const MAX_CHARS = 18_000;
// Biggest first: the best-looking version that still fits.
const ATTEMPTS = [
  [160, "image/webp", 0.8],
  [160, "image/webp", 0.6],
  [128, "image/webp", 0.6],
  [128, "image/webp", 0.45],
  [96, "image/webp", 0.5],
  [96, "image/jpeg", 0.6],
];

/**
 * Make a small square profile picture on this device: cropped to the middle, WebP
 * (JPEG where the browser can't make WebP), shrunk until it fits. Nothing leaves the device
 * until you save.
 */
async function toPicture(file) {
  if (!/^image\//.test(file.type)) throw new Error("Choose an image file.");
  if (file.size > 20 * 1024 * 1024) throw new Error("That image is too large.");
  const bitmap = await createImageBitmap(file);
  const side = Math.min(bitmap.width, bitmap.height);
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d");
  for (const [size, type, q] of ATTEMPTS) {
    canvas.width = size;
    canvas.height = size;
    ctx.imageSmoothingQuality = "high";
    ctx.clearRect(0, 0, size, size);
    ctx.drawImage(bitmap, (bitmap.width - side) / 2, (bitmap.height - side) / 2, side, side, 0, 0, size, size);
    const url = canvas.toDataURL(type, q);
    if (url.startsWith(`data:${type}`) && url.length <= MAX_CHARS) {
      bitmap.close?.();
      return url;
    }
  }
  bitmap.close?.();
  throw new Error("That image couldn't be made small enough. Try another one.");
}

/** Choose, change or remove a profile picture. value: a data: URL or "". */
export default function PictureInput({ value, onChange, disabled }) {
  const picker = useRef(null);
  const [error, setError] = useState("");
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-3">
        {value ? <img src={value} alt="Your profile picture" className="h-16 w-16 rounded-full object-cover" /> : null}
        <input
          ref={picker}
          type="file"
          accept="image/png,image/jpeg,image/webp,image/gif,image/heic"
          className="sr-only"
          tabIndex={-1}
          aria-label="Choose a picture"
          onChange={async (e) => {
            const file = e.target.files?.[0];
            e.target.value = "";
            if (!file) return;
            setError("");
            try {
              onChange(await toPicture(file));
            } catch (err) {
              setError(err.message);
            }
          }}
        />
        <Button type="button" variant="outline" size="sm" disabled={disabled} onClick={() => picker.current?.click()}>
          <ImagePlus className="mr-2 h-4 w-4" aria-hidden="true" /> {value ? "Change picture" : "Add a picture"}
        </Button>
        {value && (
          <Button type="button" variant="ghost" size="sm" disabled={disabled} onClick={() => onChange("")}>
            <Trash2 className="mr-2 h-4 w-4" aria-hidden="true" /> Remove
          </Button>
        )}
      </div>
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}