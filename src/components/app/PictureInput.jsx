import React, { useRef, useState } from "react";
import { ImagePlus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";

const SIZE = 160;
const MAX_CHARS = 46_000;

/**
 * Make a small square profile picture on this device: cropped to the middle, 160 by 160, WebP
 * (JPEG where the browser can't make WebP). Nothing leaves the device until you save.
 */
async function toPicture(file) {
  if (!/^image\//.test(file.type)) throw new Error("Choose an image file.");
  if (file.size > 20 * 1024 * 1024) throw new Error("That image is too large.");
  const bitmap = await createImageBitmap(file);
  const side = Math.min(bitmap.width, bitmap.height);
  const canvas = document.createElement("canvas");
  canvas.width = SIZE;
  canvas.height = SIZE;
  const ctx = canvas.getContext("2d");
  ctx.imageSmoothingQuality = "high";
  ctx.drawImage(bitmap, (bitmap.width - side) / 2, (bitmap.height - side) / 2, side, side, 0, 0, SIZE, SIZE);
  bitmap.close?.();
  for (const [type, q] of [["image/webp", 0.85], ["image/webp", 0.7], ["image/jpeg", 0.8], ["image/jpeg", 0.6]]) {
    const url = canvas.toDataURL(type, q);
    if (url.startsWith(`data:${type}`) && url.length <= MAX_CHARS) return url;
  }
  throw new Error("That image couldn't be made small enough.");
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
