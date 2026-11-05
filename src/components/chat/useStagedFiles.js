import { useCallback, useEffect, useRef, useState } from "react";
import { MAX_ATTACHMENTS, MAX_FILE_BYTES, previewKind } from "@/lib/secure/attachments.js";

/**
 * Files picked for the next message, kept only in memory until it's sent. Image previews are
 * local blob URLs: nothing is uploaded until you press send.
 */
export function useStagedFiles() {
  const [items, setItems] = useState([]);
  const [notice, setNotice] = useState("");
  const [progress, setProgress] = useState(null); // { done, total } while uploading
  const ref = useRef(items);
  ref.current = items;

  useEffect(() => () => ref.current.forEach((it) => it.preview && URL.revokeObjectURL(it.preview)), []);

  const add = useCallback((fileList, extra = {}) => {
    const files = [...(fileList || [])];
    if (!files.length) return;
    const room = MAX_ATTACHMENTS - ref.current.length;
    const tooBig = files.filter((f) => f.size > MAX_FILE_BYTES);
    const empty = files.filter((f) => f.size === 0);
    const ok = files.filter((f) => f.size > 0 && f.size <= MAX_FILE_BYTES).slice(0, Math.max(0, room));
    const notes = [];
    if (tooBig.length) notes.push(tooBig.length === 1 ? `${tooBig[0].name} is over 10 MB.` : `${tooBig.length} files are over 10 MB.`);
    if (empty.length) notes.push(empty.length === 1 ? `${empty[0].name || "That file"} is empty.` : `${empty.length} files are empty.`);
    if (files.length - tooBig.length - empty.length > ok.length) notes.push(`You can attach up to ${MAX_ATTACHMENTS} files to one message.`);
    setNotice(notes.join(" "));
    setItems((cur) => [
      ...cur,
      ...ok.map((file) => ({
        key: crypto.randomUUID(),
        file,
        spoiler: false,
        ...extra,
        preview: previewKind(file.type) === "image" ? URL.createObjectURL(file) : null,
      })),
    ]);
  }, []);

  const remove = useCallback((key) => {
    setItems((cur) => {
      const gone = cur.find((it) => it.key === key);
      if (gone?.preview) URL.revokeObjectURL(gone.preview);
      return cur.filter((it) => it.key !== key);
    });
  }, []);

  const toggleSpoiler = useCallback((key) => setItems((cur) => cur.map((it) => (it.key === key ? { ...it, spoiler: !it.spoiler } : it))), []);

  const clear = useCallback(() => {
    ref.current.forEach((it) => it.preview && URL.revokeObjectURL(it.preview));
    setItems([]);
    setNotice("");
    setProgress(null);
  }, []);

  const onProgress = useCallback((done, total) => setProgress({ done, total }), []);

  return { items, add, remove, toggleSpoiler, clear, notice, setNotice, progress, setProgress, onProgress };
}

export const progressText = (p) => (p && p.total ? `Encrypting and uploading… ${Math.round((p.done / p.total) * 100)}%` : null);
