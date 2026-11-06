import React, { forwardRef, useEffect, useImperativeHandle, useMemo, useRef, useState } from "react";
import { CornerUpLeft, Lock, Maximize2, Minimize2, Pencil, SendHorizontal, Smile, X } from "lucide-react";
import { progressText } from "./useStagedFiles";
import StagedStrip from "./StagedStrip";
import { MAX_MESSAGE_CHARS } from "@/lib/secure/protocol.js";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import EmojiPicker from "./EmojiPicker";

const TOKEN_RE = /(^|\s)([@#:])([\p{L}\p{N}_-]{0,32})$/u;

/**
 * Where you write. Enter sends, Shift+Enter starts a new line, Escape cancels a reply or edit.
 * Typing @ or # suggests people and channels; suggestions are worked out on this device.
 * "Typing…" is only shared if you turned it on in privacy settings (see PresenceContext).
 * staged (from useStagedFiles): files waiting to go with the next message. Paste or drop files
 * to add them; they're encrypted on this device when you send.
 */
const Composer = forwardRef(function Composer(
  { value, onChange, onSubmit, placeholder, disabledReason = "", replyTo = null, editing = false, onCancel, suggest, hint = null, sealed = true, tools = null, staged = null, customEmoji = [] },
  ref,
) {
  const input = useRef(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [caret, setCaret] = useState(0);
  const [pick, setPick] = useState(0);
  const [emojiOpen, setEmojiOpen] = useState(false);
  const insertEmoji = (e) => {
    const at = Math.min(caret || value.length, value.length);
    onChange(`${value.slice(0, at)}${e}${value.slice(at)}`);
    setCaret(at + e.length);
    setEmojiOpen(false);
    setTimeout(() => input.current?.focus(), 0);
  };
  const [dismissed, setDismissed] = useState(false);

  useImperativeHandle(ref, () => ({ focus: () => input.current?.focus() }), []);

  // Grow with the text: up to about half the window, or most of it when expanded for a long message.
  const [tall, setTall] = useState(false);
  useEffect(() => {
    const el = input.current;
    if (!el) return;
    const cap = Math.max(160, Math.round(window.innerHeight * (tall ? 0.7 : 0.45)));
    el.style.height = "auto";
    el.style.height = `${tall ? cap : Math.min(el.scrollHeight, cap)}px`;
    el.style.overflowY = el.scrollHeight > cap ? "auto" : "hidden";
  }, [value, tall]);
  const long = value.length > 280 || value.split("\n").length > 5;

  const token = useMemo(() => {
    const before = value.slice(0, caret);
    const m = before.match(TOKEN_RE);
    return m ? { kind: m[2], query: m[3], start: before.length - m[3].length - 1 } : null;
  }, [value, caret]);

  const suggestions = useMemo(() => (token && suggest && !dismissed ? suggest(token.kind, token.query).slice(0, 8) : []), [token, suggest, dismissed]);

  useEffect(() => {
    setPick(0);
  }, [token?.query, token?.kind]);

  const insert = (s) => {
    const before = value.slice(0, token.start);
    const after = value.slice(caret);
    const text = `${before}${s.insert} ${after.replace(/^\s/, "")}`;
    onChange(text);
    const pos = before.length + s.insert.length + 1;
    requestAnimationFrame(() => {
      input.current?.setSelectionRange(pos, pos);
      setCaret(pos);
    });
  };

  const files = !editing && staged ? staged.items : [];
  const canSend = Boolean(value.trim() || files.length);
  const [dragging, setDragging] = useState(false);
  const takeFiles = (list) => {
    if (!staged || editing || disabledReason || !list?.length) return false;
    staged.add(list);
    return true;
  };

  const submit = async (e) => {
    e?.preventDefault();
    if (!canSend || busy || disabledReason) return;
    setBusy(true);
    setError("");
    try {
      await onSubmit(value);
      setTall(false);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
      requestAnimationFrame(() => input.current?.focus());
    }
  };

  const onKeyDown = (e) => {
    if (suggestions.length) {
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        setPick((p) => (p + (e.key === "ArrowDown" ? 1 : suggestions.length - 1)) % suggestions.length);
        return;
      }
      if (e.key === "Enter" || e.key === "Tab") {
        e.preventDefault();
        insert(suggestions[pick]);
        return;
      }
      if (e.key === "Escape") {
        e.preventDefault();
        setDismissed(true);
        return;
      }
    }
    if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
      e.preventDefault();
      submit();
    } else if (e.key === "Escape" && (replyTo || editing)) {
      e.preventDefault();
      onCancel?.();
    }
  };

  return (
    <form
      onSubmit={submit}
      className="relative shrink-0 px-3 pb-4 sm:px-4"
      onDragOver={(e) => {
        if (!staged || editing || disabledReason || ![...(e.dataTransfer?.types || [])].includes("Files")) return;
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={(e) => !e.currentTarget.contains(e.relatedTarget) && setDragging(false)}
      onDrop={(e) => {
        setDragging(false);
        if (takeFiles(e.dataTransfer?.files)) e.preventDefault();
      }}
    >
      {dragging && (
        <div className="pointer-events-none absolute inset-x-3 bottom-4 top-0 z-30 flex items-center justify-center rounded-lg border-2 border-dashed border-primary bg-background/90 text-sm font-medium sm:inset-x-4">
          Drop to attach. Files are encrypted before they leave this device.
        </div>
      )}
      {suggestions.length > 0 && (
        <ul role="listbox" aria-label={token.kind === "@" ? "People" : token.kind === ":" ? "Emoji" : "Channels"} className="absolute bottom-full left-3 right-3 z-20 mb-1 max-h-64 overflow-y-auto rounded-lg border border-border bg-popover p-1 shadow-lg sm:left-4 sm:right-4">
          {suggestions.map((s, i) => (
            <li key={s.id} role="option" aria-selected={i === pick}>
              <button
                type="button"
                onMouseDown={(e) => {
                  e.preventDefault();
                  insert(s);
                }}
                onMouseEnter={() => setPick(i)}
                className={`flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm ${i === pick ? "bg-muted" : ""}`}
              >
                {s.icon}
                <span className="truncate font-medium">{s.label}</span>
                {s.sub && <span className="truncate text-xs text-muted-foreground">{s.sub}</span>}
              </button>
            </li>
          ))}
        </ul>
      )}
      {error && <p className="mb-1.5 text-sm text-destructive" role="alert">{error}</p>}
      {staged?.notice && <p className="mb-1.5 text-sm text-destructive" role="alert">{staged.notice}</p>}
      <div className="rounded-lg bg-[hsl(var(--panel-hover)/0.7)] focus-within:ring-2 focus-within:ring-ring/40">
        {(replyTo || editing) && (
          <div className="flex items-center gap-2 border-b border-border/60 px-3 py-1.5 text-sm">
            {editing ? <Pencil className="h-3.5 w-3.5 text-primary" aria-hidden="true" /> : <CornerUpLeft className="h-3.5 w-3.5 text-primary" aria-hidden="true" />}
            <span className="min-w-0 flex-1 truncate text-muted-foreground">
              {editing ? "Editing your message. Everyone will see it was edited." : <>Replying to <span className="font-semibold text-foreground">{replyTo.name}</span></>}
            </span>
            <button type="button" onClick={onCancel} className="rounded p-0.5 text-muted-foreground hover:bg-muted" aria-label={editing ? "Cancel editing" : "Cancel reply"}>
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
        )}
        <StagedStrip staged={staged} items={files} busy={busy} className="border-b border-border/60 px-3 py-2" />
        <div className="flex items-end gap-2 px-3 py-2">
          {tools}
          {sealed && !tools && <Lock className="mb-2 h-4 w-4 shrink-0 text-primary/70" aria-hidden="true" />}
          <textarea
            ref={input}
            value={value}
            onChange={(e) => {
              onChange(e.target.value);
              setCaret(e.target.selectionStart);
              setDismissed(false);
            }}
            onSelect={(e) => setCaret(e.target.selectionStart)}
            onKeyDown={onKeyDown}
            onPaste={(e) => {
              if (e.clipboardData?.files?.length && takeFiles(e.clipboardData.files)) e.preventDefault();
            }}
            rows={1}
            maxLength={MAX_MESSAGE_CHARS}
            placeholder={disabledReason || placeholder}
            disabled={Boolean(disabledReason)}
            aria-label={placeholder}
            className="min-h-[1.75rem] flex-1 resize-none bg-transparent py-1 text-[0.95rem] leading-relaxed outline-none placeholder:text-muted-foreground disabled:cursor-not-allowed"
          />
          {(long || tall) && !disabledReason && (
            <button
              type="button"
              onClick={() => { setTall((v) => !v); input.current?.focus(); }}
              className="mb-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
              aria-label={tall ? "Make the message box smaller" : "Make the message box bigger"}
              aria-pressed={tall}
            >
              {tall ? <Minimize2 className="h-4 w-4" aria-hidden="true" /> : <Maximize2 className="h-4 w-4" aria-hidden="true" />}
            </button>
          )}
          {!editing && !disabledReason && (
            <Popover open={emojiOpen} onOpenChange={setEmojiOpen}>
              <PopoverTrigger asChild>
                <button type="button" className="mb-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted hover:text-foreground" aria-label="Add an emoji">
                  <Smile className="h-5 w-5" aria-hidden="true" />
                </button>
              </PopoverTrigger>
              <PopoverContent align="end" side="top" className="w-auto p-0">
                <EmojiPicker onPick={insertEmoji} label="Add an emoji" custom={customEmoji} onPickCustom={customEmoji.length ? (x) => insertEmoji(`<:${x.name}:${x.id}>`) : null} />
              </PopoverContent>
            </Popover>
          )}
          <button
            type="submit"
            disabled={!canSend || busy || Boolean(disabledReason)}
            className="mb-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-primary transition-colors hover:bg-primary/10 disabled:text-muted-foreground disabled:hover:bg-transparent"
            aria-label={editing ? "Save edit" : "Send"}
          >
            <SendHorizontal className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>
      </div>
      <div className="mt-1 flex min-h-[1rem] items-center justify-between gap-2 px-1 text-xs text-muted-foreground">
        <span>{progressText(staged?.progress) || hint}</span>
        {value.length > MAX_MESSAGE_CHARS - 300 && <span>{MAX_MESSAGE_CHARS - value.length} characters left</span>}
      </div>
    </form>
  );
});

export default Composer;
