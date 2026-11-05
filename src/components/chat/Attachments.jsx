import React, { useEffect, useRef, useState } from "react";
import { Download, EyeOff, FileText, Loader2, Lock, Pause, Play, RotateCw } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { previewKind, sizeLabel } from "@/lib/secure/attachments.js";
import { openAttachment, saveAttachment } from "@/lib/secure/fileTransfer.js";

/** Decrypt an attachment once it's on screen (or straight away when asked). */
function useOpened(meta, { auto = true } = {}) {
  const box = useRef(null);
  const [state, setState] = useState({ status: "idle", url: null, error: "" });
  const start = () => {
    setState({ status: "loading", url: null, error: "" });
    openAttachment(meta)
      .then((o) => setState({ status: "ready", url: o.url, error: "" }))
      .catch((err) => setState({ status: "error", url: null, error: err.message || "This file couldn't be opened." }));
  };
  useEffect(() => {
    if (!auto || state.status !== "idle") return undefined;
    const el = box.current;
    if (!el || typeof IntersectionObserver !== "function") {
      start();
      return undefined;
    }
    const io = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) {
        io.disconnect();
        start();
      }
    }, { rootMargin: "200px" });
    io.observe(el);
    return () => io.disconnect();
     
  }, [auto, meta.ids[0]]);
  return { box, ...state, start };
}

function Spoiler({ children, hidden, onShow }) {
  if (!hidden) return children;
  return (
    <div className="relative overflow-hidden rounded-lg">
      <div className="pointer-events-none select-none blur-2xl" aria-hidden="true">{children}</div>
      <button type="button" onClick={onShow} className="absolute inset-0 flex items-center justify-center gap-1.5 bg-black/40 text-sm font-semibold text-white">
        <EyeOff className="h-4 w-4" aria-hidden="true" /> Spoiler
      </button>
    </div>
  );
}

function Failed({ error, onRetry, meta }) {
  return (
    <div className="flex items-center gap-2 rounded-lg border border-border bg-muted/40 px-3 py-2 text-sm">
      <span className="min-w-0 flex-1 truncate text-muted-foreground">{meta.name}: {error}</span>
      <button type="button" onClick={onRetry} className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground" aria-label={`Try ${meta.name} again`}>
        <RotateCw className="h-4 w-4" aria-hidden="true" />
      </button>
    </div>
  );
}

function ImageAttachment({ meta, single }) {
  const o = useOpened(meta);
  const [zoom, setZoom] = useState(false);
  const [broken, setBroken] = useState(false);
  const [shown, setShown] = useState(!meta.spoiler);
  const ratio = meta.w && meta.h ? meta.w / meta.h : 4 / 3;
  const maxW = single ? 400 : 260;
  const width = Math.min(maxW, (single ? 320 : 200) * ratio, meta.w || maxW);
  if (o.status === "error") return <Failed error={o.error} onRetry={o.start} meta={meta} />;
  if (broken) return <FileAttachment meta={meta} note="This image can't be shown here." />;
  return (
    <div ref={o.box} style={{ width: `${Math.max(120, width)}px`, aspectRatio: `${ratio}` }} className="relative max-w-full overflow-hidden rounded-lg bg-muted">
      {o.status !== "ready" && (
        <span className="absolute inset-0 flex items-center justify-center gap-1.5 text-xs text-muted-foreground">
          <Lock className="h-3.5 w-3.5" aria-hidden="true" /> Decrypting…
        </span>
      )}
      {o.url && (
        <Spoiler hidden={!shown} onShow={() => setShown(true)}>
          <button type="button" onClick={() => setZoom(true)} className="block h-full w-full" aria-label={`Open ${meta.name}`}>
            <img src={o.url} alt={meta.name} onError={() => setBroken(true)} className="h-full w-full object-cover" draggable={false} />
          </button>
        </Spoiler>
      )}
      <Dialog open={zoom} onOpenChange={setZoom}>
        <DialogContent className="max-w-[min(92vw,1100px)] gap-2 p-2">
          <DialogTitle className="sr-only">{meta.name}</DialogTitle>
          <DialogDescription className="sr-only">Image, decrypted on this device.</DialogDescription>
          {o.url && <img src={o.url} alt={meta.name} className="max-h-[80dvh] w-full rounded object-contain" />}
          <div className="flex items-center justify-between gap-2 px-1 text-sm">
            <span className="truncate text-muted-foreground">{meta.name} ({sizeLabel(meta.size)})</span>
            <button type="button" onClick={() => saveAttachment(meta)} className="flex items-center gap-1 rounded px-2 py-1 font-medium hover:bg-muted">
              <Download className="h-4 w-4" aria-hidden="true" /> Download
            </button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function VideoAttachment({ meta }) {
  const o = useOpened(meta, { auto: false });
  const [shown, setShown] = useState(!meta.spoiler);
  if (o.status === "error") return <Failed error={o.error} onRetry={o.start} meta={meta} />;
  if (o.status !== "ready") {
    return (
      <Spoiler hidden={!shown} onShow={() => setShown(true)}>
        <button type="button" onClick={o.start} disabled={o.status === "loading"} className="flex aspect-video w-[min(100%,400px)] flex-col items-center justify-center gap-1 rounded-lg bg-muted text-sm text-muted-foreground hover:bg-muted/70">
          {o.status === "loading" ? <Loader2 className="h-6 w-6 animate-spin" aria-hidden="true" /> : <Play className="h-8 w-8" aria-hidden="true" />}
          <span>{o.status === "loading" ? "Decrypting…" : `${meta.name} (${sizeLabel(meta.size)})`}</span>
        </button>
      </Spoiler>
    );
  }
  return <video src={o.url} controls autoPlay playsInline className="max-h-80 w-[min(100%,400px)] rounded-lg bg-black" aria-label={meta.name} />;
}

const clock = (s) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`;

/** A voice message: play, pause and seek. */
export function VoicePlayer({ meta }) {
  const o = useOpened(meta);
  const audio = useRef(null);
  const [playing, setPlaying] = useState(false);
  const [at, setAt] = useState(0);
  const [length, setLength] = useState(meta.duration || 0);
  if (o.status === "error") return <Failed error={o.error} onRetry={o.start} meta={meta} />;
  const toggle = () => {
    const a = audio.current;
    if (!a) return;
    if (a.paused) a.play().catch(() => {});
    else a.pause();
  };
  return (
    <div ref={o.box} className="flex w-[min(100%,320px)] items-center gap-3 rounded-full border border-border bg-muted/40 py-1.5 pl-1.5 pr-4">
      <button type="button" onClick={toggle} disabled={o.status !== "ready"} className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-primary text-primary-foreground disabled:opacity-60" aria-label={playing ? "Pause voice message" : "Play voice message"}>
        {o.status !== "ready" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : playing ? <Pause className="h-4 w-4" aria-hidden="true" /> : <Play className="h-4 w-4" aria-hidden="true" />}
      </button>
      <input
        type="range"
        min={0}
        max={length || 1}
        step={0.1}
        value={at}
        disabled={o.status !== "ready"}
        onChange={(e) => {
          if (audio.current) audio.current.currentTime = Number(e.target.value);
          setAt(Number(e.target.value));
        }}
        className="h-1 min-w-0 flex-1 accent-[hsl(var(--primary))]"
        aria-label="Position in voice message"
      />
      <span className="w-10 shrink-0 text-right text-xs tabular-nums text-muted-foreground">{clock(playing || at ? at : length)}</span>
      {o.url && (
        <audio
          ref={audio}
          src={o.url}
          preload="metadata"
          onPlay={() => setPlaying(true)}
          onPause={() => setPlaying(false)}
          onEnded={() => { setPlaying(false); setAt(0); }}
          onTimeUpdate={(e) => setAt(e.currentTarget.currentTime)}
          onLoadedMetadata={(e) => Number.isFinite(e.currentTarget.duration) && setLength(e.currentTarget.duration)}
        />
      )}
    </div>
  );
}

function AudioAttachment({ meta }) {
  const o = useOpened(meta, { auto: false });
  if (o.status === "error") return <Failed error={o.error} onRetry={o.start} meta={meta} />;
  if (o.status === "ready") return <audio src={o.url} controls autoPlay className="w-[min(100%,360px)]" aria-label={meta.name} />;
  return <FileAttachment meta={meta} onOpen={o.start} openLabel={o.status === "loading" ? "Decrypting…" : "Play"} />;
}

function FileAttachment({ meta, note = "", onOpen = null, openLabel = "" }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const save = async () => {
    setBusy(true);
    setError("");
    try {
      await saveAttachment(meta);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="flex w-[min(100%,380px)] items-center gap-3 rounded-lg border border-border bg-muted/30 px-3 py-2.5">
      <FileText className="h-8 w-8 shrink-0 text-primary/80" aria-hidden="true" />
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium">{meta.name}</p>
        <p className="truncate text-xs text-muted-foreground">{error || note || sizeLabel(meta.size)}</p>
      </div>
      {onOpen && (
        <button type="button" onClick={onOpen} className="rounded px-2 py-1 text-sm font-medium hover:bg-muted" aria-label={`${openLabel} ${meta.name}`}>{openLabel}</button>
      )}
      <button type="button" onClick={save} disabled={busy} className="rounded p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground disabled:opacity-60" aria-label={`Download ${meta.name}`}>
        {busy ? <Loader2 className="h-5 w-5 animate-spin" aria-hidden="true" /> : <Download className="h-5 w-5" aria-hidden="true" />}
      </button>
    </div>
  );
}

/** A message's attachments, each decrypted on this device. */
export default function AttachmentList({ attachments }) {
  if (!attachments?.length) return null;
  const images = attachments.filter((a) => previewKind(a.type) === "image" && !a.voice);
  const rest = attachments.filter((a) => !images.includes(a));
  return (
    <div className="mt-1 flex flex-col gap-1.5">
      {images.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {images.map((a) => <ImageAttachment key={a.ids[0]} meta={a} single={images.length === 1} />)}
        </div>
      )}
      {rest.map((a) => {
        if (a.voice) return <VoicePlayer key={a.ids[0]} meta={a} />;
        const kind = previewKind(a.type);
        if (kind === "video") return <VideoAttachment key={a.ids[0]} meta={a} />;
        if (kind === "audio") return <AudioAttachment key={a.ids[0]} meta={a} />;
        return <FileAttachment key={a.ids[0]} meta={a} />;
      })}
    </div>
  );
}
