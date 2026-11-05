import React, { useEffect, useRef, useState } from "react";
import { Loader2, Mic, Square, Trash2 } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";

const MAX_SECONDS = 600;
const clock = (s) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`;

function pickType() {
  if (typeof MediaRecorder === "undefined") return null;
  for (const t of ["audio/webm;codecs=opus", "audio/ogg;codecs=opus", "audio/mp4", "audio/webm"]) {
    if (MediaRecorder.isTypeSupported?.(t)) return t;
  }
  return "";
}

/**
 * Record a voice message. The recording stays in this tab's memory until you send it; then it's
 * encrypted like any other file. onSend(file, seconds) does the sending.
 */
export default function VoiceRecorder({ open, onOpenChange, onSend }) {
  const [phase, setPhase] = useState("idle"); // idle | recording | done | sending
  const [seconds, setSeconds] = useState(0);
  const [error, setError] = useState("");
  const [clip, setClip] = useState(null); // { file, url, seconds }
  const rec = useRef(null);
  const stream = useRef(null);
  const timer = useRef(null);
  const started = useRef(0);

  const stopAll = () => {
    clearInterval(timer.current);
    stream.current?.getTracks().forEach((t) => t.stop());
    stream.current = null;
  };

  const reset = () => {
    stopAll();
    if (rec.current && rec.current.state !== "inactive") {
      rec.current.onstop = null;
      rec.current.stop();
    }
    rec.current = null;
    setClip((c) => {
      if (c?.url) URL.revokeObjectURL(c.url);
      return null;
    });
    setPhase("idle");
    setSeconds(0);
    setError("");
  };

  useEffect(() => {
    if (!open) reset();
     
  }, [open]);
  useEffect(() => () => reset(), []);  

  const start = async () => {
    setError("");
    const type = pickType();
    if (type === null || !navigator.mediaDevices?.getUserMedia) {
      setError("This browser can't record audio.");
      return;
    }
    try {
      stream.current = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true } });
    } catch {
      setError("Commonveil couldn't use your microphone. Check your browser's permission for this site.");
      return;
    }
    const chunks = [];
    const r = new MediaRecorder(stream.current, { ...(type ? { mimeType: type } : {}), audioBitsPerSecond: 32_000 });
    r.ondataavailable = (e) => e.data.size && chunks.push(e.data);
    r.onstop = () => {
      stopAll();
      const secs = Math.max(1, Math.round((Date.now() - started.current) / 1000));
      const mime = (r.mimeType || type || "audio/webm").split(";")[0];
      const ext = mime.includes("mp4") ? "m4a" : mime.includes("ogg") ? "ogg" : "webm";
      const file = new File(chunks, `Voice message.${ext}`, { type: mime });
      setClip({ file, url: URL.createObjectURL(file), seconds: secs });
      setPhase("done");
    };
    rec.current = r;
    started.current = Date.now();
    r.start(1000);
    setPhase("recording");
    setSeconds(0);
    timer.current = setInterval(() => {
      const s = Math.floor((Date.now() - started.current) / 1000);
      setSeconds(s);
      if (s >= MAX_SECONDS) r.stop();
    }, 250);
  };

  const stop = () => rec.current?.state === "recording" && rec.current.stop();

  const send = async () => {
    if (!clip) return;
    setPhase("sending");
    setError("");
    try {
      await onSend(clip.file, clip.seconds);
      onOpenChange(false);
    } catch (err) {
      setError(err.message);
      setPhase("done");
    }
  };

  return (
    <Dialog open={open} onOpenChange={(v) => phase !== "sending" && onOpenChange(v)}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>Voice message</DialogTitle>
          <DialogDescription>Recorded on this device and encrypted before it's sent. Up to 10 minutes.</DialogDescription>
        </DialogHeader>
        <div className="flex flex-col items-center gap-4 py-2">
          {phase === "done" || phase === "sending" ? (
            <audio src={clip?.url} controls className="w-full" aria-label="Your recording" />
          ) : (
            <button
              type="button"
              onClick={phase === "recording" ? stop : start}
              className={`flex h-20 w-20 items-center justify-center rounded-full text-white transition-colors ${phase === "recording" ? "bg-destructive" : "bg-primary hover:bg-primary/90"}`}
              aria-label={phase === "recording" ? "Stop recording" : "Start recording"}
            >
              {phase === "recording" ? <Square className="h-7 w-7" aria-hidden="true" /> : <Mic className="h-8 w-8" aria-hidden="true" />}
            </button>
          )}
          <p className="text-2xl font-semibold tabular-nums" aria-live="polite">
            {phase === "recording" && <span className="mr-2 inline-block h-2.5 w-2.5 animate-pulse rounded-full bg-destructive align-middle" aria-hidden="true" />}
            {clock(phase === "done" || phase === "sending" ? clip?.seconds || 0 : seconds)}
          </p>
          {phase === "idle" && <p className="text-sm text-muted-foreground">Press the microphone to start.</p>}
          {error && <p className="text-center text-sm text-destructive" role="alert">{error}</p>}
        </div>
        {(phase === "done" || phase === "sending") && (
          <div className="flex justify-between gap-2">
            <Button variant="ghost" onClick={reset} disabled={phase === "sending"}><Trash2 className="mr-1.5 h-4 w-4" aria-hidden="true" /> Discard</Button>
            <Button onClick={send} disabled={phase === "sending"}>
              {phase === "sending" ? <><Loader2 className="mr-1.5 h-4 w-4 animate-spin" aria-hidden="true" /> Sending…</> : "Send"}
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
