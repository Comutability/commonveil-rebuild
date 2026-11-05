// Voice: the call you're in, if any. Nothing here touches the microphone or the network until
// you join a call.
//
// How a call works:
// - The voice function checks you may join and hands this device a one-minute pass.
// - The VoiceRoom actor admits you with it and passes connection set-up between devices.
// - Each pair of devices connects directly (WebRTC, so DTLS-SRTP encrypts the media).
// - Before connecting, each device checks the other's signed offer against that device's
//   certificate for the member's account, and that the connection really uses the signed
//   certificate fingerprint, so the relay can't sit in the middle.
// - Every audio frame is also sealed with a key derived from the channel's key chain
//   (post-quantum protected), see frames.js. Frames that don't open are dropped.
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { base44 } from "@/api/base44Client";
import { callFn } from "@/lib/api";
import { useSecure } from "@/lib/secure/SecureContext";
import { useServers } from "@/lib/secure/ServerContext";
import * as SP from "@/lib/secure/serverProtocol";
import { randomId, utf8 } from "@/lib/crypto/encoding";
import { hkdfAesKey } from "@/lib/crypto/primitives";
import { epochId, frameTransform } from "./frames";
import { signHello, verifyHello, fingerprintOf } from "./hello";
// Bundled as its own script (with frames.js inside), served from this site.
import frameWorkerUrl from "./frameWorker.js?worker&url";

// A STUN server tells each device its public address so devices on different networks can
// reach each other. It sees that address, never the call. There's no relay (TURN) server, so
// some strict networks can't connect.
const ICE_SERVERS = [{ urls: "stun:stun.cloudflare.com:3478" }];
const SPEAKING_LEVEL = 0.04;
const EPOCH_CHECK_MS = 60_000;

const hasLegacyStreams = () => typeof RTCRtpSender !== "undefined" && "createEncodedStreams" in RTCRtpSender.prototype;
const hasScriptTransform = () => typeof window !== "undefined" && "RTCRtpScriptTransform" in window;

/** Video uses VP8, whose frame headers the extra encryption knows how to leave readable. */
function preferVp8(tx) {
  try {
    const codecs = RTCRtpReceiver.getCapabilities?.("video")?.codecs || [];
    const vp8 = codecs.filter((x) => /vp8/i.test(x.mimeType));
    const rest = codecs.filter((x) => /rtx|red|ulpfec/i.test(x.mimeType));
    if (vp8.length) tx.setCodecPreferences([...vp8, ...rest]);
  } catch {
    // The browser picks; VP8 is offered by all of them.
  }
}

/** True if this browser can take part in calls (including the extra layer of frame encryption). */
export function voiceSupported() {
  return typeof RTCPeerConnection !== "undefined" && Boolean(navigator.mediaDevices?.getUserMedia) && (hasLegacyStreams() || hasScriptTransform());
}

const VoiceContext = createContext(null);

const IDLE = { room: null, join: async () => {}, leave: () => {}, muted: false, deafened: false, toggleMute: () => {}, toggleDeafen: () => {}, participants: [], error: "", supported: false };

export function useVoice() {
  return useContext(VoiceContext) || IDLE;
}

let workerPolicy = null;
function startWorker() {
  const href = new URL(frameWorkerUrl, window.location.href).href;
  // The page only allows script URLs made by this one policy (see the Content Security Policy).
  if (window.trustedTypes && !workerPolicy) {
    workerPolicy = window.trustedTypes.createPolicy("voice-worker", {
      createScriptURL: (u) => {
        if (u !== href) throw new TypeError("Unexpected worker script");
        return u;
      },
    });
  }
  return new Worker(workerPolicy ? workerPolicy.createScriptURL(href) : href);
}

async function certificateFingerprint(cert) {
  const fp = cert.getFingerprints?.().find((f) => f.algorithm === "sha-256");
  if (fp) return fp.value.toUpperCase();
  const pc = new RTCPeerConnection({ certificates: [cert] });
  try {
    pc.addTransceiver("audio");
    return fingerprintOf((await pc.createOffer()).sdp);
  } finally {
    pc.close();
  }
}

export function VoiceProvider({ children }) {
  const secure = useSecure();
  const servers = useServers();
  const secureRef = useRef(secure);
  const serversRef = useRef(servers);
  secureRef.current = secure;
  serversRef.current = servers;

  const call = useRef(null);
  const [room, setRoom] = useState(null);
  const [muted, setMuted] = useState(false);
  const [deafened, setDeafened] = useState(false);
  const [videoKind, setVideoKind] = useState(null);
  const [error, setError] = useState("");
  const [tick, setTick] = useState(0);
  const bump = useCallback(() => setTick((t) => t + 1), []);

  // ---------- keys for the frame layer ----------

  const deriveKey = useCallback(async (c, generation, step) => {
    const id = epochId(generation, step);
    if (c.keys.has(id)) return c.keys.get(id);
    let raw;
    try {
      // A call in a conversation has one key, sent inside the encrypted message that started it.
      raw = c.callKey ? (generation === 0 && step === 0 ? c.callKey.slice() : null) : serversRef.current.chainKeyAt(c.serverId, c.chainId, generation, step);
    } catch {
      return null;
    }
    if (!raw) return null;
    const key = await hkdfAesKey(raw, utf8("commonveil/voice-frame/v1"), `${c.roomId}|${c.chainId}|${generation}|${step}`);
    raw.fill(0);
    c.keys.set(id, key);
    c.worker?.postMessage({ type: "key", generation, step, key });
    return key;
  }, []);

  const refreshEpoch = useCallback(async (c) => {
    const e = c.callKey ? { generation: 0, step: 0 } : serversRef.current.voiceEpoch(c.serverId, c.channel);
    const key = await deriveKey(c, e.generation, e.step);
    if (!key) throw new Error("This device doesn't have this channel's keys yet, so it can't join the call.");
    c.current = { generation: e.generation, step: e.step, key };
    c.worker?.postMessage({ type: "current", generation: e.generation, step: e.step });
  }, [deriveKey]);

  // ---------- speaking indicators ----------

  const watchLevel = useCallback((c, key, stream) => {
    try {
      if (!c.audioCtx) c.audioCtx = new AudioContext();
      const source = c.audioCtx.createMediaStreamSource(stream);
      const analyser = c.audioCtx.createAnalyser();
      analyser.fftSize = 512;
      source.connect(analyser);
      c.levels.set(key, { analyser, buf: new Float32Array(analyser.fftSize), speaking: false });
    } catch {
      // Speaking indicators are a nicety; the call works without them.
    }
  }, []);

  // ---------- peers ----------

  const send = (c, msg) => {
    try {
      c.conn?.send(msg);
    } catch {
      // The socket reconnects by itself; set-up messages are retried by the peers.
    }
  };

  const closePeer = useCallback((c, seat) => {
    const p = c.peers.get(seat);
    if (!p) return;
    clearTimeout(p.restartTimer);
    try {
      p.pc?.close();
    } catch {
      // already closed
    }
    if (p.audio) {
      p.audio.srcObject = null;
      p.audio.remove();
    }
    c.levels.delete(seat);
    c.peers.delete(seat);
  }, []);

  const attachSend = (c, sender) => {
    if (c.worker) sender.transform = new window.RTCRtpScriptTransform(c.worker, { side: "send" });
    else {
      const { readable, writable } = sender.createEncodedStreams();
      readable.pipeThrough(frameTransform("send", c.keySource, c.stats)).pipeTo(writable).catch(() => {});
    }
  };
  const attachRecv = (c, receiver) => {
    if (c.worker) receiver.transform = new window.RTCRtpScriptTransform(c.worker, { side: "recv" });
    else {
      const { readable, writable } = receiver.createEncodedStreams();
      readable.pipeThrough(frameTransform("recv", c.keySource, c.stats)).pipeTo(writable).catch(() => {});
    }
  };

  const restartIce = useCallback(async (c, seat) => {
    const p = c.peers.get(seat);
    const pc = p?.pc;
    if (!pc || call.current !== c || c.closed || pc.connectionState === "connected" || pc.signalingState !== "stable") return;
    p.restarts = (p.restarts || 0) + 1;
    if (p.restarts > 5) return;
    try {
      pc.restartIce();
      await pc.setLocalDescription(await pc.createOffer({ iceRestart: true }));
      send(c, { type: "signal", to: seat, data: { sdp: pc.localDescription.toJSON() } });
    } catch {
      // The next state change tries again.
    }
  }, []);

  const connectPeer = useCallback(async (c, seat, initiator) => {
    const p = c.peers.get(seat);
    if (!p || p.pc) return;
    const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS, certificates: [c.cert], ...(c.worker ? {} : { encodedInsertableStreams: true }) });
    p.pc = pc;
    p.initiator = initiator;
    p.state = "connecting";
    for (const track of c.stream.getAudioTracks()) attachSend(c, pc.addTrack(track, c.stream));
    if (initiator) {
      // One video slot, for a camera or a shared screen, switched without renegotiating.
      const tx = pc.addTransceiver("video", { direction: "sendrecv" });
      preferVp8(tx);
      attachSend(c, tx.sender);
      p.videoSender = tx.sender;
      if (c.videoTrack) tx.sender.replaceTrack(c.videoTrack).catch(() => {});
    }
    pc.ontrack = (e) => {
      attachRecv(c, e.receiver);
      if (e.track.kind === "video") {
        p.videoStream = new MediaStream([e.track]);
        bump();
        return;
      }
      const stream = e.streams[0] || new MediaStream([e.track]);
      if (!p.audio) {
        p.audio = document.createElement("audio");
        p.audio.autoplay = true;
        p.audio.hidden = true;
        document.body.appendChild(p.audio);
      }
      p.audio.srcObject = stream;
      p.audio.muted = c.deafened || p.canSpeak === false;
      p.audio.play?.().catch(() => {});
      watchLevel(c, seat, stream);
    };
    pc.onicecandidate = (e) => {
      if (e.candidate) send(c, { type: "signal", to: seat, data: { candidate: e.candidate.toJSON() } });
    };
    pc.onconnectionstatechange = () => {
      const s = pc.connectionState;
      p.state = s === "connected" ? "connected" : s === "failed" || s === "closed" ? "failed" : p.state === "unverified" ? "unverified" : "connecting";
      clearTimeout(p.restartTimer);
      if (s === "connected") {
        p.restarts = 0;
        // Tell them what this device is showing; it travels encrypted inside the connection set-up.
        send(c, { type: "signal", to: seat, data: { show: c.videoKind || null } });
      }
      // Networks change and connections drop: whoever called first finds a new route, keeping the same keys.
      if (initiator && (s === "failed" || s === "disconnected")) {
        p.restartTimer = setTimeout(() => restartIce(c, seat), s === "failed" ? 0 : 4000);
      }
      bump();
    };
    if (initiator) {
      await pc.setLocalDescription(await pc.createOffer());
      send(c, { type: "signal", to: seat, data: { sdp: pc.localDescription.toJSON() } });
    }
    bump();
  }, [bump, watchLevel, restartIce]);

  const handleSignal = useCallback(async (c, seat, data) => {
    const p = c.peers.get(seat);
    if (!p || p.state === "unverified") return;
    if (!p.verified) {
      // Still checking their offer: keep the message until then.
      p.queue.push(data);
      return;
    }
    const pc = p.pc;
    if (!pc) return;
    try {
      if (data?.sdp && typeof data.sdp.sdp === "string") {
        if (fingerprintOf(data.sdp.sdp) !== p.hello.fingerprint) {
          // Their connection uses a certificate other than the one they signed: someone's in between.
          p.state = "unverified";
          closePeer(c, seat);
          c.peers.set(seat, { ...p, pc: null, state: "unverified" });
          bump();
          return;
        }
        await pc.setRemoteDescription(data.sdp);
        if (data.sdp.type === "offer") {
          if (!p.videoSender) {
            // Answering: use the video slot the caller offered.
            const tx = pc.getTransceivers().find((t) => t.receiver.track?.kind === "video" && !t.stopped);
            if (tx) {
              tx.direction = "sendrecv";
              preferVp8(tx);
              attachSend(c, tx.sender);
              p.videoSender = tx.sender;
              if (c.videoTrack) await tx.sender.replaceTrack(c.videoTrack).catch(() => {});
            }
          }
          await pc.setLocalDescription(await pc.createAnswer());
          send(c, { type: "signal", to: seat, data: { sdp: pc.localDescription.toJSON() } });
        }
        for (const cand of p.candidates.splice(0)) await pc.addIceCandidate(cand).catch(() => {});
      } else if (data?.candidate) {
        if (pc.remoteDescription) await pc.addIceCandidate(data.candidate).catch(() => {});
        else p.candidates.push(data.candidate);
      } else if (data && "show" in data) {
        p.video = data.show === "camera" || data.show === "screen" ? data.show : null;
        bump();
      }
    } catch {
      p.state = "failed";
      bump();
    }
  }, [bump, closePeer]);

  const addPeer = useCallback(async (c, peer, initiator) => {
    const seat = Number(peer.seat);
    if (c.peers.has(seat)) closePeer(c, seat);
    const p = { seat, userId: peer.user_id, deviceId: peer.device_id, hello: peer.hello, muted: Boolean(peer.muted), deafened: Boolean(peer.deafened), canSpeak: peer.can_speak !== false, hand: Boolean(peer.hand), moderator: Boolean(peer.moderator), state: "checking", verified: false, queue: [], candidates: [], pc: null, audio: null };
    c.peers.set(seat, p);
    bump();
    const s = secureRef.current;
    let ok = false;
    try {
      if (peer.user_id !== s.userId) await s.loadPeers([peer.user_id]);
      ok = await verifyHello({ room: c.roomId, peer, chain: s.latestChainOf(peer.user_id), devices: s.devicesOf(peer.user_id) });
    } catch {
      ok = false;
    }
    if (call.current !== c || c.peers.get(seat) !== p) return;
    if (!ok) {
      p.state = "unverified";
      bump();
      return;
    }
    p.verified = true;
    await connectPeer(c, seat, initiator);
    for (const data of p.queue.splice(0)) await handleSignal(c, seat, data);
  }, [bump, closePeer, connectPeer, handleSignal]);

  // ---------- leaving ----------

  const teardown = useCallback((c, message = "") => {
    if (!c) return;
    c.closed = true;
    clearInterval(c.epochTimer);
    clearInterval(c.levelTimer);
    send(c, { type: "leave" });
    try {
      c.sub?.unsubscribe();
      c.conn?.close();
    } catch {
      // gone already
    }
    for (const seat of [...c.peers.keys()]) closePeer(c, seat);
    for (const t of c.stream?.getTracks() || []) t.stop();
    c.videoTrack?.stop();
    if (call.current === c) setVideoKind(null);
    c.audioCtx?.close().catch(() => {});
    c.worker?.terminate();
    c.keys.clear();
    if (call.current === c) {
      call.current = null;
      setRoom(null);
      setError(message);
    }
  }, [closePeer]);

  const leave = useCallback(() => teardown(call.current), [teardown]);

  // ---------- joining ----------

  const getPass = useCallback(async (c) => {
    const s = secureRef.current;
    const res = c.conversationId
      ? await callFn("voice", await SP.serverRequest({ userId: s.userId, device: s.device, action: "call_ticket", payload: { conversation_id: c.conversationId, call_id: c.callId } }))
      : await callFn("voice", await SP.serverRequest({ userId: s.userId, device: s.device, action: "voice_ticket", payload: { server_id: c.serverId, channel_id: c.channel.id } }));
    if (res.room !== c.roomId) throw new Error("The call's address didn't match this channel.");
    c.canSpeak = res.can_speak !== false;
    c.canModerate = res.can_moderate === true;
    c.stage = res.stage === true;
    return res.ticket;
  }, []);

  const onMessage = useCallback(async (c, msg) => {
    if (call.current !== c || !msg || typeof msg !== "object") return;
    if (msg.type === "pass-needed") {
      // First connection, or the relay restarted: show a (fresh) pass.
      try {
        const ticket = c.ticket || (await getPass(c));
        c.ticket = null;
        send(c, { type: "join", ticket, hello: c.hello, muted: c.muted, deafened: c.deafened });
      } catch (err) {
        teardown(c, err.message);
      }
    } else if (msg.type === "welcome") {
      // A new place in the call means the others saw this device leave: connect to everyone afresh.
      if (c.seat && c.seat !== msg.seat) for (const seat of [...c.peers.keys()]) closePeer(c, seat);
      c.seat = msg.seat;
      if (msg.can_speak === false) c.canSpeak = false;
      c.canModerate = msg.can_moderate === true;
      c.stage = msg.stage === true;
      setRoom((r) => (r ? { ...r, status: "connected" } : r));
      const fresh = new Set((msg.peers || []).map((p) => Number(p.seat)));
      for (const seat of [...c.peers.keys()]) if (!fresh.has(seat)) closePeer(c, seat);
      // The newcomer calls everyone already here.
      for (const peer of msg.peers || []) if (!c.peers.get(Number(peer.seat))?.pc) addPeer(c, peer, true);
      bump();
    } else if (msg.type === "peer-joined" && msg.peer) {
      addPeer(c, msg.peer, false);
    } else if (msg.type === "peer-left") {
      closePeer(c, Number(msg.seat));
      bump();
    } else if (msg.type === "peer-state") {
      if (Number(msg.seat) === c.seat) {
        // About this device: a moderator brought it up to speak, sent it back, or muted it.
        if (typeof msg.can_speak === "boolean") c.canSpeak = msg.can_speak;
        c.hand = Boolean(msg.hand);
        if (msg.muted && !c.muted) {
          c.muted = true;
          for (const t of c.stream?.getAudioTracks() || []) t.enabled = false;
          setMuted(true);
        }
        if (!c.canSpeak && c.videoTrack) setVideoRef.current?.(null);
        bump();
        return;
      }
      const p = c.peers.get(Number(msg.seat));
      if (p) {
        p.muted = Boolean(msg.muted);
        p.deafened = Boolean(msg.deafened);
        if (typeof msg.can_speak === "boolean") p.canSpeak = msg.can_speak;
        p.hand = Boolean(msg.hand);
        if (p.audio) p.audio.muted = c.deafened || p.canSpeak === false;
        bump();
      }
    } else if (msg.type === "signal") {
      handleSignal(c, Number(msg.from), msg.data);
    } else if (msg.type === "error") {
      if ((msg.code === "PASS_INVALID" || msg.code === "PASS_USED") && !c.retried) {
        // The pass ran out (a slow microphone prompt, say): get one more.
        c.retried = true;
        try {
          send(c, { type: "join", ticket: await getPass(c), hello: c.hello, muted: c.muted, deafened: c.deafened });
          return;
        } catch {
          // fall through
        }
      }
      teardown(c, msg.message || "The call ended.");
    }
  }, [addPeer, bump, closePeer, getPass, handleSignal, teardown]);

  /**
   * Join a call: a server's voice or stage channel ({ serverId, channel }), or a call in a
   * conversation ({ conversationId, callId, callKey }) whose key came in its encrypted message.
   */
  const start = useCallback(async (target) => {
    if (!voiceSupported()) throw new Error("This browser can't join encrypted calls. Try a recent version of Firefox, Safari, Chrome or Edge.");
    const { serverId = null, channel = null, conversationId = null, callId = null, callKey = null } = target;
    if (serverId && serversRef.current.keyState(serverId, channel) !== "ready") throw new Error("This device doesn't have this channel's keys yet. Try again once they arrive.");
    teardown(call.current);
    setError("");
    const c = {
      serverId,
      channel,
      conversationId,
      callId,
      callKey,
      chainId: serverId ? SP.chainForChannel(serverId, channel) : `call.${callId}`,
      // The same address the voice function gives out.
      roomId: serverId ? `${serverId}.${channel.id}` : `dm.${conversationId}.${callId}`,
      peers: new Map(),
      keys: new Map(),
      levels: new Map(),
      stats: { sealed: 0, opened: 0, dropped: 0 },
      current: null,
      muted: false,
      deafened: false,
      canSpeak: true,
    };
    c.keySource = { current: () => c.current, keyFor: (g, s) => deriveKey(c, g, s) };
    call.current = c;
    try {
      c.stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true }, video: false });
      c.cert = await RTCPeerConnection.generateCertificate({ name: "ECDSA", namedCurve: "P-256" });
      const s = secureRef.current;
      c.hello = await signHello({ device: s.device, room: c.roomId, userId: s.userId, callId: randomId(12), fingerprint: await certificateFingerprint(c.cert) });
      if (!hasLegacyStreams()) {
        c.worker = startWorker();
        c.worker.onmessage = async (e) => {
          const m = e.data || {};
          if (m.type === "need-key") {
            const key = await deriveKey(c, m.generation, m.step);
            if (!key) c.worker?.postMessage({ type: "no-key", generation: m.generation, step: m.step });
          }
        };
      }
      await refreshEpoch(c);
      c.epochTimer = setInterval(() => refreshEpoch(c).catch(() => {}), EPOCH_CHECK_MS);
      watchLevel(c, "self", c.stream);
      c.levelTimer = setInterval(() => {
        let changed = false;
        for (const [key, l] of c.levels) {
          l.analyser.getFloatTimeDomainData(l.buf);
          let sum = 0;
          for (const v of l.buf) sum += v * v;
          const speaking = Math.sqrt(sum / l.buf.length) > SPEAKING_LEVEL && !(key === "self" ? c.muted : c.peers.get(key)?.muted);
          if (speaking !== l.speaking) {
            l.speaking = speaking;
            changed = true;
          }
        }
        if (changed) bump();
      }, 250);
      if (call.current !== c) return;
      // Ask for the pass last, so it's fresh when the relay checks it.
      c.ticket = await getPass(c);
      if (!c.canSpeak) for (const t of c.stream.getAudioTracks()) t.enabled = false;
      c.muted = !c.canSpeak;
      setMuted(c.muted);
      setDeafened(false);
      setRoom(serverId ? { serverId, channelId: channel.id, status: "connecting" } : { conversationId, callId, status: "connecting" });
      c.conn = base44.actors.VoiceRoom(c.roomId).connect({ id: randomId(16) });
      c.sub = c.conn.subscribe((msg) => onMessage(c, msg));
    } catch (err) {
      const message = err?.name === "NotAllowedError" ? "Commonveil needs your permission to use the microphone." : err?.message || "Couldn't join the call.";
      teardown(c);
      throw new Error(message);
    }
  }, [deriveKey, getPass, onMessage, refreshEpoch, teardown, watchLevel, bump]);

  const join = useCallback((serverId, channel) => start({ serverId, channel }), [start]);
  const joinCall = useCallback((conversationId, callId, callKey) => start({ conversationId, callId, callKey }), [start]);

  // ---------- stage ----------

  const raiseHand = useCallback((raised) => {
    const c = call.current;
    if (c?.stage) send(c, { type: "hand", raised });
  }, []);
  const setSpeaker = useCallback((userId, speak) => {
    const c = call.current;
    if (!c?.canModerate) return;
    for (const p of c.peers.values()) if (p.userId === userId) send(c, { type: "set-speaker", seat: p.seat, speak });
  }, []);
  const mutePeer = useCallback((userId) => {
    const c = call.current;
    if (!c?.canModerate) return;
    for (const p of c.peers.values()) if (p.userId === userId) send(c, { type: "mute-peer", seat: p.seat });
  }, []);

  // ---------- controls ----------

  const toggleMute = useCallback(() => {
    const c = call.current;
    if (!c) return;
    if (!c.canSpeak) {
      setError("You don't have permission to speak in this channel.");
      return;
    }
    c.muted = !c.muted;
    if (!c.muted && c.deafened) {
      c.deafened = false;
      for (const p of c.peers.values()) if (p.audio) p.audio.muted = p.canSpeak === false;
      setDeafened(false);
    }
    for (const t of c.stream.getAudioTracks()) t.enabled = !c.muted;
    setMuted(c.muted);
    send(c, { type: "state", muted: c.muted, deafened: c.deafened });
  }, []);

  const toggleDeafen = useCallback(() => {
    const c = call.current;
    if (!c) return;
    c.deafened = !c.deafened;
    for (const p of c.peers.values()) if (p.audio) p.audio.muted = c.deafened || p.canSpeak === false;
    // Deafening mutes you too; undeafening restores what you had.
    if (c.deafened) {
      c.mutedBeforeDeafen = c.muted;
      c.muted = true;
    } else {
      c.muted = c.mutedBeforeDeafen ?? c.muted;
    }
    if (!c.canSpeak) c.muted = true;
    for (const t of c.stream.getAudioTracks()) t.enabled = !c.muted;
    setMuted(c.muted);
    setDeafened(c.deafened);
    send(c, { type: "state", muted: c.muted, deafened: c.deafened });
  }, []);

  const setVideo = useCallback(async (kind) => {
    const c = call.current;
    if (!c) return;
    if (!c.canSpeak && kind) {
      setError("You don't have permission to share video in this channel.");
      return;
    }
    let track = null;
    if (kind) {
      try {
        const stream = kind === "screen"
          ? await navigator.mediaDevices.getDisplayMedia({ video: { frameRate: 15 }, audio: false })
          : await navigator.mediaDevices.getUserMedia({ video: { width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 24 } }, audio: false });
        track = stream.getVideoTracks()[0];
      } catch (err) {
        if (err?.name !== "NotAllowedError" && err?.name !== "AbortError") setError(kind === "screen" ? "Couldn't share your screen." : "Couldn't start your camera.");
        return;
      }
      if (kind === "screen") track.contentHint = "detail";
      track.onended = () => {
        if (call.current === c && c.videoTrack === track) setVideoRef.current?.(null);
      };
    }
    if (call.current !== c) {
      track?.stop();
      return;
    }
    const old = c.videoTrack;
    c.videoTrack = track;
    c.videoKind = kind;
    c.localVideo = track ? new MediaStream([track]) : null;
    for (const p of c.peers.values()) {
      p.videoSender?.replaceTrack(track).catch(() => {});
      if (p.pc) send(c, { type: "signal", to: p.seat, data: { show: kind } });
    }
    old?.stop();
    setVideoKind(kind);
  }, []);
  const setVideoRef = useRef(null);
  setVideoRef.current = setVideo;
  const toggleCamera = useCallback(() => setVideo(call.current?.videoKind === "camera" ? null : "camera"), [setVideo]);
  const toggleScreen = useCallback(() => setVideo(call.current?.videoKind === "screen" ? null : "screen"), [setVideo]);

  // Leave the call when signing out or closing the app.
  useEffect(() => () => teardown(call.current), [teardown]);
  useEffect(() => {
    if (secure.phase !== "ready" && call.current) teardown(call.current);
  }, [secure.phase, teardown]);

  const participants = useMemo(() => {
    const c = call.current;
    if (!c || !room) return [];
    const list = [{ userId: secure.userId, self: true, muted, deafened, speaking: Boolean(c.levels.get("self")?.speaking), state: "connected", video: videoKind, stream: c.localVideo || null, canSpeak: c.canSpeak !== false, hand: Boolean(c.hand), moderator: Boolean(c.canModerate) }];
    for (const p of c.peers.values()) {
      list.push({ userId: p.userId, self: false, muted: p.muted, deafened: p.deafened, speaking: p.canSpeak !== false && Boolean(c.levels.get(p.seat)?.speaking), state: p.state, video: p.canSpeak === false ? null : p.video || null, stream: p.video && p.canSpeak !== false ? p.videoStream || null : null, canSpeak: p.canSpeak !== false, hand: Boolean(p.hand), moderator: Boolean(p.moderator) });
    }
    return list;
    // tick re-reads the refs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [room, muted, deafened, videoKind, tick, secure.userId]);

  const value = useMemo(() => ({
    room,
    join,
    joinCall,
    leave,
    /** On a stage: whether this device may speak or bring others up, and the stage controls. */
    stage: Boolean(call.current?.stage),
    canSpeak: call.current ? call.current.canSpeak !== false : true,
    canModerate: Boolean(call.current?.canModerate),
    raiseHand,
    setSpeaker,
    mutePeer,
    muted,
    deafened,
    toggleMute,
    toggleDeafen,
    video: videoKind,
    toggleCamera,
    toggleScreen,
    canShareScreen: typeof navigator !== "undefined" && Boolean(navigator.mediaDevices?.getDisplayMedia),
    participants,
    error,
    supported: voiceSupported(),
    /** Frame counts for this call (sealed, opened, dropped), for the call's details. */
    frameStats: () => ({ ...(call.current?.stats || {}) }),
  }), [room, join, joinCall, leave, muted, deafened, toggleMute, toggleDeafen, videoKind, toggleCamera, toggleScreen, participants, error, raiseHand, setSpeaker, mutePeer, tick]);

  return <VoiceContext.Provider value={value}>{children}</VoiceContext.Provider>;
}
