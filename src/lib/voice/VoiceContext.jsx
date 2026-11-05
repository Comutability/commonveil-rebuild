// Voice: the call you're in, if any. Filled in by the voice room code; until you join one,
// nothing here touches the microphone or the network.
import React, { createContext, useContext, useMemo, useState } from "react";

const VoiceContext = createContext(null);

export function useVoice() {
  return useContext(VoiceContext) || { room: null, join: async () => {}, leave: () => {}, muted: false, deafened: false, toggleMute: () => {}, toggleDeafen: () => {}, participants: [], error: "" };
}

export function VoiceProvider({ children }) {
  const [room] = useState(null);
  const value = useMemo(() => ({
    room,
    join: async () => {
      throw new Error("Voice isn't available yet.");
    },
    leave: () => {},
    muted: false,
    deafened: false,
    toggleMute: () => {},
    toggleDeafen: () => {},
    participants: [],
    error: "",
  }), [room]);
  return <VoiceContext.Provider value={value}>{children}</VoiceContext.Provider>;
}
