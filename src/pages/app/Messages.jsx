import React, { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Lock } from "lucide-react";
import { useChat } from "@/lib/secure/ChatContext";
import ConversationList from "@/components/chat/ConversationList";
import ConversationView from "@/components/chat/ConversationView";
import NewConversationDialog from "@/components/chat/NewConversationDialog";
import ConversationInfoDialog from "@/components/chat/ConversationInfoDialog";

export default function Messages() {
  const { conversationId } = useParams();
  const navigate = useNavigate();
  const { conversations, loaded } = useChat();
  const [newOpen, setNewOpen] = useState(false);
  const [infoOpen, setInfoOpen] = useState(false);
  const active = conversations.find((c) => c.id === conversationId) || null;

  return (
    <div className="mx-auto flex h-[calc(100dvh-3.5rem)] w-full max-w-7xl">
      <div className={`w-full border-border md:w-80 md:shrink-0 md:border-r lg:w-96 ${active ? "hidden md:block" : "block"}`}>
        <ConversationList activeId={conversationId} onNew={() => setNewOpen(true)} />
      </div>
      <div className={`min-w-0 flex-1 ${active ? "block" : "hidden md:block"}`}>
        {active ? (
          <ConversationView conversation={active} onBack={() => navigate("/app")} onInfo={() => setInfoOpen(true)} />
        ) : (
          <div className="flex h-full flex-col items-center justify-center p-8 text-center text-muted-foreground">
            <Lock className="h-8 w-8 text-primary" aria-hidden="true" />
            <p className="mt-4 font-heading text-xl text-foreground">{conversationId && loaded ? "That conversation isn't available" : "Pick a conversation"}</p>
            <p className="mt-1 max-w-xs text-sm">Everything here is encrypted on your device before it's sent.</p>
          </div>
        )}
      </div>
      <NewConversationDialog open={newOpen} onOpenChange={setNewOpen} onCreated={(c) => navigate(`/app/c/${c.id}`)} />
      <ConversationInfoDialog conversation={active} open={infoOpen && Boolean(active)} onOpenChange={setInfoOpen} onLeft={() => navigate("/app")} />
    </div>
  );
}
