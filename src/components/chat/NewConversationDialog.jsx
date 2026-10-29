import React, { useState } from "react";
import { X } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ErrorNote } from "@/components/site/bits";
import { callFn } from "@/lib/api";
import { useChat } from "@/lib/secure/ChatContext";
import { useSecure } from "@/lib/secure/SecureContext";

const clean = (u) => u.trim().replace(/^@/, "");

export default function NewConversationDialog({ open, onOpenChange, onCreated }) {
  const { startDm, startGroup, setTitle } = useChat();
  const { me, loadPeers } = useSecure();
  const [username, setUsername] = useState("");
  const [groupName, setGroupName] = useState("");
  const [memberInput, setMemberInput] = useState("");
  const [members, setMembers] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const reset = () => {
    setUsername("");
    setGroupName("");
    setMemberInput("");
    setMembers([]);
    setError("");
    setBusy(false);
  };

  const close = (v) => {
    if (!v) reset();
    onOpenChange(v);
  };

  const startDirect = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const conv = await startDm(clean(username));
      close(false);
      onCreated(conv);
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  };

  const addMember = async (e) => {
    e.preventDefault();
    const u = clean(memberInput);
    if (!u) return;
    setError("");
    if (u.toLowerCase() === me?.profile?.username?.toLowerCase()) {
      setError("You're already in the group.");
      return;
    }
    if (members.some((m) => m.username.toLowerCase() === u.toLowerCase())) return;
    try {
      const res = await callFn("profile", { action: "find", username: u });
      if (!res.encryption_ready) throw new Error(`${res.profile.username} hasn't finished setting up encryption yet.`);
      setMembers((m) => [...m, res.profile]);
      setMemberInput("");
    } catch (err) {
      setError(err.message);
    }
  };

  const createGroup = async () => {
    setBusy(true);
    setError("");
    try {
      const { conversation } = await startGroup(members.map((m) => m.username));
      if (groupName.trim()) {
        await loadPeers(conversation.member_ids, { force: true });
        try {
          await setTitle(conversation, groupName.trim());
        } catch {
          /* the group exists; the name can be set from its details */
        }
      }
      close(false);
      onCreated(conversation);
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>New conversation</DialogTitle>
          <DialogDescription>Enter someone's exact username. There's no directory to search.</DialogDescription>
        </DialogHeader>
        <Tabs defaultValue="dm">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="dm">Direct message</TabsTrigger>
            <TabsTrigger value="group">Group</TabsTrigger>
          </TabsList>
          <TabsContent value="dm">
            <form onSubmit={startDirect} className="space-y-4 pt-2">
              <div className="space-y-1.5">
                <Label htmlFor="dm-username">Username</Label>
                <Input id="dm-username" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="@username" autoComplete="off" autoCapitalize="none" spellCheck={false} />
              </div>
              <ErrorNote>{error}</ErrorNote>
              <Button type="submit" className="w-full" disabled={!clean(username) || busy}>{busy ? "Starting…" : "Start conversation"}</Button>
            </form>
          </TabsContent>
          <TabsContent value="group">
            <div className="space-y-4 pt-2">
              <div className="space-y-1.5">
                <Label htmlFor="group-name">Group name <span className="font-normal text-muted-foreground">(encrypted)</span></Label>
                <Input id="group-name" value={groupName} onChange={(e) => setGroupName(e.target.value)} maxLength={80} />
              </div>
              <form onSubmit={addMember} className="space-y-1.5">
                <Label htmlFor="group-member">Add people</Label>
                <div className="flex gap-2">
                  <Input id="group-member" value={memberInput} onChange={(e) => setMemberInput(e.target.value)} placeholder="@username" autoComplete="off" autoCapitalize="none" spellCheck={false} />
                  <Button type="submit" variant="outline">Add</Button>
                </div>
              </form>
              {members.length > 0 && (
                <ul className="flex flex-wrap gap-2">
                  {members.map((m) => (
                    <li key={m.user_id} className="inline-flex items-center gap-1 rounded-full bg-muted py-1 pl-3 pr-1 text-sm">
                      {m.display_name || m.username}
                      <button type="button" className="rounded-full p-0.5 hover:bg-background" onClick={() => setMembers((list) => list.filter((x) => x.user_id !== m.user_id))} aria-label={`Remove ${m.username}`}>
                        <X className="h-3.5 w-3.5" />
                      </button>
                    </li>
                  ))}
                </ul>
              )}
              <ErrorNote>{error}</ErrorNote>
              <Button className="w-full" onClick={createGroup} disabled={members.length === 0 || busy}>{busy ? "Creating…" : "Create group"}</Button>
              <p className="text-xs text-muted-foreground">Groups can have up to 32 people. People who join later can't read earlier messages.</p>
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
