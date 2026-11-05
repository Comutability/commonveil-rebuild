import React, { useEffect, useState } from "react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ErrorNote } from "@/components/site/bits";
import { useServers } from "@/lib/secure/ServerContext";
import { useSecure } from "@/lib/secure/SecureContext";

/** Your name in one server (or, for moderators, someone else's). Encrypted like everything else here. */
export default function NicknameDialog({ serverId, open, onOpenChange, targetId = null }) {
  const { userId } = useSecure();
  const { setNickname, memberName, nickOf, serverLook } = useServers();
  const who = targetId || userId;
  const [value, setValue] = useState("");
  const [state, setState] = useState({ busy: false, error: "" });

  useEffect(() => {
    if (open) {
      setValue(nickOf(serverId, who));
      setState({ busy: false, error: "" });
    }
    // Only when the dialog opens.
     
  }, [open]);

  const save = async (e) => {
    e.preventDefault();
    setState({ busy: true, error: "" });
    try {
      await setNickname(serverId, value.trim(), who === userId ? null : who);
      onOpenChange(false);
    } catch (err) {
      setState({ busy: false, error: err.message });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-sm">
        <form onSubmit={save} className="space-y-4">
          <DialogHeader>
            <DialogTitle>{who === userId ? "Your nickname" : `Nickname for ${memberName(serverId, who)}`}</DialogTitle>
            <DialogDescription>Shown instead of the display name in {serverLook(serverId).name} only. It's encrypted: only members can read it.</DialogDescription>
          </DialogHeader>
          <div className="space-y-1.5">
            <Label htmlFor="nick">Nickname</Label>
            <Input id="nick" value={value} onChange={(e) => setValue(e.target.value)} maxLength={32} placeholder="Leave empty to use the display name" autoFocus />
          </div>
          <ErrorNote>{state.error}</ErrorNote>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button type="submit" disabled={state.busy}>{state.busy ? "Saving…" : "Save"}</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
