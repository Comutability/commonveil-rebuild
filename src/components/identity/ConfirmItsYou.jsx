import React, { useCallback, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PROOF_REQUIRED } from "@/lib/identity/client";

/**
 * Changes to how your account is protected are proven with this browser's encryption device. When
 * it can't (encryption locked or not set up yet), this asks for your password instead.
 *
 *   const { confirm, dialog } = useConfirmItsYou();
 *   await confirm((opts) => addPasskey("device", "", opts));
 *   ...render {dialog} somewhere
 */
export function useConfirmItsYou() {
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const waiting = useRef(null);

  const confirm = useCallback(async (fn) => {
    try {
      return await fn({});
    } catch (err) {
      if (err?.code !== PROOF_REQUIRED) throw err;
      const given = await new Promise((resolve, reject) => {
        waiting.current = { resolve, reject };
        setPassword("");
        setOpen(true);
      });
      return fn({ password: given });
    }
  }, []);

  const finish = (value) => {
    const w = waiting.current;
    waiting.current = null;
    setOpen(false);
    setPassword("");
    if (!w) return;
    if (value === null) w.reject(new Error("Not changed: you didn't confirm it was you."));
    else w.resolve(value);
  };

  const dialog = (
    <Dialog open={open} onOpenChange={(o) => !o && finish(null)}>
      <DialogContent>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (password) finish(password);
          }}
        >
          <DialogHeader>
            <DialogTitle>Confirm it's you</DialogTitle>
            <DialogDescription>This changes how your account is protected, so enter your password first.</DialogDescription>
          </DialogHeader>
          <div className="my-4 space-y-1.5">
            <Label htmlFor="confirm-password">Password</Label>
            <Input id="confirm-password" type="password" autoComplete="current-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => finish(null)}>Cancel</Button>
            <Button type="submit" disabled={!password}>Confirm</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );

  return { confirm, dialog };
}
