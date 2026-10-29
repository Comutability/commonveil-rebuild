import React, { useState } from "react";
import { Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ErrorNote } from "@/components/site/bits";
import { useSecure } from "@/lib/secure/SecureContext";

export function DeletionExplainer() {
  return (
    <ul className="list-disc space-y-1.5 pl-5 text-sm text-muted-foreground">
      <li>Your profile and username, your keys and devices, and every message you've sent are deleted.</li>
      <li>Direct-message conversations with you disappear for the other person too. You're removed from your groups.</li>
      <li>Blocks and reports involving you are deleted. Security reports you sent are kept, without your name.</li>
      <li>Your sign-in is removed. Base44, our host, keeps removed sign-ins for 30 days before erasing them.</li>
      <li>This can't be undone.</li>
    </ul>
  );
}

/** Confirmation and progress. Renders inline, or inside a dialog via DeleteAccountDialog. */
export function DeleteAccountForm({ onCancel }) {
  const { deleteAccount } = useSecure();
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await deleteAccount();
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="space-y-4">
      <DeletionExplainer />
      <div className="space-y-1.5">
        <Label htmlFor="confirm-delete">Type DELETE to confirm</Label>
        <Input id="confirm-delete" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" disabled={busy} />
      </div>
      <ErrorNote>{error}</ErrorNote>
      <div className="flex flex-wrap gap-2">
        <Button type="submit" variant="destructive" disabled={typed !== "DELETE" || busy}>
          <Trash2 className="mr-2 h-4 w-4" aria-hidden="true" />
          {busy ? "Deleting… keep this page open" : "Delete my account"}
        </Button>
        {onCancel && <Button type="button" variant="ghost" onClick={onCancel} disabled={busy}>Cancel</Button>}
      </div>
    </form>
  );
}

/** A quiet link that opens the deletion form, for screens before setup is finished. */
export function DeleteAccountLink() {
  const { isAdmin } = useSecure();
  const [open, setOpen] = useState(false);
  if (isAdmin) return null;
  return (
    <>
      <button type="button" onClick={() => setOpen(true)} className="text-sm text-muted-foreground underline-offset-2 hover:underline">
        Not for you? Delete this account
      </button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Delete your account</DialogTitle>
            <DialogDescription>Everything you've set up so far is removed.</DialogDescription>
          </DialogHeader>
          <DeleteAccountForm onCancel={() => setOpen(false)} />
        </DialogContent>
      </Dialog>
    </>
  );
}
