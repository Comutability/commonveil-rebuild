import React, { useState } from "react";
import { AlertDialog, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { ErrorNote } from "@/components/site/bits";

/**
 * Ask before doing something that can't be undone. onConfirm may be async; the dialog stays open
 * with the error if it fails.
 */
export default function ConfirmDialog({ open, onOpenChange, title, children, confirmLabel = "Confirm", busyLabel, destructive = true, onConfirm }) {
  const [state, setState] = useState({ busy: false, error: "" });
  const run = async () => {
    setState({ busy: true, error: "" });
    try {
      await onConfirm();
      setState({ busy: false, error: "" });
      onOpenChange(false);
    } catch (err) {
      setState({ busy: false, error: err.message });
    }
  };
  return (
    <AlertDialog open={open} onOpenChange={(v) => !state.busy && onOpenChange(v)}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="space-y-2 text-sm text-muted-foreground">{children}</div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <ErrorNote>{state.error}</ErrorNote>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={state.busy}>Cancel</AlertDialogCancel>
          <Button variant={destructive ? "destructive" : "default"} disabled={state.busy} onClick={run}>
            {state.busy ? busyLabel || `${confirmLabel}…` : confirmLabel}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
