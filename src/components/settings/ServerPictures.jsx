import React, { useRef, useState } from "react";
import { ImagePlus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useServers } from "@/lib/secure/ServerContext";
import { ErrorNote } from "@/components/site/bits";
import { shrinkPicture } from "@/lib/secure/serverPictures";

/**
 * A server's picture and banner. Both are shrunk on this device, encrypted with the server's keys
 * and saved as their own encrypted item, so Commonveil stores a picture it can't see.
 */
function PictureRow({ sid, kind, label, help, current, shape }) {
  const { setServerSet } = useServers();
  const picker = useRef(null);
  const [state, setState] = useState({ busy: false, error: "" });

  const choose = async (file) => {
    if (!file) return;
    setState({ busy: true, error: "" });
    try {
      const img = await shrinkPicture(file, kind);
      await setServerSet(sid, kind, { img });
      setState({ busy: false, error: "" });
    } catch (err) {
      setState({ busy: false, error: err?.message || "That picture couldn't be saved." });
    }
  };

  const remove = async () => {
    setState({ busy: true, error: "" });
    try {
      await setServerSet(sid, kind, null);
      setState({ busy: false, error: "" });
    } catch (err) {
      setState({ busy: false, error: err?.message || "That picture couldn't be removed." });
    }
  };

  return (
    <div className="space-y-2">
      <div>
        <p className="text-sm font-medium">{label}</p>
        <p className="text-xs text-muted-foreground">{help}</p>
      </div>
      <div className={`overflow-hidden border border-border bg-muted ${shape}`}>
        {current ? (
          <img src={current} alt="" className="h-full w-full object-cover" />
        ) : (
          <span className="flex h-full w-full items-center justify-center text-muted-foreground">
            <ImagePlus className="h-5 w-5" aria-hidden="true" />
          </span>
        )}
      </div>
      <input ref={picker} type="file" accept="image/png,image/jpeg,image/webp" className="hidden" aria-hidden="true" tabIndex={-1} onChange={(ev) => { const f = ev.target.files?.[0]; ev.target.value = ""; choose(f); }} />
      <div className="flex items-center gap-2">
        <Button type="button" size="sm" variant="outline" disabled={state.busy} onClick={() => picker.current?.click()}>
          {state.busy ? "Encrypting…" : current ? "Replace" : "Upload"}
        </Button>
        {current && (
          <Button type="button" size="sm" variant="ghost" disabled={state.busy} onClick={remove} aria-label={`Remove the ${label.toLowerCase()}`}>
            <Trash2 className="h-4 w-4" aria-hidden="true" />
          </Button>
        )}
      </div>
      <ErrorNote>{state.error}</ErrorNote>
    </div>
  );
}

export default function ServerPictures({ sid }) {
  const { serverLook } = useServers();
  const look = serverLook(sid);
  return (
    <div className="grid gap-5 sm:grid-cols-[auto_1fr]">
      <PictureRow sid={sid} kind="icon" label="Picture" help="Replaces the emoji or letters in the server list. Shown round." current={look.picture} shape="h-24 w-24 rounded-full" />
      <PictureRow sid={sid} kind="banner" label="Banner picture" help="The wide picture across the top of the welcome new members see." current={look.banner_image} shape="h-24 w-full rounded-lg sm:h-24" />
    </div>
  );
}