import React, { useEffect, useRef, useState } from "react";
import { Download, FileKey2, KeyRound, Loader2, Trash2, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ErrorNote } from "@/components/site/bits";
import { SettingsGroup, SettingsTitle } from "@/components/settings/SettingsLayout";
import { buildExport, downloadJson } from "@/lib/secure/exportData";
import { useSecure } from "@/lib/secure/SecureContext";
import { handleOf, useSiteInfo } from "@/lib/site/siteInfo";
import { clearArchive, loadArchive, saveArchive } from "@/lib/identity/archive";
import { buildPassport, fingerprint, openPassport, ownerIdentity, readPassport, verifyPassport } from "@/lib/identity/passport";
import ArchiveBrowser from "./ArchiveBrowser";

/**
 * Experimental signed, encrypted archive. This is NOT an identity transfer or live account import.
 * Secure Net's protocol inbox/outbox and signed remote migration are not yet connected to this.
 */
export default function PassportSettings() {
  const sec = useSecure();
  const { userId, me, keyring, chainDigest } = sec;
  const info = useSiteInfo();
  const username = me?.profile?.username || "";
  const handle = handleOf(username, info) || (username ? `@${username}` : "");
  const home = (typeof window !== "undefined" && window.location.host) || info?.host || "";
  const [phrase, setPhrase] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [incoming, setIncoming] = useState(null);
  const [saved, setSaved] = useState(null); // Only the encrypted file is stored persistently.
  const [preview, setPreview] = useState(null); // Plaintext exists only while this settings screen is open.
  const [ownerFp, setOwnerFp] = useState("");
  const fileRef = useRef(null);

  useEffect(() => {
    if (!userId) return;
    let alive = true;
    setPreview(null);
    setIncoming(null);
    loadArchive(userId).then((result) => { if (alive) setSaved(result); });
    return () => { alive = false; };
  }, [userId]);

  useEffect(() => {
    let alive = true;
    setPreview(null);
    if (!phrase.trim()) { setOwnerFp(""); return undefined; }
    const timer = setTimeout(async () => {
      try {
        const owner = await ownerIdentity(phrase.trim());
        if (alive) setOwnerFp(fingerprint(owner.hybrid));
        owner.secret.fill(0);
        owner.signKey.secretKey = "";
      } catch {
        if (alive) setOwnerFp("");
      }
    }, 450);
    return () => { alive = false; clearTimeout(timer); };
  }, [phrase]);

  const run = async (name, fn) => {
    setBusy(name);
    setError("");
    setNote("");
    try { await fn(); }
    catch (err) { setError(err.message || "That didn't work."); }
    finally { setBusy(""); }
  };

  const exportPassport = () => run("export", async () => {
    if (!userId || !keyring) throw new Error("Unlock your encryption keys first.");
    const data = await buildExport(sec, { onProgress: () => {} });
    const doc = await buildPassport({
      phrase: phrase.trim(), handle, home, profile: me?.profile, userId,
      keyVersion: keyring?.versions?.[0]?.version ?? null, chainHead: chainDigest, data,
    });
    downloadJson(doc, `commonveil-encrypted-archive-${new Date().toISOString().slice(0, 10)}.json`);
    setNote("Encrypted archive downloaded. Keep it secure with your recovery phrase. Check for messages that were unavailable.");
  });

  const chooseFile = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    await run("read", async () => {
      if (file.size > 128 * 1024 * 1024) throw new Error("This archive is too large for the current preview.");
      const doc = readPassport(await file.text());
      const verdict = verifyPassport(doc);
      if (!verdict.ok) throw new Error(verdict.problems[0]);
      setIncoming(doc);
      setPreview(null);
      setNote("Signatures and encrypted content hashes verified. This has not changed your account.");
    });
    if (fileRef.current) fileRef.current.value = "";
  };

  const open = () => run("open", async () => {
    const doc = incoming || saved;
    if (!doc) throw new Error("Choose or save an archive first.");
    if (!phrase.trim()) throw new Error("Enter the recovery phrase for this archive.");
    const result = await openPassport(doc, phrase.trim());
    setPreview(result);
    setNote("Archive opened in this browser session. It is read-only, not a live account import.");
  });

  const keep = () => run("save", async () => {
    if (!incoming || !userId) throw new Error("Choose an archive first.");
    await saveArchive(userId, incoming);
    setSaved(incoming);
    setIncoming(null);
    setNote("Saved the encrypted file to this browser. Its contents will require your phrase each time.");
  });

  const forget = () => run("remove", async () => {
    await clearArchive(userId);
    setSaved(null);
    setIncoming(null);
    setPreview(null);
    setNote("Removed the encrypted archive from this browser.");
  });

  const candidate = incoming || saved;
  const status = candidate ? verifyPassport(candidate) : null;
  return (
    <>
      <SettingsTitle intro="Keep an encrypted, signed copy of the history this device can read. Full identity migration between self-hosted sites is still under development." help="your-data">
        Identity and portable archive (experimental)
      </SettingsTitle>
      <SettingsGroup title="Your current identity" description="The site address is an alias, not yet a portable protocol-level account identifier.">
        <dl className="grid gap-2 text-sm sm:grid-cols-[10rem_minmax(0,1fr)]">
          <dt className="text-muted-foreground">Current address</dt><dd className="break-all">{handle || "No federation address yet"}</dd>
          <dt className="text-muted-foreground">Current site</dt><dd className="break-all">{home}</dd>
          <dt className="text-muted-foreground">Archive signing key</dt>
          <dd>{ownerFp || "Enter your phrase below to see its fingerprint."} <span className="text-muted-foreground">(Ed25519 and ML-DSA-65)</span></dd>
        </dl>
        <p className="mt-3 text-xs text-muted-foreground">
          The archive is signed with a hybrid post-quantum key. This is a file signature, not a new sign-in method, an independently audited zero-knowledge proof, or a completed protocol migration.
        </p>
      </SettingsGroup>

      <SettingsGroup title="Export an encrypted archive" description="Your contacts and the conversations you can currently decrypt, saved in a signed file.">
        <div className="space-y-2">
          <Label htmlFor="passport-phrase">Recovery phrase or private key</Label>
          <Input id="passport-phrase" type="password" autoComplete="off" value={phrase} onChange={(e) => setPhrase(e.target.value)} placeholder="24 words or cvkey1…" />
          <p className="text-xs text-muted-foreground">
            Used by this browser to sign and encrypt the export. Only enter it on devices and websites you trust. A site can change the JavaScript it serves.
          </p>
        </div>
        <Button className="mt-3" size="sm" disabled={Boolean(busy) || !phrase.trim() || !keyring} onClick={exportPassport}>
          {busy === "export" ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Download className="mr-2 h-4 w-4" />}
          Export encrypted archive
        </Button>
        <p className="mt-3 text-xs text-muted-foreground">
          This export does not move your account, reconnect contacts, change where messages are delivered or recover expired, unavailable or unreadable messages. Attachments and server permissions may need separate handling.
        </p>
      </SettingsGroup>

      <SettingsGroup title="Read an archive from another site" description="Verify and open an encrypted file without changing the signed-in account.">
        <input ref={fileRef} type="file" accept="application/json,.json" onChange={chooseFile} className="block w-full text-sm file:mr-3 file:rounded-md file:border file:border-input file:bg-transparent file:px-3 file:py-1.5 file:text-sm file:font-medium hover:file:bg-accent" />
        {candidate && status?.ok && (
          <div className="mt-3 space-y-2 rounded-lg border p-3 text-sm">
            <p className="flex items-center gap-2 font-medium"><FileKey2 className="h-4 w-4" /> Verified encrypted archive</p>
            <p className="break-all text-muted-foreground">{status.body.handle || status.body.profile?.username || "Unnamed source"} from {status.body.home}</p>
            <p className="text-muted-foreground">{status.body.parts?.contacts?.count || 0} contacts, {status.body.parts?.archive?.messages || 0} message records. Counts are signed but not a guarantee every message is readable.</p>
            <div className="flex flex-wrap gap-2">
              <Button size="sm" disabled={Boolean(busy) || !phrase.trim()} onClick={open}>
                {busy === "open" ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <KeyRound className="mr-1.5 h-4 w-4" />}
                Unlock read-only preview
              </Button>
              {incoming && <Button size="sm" variant="outline" disabled={Boolean(busy)} onClick={keep}><Upload className="mr-1.5 h-4 w-4" /> Keep encrypted file locally</Button>}
              {saved && <Button size="sm" variant="outline" disabled={Boolean(busy)} onClick={forget}><Trash2 className="mr-1.5 h-4 w-4" /> Remove saved file</Button>}
            </div>
          </div>
        )}
        <ErrorNote>{error}</ErrorNote>
        {note && <p className="mt-2 text-sm text-primary" role="status">{note}</p>}
      </SettingsGroup>

      {preview && (
        <SettingsGroup title="Unlocked history (read-only)" description="Plaintext exists temporarily on this screen. It is not written unencrypted to browser storage.">
          <ArchiveBrowser archive={preview} />
          <p className="mt-2 text-xs text-muted-foreground">
            This is an archive viewer, not a Commonveil inbox. Existing conversations and contacts have not been added to the destination account.
          </p>
        </SettingsGroup>
      )}
      <p className="text-xs text-muted-foreground">
        Secure Net remains the independent protocol for inboxes, outboxes and federation. A fully portable, end-to-end encrypted account move requires its separately reviewed transfer and routing extension.
      </p>
    </>
  );
}
