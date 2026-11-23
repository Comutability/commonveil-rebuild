import React, { useEffect, useRef, useState } from "react";
import { ArrowRight, CheckCircle2, Download, Globe, KeyRound, Loader2, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ErrorNote } from "@/components/site/bits";
import { SettingsGroup } from "@/components/settings/SettingsLayout";
import { buildExport, downloadJson } from "@/lib/secure/exportData";
import { useSecure } from "@/lib/secure/SecureContext";
import { handleOf, useSiteInfo } from "@/lib/site/siteInfo";
import { clearArchive, loadArchive, loadChain, saveArchive, saveChain } from "@/lib/identity/archive";
import { buildPassport, fingerprint, makeMove, nextSeq, openPassport, ownerIdentity, readPassport, verifyPassport } from "@/lib/identity/passport";
import ArchiveBrowser from "./ArchiveBrowser";

/**
 * An identity passport (docs/IDENTITY.md): the account's owner key in quantum-resistant form, its
 * move history, contacts and messages, sealed under the recovery phrase. Export it from here and
 * open it on any Commonveil site; no site can read it on the way.
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
  const [chain, setChain] = useState([]);
  const [archive, setArchive] = useState(null);
  const [moveTo, setMoveTo] = useState("");
  const [incoming, setIncoming] = useState(null);
  const [ownerFp, setOwnerFp] = useState("");
  const fileRef = useRef(null);

  useEffect(() => {
    if (!userId) return;
    loadChain(userId).then(setChain);
    loadArchive(userId).then(setArchive);
  }, [userId]);

  // Reading the phrase gives the owner key's fingerprint, so it can be compared out loud with
  // what another site or a friend shows. It reveals nothing: a fingerprint of a public key.
  useEffect(() => {
    let live = true;
    const typed = phrase.trim();
    if (typed.length < 12) {
      setOwnerFp("");
      return undefined;
    }
    const timer = setTimeout(async () => {
      try {
        const owner = await ownerIdentity(typed);
        owner.secret.fill(0);
        if (live) setOwnerFp(fingerprint(owner.hybrid));
      } catch {
        if (live) setOwnerFp("");
      }
    }, 400);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [phrase]);

  const run = async (name, fn) => {
    setBusy(name);
    setError("");
    setNote("");
    try {
      await fn();
    } catch (err) {
      setError(err.message || "That didn't work.");
    } finally {
      setBusy("");
    }
  };

  const exportPassport = () =>
    run("export", async () => {
      const data = await buildExport(sec, { onProgress: () => {} });
      const file = await buildPassport({
        phrase,
        handle,
        home,
        profile: me?.profile,
        userId,
        keyVersion: keyring?.versions?.[0]?.version ?? null,
        chainHead: chainDigest,
        data,
        chain,
      });
      downloadJson(file, `commonveil-passport-${new Date().toISOString().slice(0, 10)}.json`);
      setNote("Saved. Keep it somewhere only you can reach: it holds your contacts and your messages, sealed under your phrase.");
    });

  const move = () =>
    run("move", async () => {
      const to = moveTo.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      if (!to) throw new Error("Name the site you're moving to, like chat.example.com.");
      const owner = await ownerIdentity(phrase);
      try {
        const notice = makeMove({ subject: handle || username || home, from: home, to, seq: nextSeq(chain) }, owner.signKey);
        const next = [...chain, notice];
        await saveChain(userId, next);
        setChain(next);
      } finally {
        owner.secret.fill(0);
      }
      setMoveTo("");
      setNote("Recorded. Your next passport carries the move, signed by your key, so the site you're on now can't claim you still live there.");
    });

  const chooseFile = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    await run("read", async () => {
      const doc = readPassport(await file.text());
      const verdict = verifyPassport(doc);
      setIncoming({ doc, verdict });
      if (!verdict.ok) throw new Error(verdict.problems[0]);
      setNote(`This is ${verdict.body.profile?.display_name || verdict.body.handle || "an identity"}'s passport, and it checks out.`);
    });
  };

  const keep = () =>
    run("keep", async () => {
      const { doc } = incoming;
      const opened = await openPassport(doc, phrase);
      const saved = await saveArchive(userId, {
        from: opened.body.home,
        imported_at: new Date().toISOString(),
        body: opened.body,
        contacts: opened.contacts,
        data: opened.data,
      });
      await saveChain(userId, opened.body.chain || []);
      setChain(opened.body.chain || []);
      setArchive(saved);
      setIncoming(null);
      if (fileRef.current) fileRef.current.value = "";
      setNote(`Brought ${opened.contacts.length} contact${opened.contacts.length === 1 ? "" : "s"} and ${opened.data?.conversations?.length || 0} conversation${opened.data?.conversations?.length === 1 ? "" : "s"} across. They stay in this browser.`);
    });

  const forget = () =>
    run("forget", async () => {
      await clearArchive(userId);
      setArchive(null);
      setNote("The brought archive is gone from this browser.");
    });

  return (
    <>
      <SettingsGroup
        title="Your identity"
        description="Your account belongs to a key made from your recovery phrase, not to this site. Nothing here needs an email address, and no site can take the account from you."
      >
        <dl className="grid gap-2 text-sm sm:grid-cols-[9rem_minmax(0,1fr)]">
          <dt className="text-muted-foreground">Address</dt>
          <dd className="break-all font-medium">{handle || "This site doesn't federate yet, so you have no cross-site address."}</dd>
          <dt className="text-muted-foreground">Home</dt>
          <dd className="break-all">{home}</dd>
          <dt className="text-muted-foreground">Owner key</dt>
          <dd className="break-all">{ownerFp || "Enter your phrase below to see it."} <span className="text-muted-foreground">(Ed25519 + ML-DSA-65)</span></dd>
          <dt className="text-muted-foreground">Moves</dt>
          <dd>{chain.length ? `${chain.length}, most recently ${chain[chain.length - 1]?.body?.to}` : "None: this is where your account has always lived."}</dd>
        </dl>
        <p className="mt-3 text-xs text-muted-foreground">
          A passport is signed twice: once with Ed25519 and once with ML-DSA-65, so a quantum computer can't forge one. It also carries a zero-knowledge proof of your owner key: the site you arrive at learns that you hold it, and nothing else.
        </p>
      </SettingsGroup>

      <SettingsGroup
        title="Take it with you"
        description="A passport holds your identity, your contacts and your messages in one file, sealed under your recovery phrase. Any Commonveil site can check it; none can read what's inside."
      >
        <div className="space-y-2">
          <Label htmlFor="passport-phrase">Your recovery phrase, or private key</Label>
          <Input
            id="passport-phrase"
            type="password"
            autoComplete="off"
            value={phrase}
            onChange={(e) => setPhrase(e.target.value)}
            placeholder="24 words, or cvkey1…"
          />
          <p className="text-xs text-muted-foreground">Used here in your browser only, and never sent anywhere. It's the one thing that makes a passport yours, so it's asked for each time.</p>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <Button size="sm" disabled={Boolean(busy) || !phrase} onClick={exportPassport}>
            {busy === "export" ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" aria-hidden="true" /> : <Download className="mr-1.5 h-4 w-4" aria-hidden="true" />}
            Export a passport
          </Button>
        </div>

        <div className="mt-5 space-y-2 border-t border-border/60 pt-4">
          <Label htmlFor="passport-move">Moving to another site?</Label>
          <div className="flex flex-wrap gap-2">
            <Input
              id="passport-move"
              value={moveTo}
              onChange={(e) => setMoveTo(e.target.value)}
              placeholder="chat.example.com"
              className="max-w-xs"
            />
            <Button size="sm" variant="outline" disabled={Boolean(busy) || !phrase || !moveTo.trim()} onClick={move}>
              {busy === "move" ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" aria-hidden="true" /> : <ArrowRight className="mr-1.5 h-4 w-4" aria-hidden="true" />}
              Record the move
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            This signs a notice with your key saying where you've gone. It goes into your next passport, and other sites follow the chain, so a site you've left can't pass itself off as your current one.
          </p>
        </div>
      </SettingsGroup>

      <SettingsGroup
        title="Bring an identity here"
        description="Open a passport made on another site. It's checked here, in your browser: the signatures, the zero-knowledge proof, and every move in its history."
      >
        <input
          ref={fileRef}
          type="file"
          accept="application/json,.json"
          onChange={chooseFile}
          className="block w-full text-sm file:mr-3 file:rounded-md file:border file:border-input file:bg-transparent file:px-3 file:py-1.5 file:text-sm file:font-medium hover:file:bg-accent"
        />
        {incoming && (
          <div className="mt-3 space-y-2 rounded-lg border border-border p-3 text-sm">
            <p className="flex items-center gap-2 font-medium">
              {incoming.verdict.ok ? <CheckCircle2 className="h-4 w-4 text-primary" aria-hidden="true" /> : <KeyRound className="h-4 w-4 text-destructive" aria-hidden="true" />}
              {incoming.verdict.ok ? "Checks out" : "This passport can't be trusted"}
            </p>
            {incoming.verdict.ok ? (
              <ul className="space-y-1 text-muted-foreground">
                <li>{incoming.verdict.body.profile?.display_name || incoming.verdict.body.profile?.username || "Unnamed"}{incoming.verdict.body.handle ? ` (${incoming.verdict.body.handle})` : ""}</li>
                <li>Home: {incoming.verdict.body.home}</li>
                <li>{incoming.verdict.body.parts?.contacts?.count || 0} contacts, {incoming.verdict.body.parts?.archive?.messages || 0} messages</li>
                <li>{(incoming.verdict.body.chain || []).length} recorded move{(incoming.verdict.body.chain || []).length === 1 ? "" : "s"}, in order</li>
              </ul>
            ) : (
              <ul className="list-disc space-y-1 pl-5 text-muted-foreground">
                {incoming.verdict.problems.map((p) => <li key={p}>{p}</li>)}
              </ul>
            )}
            {incoming.verdict.ok && (
              <Button size="sm" disabled={Boolean(busy) || !phrase} onClick={keep}>
                {busy === "keep" ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" aria-hidden="true" /> : <Upload className="mr-1.5 h-4 w-4" aria-hidden="true" />}
                Open it and keep it
              </Button>
            )}
          </div>
        )}
        <ErrorNote>{error}</ErrorNote>
        {note && <p className="mt-2 text-sm text-primary" role="status">{note}</p>}
      </SettingsGroup>

      {archive && (
        <SettingsGroup
          title="Your archive, brought along"
          description={`From ${archive.from || "another site"}, kept ${archive.imported_at ? new Date(archive.imported_at).toLocaleDateString() : ""}. Only this browser has it; the site it's stored on can't read a word.`}
        >
          <ArchiveBrowser archive={archive} />
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <p className="text-xs text-muted-foreground">{archive.contacts?.length || 0} contacts came with it.</p>
            <Button size="sm" variant="outline" disabled={Boolean(busy)} onClick={forget}>Remove the archive</Button>
          </div>
        </SettingsGroup>
      )}

      <p className="flex items-start gap-2 text-xs text-muted-foreground">
        <Globe className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        The protocol's inbox and outbox stay the way sites reach each other, sealed hop by hop. Your passport never travels that way in readable form: it's a file you carry, and a site only ever sees it when you choose to open it there.
      </p>
    </>
  );
}