import React from "react";
import { PageHeader } from "@/components/site/bits";

const PIECES = [
  ["Account keys", "Each account has an encryption key pair and a signing key pair (P-256). Every device you approve holds them. They're published as signed statements, so a new key must be signed by the previous one."],
  ["Device keys", "Each browser also has its own signing key, created so it can't be exported. Your account key certifies each device; the server rejects messages from devices that aren't certified and active."],
  ["Messages", "Each message gets a fresh 256-bit key and is encrypted with AES-256-GCM. That key is sealed separately to every member's current account key, and the whole thing is bound to the conversation, message, sender and device."],
  ["Signatures", "The sending device signs every message. Your app checks the signature and the device's certificate back to the sender's account key before marking a message as verified."],
  ["Adding a device", "A new browser stays pending until a device you already have approves it after you compare a 20-digit code on both screens, or until you enter your recovery phrase. A signed-in session alone can't add a device."],
  ["Recovery phrase", "24 standard words that derive a recovery key. Your devices keep an encrypted backup of your keys sealed to it. The phrase never leaves your head or your paper."],
  ["Removing a device", "Removing a device rotates your keys: a new version signed by the old one goes to your remaining devices, so the removed one can't read anything new."],
  ["Safety numbers", "A 60-digit number for each pair of people. If it matches when you compare in person, nobody has swapped the keys. If a contact's keys change unexpectedly, the app tells you before you send."],
  ["Who's in a group", "The server keeps member lists, so adding someone needs a signature from one of your devices, not just your password. Everyone else's app pauses before sending until they've seen who's new."],
];

const LIMITS = [
  "Metadata isn't hidden. The server knows who is in each conversation and when messages are sent.",
  "There's no forward secrecy yet. Anyone who steals an account key can read past messages sent to that key. Removing a device or changing your phrase rotates keys, which limits what a stolen key can read from then on.",
  "The server can delay, drop or reorder messages. Each message is checked on its own, but the conversation as a whole isn't.",
  "A compromised device, browser extension or malicious script on the page can read what you can read. Keep your browser up to date and extensions few.",
  "Keys are stored in this browser's storage. Anyone with full access to your unlocked browser profile can use them. On shared computers, sign out with \"remove this device\".",
  "Web apps are delivered fresh on every visit, so you are trusting the code served to you each time. Native apps with reproducible builds would reduce that; they're not built yet.",
  "Encryption doesn't use post-quantum algorithms yet.",
  "There has been no independent audit. The protocol is documented and has automated tests, including attack cases, but that isn't the same thing.",
];

export default function Security() {
  return (
    <>
      <PageHeader
        eyebrow="Security"
        title="How the encryption works, and where it stops"
        intro="Commonveil was rebuilt in October 2026 around a small protocol that can be reviewed in an afternoon. Here's all of it, in plain language."
      />
      <div className="container-cv space-y-14 py-12">
        <section>
          <h2 className="text-2xl font-semibold">The pieces</h2>
          <ul className="mt-6 grid gap-4 md:grid-cols-2">
            {PIECES.map(([t, d]) => (
              <li key={t} className="card-cv p-5">
                <h3 className="font-semibold">{t}</h3>
                <p className="mt-1.5 text-sm text-muted-foreground">{d}</p>
              </li>
            ))}
          </ul>
        </section>
        <section className="max-w-3xl">
          <h2 className="text-2xl font-semibold">What it doesn't protect</h2>
          <ul className="mt-4 list-disc space-y-2 pl-5 text-muted-foreground">
            {LIMITS.map((l) => <li key={l}>{l}</li>)}
          </ul>
        </section>
        <section className="max-w-3xl">
          <h2 className="text-2xl font-semibold">Status</h2>
          <p className="mt-3 text-muted-foreground">
            The full protocol description and threat model are kept with the source. A private address for reporting security problems will be
            published here before Commonveil opens to the public. Until an independent review is complete, please don't rely on Commonveil where
            your physical safety depends on it.
          </p>
        </section>
      </div>
    </>
  );
}
