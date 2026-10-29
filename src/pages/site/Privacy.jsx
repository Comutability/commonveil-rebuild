import React from "react";
import { Link } from "react-router-dom";
import { PageHeader } from "@/components/site/bits";

const HOLD = [
  ["Your sign-in email", "Used only to sign you in and for password resets, by our hosting platform (Base44). It is never shown to other members. An alias address works fine."],
  ["Your username, display name and short bio", "Visible only to people who look up your exact username or share a conversation with you."],
  ["Public keys and your device list", "Public keys let others encrypt to you and check your signatures. Your device list includes a label like \"Firefox on Linux\" so you can recognise them; other members don't see labels."],
  ["Who is in each conversation, and when messages are sent", "We need this to deliver messages. We can see that you and someone else exchanged messages and roughly how large they were."],
  ["Encrypted messages and group names", "Stored as ciphertext. We have no key that opens them."],
  ["Encrypted backup of your keys", "Sealed to your recovery phrase. Without the phrase it's unreadable, including to us."],
  ["Blocks and reports", "If you report someone, staff see the reason and anything you choose to paste in. They can't read your messages."],
];

const NEVER = [
  "Your messages or group names, in readable form",
  "Your private keys or your 24-word recovery phrase",
  "What you've read: read markers stay on your device",
  "Analytics, advertising IDs or third-party trackers: this site's code has none",
];

export default function Privacy() {
  return (
    <>
      <PageHeader eyebrow="Privacy" title="Exactly what we hold, and what we can't see" intro="Plain language, no surprises. If something here is wrong, it's a bug: tell us." />
      <div className="container-cv grid gap-12 py-12 lg:grid-cols-[1.4fr_1fr]">
        <section>
          <h2 className="text-2xl font-semibold">What we store</h2>
          <dl className="mt-6 space-y-6">
            {HOLD.map(([t, d]) => (
              <div key={t} className="border-l-2 border-primary/50 pl-4">
                <dt className="font-semibold">{t}</dt>
                <dd className="mt-1 text-muted-foreground">{d}</dd>
              </div>
            ))}
          </dl>
        </section>
        <aside className="space-y-6">
          <div className="card-cv p-6">
            <h2 className="text-xl font-semibold">What we never have</h2>
            <ul className="mt-4 list-disc space-y-2 pl-5 text-muted-foreground">
              {NEVER.map((n) => <li key={n}>{n}</li>)}
            </ul>
          </div>
          <div className="card-cv p-6 text-sm text-muted-foreground">
            <h2 className="text-lg font-semibold text-foreground">Where it lives</h2>
            <p className="mt-2">
              Commonveil runs on Base44, which hosts the database and handles sign-in. Base44 can see the same metadata we can. End-to-end
              encryption is what keeps message content out of reach of both of us.
            </p>
            <h2 className="mt-5 text-lg font-semibold text-foreground">Deleting your data</h2>
            <p className="mt-2">
              You can delete individual messages and remove devices today. Self-service account deletion isn't built yet; it's next on the list,
              and this page will say when it's live.
            </p>
            <p className="mt-4">
              See <Link to="/security" className="text-primary underline">Security</Link> for how the encryption works and its limits.
            </p>
          </div>
        </aside>
      </div>
    </>
  );
}
