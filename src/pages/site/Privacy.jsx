import React from "react";
import { Link } from "react-router-dom";
import { PageHeader } from "@/components/site/bits";

const HOLD = [
  ["Your sign-in email", "Used by our hosting platform (Base44) to sign you in and for password resets, and by us only for security emails: when a device is added to your account, when your recovery phrase is used, when someone asks to reset your encryption and when a reset completes, and a week before an account you've set to delete itself is deleted. The emails say what happened and when, and nothing about your devices or who you talk to. Your address is never shown to other members, and an alias works fine."],
  ["Your username, display name and short bio", "Visible only to people who look up your exact username or share a conversation with you."],
  ["Public keys and your device list", "Public keys let others encrypt to you and check your signatures. Your device list includes a label like \"Firefox on Linux\" so you can recognise them; other members don't see labels."],
  ["Who is in each conversation, and when messages are sent", "We need this to deliver messages. We can see that you and someone else exchanged messages, roughly how large they were, and which accounts each message was encrypted for."],
  ["Encrypted messages and group names", "Stored as ciphertext. We have no key that opens them. Replies, reactions and edits are encrypted messages too, so we can't tell them apart from any other message or see what they point at."],
  ["Conversation settings", "A group's admins, and a conversation's disappearing-message timer with who last changed it and when. The server needs these to enforce them."],
  ["Disappearing messages", "With a timer on, each new message is stored with the time it's due to go. When that time comes your app stops showing it, and the server deletes it (blanked first) within about half an hour."],
  ["Auto-delete, only if you turn it on", "The date (not the time) you last opened Commonveil, and whether you've been sent the warning. Turning it off forgets the date. If it's off, we keep nothing about when you use Commonveil."],
  ["Encrypted backup of your keys", "Sealed to your recovery phrase. Without the phrase it's unreadable, including to us."],
  ["Servers you're in", "Which servers you belong to, your roles there, whether you chose to be listed, and when you joined. Server names, channel and role names, rules, nicknames and messages are encrypted. A server listed in Discover has a public card its admins wrote."],
  ["Calls", "For a minute, a single-use pass saying your device may join a call. While you're in a call, the relay knows you're in it so it can introduce your device to the others, and on a stage who may speak. Audio and video never reach us, and nothing about a call is kept after it."],
  ["Scheduled messages and check-ins", "Encrypted when you write them, held apart from messages until they're due, then delivered and the held copy deleted (blanked first). We see when each is due and who it's for, never what it says. Cancelling or checking in needs one of your devices."],
  ["Self-destructing conversations", "The time a conversation is set to erase itself and who set it. When it comes, everything in it is deleted for everyone, blanked first, within a few minutes."],
  ["Files and voice messages", "The encrypted parts, their sizes, and which message and place they belong to. Their names, types, keys and contents travel inside the encrypted message. Parts are forgotten once their message is deleted or disappears."],
  ["Reports and moderation", "If you report someone in a server, we know you reported them and when, not what you said: it's encrypted to that server's moderators. Warnings and notes are encrypted too; we keep a numbered record that they exist. If you or a moderator choose to tell the Commonveil team, we read what you wrote."],
  ["Events", "That a server has an event, and which members answered it. What it's called, when and where it is, and the answers are encrypted."],
  ["Online status, only if you turn it on", "While you share it, the live room for the server or conversation you have open knows you're there and when you're typing. It's kept in memory and written nowhere, and gone when you close it."],
  ["Support tickets", "A ticket is an encrypted group with the server's support team. We know who's in it, its number and whether it's open, not what's said."],
  ["Blocks and reports", "If you report someone, staff see the reason and anything you choose to paste in. They can't read your messages. A report about someone stays with staff even if that person later deletes their account."],
];

const NEVER = [
  "Your messages or group names, in readable form",
  "Your private keys, your 24-word recovery phrase or your passcode",
  "What you've read: read markers stay on your device",
  "What you search for: message search runs on your device, site search in your browser",
  "Your notification settings: they stay in your browser, and there are no push notifications",
  "Analytics, advertising IDs or third-party trackers: this site's code has none",
];

const ON_DEVICE = [
  ["Quiet hours and focus", "When notifications stay silent. We never learn when you sleep or don't want to be disturbed."],
  ["Your privacy checkup", "Worked out on your device from settings it already has. Which suggestions you follow isn't sent anywhere."],
  ["Passcode lock", "If you set one, your keys on that browser are stored encrypted with it. The passcode itself is never stored or sent."],
  ["Your organisation", "Saved messages, private notes on people, server folders and per-channel notification choices are kept in this browser only."],
  ["Online status and typing", "Whether you share them. Off unless you turn them on."],
  ["Alerts", "Whether to show notifications, whether they name the sender, and whether to put an unread count in the tab title. All off until you turn them on."],
  ["Your data download", "Made in your browser from what you can already see, and saved straight to your device. It holds your messages in readable form, so keep it safe."],
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
          <div className="card-cv p-6">
            <h2 className="text-xl font-semibold">Kept only in your browser</h2>
            <dl className="mt-4 space-y-3 text-sm">
              {ON_DEVICE.map(([t, d]) => (
                <div key={t}>
                  <dt className="font-semibold">{t}</dt>
                  <dd className="mt-0.5 text-muted-foreground">{d}</dd>
                </div>
              ))}
            </dl>
          </div>
          <div className="card-cv p-6 text-sm text-muted-foreground">
            <h2 className="text-lg font-semibold text-foreground">Where it lives</h2>
            <p className="mt-2">
              Commonveil runs on Base44, which hosts the database and handles sign-in. Base44 can see the same metadata we can. End-to-end
              encryption is what keeps message content out of reach of both of us.
            </p>
            <h2 className="mt-5 text-lg font-semibold text-foreground">Deleting your data</h2>
            <p className="mt-2">
              You can download everything we hold about your account from Settings, decrypted in your browser. You can also set your account
              to delete itself after six months or a year without use.
            </p>
            <p className="mt-2">
              You can delete single messages, remove devices, or delete your whole account from Settings. Account deletion blanks and then
              deletes your profile, keys, devices and every message you've sent. Direct-message conversations go for both people, and you're
              removed from groups. Your username is retired rather than freed: it's kept on its own, linked to nothing, so nobody else can
              claim it and pose as you to people who knew you. Reports you made go; reports other people made about you stay with staff, so
              deleting an account can't erase a record of abuse.
            </p>
            <p className="mt-2">
              If your sign-in is removed in Base44 rather than here, staff can erase what's left in exactly the same way.
            </p>
            <p className="mt-2">
              Messages other people sent to a group while you were in it stay in that group. Each one records the account numbers it was
              encrypted for, so yours stays in them; once Base44 erases your sign-in, that number no longer points to anyone.
            </p>
            <p className="mt-2">
              Two things are outside our control. Base44 keeps removed sign-ins for 30 days before erasing them, along with the email address.
              And Base44 keeps deleted records in a recycle bin and, on some plans, up to 30 days of change history. We blank everything before
              deleting it, so the recycle bin holds nothing readable, but change history can hold earlier versions until it expires.
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
