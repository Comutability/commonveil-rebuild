import React from "react";
import { Link } from "react-router-dom";
import { PageHeader } from "@/components/site/bits";

const PIECES = [
  ["Account keys", "Each account has a signing key pair (P-256) and an encryption key that's post-quantum hybrid: ML-KEM-768 combined with P-256, so breaking it needs both broken. Every device you approve holds them. They're published as signed statements, so a new key must be signed by the previous one."],
  ["Device keys", "Each browser also has its own signing key, created so it can't be exported. Your account key certifies each device; the server rejects messages from devices that aren't certified and active."],
  ["Messages", "Each message gets a fresh 256-bit key and is encrypted with AES-256-GCM. That key is sealed separately to every member's current account key, with the post-quantum hybrid, and the whole thing is bound to the conversation, message, sender and device."],
  ["Servers", "A server's channels are encrypted with shared key chains. Members' apps hand the keys to newcomers, sealed to each newcomer's account key with the post-quantum hybrid. The server only stores ciphertext and checks permissions. Channel names, roles, rules, the server's own name, its picture and banner, and the welcome new members see are encrypted too."],
  ["History from joining", "Most channels use a key that moves on every hour, one way only. Someone who joins gets the key from that hour, so they can't read what was said before they arrived. Channels set to full history use a key newcomers get from the start."],
  ["Private channels", "A private channel has its own key chain, given only to the members who can see it. Removing someone's access moves the chain to a new key they never get."],
  ["Invites", "An invite link ends in a secret after the #. Browsers never send that part to us, and the server's name in the preview is encrypted with it, so the invite list can't be used to rebuild links or read previews."],
  ["Member lists", "Nobody is listed unless they choose to be, except staff, so members can see who runs a server. There's no list of everyone for moderators."],
  ["Online status and typing", "Off unless you turn them on, and mutual: you only see other people's while you share yours. They pass through a live room that keeps them in memory and writes nothing down, only for the server or conversation you have open. Typing is never shared in private channels."],
  ["Files and voice messages", "Encrypted on your device before upload, in parts, each with AES-256-GCM under a key made for that file and bound to its place in the file. The key, name and type travel inside the encrypted message. The service stores sealed parts it can't read and hands out links that last five minutes, only to people who can see where the file was sent."],
  ["Threads, polls and events", "Thread replies, polls, votes, scheduled events and the answers to them are encrypted like messages. The service sees that there's a thread, a reply or an event, and who answered an event, but not what anything says, or an event's time or place."],
  ["Reports and moderation", "Reports to a server's moderators are sealed to exactly those moderators, with their keys, so even we can't read them. Warnings and notes are encrypted with the server's key. Automatic rules (warning steps, flood and raid protection, limits on staff actions) work from counts alone. A moderator can choose to send a report on to the Commonveil team, and then shares what they write with us readably."],
  ["Emoji, stickers and AutoMod", "A server's own emoji and stickers are shrunk on the uploader's device and kept in one encrypted item, so only members see them or their names. AutoMod rules are encrypted too, and members' apps apply them: the sender's app won't send a message that breaks them, and everyone else's hides one that does."],
  ["Voice calls", "Audio goes directly between the devices in a call, encrypted by WebRTC. Before connecting, each app checks that the other device's connection key was signed by a device certified for that member. Every audio and video frame is also sealed with AES-256-GCM under a key from the channel's chain, so the post-quantum protection covers calls too. Calls in conversations use a fresh key sent inside the encrypted message that starts the call. On a stage, apps don't play anyone a moderator hasn't brought up to speak."],
  ["Signatures", "The sending device signs every message. Your app checks the signature and the device's certificate back to the sender's account key before marking a message as verified."],
  ["Adding a device", "A new browser stays pending until a device you already have approves it after you compare a 20-digit code on both screens, or until you enter your recovery phrase. The code covers the new device's keys and your account's whole key history, so neither can be swapped. A signed-in session alone can't add a device."],
  ["Recovery phrase", "24 standard words that derive a recovery key. Your devices keep an encrypted backup of your keys sealed to it, and keys published with the phrase carry a check only the phrase can make, so a new device can't be handed a forged account. The phrase never leaves your head or your paper."],
  ["Removing a device", "Removing a device rotates your keys: a new version signed by the old one goes to your remaining devices, so the removed one can't read anything new. Anything it signs after its removal is marked as such."],
  ["Safety numbers", "A 60-digit number for each pair of people, covering every key each of you has ever had. If it matches when you compare in person, nobody has swapped any of them. If a contact's keys change unexpectedly, the app tells you before you send."],
  ["Who's in a group", "The server keeps member lists, so starting a conversation or adding someone needs a signature from one of your devices, not just your password. When you're added to a group you're shown who's in it before you can send, everyone else's app pauses until they've seen who's new, and newcomers don't see earlier messages."],
  ["If you lose everything", "With every device and your phrase gone, you can reset your encryption. It waits seven days: your devices show the request and can cancel it, using your phrase cancels it, and we email your sign-in address. So someone who only has your password can't take your account over."],
  ["Security emails", "Your sign-in address is told when a device is added, when your recovery phrase is used and when a reset is asked for or completes. If that wasn't you, you'll know to act."],
  ["Replies, reactions and edits", "Each is an ordinary encrypted, signed message, so the server can't tell them from any other. Your app only accepts an edit from the person who sent the original, within a day of sending it, and shows that it was edited. Reactions are limited to a fixed list of emoji (and, in servers, the server's own), so a reaction can't carry a hidden message."],
  ["Disappearing messages", "The timer goes inside each encrypted, signed message as well as on the server, so the server can't keep a message showing longer than its sender chose. Either person in a direct message, or a group's admins, can set it, and everyone sees who did."],
  ["Group admins", "Whoever starts a group runs it and can make others admins. Only admins can add or remove people, rename the group or change its timer, and the server enforces it with a signature from one of their devices. A group always keeps at least one admin."],
  ["Passcode lock", "Optional, per browser. Your keys there are encrypted with a key made from your passcode (PBKDF2-SHA-256, 600,000 rounds, then AES-256-GCM). Locked, the keys aren't in memory and nothing is shown. It locks after the time you choose, and locking one tab locks the others."],
];

const LIMITS = [
  "Metadata isn't hidden. The server knows who is in each conversation and when messages are sent.",
  "There's no forward secrecy yet. Anyone who steals an account key can read past messages sent to that key. Removing a device or changing your phrase rotates keys, which limits what a stolen key can read from then on.",
  "The server can delay, drop or reorder messages. Each message is checked on its own, but the conversation as a whole isn't.",
  "A compromised device, browser extension or malicious script on the page can read what you can read. Keep your browser up to date and extensions few.",
  "Keys are stored in this browser's storage. Anyone with full access to your unlocked browser profile can use them. On shared computers, sign out with \"remove this device\". A passcode lock keeps the message keys encrypted while it's locked, but someone who copies the browser's files can try passcodes offline, so use a long one. Each browser's own signing key can't be exported, which also means it can't be locked: code running in your browser profile could still use it.",
  "Disappearing messages can't stop anyone copying, photographing or screenshotting a message before it goes, and the hosting platform may keep backups of deleted records for a time.",
  "Notifications are shown by your browser and operating system, which may keep them in a notification history. They say \"New message\" and, only if you choose, who it's from.",
  "Web apps are delivered fresh on every visit, so you are trusting the code served to you each time. Native apps with reproducible builds would reduce that; they're not built yet.",
  "Post-quantum protection covers how keys are shared, so recorded messages and calls stay safe from a future quantum computer. Signatures are still P-256: such a computer could forge them, which would let someone impersonate a device from then on, but not read what was recorded.",
  "In servers, the service sees who is in which server, their roles, how many channels there are and when messages are sent. A server listed in Discover publishes a public card (name, description, tags) that isn't encrypted.",
  "The community server everyone joins uses keys handed out only by its staff, so members can't see who joins. Until a staff member's device is online, newcomers wait for keys.",
  "A call connects devices directly, so the people in it can see each other's network address, and a STUN server (Cloudflare's) sees yours when you join. The service sees who joined which call and when. Some strict networks can't connect, because there's no relay server.",
  "Display names aren't unique, so anyone can call themselves anything. Check the @username, shown beside names in groups and in conversation details.",
  "A removed device working with the server could make a message look as if it was sent before the device was removed.",
  "AutoMod runs in members' apps, not on the service, because the service can't read messages. Someone with a modified app can still send a message that breaks the rules; everyone else's app hides it, but it's been delivered.",
  "File sizes and the number of parts are visible to the service, as are when files are uploaded and downloaded. Links to download a file work for five minutes for whoever has them.",
  "Calls connect every pair of people directly, so they're limited to 8 people (16 on a stage, where listeners send nothing).",
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
            The full protocol description and threat model are kept with the source. Until an independent review is complete, please don't rely
            on Commonveil where your physical safety depends on it.
          </p>
          <p className="mt-3 text-muted-foreground">
            Found a problem?{" "}
            <Link to="/security/report" className="font-medium text-primary underline">Report it privately</Link>. You don't need an account.
          </p>
        </section>
      </div>
    </>
  );
}