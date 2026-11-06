# Commonveil: the complete guide

Everything Commonveil does, what each feature is for, how to use it, and exactly what it shares.

The same guide is on the website, one topic per page, at [https://commonveil-rebuild-71d823fd.base44.app/help](https://commonveil-rebuild-71d823fd.base44.app/help).

> This file is generated from `src/content/help/*.md` by `scripts/build-user-guide.mjs`. Edit the articles, then run
> `node scripts/build-user-guide.mjs`; `npm test` fails if this file is out of date. For the technical design, see
> `PROTOCOL.md`, `SERVERS_AND_VOICE.md` and `THREAT_MODEL.md` in this folder.

## Contents

**Getting started**

- [Welcome to Commonveil](#welcome-to-commonveil): What Commonveil is for, what makes it different, and where to start.
- [Create your account](#create-your-account): Sign in, choose a username, make your keys and keep your recovery phrase safe.
- [Devices, recovery and resets](#devices-recovery-and-resets): Add another device, remove a lost one, use your recovery phrase, and what a reset does.
- [Install the app](#install-the-app): Use Commonveil like an app on your phone, tablet or computer, with its own icon and window.

**Messages and calls**

- [Direct messages and groups](#direct-messages-and-groups): Start a conversation, make a group, manage who's in it and who runs it.
- [Writing and sending messages](#writing-and-sending-messages): Formatting, replies, reactions, edits, files, voice messages, polls, stickers and more.
- [Voice and video calls](#voice-and-video-calls): Calls in conversations, voice channels and stages, with camera and screen sharing.
- [Disappearing messages and self-destructing conversations](#disappearing-messages-and-self-destructing-conversations): Have messages delete themselves after a while, or set a whole conversation to erase itself.
- [Send later and safety check-ins](#send-later-and-safety-check-ins): Write a message now and have it delivered later, or have it sent only if you don't check in.
- [Offline mode](#offline-mode): Keep writing with no connection. Messages are sealed now and sent when you're back.
- [People on other sites](#people-on-other-sites): Your address, talking to people on other Commonveil sites, and joining their servers.

**Servers**

- [Joining and using servers](#joining-and-using-servers): Join with an invite or from Discover, find your way around, and choose how visible you are.
- [Channels, threads and more](#channels-threads-and-more): Text, announcement, forum, voice, stage, ticket and rules channels; threads, pins, saved messages, events, emoji and stickers.

**Running a server**

- [Creating and setting up a server](#creating-and-setting-up-a-server): Make a server, invite people, set up channels, roles, privacy, rules and discovery.
- [Roles and permissions](#roles-and-permissions): What each permission allows, how roles stack, and how to make a channel private.
- [Moderation and safety tools](#moderation-and-safety-tools): Reports, escalating to Commonveil, warnings, timeouts, kicks and bans, AutoMod, spam and raid protection, staff limits and lockdown.

**Privacy and safety**

- [Safety numbers and key changes](#safety-numbers-and-key-changes): Prove nobody is in the middle of your conversation, and what to do when someone's keys change.
- [Privacy settings, blocking and reporting](#privacy-settings-blocking-and-reporting): Choose who can contact you and see your profile, share your online status or not, block and report.
- [Privacy report and checkup](#privacy-report-and-checkup): See everything Commonveil holds about you, and a checklist of ways to share less.
- [Passcode lock and keeping your account safe](#passcode-lock-and-keeping-your-account-safe): Lock this browser's keys with a passcode, and simple habits that keep your account yours.
- [How the encryption works](#how-the-encryption-works): In plain language: what end-to-end encryption protects, what Commonveil can and can't see, and the limits.

**Your account**

- [Notifications, quiet hours and focus](#notifications-quiet-hours-and-focus): Get alerts without giving anything away, silence them overnight or for a while, and mute what's noisy.
- [Your profile and how Commonveil looks](#your-profile-and-how-commonveil-looks): Display name, pronouns, bio, avatar and colour; theme, text size, message layout and motion.
- [Download your data or delete your account](#download-your-data-or-delete-your-account): Get a copy of everything, have your account delete itself if unused, or delete it now.
- [Sign-in, passkeys and recovery](#sign-in-passkeys-and-recovery): Your username and password, passkeys, confirming a new device, and getting back in.

**Running your own site**

- [Run your own Commonveil site](#run-your-own-commonveil-site): Host Commonveil on your own hardware with Docker, keep it up to date, and run it with no internet.

**Help**

- [Troubleshooting and questions](#troubleshooting-and-questions): Fixes for the things people most often run into, and answers to common questions.

## Getting started

### Welcome to Commonveil

_What Commonveil is for, what makes it different, and where to start._

Commonveil is a place to talk: one-to-one, in small groups, and in larger communities called servers, with voice and video calls. Everything you say is **end-to-end encrypted**. Your messages are locked on your device before they leave it and unlocked only on the devices of the people you're talking to. Commonveil stores the locked copies so they can be delivered, but it has no way to read them.

#### What makes it different

- **Nobody can browse for you.** There's no member directory and no "people you may know". Someone can only find you by typing your exact username.
- **Collects only what it needs.** No phone number, no contacts, no location, no adverts, no trackers. The [privacy report](#privacy-report-and-checkup) shows exactly what is held about you.
- **Your keys stay with you.** Your private keys are made on your device and never leave your devices. A stolen password isn't enough to read your messages or take over your account.
- **Servers without a server that can read them.** Channels, roles, threads, events, emoji and moderation, all encrypted, with member lists that only show people who choose to be listed.
- **Features built for privacy and safety:** [disappearing messages and self-destructing conversations](#disappearing-messages-and-self-destructing-conversations), [send later and safety check-ins](#send-later-and-safety-check-ins), [quiet hours](#notifications-quiet-hours-and-focus), a passcode lock, and [safety numbers](#safety-numbers-and-key-changes) to prove nobody is in the middle.
- **Protected against tomorrow's computers too.** Keys are sealed with a post-quantum hybrid (ML-KEM-768 with P-256), so traffic recorded today stays protected against a future quantum computer.

#### Where to start

1. [Create your account](#create-your-account) and write down your 24-word recovery phrase.
2. [Start a conversation](#direct-messages-and-groups) with someone whose username you know.
3. [Compare safety numbers](#safety-numbers-and-key-changes) with the people who matter most.
4. Run the [privacy checkup](#privacy-report-and-checkup) to tighten the rest.

#### An honest note

Commonveil is working and tested, but its encryption hasn't yet been independently audited. Until a review is published, don't rely on it where someone's safety depends on it. [How the encryption works](#how-the-encryption-works) explains what is and isn't protected.

### Create your account

_Sign in, choose a username, make your keys and keep your recovery phrase safe._

Setting up takes about two minutes. You'll need somewhere safe to write down 24 words.

#### 1. Sign in

Commonveil is for people **16 and over**. When you sign up you confirm you're 16 or older; nothing about your age is stored beyond that. If we find out an account belongs to someone under 16, it's closed ([Terms of Use](https://commonveil-rebuild-71d823fd.base44.app/terms)).

Choose **Sign in** at the top of any page.

- **On commonveil.online**, register with an email address and password, or with one of the sign-in providers offered. Your sign-in address is only used to sign you in and to send you security emails. Nobody else sees it.
- **On a self-hosted Commonveil site**, there's no email: you choose your username and a password, and the username step below is already done. Your recovery phrase is how you get back in ([Sign-in, passkeys and recovery](#sign-in-passkeys-and-recovery)).

#### 2. Choose your username

Your username is how people find you, so pick one you're happy to share. It has to be typed exactly to find you: there's no search and no directory. Usernames are unique regardless of capitals, and **a username can't be changed later**.

#### 3. Make your keys

Choose **Create my keys**. Your device makes a set of private keys that lock and sign everything you send. They never leave your devices.

#### 4. Write down your recovery phrase

You'll be shown 24 words. They're the only way back into your messages if you lose every device you're signed in on.

- Write them on paper, in order, and keep them somewhere safe and private.
- Don't screenshot them, email them to yourself or store them in a notes app that syncs.
- Commonveil doesn't have a copy and can't recover them for you.

To prove you've written them down, you'll be asked for a few of the words before you finish.

#### 5. You're in

You'll land in your direct messages. Every new account also joins the Commonveil Community server, which you can leave at any time.

#### Next steps

- [Start a conversation](#direct-messages-and-groups)
- [Add your phone or another computer](#devices-recovery-and-resets)
- [Set up your profile](#your-profile-and-how-commonveil-looks)
- Lock this browser with a [passcode](#passcode-lock-and-keeping-your-account-safe)

### Devices, recovery and resets

_Add another device, remove a lost one, use your recovery phrase, and what a reset does._

Each device you use has its own keys, certified by your account. You can use Commonveil on several devices at once.

#### Add another device

On the new device, sign in to the same account. You'll be asked how to bring your keys over.

**Approve it from another device (recommended)**

1. On the new device, choose **Approve it from another device**. It shows a **device link code**.
2. On a device that's already set up, open **Settings → Devices and keys**. The new device appears there, waiting.
3. Check that the code is **exactly** the one on the new device's screen, then choose **Approve**.

The new device receives your keys and can read your history. Comparing the code is what stops anyone else slipping in a device of their own.

**Use your recovery phrase instead**

If you don't have another device to hand, choose **Use my recovery phrase instead** and type your 24 words.

#### Remove a device

Open **Settings → Devices and keys** and remove any device you don't recognise or no longer have. Your keys are then renewed, so it can't read anything new. Messages it already had stay on it, so if it was stolen, also think about what was on it.

Removing *this* browser deletes its keys and signs it out of encryption. You can set it up again later.

#### Make a new recovery phrase

In **Settings → Devices and keys → Recovery phrase**, choose **Make a new recovery phrase** if you think someone saw yours. The old phrase stops opening anything straight away.

#### If you've lost everything: a reset

If you've lost every device **and** your recovery phrase, you can still keep your account and username by resetting your encryption:

- Type **RESET** to ask for it. The reset waits **a week** before it happens. That wait is deliberate: it means someone who steals your password can't take over your account, because any of your devices, or your recovery phrase, can cancel it in the meantime. You'll get an email when a reset is asked for.
- When it completes, you get new keys and all your other devices are removed.
- **Messages sent to you before the reset become permanently unreadable.**
- The people you talk to will see a warning that your keys changed. Ask them to [compare safety numbers](#safety-numbers-and-key-changes) with you again.

If you change your mind, choose **Withdraw the request**.

#### Security emails

Commonveil emails your sign-in address when a new device is added, when your recovery phrase is used, and when a reset is asked for or finishes. The emails never say which device or where. If you get one you don't expect, open **Settings → Devices and keys** straight away.

### Install the app

_Use Commonveil like an app on your phone, tablet or computer, with its own icon and window._

Commonveil can be installed like an app: its own icon and window, opening straight to your messages, and working without a connection. It's still this website, so there's no app store, no separate download to trust, and updates arrive by themselves.

#### Install it

- **Android, Windows, Mac, Linux or ChromeOS with Chrome or Edge:** open **Settings → Install the app** and choose **Install Commonveil**. Or use the install icon in the address bar, or **Install** in the browser's menu.
- **iPhone and iPad:** in Safari, tap **Share**, then **Add to Home Screen**.
- **Safari on a Mac:** choose **File → Add to Dock**.
- **Firefox on Android:** choose **Add to Home screen** from the menu. Firefox on a computer can't install apps, but Commonveil works the same in a tab.

#### Using it

- **Updates:** when a new version is ready, a bar says so. Choose **Update now** when it suits you.
- **Push notifications:** turn them on in **Settings → Notifications**. On iPhone and iPad they only work in the installed app. See [Notifications](#notifications-quiet-hours-and-focus).
- **Offline:** the app opens without a connection, and anything you write waits, already encrypted. See [Offline mode](#offline-mode).

#### What it keeps

Only the app itself: its pages, code and icons. Your messages and keys stay in the same encrypted storage as always. Installing gives Commonveil no extra permissions: notifications, the microphone and the camera still ask first.

To remove it, uninstall it like any other app. To clear what your browser kept too, clear this site's data in your browser's settings.

## Messages and calls

### Direct messages and groups

_Start a conversation, make a group, manage who's in it and who runs it._

Direct messages are between two people. Groups are for up to 32. Both are end-to-end encrypted: only the people in the conversation can read it.

#### Start a conversation

1. Choose **New conversation** (the + button beside "Direct messages").
2. Pick **Direct message** or **Group**.
3. Type the person's **exact username**. There's no directory to search, which is deliberate: nobody can trawl for you either.
4. Choose **Start conversation** (or **Create group**).

Whether someone can message you depends on their privacy choice: anyone who knows their username, only people they share a server with, or nobody new. See [privacy settings](#privacy-settings-blocking-and-reporting).

#### Groups

- **Names are encrypted.** The group's name is only readable by its members.
- **Admins.** Whoever makes a group is its first admin. Admins can add and remove people, rename the group, set its timers and choose other admins. A group always keeps at least one admin; if all its admins leave, the creator (or else the longest-standing member) takes over.
- **New members only see what's sent after they join.** Messages from before were locked for the people there at the time.
- **You're shown who's new.** When someone is added, everyone sees it before they next send, so nobody can be slipped in quietly.

#### Conversation details

Choose the **i** (details) button at the top of a conversation to:

- see who's in it and [compare safety numbers](#safety-numbers-and-key-changes);
- turn on [disappearing messages or self-destruct](#disappearing-messages-and-self-destructing-conversations);
- rename the group, add or remove people, or make someone an admin (admins only);
- **Block** or **Report** someone, or leave the group.

#### Leaving

When you leave a group you stop receiving its messages. When the last person leaves, the group and its messages are deleted.

#### Finding things

The search box above your conversations searches messages **on this device only**: nothing you type is sent anywhere. Choose **Search older messages too** to fetch and decrypt more history first. Press **Ctrl + K** to jump to any conversation, server or channel.

### Writing and sending messages

_Formatting, replies, reactions, edits, files, voice messages, polls, stickers and more._

Press **Enter** to send and **Shift + Enter** for a new line.

#### Formatting

- `**bold**`, `*italic*` or `_italic_`, `__underline__`, `~~strikethrough~~`
- `||spoiler||`: hidden until someone taps it
- `` `code` `` for inline code, and three backticks above and below for a code block
- `> ` at the start of a line for a quote; `# `, `## ` for headings; `- ` or `1. ` for lists
- `@username` to mention someone, and `#channel` to link a channel in a server

Links are never previewed. Nothing is fetched until you choose to open one, so sending a link doesn't tell anyone's server that you're looking.

#### Replies, reactions, edits and deletes

Hover over a message (or long-press on a phone) to see its tools:

- **Reply** quotes the message you're answering. Press **Esc** to cancel.
- **React** with an emoji.
- **Edit** your own message, for up to 24 hours after sending. Everyone sees that it was edited.
- **Delete for everyone** removes it from the server and everyone's app.
- **Forward** sends it on to another conversation or channel, files included, without them ever being opened on the way.
- **Copy text**, or **Report message** to the right people.

To the server, replies, reactions and edits look exactly like ordinary messages: it can't tell what you reacted to, or that you edited anything.

#### Files and voice messages

Choose the **+** button next to the message box:

- **Files:** up to 10 files a message, 10 MB each. Each file is encrypted with its own key before it's uploaded. Images, video and audio preview in the conversation; anything else downloads.
- **Voice message:** record up to 10 minutes, listen back, then send.
- **Poll:** a question with 2 to 10 answers, open from an hour to a week, with one or several choices allowed. Votes are encrypted messages too, so only members see the results.
- **Send later** and **Safety check-in:** see [Send later and safety check-ins](#send-later-and-safety-check-ins).

#### Emoji and stickers

Choose the smiley to add an emoji. In servers you can also use the server's own emoji and send its stickers. See [Channels, threads and more](#channels-threads-and-more).

#### What the little labels mean

- **Decrypting…**: your device is unlocking the message. It normally takes a moment.
- **Scheduled**: it was written earlier and delivered at the time its sender chose.
- **Forwarded**: someone passed it on from elsewhere.
- **Sent before you could read here**: it was locked before you joined, so you can't open it. This is the encryption working as intended.
- **Their security keys changed**: see [safety numbers](#safety-numbers-and-key-changes).
- **Unverified**: the message couldn't be proven to come from one of the sender's own devices. Be careful with it, and compare safety numbers.

### Voice and video calls

_Calls in conversations, voice channels and stages, with camera and screen sharing._

Calls go **directly between devices**. Commonveil helps them find each other, then steps out of the way: it never receives your audio or video.

#### Calling someone

In a conversation, choose **Start a call**. Everyone in the conversation gets a call message they can join from. Calls hold up to 8 devices.

#### Voice channels in servers

Select a voice channel to join it. Anyone with permission to connect can drop in and out.

#### In a call

- **Mute** or **Unmute** your microphone.
- **Deafen** to stop hearing everyone else.
- **Turn camera on**, or **Share your screen**.
- **Leave the call** when you're done.

#### Stages

A stage is a voice channel for talks and events, for up to 16 people. Moderators speak; everyone else listens. Listeners can ask to speak, and a moderator can **Invite to speak**, **Move to the audience** or mute them. Apps won't play anyone the stage says can't speak, even if they try.

#### How calls are protected

- Before your device connects to someone, it checks that their connection was signed by one of their own certified devices. If it wasn't, it refuses and tells you. This stops anyone, including whoever runs the call relay, from sitting in the middle.
- Every audio and video frame is encrypted twice: once by the browser's own call encryption, and again with the channel's or call's own keys.

#### Good to know

- As with any direct call, the people in a call can see each other's network addresses. A public STUN server (Cloudflare) helps devices find each other and sees yours.
- Some very strict networks (for example some workplaces) block direct calls. If a call won't connect, try another network.
- Commonveil knows who joined which call and when, but not what was said.
- Moderator mutes in servers hold until a moderator lifts them.

### Disappearing messages and self-destructing conversations

_Have messages delete themselves after a while, or set a whole conversation to erase itself._

Two ways to make sure what you say doesn't hang around: a timer on each message, or a deadline for the whole conversation.

#### Disappearing messages

**What it's for:** everyday privacy. Messages delete themselves a set time after they're sent, so there's less to leak later.

1. Open the conversation's details (the **i** button).
2. Under **Disappearing messages**, choose **1 day**, **1 week** or **4 weeks**.

- In a direct message either person can set it; in a group, admins can.
- Everyone sees who set it. It applies to messages sent from then on.
- When a message's time is up, every app hides it straight away and the server deletes it (wiped first) within about half an hour.
- The timer is also sealed inside each message, so even the server can't keep one showing for longer than its sender chose.

#### Self-destructing conversations

**What it's for:** a "burner" chat for a one-off plan, a surprise party, a sensitive conversation that shouldn't exist next week.

1. Open the conversation's details.
2. Under **Self-destruct**, choose **In 1 hour**, **6 hours**, **1 day**, **3 days**, **1 week** or **30 days**.

- A countdown shows at the top of the conversation for everyone.
- At that time, **the whole conversation is deleted for everyone**: every message, every file and the conversation itself, from the server and from each member's app. It disappears from view immediately, and the server erases it within a few minutes.
- In a direct message either person can set it, change it or **Turn off**; in a group, admins can.

#### What neither can do

Nothing can stop someone copying, photographing or screenshotting a message before it goes. Use these to reduce what's kept, not as a guarantee about the people you're talking to.

### Send later and safety check-ins

_Write a message now and have it delivered later, or have it sent only if you don't check in._

Both are ordinary encrypted messages, sealed when you write them and held unreadable until they're due. The people in the conversation can't see them, or tell that they exist, until they're delivered.

#### Send later

**What it's for:** birthday wishes at midnight, a reminder for tomorrow morning, a message to someone in another time zone at a sensible hour.

1. Choose the **+** button next to the message box, then **Send later**.
2. Write the message and choose when to **Deliver** it: from a minute to a year ahead.
3. Choose **Schedule**.

Waiting messages show in a bar above the message box, only to you, with a button to cancel. When it's delivered it's labelled **Scheduled** and appears at the time it arrived. It can arrive a few minutes after the time you chose.

#### Safety check-in

**What it's for:** a first date, a long walk or run, a solo trip, getting home late. If you don't say you're OK in time, someone you trust is told.

1. Choose the **+** button, then **Safety check-in**.
2. Write the message you want sent if you don't check in. A suggestion is filled in for you.
3. Choose how long until you must check in: from 1 hour to 1 week.
4. Choose **Start check-in**.

While it's running, a bar shows how long is left. Tap **I'm OK** to start the same time again, or end the check-in when you're safely back. If time runs out, the message is delivered by itself.

Only your own device can check in or end a check-in, so someone who has your password can't silence it or fake an "I'm OK".

**A safety check-in is a help, not an emergency service.** It can arrive a few minutes late, and it only reaches the people in that conversation. If you're in danger, call the emergency services.

#### Good to know

- Only the people in the conversation when you wrote it can read it. If someone leaves before it's delivered, they don't get it. Anyone added later can't read it.
- If you block someone or they block you, a waiting direct message to them isn't delivered.
- The conversation's disappearing-message timer starts when it's delivered, not when you wrote it.
- Commonveil can see when each waiting message is due and who it's for, but never what it says. You can have up to 50 waiting at a time.

### Offline mode

_Keep writing with no connection. Messages are sealed now and sent when you're back._

Commonveil keeps working when your connection drops. Write as usual.

#### While you're offline

- A bar at the top says **You're offline**.
- Each message you send is **encrypted and signed on your device straight away**, and shows as **Waiting to send**.
- When your connection comes back, waiting messages go out in order. The people you sent them to see the time you wrote them, marked **written offline**.

Nothing waits in plain text: your device keeps the encrypted message, and opens its own copy to show it to you. Messages wait for up to a week.

#### Offline mode, on purpose

**Settings → Offline mode** makes the app stop reaching the server until you turn it off: useful on a connection you don't trust, or to save data. Everything you send waits, already encrypted. Choose **Go back online** in the bar to send it all.

#### If a message couldn't go out

If something changed while you were away (someone joined the conversation, or a channel's keys moved on), the old message can't be delivered as it was sealed. It's marked **Not sent**, with:

- **Send again**, which seals it afresh for the people there now.
- **Delete**, to let it go.

You can also cancel a waiting message with **Don't send**.

#### When the other site is down

If you're talking to someone on another Commonveil site that can't be reached, your own site holds your message and passes it on when it can. It shows **Your site is holding it**.

#### With no internet at all

A Commonveil site can run on a small computer with its own Wi-Fi, so people nearby can chat with no internet. Ask whoever runs your site, or see [Run your own Commonveil site](#run-your-own-commonveil-site).

#### Good to know

- Keep the tab open: the app needs the server to start.
- Only messages wait. Attachments, calls and settings need a connection.

### People on other sites

_Your address, talking to people on other Commonveil sites, and joining their servers._

Anyone can run their own Commonveil site, and sites talk to each other. You can message people on other sites and join their servers, and everything stays end-to-end encrypted the whole way. This works between **self-hosted** sites.

#### Your address

Your address is your username followed by your site's name: **ann** on **chat.example.com** is **@ann.chat.example.com** (underscores become hyphens). It's in **Settings → My profile**.

- Share it so people on other sites can reach you.
- Opened in a browser, it shows your profile page: only what you chose to share, and a **Send a message** button.

#### Messaging someone on another site

Choose **New conversation** and enter their full address, like `alex.other.example`. Mention them in a message with **@** and their full address too.

They have to accept new conversations from **anyone** (in **Settings → Privacy and safety**). If they only take them from people they share a server with, they can't be reached from other sites.

#### Servers on other sites

In **Discover**, type another site's address in **Showing servers on** and choose **Browse**. Join any open server listed there. An invite link from another site works too: open it and choose to join from your own site.

#### What other sites see

The site a conversation or server lives on sees what any site would: your address, profile (as you share it), public keys, and when you send things there. It never sees what you say, or anything else about you. Your own site sees which other sites you use. More detail is in `docs/FEDERATION.md` on GitHub.

#### Blocking

Blocking someone on another site works as usual, on your site and theirs. Site admins can also stop talking to a whole site.

## Servers

### Joining and using servers

_Join with an invite or from Discover, find your way around, and choose how visible you are._

A server is a community: channels for different topics, roles for the people who run it, voice channels, events and more. Everything inside a server, including its name, its channels' names and every message, is end-to-end encrypted. Only members can read it.

#### Join a server

- **With an invite link:** open it, or choose **Add a server** (the + on the left-hand rail), then **Have an invite?** and paste it. Invite links look like `…/invite/AbCd1234#…`. The part after `#` is a secret that never reaches Commonveil, which is how even the invite's preview stays encrypted.
- **From Discover:** choose **Discover servers** (the compass) to browse servers whose admins chose to list them. Filter by name or topic, then **Join**.

Every new account starts in the **Commonveil Community** server. You can leave it like any other.

#### Finding your way around

- **The rail** on the left holds your servers. Drag them, or right-click (or use the menu) to **Move up**, **Move down** or **Add to folder** to group them.
- **Channels** are listed down the side, in categories. Unread channels are brighter.
- **The inbox** (the tray icon) collects your **Mentions**, **Unread** channels and **Saved** messages in one place.
- **Ctrl + K** finds any server, channel or conversation. **Ctrl + /** shows every keyboard shortcut.

#### Notifications per server and channel

Right-click a server or channel (or use its menu) and choose **Notifications**: **All messages**, **Only @mentions** or **Nothing**. **Mute** silences it completely, and **Mark as read** clears it. These choices are remembered on this device only.

#### You, in this server

From the server's menu choose **Privacy settings** (or **Server settings → Privacy and encryption**). Under **You, in this server** you can:

- **List me in the member list:** off unless you turn it on. Nobody appears in a server's member list unless they choose to, except its staff, so members can see who runs it.
- **Change my nickname here:** a name just for this server, encrypted like everything else.
- **Mute this server.**

#### Leaving

Choose **Leave server** from the server's menu. When you leave, the server's keys move on, so you can't read anything sent after you've gone.

#### Make your own

See [Creating and setting up a server](#creating-and-setting-up-a-server).

### Channels, threads and more

_Text, announcement, forum, voice, stage, ticket and rules channels; threads, pins, saved messages, events, emoji and stickers._

#### Kinds of channel

- **Text:** everyday conversation, one message after another.
- **Announcement:** staff post, everyone reads and reacts.
- **Forum:** each topic gets its own post with its own thread. Choose **New post** to start one.
- **Voice:** talk together, peer to peer and encrypted. See [calls](#voice-and-video-calls).
- **Stage:** moderators speak, everyone else listens and can ask to speak. Up to 16 people.
- **Tickets:** open a private ticket with the server's support team.
- **Rules:** the server's rules, read-only for members.

Some channels are **private**: only people with the right roles can see them, and they have their own keys, so nobody else in the server can read them even in principle.

#### Threads

Reply in a thread to keep a side conversation out of the main channel. Forum posts are threads. Moderators can lock a thread.

#### Pins and saved messages

- **Pin** an important message to the channel (if you're allowed to). Open **Pinned messages** from the channel's header to see them.
- **Save** a message for yourself from its menu. Saved messages are listed in your inbox under **Saved**, and are kept on this device only.

#### Search a channel

Use **Search this channel** in the channel's header. Like everything else, the search runs on your device.

#### Events

Servers can schedule events: a title, description, place and times, all encrypted. Open **Events** to see what's coming up and answer **Going** or **Maybe**. **Add to calendar** makes a calendar file on your device; nothing is sent to a calendar service.

#### Emoji and stickers

Servers can have up to 40 of their own emoji and 8 stickers. Use them from the emoji picker, or choose **Send a sticker**. They're encrypted like messages, so only members can see them.

#### Support tickets

In a tickets channel, open a ticket to talk privately with the server's support team. A ticket is an encrypted group between you and up to 31 of the team, and you're shown exactly who's in it before you send anything. **Your tickets** lists the ones you've opened.

#### When a message can't be read

**Sent before you could read here** means the message was locked before you had the keys for it. In channels where newcomers only read from when they joined, that's expected.

## Running a server

### Creating and setting up a server

_Make a server, invite people, set up channels, roles, privacy, rules and discovery._

#### Create it

1. Choose **Add a server** (the + on the rail), then **Create a server**.
2. Pick a starting point. You can change everything later.
3. **Name your server** and choose an icon (an emoji or two letters). Only members can see the name and icon: they're encrypted on your device.
4. Choose **Create server**.

You're the **owner**: above every role, and the only person who can delete the server or hand it on.

#### Invite people

From the server's menu choose **Invite people**. Set **Expire after** and **Max uses** if you like, then **Make invite link** and copy it. Anyone with the link can join while it's valid, so only send it to people you mean to invite. **Make a different link** to start again. Manage and revoke links under **Server settings → Invites**.

#### Channels and categories

From the server's menu choose **Create channel** or **Create category**. Each channel has its own settings: name, topic and category; **History for people who join later**; **Slow mode** (how often each person can post); **Disappearing messages** for the channel; and **Permissions**, to change what each role can do there (see [roles and permissions](#roles-and-permissions)).

#### Server settings

Open **Server settings** from the server's menu. The sections are:

- **Overview:** name, description, icon and colour.
- **Roles:** see [roles and permissions](#roles-and-permissions).
- **Invites:** every link, with its uses and expiry.
- **Emoji and stickers:** upload images; they're resized and encrypted on your device.
- **Privacy and encryption:**
  - **Member list:** *Members choose* (nobody is listed unless they opt in), *Staff only*, or *Just a count*.
  - **New channels start with:** *History from joining* (newcomers read only what's sent after they arrive) or *Full history*.
  - **Who hands out keys:** *Any member's app* (newcomers get keys quickly, but members' apps learn who joins) or *Only staff with Manage encryption* (ordinary members never learn who joins; newcomers wait until a staff member is online).
  - **Encryption keys:** renew all of the server's keys if you think they've been exposed.
- **Rules and screening:** write the server's rules and turn on **Rules screening**, so new members can read but not post until they accept them. Staff aren't affected.
- **Discovery:** list the server in Discover with a **public card** (name, description, tags, icon, colour). The card is public and not encrypted; everything inside the server still is. Off unless you turn it on.
- **Safety:** AutoMod, spam and raid protection, staff limits and lockdown. See [moderation](#moderation-and-safety-tools).
- **Reports, Cases, Members, Bans, Audit log:** see [moderation](#moderation-and-safety-tools).

#### Hand it on or delete it

Under **Ownership**, **Hand the server on** to another member, or **Delete the server** for everyone. Deleting can't be undone.

### Roles and permissions

_What each permission allows, how roles stack, and how to make a channel private._

Roles decide what people can do. Everyone has the **@everyone** role; you add others for moderators, helpers, regulars and so on. Commonveil checks permissions on every action, and changes are signed by a device, so a stolen sign-in alone can't change anything.

#### Make and give roles

Open **Server settings → Roles**. Create a role, name it (the name is encrypted), choose a colour, and tick its permissions. Give it to someone from their profile card in the server.

- **Order matters.** Roles higher in the list outrank lower ones. Someone with **Manage roles** can only edit and give roles below their own highest role.
- **The owner** is above every role.

#### The permissions

**General**
- **View channels:** see channels and read what's in them.
- **Manage channels:** create, edit, reorder and delete channels.
- **Manage roles:** create and edit roles below their own, and give them to members.
- **Manage server:** change the server's name, settings, rules and discovery listing.
- **View audit log:** see who changed what in the server's settings.
- **Manage emoji and stickers.**
- **Manage events:** schedule, edit and cancel events.
- **Manage encryption:** start new key generations, so people who left can't read what comes next.

**Membership**
- **Create invites** and **Manage invites** (see and revoke everyone's links).
- **Change nickname** (their own) and **Manage nicknames** (other people's).
- **Kick members:** remove people; they can come back with an invite.
- **Ban members:** remove people for good. Keys are renewed so they can't read anything new.
- **Time out members:** stop people posting or joining calls for a while.

**Text**
- **Send messages**, **Create forum posts**, **Add reactions**.
- **Read message history:** page back through earlier messages.
- **Mention @everyone:** notify everyone in a channel at once.
- **Manage threads:** rename, archive, lock and delete anyone's threads.
- **Manage messages:** delete anyone's messages and pin messages.

**Support**
- **Handle support tickets:** receive and answer the server's tickets.

**Voice**
- **Connect**, **Speak**.
- **Mute members and run stages:** mute people in calls, and invite or move speakers on a stage.

**Advanced**
- **Administrator:** every permission, in every channel. Give it carefully.

#### Per-channel permissions

In a channel's settings, under **Permissions**, you can allow or deny any permission for a role in just that channel.

**To make a channel private,** deny **@everyone** the **View channels** permission there, then allow it for the roles that should see it. A private channel gets its own keys, given only to people who can see it, so nobody else in the server can read it.

#### Staff and the member list

People with moderation or management permissions count as **staff**. Staff are always shown in the member list, so members can see who runs the server. Everyone else is only listed if they choose to be.

### Moderation and safety tools

_Reports, escalating to Commonveil, warnings, timeouts, kicks and bans, AutoMod, spam and raid protection, staff limits and lockdown._

Commonveil can't read anything in a server, so it can't moderate it for you. Instead, it gives your moderators the tools that popular moderation bots offer, built in and working without breaking the encryption. Owners decide how each one behaves in their own server.

#### Reports from members

Members choose **Report message** from a message's menu, pick **What's wrong?** (spam or scams, harassment, hate speech, threats, unwanted sexual content, fraud, something illegal, someone at risk of harming themselves, or something else) and add a note if they want.

- The report is **encrypted to the server's moderators only**: the reporter plus up to 31 moderators, highest first, and never the person reported. Moderators who join later can't read earlier reports.
- Members can also tick to **tell the Commonveil team**, for things that break the law or Commonveil's rules. What they write (and the message, if they include it) is shared with the team in readable form, since the team can't read anything otherwise.

Moderators find reports under **Server settings → Reports**, where they can act on them, **Dismiss** them, or close them.

#### Escalating to Commonveil

For something serious (illegal content, a threat to someone's safety, abuse across servers), a moderator can choose **Send to the Commonveil team** on a report. Choose **What kind of problem** it is and edit **What to share** down to what's needed, leaving out other people's private details. It reaches the Commonveil team as a readable report, with the server it came from.

#### Acting on someone

Open a person's profile card (click their name) and use **Moderation**:

- **Warning:** a formal warning they can see. Warnings count towards your warning steps (below). **Pardon** a warning to stop it counting.
- **Note:** a private note for moderators only.
- **Time out for** a set time: they can't post or join calls.
- **Kick:** they're removed and their copies of the server's keys are deleted. They can come back with an invite.
- **Ban:** for good or for a set time. Keys are renewed so they can't read anything new. **Delete their messages from** a recent period at the same time if you need to.

Reasons are encrypted and only moderators see them. Bans are listed under **Server settings → Bans**, where you can lift them.

#### Cases

Every warning, note, timeout, kick, ban, unban and purge, whether done by a person or by the server's own rules, becomes a numbered case under **Server settings → Cases**. Members can see their own warnings.

#### Safety settings

Under **Server settings → Safety**:

**AutoMod** checks messages on each person's device, before sending and before showing, so it works without anyone's messages being decrypted by Commonveil. Set **Blocked words** (use `*` as a wildcard), and block links, invite links or too many mentions. Staff with **Manage messages** are exempt.

**Warnings:** add steps such as "at 3 warnings, time out for a day" or "at 5, ban". Choose the **Number of warnings**, **What happens** (time out, kick or ban) and **For how long**, and how far back warnings count (**Count warnings from the last**).

**Spam and raids** work from counts and times alone:
- **Flood protection:** time out anyone who sends more than a set number of **Messages** in a few **Seconds**.
- **Raid protection:** if more than a set number of people join in a minute (**Joins per minute**), joining pauses.

**New accounts and newcomers:** before they can post, accounts must be a minimum age (**Accounts must be at least**, from 5 minutes to a day) and newcomers must have been in the server a while (**Newcomers wait**).

**Staff limits** stop a compromised or rogue staff account wrecking the server: anyone but the owner who bans, kicks, times out, or deletes channels or roles too many times in ten minutes is stopped, and loses their roles until the owner gives them back. Only the owner can turn this off.

**Lockdown**, for when something's going wrong:
- **Pause invites:** existing links stop working until you turn it off.
- **Pause joining:** nobody new can join, by invite or from Discover.

#### Rules screening

Under **Rules and screening**, write your rules and turn on **Rules screening**. New members can read but not post until they accept them.

#### In calls

Moderators with **Mute members and run stages** can **Mute for everyone** in a call. The mute holds until a moderator lifts it, and every app silences that person. Anyone removed or timed out is taken out of calls within a minute.

#### Audit log

**Server settings → Audit log** shows who changed what in the server's settings. Choose how long it's kept with **Keep the audit log for**.

## Privacy and safety

### Safety numbers and key changes

_Prove nobody is in the middle of your conversation, and what to do when someone's keys change._

End-to-end encryption protects you from everyone *between* you and the person you're talking to. A safety number lets you check that the person really is who they say, and that nobody has swapped in their own keys.

#### Compare safety numbers

1. Open a direct message and choose the **i** (details) button.
2. Choose **Show safety number**.
3. Compare it with what the other person sees, **in person or on a call**, not by message in the same app.
4. If every digit matches, nobody is in between. Tick **Mark as verified**.

Do this with the people where it matters most. It only takes a minute, and it covers each person's whole key history: if their keys are ever swapped, you'll be warned.

Your own key fingerprint (half of every safety number you share) is shown under **Settings → Devices and keys**.

#### When someone's keys change

You'll see **Their security keys changed** in the conversation. That happens when someone resets their account, for example after losing all their devices and their recovery phrase. It can also be a sign that someone is trying to get in between you.

- Until you **Accept the new keys**, their new messages show as **unverified**.
- Before you accept, check with them in person or on a call that they really did reset. Then compare the new safety number.

#### When your keys change

Removing a device renews your keys. That's signed by your existing keys, so the people you talk to follow the change automatically, without a warning, and anyone who marked you as verified keeps you verified. Your safety number moves on with it, so if you compare again later it will be different. Only a reset starts a new identity, and that's when people are warned.

#### What "unverified" means

A message is marked unverified if it couldn't be proven to come from one of the sender's own devices: for example, it was sent by a device that had since been removed, or by keys you haven't accepted yet. Treat it with care.

### Privacy settings, blocking and reporting

_Choose who can contact you and see your profile, share your online status or not, block and report._

Open **Settings → Privacy and safety**. Everything starts private; you choose what to share.

#### Who can start a conversation with you

- **Anyone who knows my username.** They have to type it exactly: nobody can browse for you.
- **Only people I share a server with.** Servers can turn this off for their members.
- **Nobody new.** Only existing conversations, and people you start one with.

People you already have a conversation with can always keep writing to you.

#### Who can see your profile

Your display name, pronouns, bio and avatar can be seen by:

- **People I share a conversation or server with**, or
- **Only people I have a conversation with** (in servers, others see just your username), or
- **Nobody** (everyone sees just your username).

#### Online status and typing

Both are **off** unless you turn them on, and they're **mutual**: you only see other people's while you share yours.

- **Show when I'm online:** people in the same server or conversation see a dot by your name while you have it open.
- **Show when I'm typing:** others see "typing…" while you write. It's never shown in private channels.

Status passes through a live room that writes nothing down, and only for the server or conversation you have open. This choice is kept on this device.

#### Blocking

Block someone from their profile, or from a conversation's details. Once blocked, neither of you can message the other, you can't find each other by username, and any message they'd scheduled to you isn't delivered. Unblock people under **Settings → Privacy and safety → Blocked people**.

#### Reporting

- **In a server:** use **Report message**. It goes, encrypted, to that server's moderators. See [moderation](#moderation-and-safety-tools).
- **In a conversation:** choose **Report** in the conversation's details. It goes to the Commonveil team. Staff can't read your messages, so paste anything they need to see.

Because the team can't read your messages, a report includes only what you choose to share. Every report you've made is included when you **Download your data** (under **Settings → Data and account**).

If someone is in immediate danger, contact your local emergency services.

#### Report a security problem

Found a weakness in Commonveil itself? Use [Report a security problem](https://commonveil-rebuild-71d823fd.base44.app/security/report). You don't need an account.

### Privacy report and checkup

_See everything Commonveil holds about you, and a checklist of ways to share less._

Open **Settings → Privacy report**.

#### The checkup

A short checklist, worked out **on your device** from settings it already knows. Which suggestions you follow is never sent anywhere. Each one has a **Fix** link to the right setting:

- Lock this browser with a passcode.
- Compare safety numbers with the people you talk to.
- Turn on disappearing messages in your conversations.
- Keep your online status private.
- Show your profile to fewer people.
- Limit who can start a conversation with you.
- Have your account deleted if you stop using it.

None of these are required. They're there so you can decide, knowing what each one does.

#### What Commonveil holds about you

The report asks the service what it stores about you, and shows it:

- **Your account:** your username, your sign-in address (partly hidden), when you joined, which profile details you've filled in, and your privacy choices. The day you were last active is only recorded if you've asked for your account to be deleted after a while without use.
- **Devices:** each device's name, whether it's active, and the day it was last used.
- **Who you talk to:** how many direct conversations, groups and support tickets you're in, with how many different people, and how many servers. The service has to know who's in a conversation to deliver to them, but it can't read what's said or the names of groups.
- **Stored, encrypted:** how many of your messages still exist, files you've uploaded, scheduled messages and check-ins waiting, reports you've made, and people you've blocked. These are counted, never read.
- **Never collected:** what anything says; your contacts, phone number or location; when you're online or typing (unless you turn status on, and even then it isn't stored); your quiet hours, mutes, searches and theme; advertising or tracking identifiers.

Choose **Check again** to refresh it, or **Download or delete your data** to go to [your data](#download-your-data-or-delete-your-account).

### Passcode lock and keeping your account safe

_Lock this browser's keys with a passcode, and simple habits that keep your account yours._

#### Passcode lock

**What it's for:** if someone else can use your computer or phone, a passcode stops them reading your messages there.

Open **Settings → Devices and keys → Passcode lock** and set a passcode. Your keys on this browser are then stored **encrypted with it**, and Commonveil locks itself after a while without use: choose how long with **Lock after**. You can also lock it straight away, or **Change passcode**.

- The passcode is for this browser only. Each device has its own.
- It never leaves the device and Commonveil can't recover it. If you forget it, choose **Forgot your passcode?** on the lock screen to remove this browser and set it up again. See [troubleshooting](#troubleshooting-and-questions).

#### Habits that help

- **Keep your recovery phrase offline** and private. See [devices and recovery](#devices-recovery-and-resets).
- **Remove devices you no longer use** under **Settings → Devices and keys**.
- **Compare safety numbers** with the people who matter. See [safety numbers](#safety-numbers-and-key-changes).
- **Use a strong, unique password** for your sign-in. Even if it's stolen, it isn't enough to read your messages, and a reset can't happen without a week's wait that your devices can cancel.
- **Read the security emails.** You're emailed when a device is added, your recovery phrase is used, or a reset is asked for. If you didn't expect one, check your devices straight away.
- **Keep your browser up to date.** Commonveil runs in your browser, so your browser's security is part of yours.

#### What a passcode doesn't do

It protects the keys stored on this device. It doesn't protect against someone who can install software on your device while it's unlocked, or who sees your screen.

### How the encryption works

_In plain language: what end-to-end encryption protects, what Commonveil can and can't see, and the limits._

#### The short version

Your device locks every message before it leaves, using keys that only the people in the conversation hold. Commonveil stores and delivers locked messages it can't open. Even if someone took a full copy of Commonveil's database, they'd have ciphertext, not conversations.

#### Your keys

- When you set up a device, it makes its own private keys. They **never leave your devices**.
- Your account has a key history: every key you've ever used, each one signed by the one before. The people you talk to check that history, and [safety numbers](#safety-numbers-and-key-changes) let you check it together.
- A new device only gets your keys if one of your existing devices approves it after you compare a code, or if you type your recovery phrase.
- Your **recovery phrase** unlocks an encrypted backup of your keys. Commonveil doesn't have a copy.

#### What's encrypted

Messages, replies, reactions, edits, polls and votes, files and voice messages, group names, call audio and video, and everything inside a server: its name and description, channel and role names, nicknames, rules, events, emoji, stickers, AutoMod settings, moderation reasons and reports to moderators.

Keys are sealed with a **post-quantum hybrid** (ML-KEM-768 combined with P-256), so an attacker would have to break both. Messages recorded today stay protected against a future quantum computer.

#### What Commonveil can see

It needs some information just to work, and it keeps that to a minimum:

- your sign-in address, username, and the profile you choose to fill in (profiles aren't encrypted);
- your devices' names and the day each was last used;
- who is in which conversation and server, and when messages are sent, roughly how big they are, and who each was locked for;
- settings it has to enforce: group admins, timers and who set them, roles and permissions, bans and timeouts;
- when scheduled messages and check-ins are due and for whom, and when a conversation will self-destruct;
- who joined which call and when;
- for servers listed in Discover, their public card.

It **never** sees what anything says, and it doesn't collect contacts, phone numbers, location, or advertising or tracking identifiers. The [privacy report](#privacy-report-and-checkup) shows what it holds about you.

#### What it can't protect against

- **The people you talk to.** Anyone in a conversation can read it, and can copy or screenshot it, even disappearing messages.
- **Your own device.** If someone can use your unlocked device, or installs software on it, they can read what you can. A [passcode lock](#passcode-lock-and-keeping-your-account-safe) helps.
- **Before you compare safety numbers.** The very first time you talk to someone, you trust that the keys you're given are theirs. Comparing safety numbers removes that trust.
- **The app itself.** Commonveil runs in your browser, so you're trusting the code the site sends you. That's one reason an independent review matters.
- **Metadata.** It can see who talks to whom and when, as above.
- **Delivery.** It could delay or drop messages, including a scheduled message or a check-in. It can't read or change them without it showing.

#### No audit yet

The design and code are tested, but not yet independently audited. The [complete guide](#contents) has everything on one page, and the [Security](https://commonveil-rebuild-71d823fd.base44.app/security) page covers the technical design and its status.

## Your account

### Notifications, quiet hours and focus

_Get alerts without giving anything away, silence them overnight or for a while, and mute what's noisy._

Notifications never give anything away. They say **New message** or **New activity**, and nothing about who, where or what, so your phone, your browser and the companies behind them keep no record of your conversations.

#### Push notifications

**What they're for:** being told about a new message when Commonveil is closed.

Open **Settings → Notifications → Push notifications** and choose **Turn on**. Your browser asks for permission. They're off until you turn them on, and set for each device separately.

- A push notification says only **Commonveil: New message**. Never the sender, the conversation or a word of the message.
- Tap it and Commonveil opens straight to that conversation. The app asks the server where to go, once you're signed in, so the notification itself never knows.
- Each one replaces the last, so only one is ever kept on your device. A burst of messages makes one notification.
- Only conversations send pushes. Servers stay quiet.
- Quiet hours and focus (below) make them silent.
- **Send a test** checks they're working. **Turn off**, or signing out, stops them on that device.

On **iPhone or iPad**, add Commonveil to your Home Screen first ([Install the app](#install-the-app)), then open it from there to turn these on.

Pushes travel through your browser's push service (Google, Mozilla, Apple or Microsoft), encrypted so they can't read them. Even decrypted, a push holds only a one-time code.

#### Alerts in an open tab

Open **Settings → Notifications**. All of these are off until you turn them on, and they're set for this browser only.

- **Notify me of new messages:** shown while Commonveil is open in a tab, when you're not already looking at that conversation. A notification says "New message" and never what it says.
- **Say who it's from:** off by default, because notifications can appear on a locked screen.
- **Show the number of unread conversations in the tab's title**, for example "(2) Commonveil".

#### Quiet hours

**What it's for:** no buzzing at night, or during dinner, or in the school run.

Turn on **Quiet hours** and choose **From** and **Until** (in this device's time zone). Between those times notifications stay silent. Messages still arrive; you just aren't interrupted. Quiet hours can run past midnight, for example 22:00 until 07:00.

#### Focus

**What it's for:** an hour of deep work, a meeting, a film.

Choose **Focus for 1 hour**, **2 hours**, **4 hours** or **8 hours**. Notifications stay silent until it ends, or until you choose **End focus**.

Quiet hours and focus are kept on this device only, so **Commonveil never learns when you sleep or when you're busy**.

#### Muting servers and channels

Right-click a server or channel (or use its menu) and choose **Mute**, or set **Notifications** to **All messages**, **Only @mentions** or **Nothing**. Muting is remembered on this device only.

### Your profile and how Commonveil looks

_Display name, pronouns, bio, avatar and colour; theme, text size, message layout and motion._

#### Your profile

Open **Settings → My profile** (or choose your name in the bottom corner).

- **Username:** chosen when you signed up. It can't be changed, and people find you only by typing it exactly.
- **Display name**, **Pronouns** and **About me**: all optional.
- **Avatar emoji:** one emoji, or leave it empty for your initials. There are no uploaded pictures, so showing your avatar never makes anyone's device fetch an image from somewhere.
- **Profile colour.**

Choose **Save changes**. A preview card shows how others see you.

**Your profile isn't encrypted.** It's plain text the service can read, like the name on the outside of a letter. Only fill in what you're happy for it to hold, and choose who sees it in [privacy settings](#privacy-settings-blocking-and-reporting).

In a server you can also have a **nickname** just for that server. Nicknames *are* encrypted. See [servers](#joining-and-using-servers).

#### Appearance

Open **Settings → Appearance**. These choices are saved in this browser only.

- **Theme:** light, dark, or **Match my system**.
- **Text size.**
- **Message display:** **Cozy** (avatars and names at the start of each run of messages) or **Compact** (one line per message, with the time and name in front).
- **Reduce motion:** turns off animations, whatever your system says.

#### Keyboard shortcuts

On a Mac, use Cmd instead of Ctrl. Press **Ctrl + /** in the app to see them at any time.

- **Ctrl + K:** find a server, channel or conversation
- **Alt + ↑ / ↓:** previous or next channel
- **Alt + Shift + ↑ / ↓:** previous or next channel with something new
- **Ctrl + Alt + ↑ / ↓:** previous or next server
- **Shift + Esc:** mark this server as read
- **Enter / Shift + Enter:** send / new line
- **Esc:** cancel a reply or an edit
- **Ctrl + /:** show these shortcuts

### Download your data or delete your account

_Get a copy of everything, have your account delete itself if unused, or delete it now._

Open **Settings → Data and account**.

#### Download your data

Choose **Download your data** for everything Commonveil holds about your account in one file: your profile and devices, the people you talk to, your conversations, the people you've blocked and the reports you've made.

It's put together and **decrypted in your browser**, then saved to your downloads. Nothing is sent anywhere to make it, and it never includes your keys. Keep the file somewhere safe: unlike Commonveil, it isn't encrypted.

#### Delete my account if I stop using it

**What it's for:** if you ever walk away, nothing of yours is left behind.

Choose to have your account deleted after **six months** or **a year** without use. Off unless you turn it on.

- A week before, you're emailed a warning. Signing in at any point keeps your account.
- While it's on, Commonveil notes the day (never the time) you last opened the app. When it's off, it doesn't record that at all.
- Staff accounts can't use this.

#### Delete your account now

Type **DELETE** to confirm. It can't be undone.

- Your profile, your keys and devices, and every message you've sent are deleted.
- Your username is retired: kept on its own, linked to nothing, so nobody else can take it and pose as you.
- Direct-message conversations with you disappear for the other person too. You're removed from your groups.
- Blocks involving you and reports you made are deleted. Reports other people made about you stay with staff. Security reports you sent are kept, without your name.
- Your sign-in is removed. Base44, Commonveil's host, keeps removed sign-ins for 30 days before erasing them.

#### Sign out

**Sign out** keeps this browser's keys so you can sign back in quickly. On a shared or borrowed computer, choose **Sign out and remove this device** instead.

### Sign-in, passkeys and recovery

_Your username and password, passkeys, confirming a new device, and getting back in._

This is how accounts work on **self-hosted Commonveil sites**. On commonveil.online, you still sign in with your email for now.

Open **Settings → Sign-in and recovery** to see and change all of it.

#### Signing in

Your account is a **username and password**. There's no email. You can sign in either way:

- **Sign in with a passkey**: your fingerprint, face or device PIN, and that's it.
- **Your username and password.**

#### Passkeys

A passkey is a key your device keeps for this site. Nobody can phish it, and there's nothing to type. Add one in settings:

- **Add a passkey on this device** keeps it on this computer or phone only.
- **Add one to a password manager** syncs it to your other devices (iCloud Keychain, Google Password Manager, 1Password, Bitwarden and others).

You can have several, and remove any of them.

#### A new device

The first time a browser signs in to your account, you'll be asked to **confirm it's you**, with one of:

- **A passkey.**
- **Your recovery phrase or private key.** It stays on the device: only a signature made with it is sent.
- **Another device.** On a device where you're already signed in, a bar asks whether you're signing in somewhere new, and shows a code. Approve it only if the code matches.

After that, it isn't asked again. **Signed-in devices** in settings lists every browser that's signed in, how it was confirmed, and when it was last used. **Disconnect** signs one out straight away.

#### Recovery phrase and private key

Your **24-word recovery phrase** is made when you set up encryption, and you'll need it: it's how you get back in if you forget your password, and how you unlock your messages on a new device.

Your **private key** is the same secret written as one string, starting `cvkey1`. Keep whichever is easier to store safely: on paper, or in a password manager. In settings you can turn one into the other. Anyone who has either can take over your account, so never share them.

#### Getting back in

Forgot your password? Choose **Can't sign in?** on the sign-in page. Enter your username, then your **recovery phrase or private key**, or use a **passkey**, and choose a new password. Every other session is signed out.

Nobody else can do this for you, not even the site's admin. If you lose your password, your phrase and every passkey and device, the account can't be recovered.

#### Accounts made with an email

If you made your account with an email before usernames arrived, it still works: sign in with your email or your username. You'll be asked to **add a passkey** and **confirm your recovery phrase**, because email sign-in is going away. Once your phrase is confirmed, **Remove my email** deletes it from the site.

## Running your own site

### Run your own Commonveil site

_Host Commonveil on your own hardware with Docker, keep it up to date, and run it with no internet._

Commonveil is free and open source (AGPL-3.0). Anyone can run their own site, on a small server, a home computer or a Raspberry Pi, with Docker. It's the same app, with the same end-to-end encryption, and it doesn't depend on us.

#### Setting it up

You need a computer that stays on, Docker, and a domain name. In an empty folder, run:

```
curl -fsSLO https://raw.githubusercontent.com/Comutability/commonveil-rebuild/main/deploy/install.sh
sh install.sh
```

It asks for your domain and the username you'll use, then starts everything, including HTTPS. Open your site and create your account: it's the site's admin. The full guide, with every setting, is `docs/SELF_HOSTING.md` on GitHub.

#### Updates

Every Commonveil release is published for self-hosted sites.

- When there's a new one, admins see a notice in **Site admin**, and **Updates** shows what's new with a button to install it.
- Turn on **Install updates automatically** to have it done in the background.
- Before each update the database is backed up, and if the new version doesn't start, the site goes back to the old one.

Release notes for every version are at [Releases](https://commonveil-rebuild-71d823fd.base44.app/releases).

#### Other sites

Your site talks to other Commonveil sites, so its people can message people elsewhere ([People on other sites](#people-on-other-sites)). Under **Site admin → Other sites** you can see each site yours has talked to, and block any of them. Turn it off with `FEDERATION=false`.

#### With no internet

A Commonveil site needs a network, not the internet. On a Raspberry Pi with its own Wi-Fi hotspot, everyone in range can make an account and chat, with nothing leaving the room. When it gets an internet connection again, anything that was waiting for other sites goes out. The set-up, including the certificate browsers need, is in `docs/SELF_HOSTING.md`.

## Help

### Troubleshooting and questions

_Fixes for the things people most often run into, and answers to common questions._

#### "Decrypting…" doesn't go away

Your device is waiting for the keys to open a message. Wait a moment, or reload the page. In a server, newcomers get keys from staff or members whose apps are online, so it can take a little while the first time.

#### "Waiting for your latest keys"

This device is approved, but your keys changed since, for example because you removed another device. Your other devices send the update automatically the next time one of them opens Commonveil. If that's not possible, remove this device and set it up again with your recovery phrase.

#### "Sent before you could read here"

The message was locked before you had the keys for it: in a group, before you were added; in a server channel that shows history only from when people join, before you joined. It can't be opened, by design.

#### "Their security keys changed"

They've reset their account, or something is wrong. Check with them in person or on a call before you **Accept the new keys**. See [safety numbers](#safety-numbers-and-key-changes).

#### I can't find someone

They have to give you their exact username. They might also have chosen to accept new conversations only from people they share a server with, or from nobody new.

#### A call won't connect

Calls go directly between devices, and some strict networks (often workplaces or public Wi-Fi) block that. Try another network, or a phone hotspot. Allow the browser to use your microphone and camera when it asks.

#### I'm not getting notifications

Notifications only appear while Commonveil is open in a tab. Check that **Notify me of new messages** is on in **Settings → Notifications**, that your browser allows notifications for this site, and that quiet hours or focus aren't on. Muted servers and channels don't notify.

#### "The service is busy"

Commonveil has a limit on how much it can do per minute. It tries again by itself; if it keeps happening, wait a minute and try again.

#### My scheduled message or check-in arrived late

They're delivered by a task that runs every few minutes, so they can arrive up to about five minutes after the time.

#### I forgot my passcode

There's no way to recover a passcode: Commonveil never had it. On the lock screen choose **Forgot your passcode?** and type **REMOVE**. This browser is removed from your account and its keys wiped; set it up again by linking it from another device or with your recovery phrase. Your account and messages stay as they are on your other devices.

#### I lost my phone

From another device, open **Settings → Devices and keys** and remove it. Your keys are renewed so it can't read anything new.

#### I lost every device and my recovery phrase

You can [reset your encryption](#devices-recovery-and-resets) to keep your account and username. It waits a week, and messages sent to you before then can't be recovered.

#### Can Commonveil read my messages?

No. It stores them locked and doesn't have the keys. See [how the encryption works](#how-the-encryption-works).

#### Are there adverts or trackers?

No. There are no adverts, no analytics and no trackers, on the site or in the app.

#### Still stuck?

Ask in the Commonveil Community server, or open a support ticket there. To report a weakness in Commonveil itself, use [Report a security problem](https://commonveil-rebuild-71d823fd.base44.app/security/report).
