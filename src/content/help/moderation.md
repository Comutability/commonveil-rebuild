---
title: Moderation and safety tools
summary: Reports, escalating to Commonveil, warnings, timeouts, kicks and bans, AutoMod, spam and raid protection, staff limits and lockdown.
section: Running a server
order: 3
---

Commonveil can't read anything in a server, so it can't moderate it for you. Instead, it gives your moderators the tools that popular moderation bots offer, built in and working without breaking the encryption. Owners decide how each one behaves in their own server.

## Reports from members

Members choose **Report message** from a message's menu, pick **What's wrong?** (spam or scams, harassment, hate speech, threats, unwanted sexual content, fraud, something illegal, someone at risk of harming themselves, or something else) and add a note if they want.

- The report is **encrypted to the server's moderators only**: the reporter plus up to 31 moderators, highest first, and never the person reported. Moderators who join later can't read earlier reports.
- Members can also tick to **tell the Commonveil team**, for things that break the law or Commonveil's rules. What they write (and the message, if they include it) is shared with the team in readable form, since the team can't read anything otherwise.

Moderators find reports under **Server settings → Reports**, where they can act on them, **Dismiss** them, or close them.

## Escalating to Commonveil

For something serious (illegal content, a threat to someone's safety, abuse across servers), a moderator can choose **Send to the Commonveil team** on a report. Choose **What kind of problem** it is and edit **What to share** down to what's needed, leaving out other people's private details. It reaches the Commonveil team as a readable report, with the server it came from.

## Acting on someone

Open a person's profile card (click their name) and use **Moderation**:

- **Warning:** a formal warning they can see. Warnings count towards your warning steps (below). **Pardon** a warning to stop it counting.
- **Note:** a private note for moderators only.
- **Time out for** a set time: they can't post or join calls.
- **Kick:** they're removed and their copies of the server's keys are deleted. They can come back with an invite.
- **Ban:** for good or for a set time. Keys are renewed so they can't read anything new. **Delete their messages from** a recent period at the same time if you need to.

Reasons are encrypted and only moderators see them. Bans are listed under **Server settings → Bans**, where you can lift them.

## Cases

Every warning, note, timeout, kick, ban, unban and purge, whether done by a person or by the server's own rules, becomes a numbered case under **Server settings → Cases**. Members can see their own warnings.

## Safety settings

Under **Server settings → Safety**:

**AutoMod** checks messages on each person's device, before sending and before showing, so it works without anyone's messages being decrypted by Commonveil. Set **Blocked words** (use `*` as a wildcard), and block links, invite links or too many mentions. Staff with **Manage messages** are exempt.

**Warnings:** add steps such as "at 3 warnings, time out for a day" or "at 5, ban". Choose the **Number of warnings**, **What happens** (time out, kick or ban) and **For how long**, and how far back warnings count (**Count warnings from the last**).

**Spam and raids** work from counts and times alone:
- **Flood protection:** time out anyone who sends more than a set number of **Messages** in a few **Seconds**.
- **Raid protection:** if more than a set number of people join in a minute (**Joins per minute**), joining pauses.

**New accounts and newcomers:** require accounts to be a minimum age before joining (**Accounts must be at least**), and make newcomers wait before posting (**Newcomers wait**).

**Staff limits** stop a compromised or rogue staff account wrecking the server: anyone but the owner who bans, kicks, times out, or deletes channels or roles too many times in ten minutes is stopped, and loses their roles until the owner gives them back. Only the owner can turn this off.

**Lockdown**, for when something's going wrong:
- **Pause invites:** existing links stop working until you turn it off.
- **Pause joining:** nobody new can join, by invite or from Discover.

## Rules screening

Under **Rules and screening**, write your rules and turn on **Rules screening**. New members can read but not post until they accept them.

## In calls

Moderators with **Mute members and run stages** can **Mute for everyone** in a call. The mute holds until a moderator lifts it, and every app silences that person. Anyone removed or timed out is taken out of calls within a minute.

## Audit log

**Server settings → Audit log** shows who changed what in the server's settings. Choose how long it's kept with **Keep the audit log for**.
