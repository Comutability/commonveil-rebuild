---
title: Roles and permissions
summary: What each permission allows, how roles stack, and how to make a channel private.
section: Running a server
order: 2
---

Roles decide what people can do. Everyone has the **@everyone** role; you add others for moderators, helpers, regulars and so on. Commonveil checks permissions on every action, and changes are signed by a device, so a stolen sign-in alone can't change anything.

## Make and give roles

Open **Server settings → Roles**. Create a role, name it (the name is encrypted), choose a colour, and tick its permissions. Give it to someone from their profile card in the server.

- **Order matters.** Roles higher in the list outrank lower ones. Someone with **Manage roles** can only edit and give roles below their own highest role.
- **The owner** is above every role.

## The permissions

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

## Per-channel permissions

In a channel's settings, under **Permissions**, you can allow or deny any permission for a role in just that channel.

**To make a channel private,** deny **@everyone** the **View channels** permission there, then allow it for the roles that should see it. A private channel gets its own keys, given only to people who can see it, so nobody else in the server can read it.

## Staff and the member list

People with moderation or management permissions count as **staff**. Staff are always shown in the member list, so members can see who runs the server. Everyone else is only listed if they choose to be.
