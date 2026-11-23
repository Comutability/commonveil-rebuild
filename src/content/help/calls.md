---
title: Voice and video calls
summary: Calls in conversations, voice channels and stages, with camera and screen sharing.
section: Messages and calls
order: 3
---

Calls go **directly between devices**. Commonveil helps them find each other, then steps out of the way: it never receives your audio or video.

## Calling someone

In a conversation, choose **Start a call**. Everyone in the conversation gets a call message they can join from. Calls hold up to 8 devices.

## Voice channels in servers

Select a voice channel to join it. Anyone with permission to connect can drop in and out.

## In a call

- **Mute** or **Unmute** your microphone.
- **Deafen** to stop hearing everyone else.
- **Turn camera on**, or **Share your screen**.
- **Leave the call** when you're done.

## Stages

A stage is a voice channel for talks and events, for up to 16 people. Moderators speak; everyone else listens. Listeners can ask to speak, and a moderator can **Invite to speak**, **Move to the audience** or mute them. Apps won't play anyone the stage says can't speak, even if they try.

## How calls are protected

- Before your device connects to someone, it checks that their connection was signed by one of their own certified devices. If it wasn't, it refuses and tells you. This stops anyone, including whoever runs the call relay, from sitting in the middle.
- Every audio and video frame is encrypted twice: once by the browser's own call encryption, and again with the channel's or call's own keys.

## Good to know

- Direct calls can reveal the participants' network addresses to one another. Cloudflare STUN helps devices discover their routes. Where an operator has configured a TURN relay, it may carry encrypted media when a direct connection is blocked; the TURN operator sees network metadata, never decrypted audio or video.
- Commonveil shows **Waiting for others** until a second participant joins. **Connected** means a WebRTC link is actually established, not merely that the signalling server accepted you. A connection that cannot succeed reports a reason instead of spinning indefinitely.
- Some restrictive networks require a TURN relay. If a call fails, try another network or ask the server operator to configure TURN. Both people can leave and rejoin to retry with fresh connection details.
- Commonveil knows who joined which call and when, but not what was said.
- Moderator mutes in servers hold until a moderator lifts them.
