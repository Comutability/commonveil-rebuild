# Site ownership, public rules and federation moderation

Commonveil's **site-wide** moderation is separate from permissions inside individual community servers. It takes cues from Mastodon's domain moderation while respecting Commonveil's encrypted messaging.

**Secure Net is an independent open protocol.** A Commonveil host's policy applies only to that host, not to the whole protocol or another independent site's content.

## Management and permissions

Sign in as a site administrator and open **Site admin → Site rules & safety**. Public site rules are shown at **/rules**. Unlike a community's encrypted membership rules, these are deliberately public.

| Capability | Site owner | Site admin | User |
| --- | --- | --- | --- |
| Read public rules | Yes | Yes | Yes |
| Set site rules, appeals contact and blocklist disclosure | Yes | Yes | No |
| Suspend, limit, reject media or allow an exact remote host | Yes | Yes | No |
| Change sign-up and federation mode | Yes | No | No |
| Decrypt someone else's private messages | No | No | No |

Operators should base restrictions on legitimate reports, visible metadata and evidence supplied voluntarily. Neither owner nor administrators can scan private encrypted messages just to determine whether they are inappropriate.

## Federation modes

- **Open:** accept compatible sites except those explicitly suspended.
- **Approved sites only:** only communicate with exact hosts explicitly marked Allow. Suspended hosts stay denied.
- **Off:** refuse incoming and outgoing federation, without deleting existing locally held encrypted messages. The Docker operator can additionally set `FEDERATION=false` to disable the federation subsystem itself.

Every policy change applies to new inbound and outbound requests, including previously cached trusted remote-site documents. These are exact hostnames, so blocking `chat.example.net` does not automatically block `other.chat.example.net`.

## Per-domain moderation

| Action | Behaviour on this host |
| --- | --- |
| Suspend | Reject authenticated incoming and outgoing site transport, remote discovery and media proxy traffic |
| Limit | Refuse new remote conversations, groups, member additions and joins, plus directory discovery, but preserve established encrypted exchanges |
| Reject media | Reject files through the Commonveil remote-file proxy. Already downloaded attachments cannot be erased by this setting |
| Allow | Add the exact hostname to the approved-site set for restricted federation |

The original legacy federation blocklist remains effective independently. The self-hosted Node and Rust server implementations enforce these policies. The separately disabled experimental CVP-019 Rust relay checks local suspensions and approved-site restrictions before accepting remote delivery, queuing messages to remote sites or flushing queued ciphertext.

## Reasons and appeals

The operator can optionally disclose the list of suspended and limited domains with a public reason. Private staff notes are available only through administrator actions and are not included in the public rules response.

Do not put report authors, usernames from private cases, sensitive evidence or private-message contents in published reasons. The host should provide an appeals contact if possible.

## Registration and Docker

The owner can stop new account registration, and authorised admins can switch off remote directory discovery. The Docker `OPEN_REGISTRATION=false` setting remains an upper bound: a web setting cannot reopen registration when the environment disabled it. The site's first-account setup code still applies.

The settings are saved in the persistent data volume as backend-only `SitePolicy` and `SiteDomainRule` records, not as a plaintext public file. Default values remain permissive, subject to the site's existing Docker configuration.

```env
OPEN_REGISTRATION=true
FEDERATION=true
```

Back up the database before major production federation changes. The host operator is responsible for exercising these choices fairly and explaining their own moderation procedures.

## Limitations

These are local transport restrictions, not a global content-control service, not an automatic abuse classifier and not an inspection of end-to-end encrypted messages. Limiting a remote host is not the same as Mastodon's ActivityPub semantics. Wildcard/suffix domain blocks are not implemented, and previously downloaded media cannot be removed remotely.

Mastodon reference: https://docs.joinmastodon.org/admin/moderation/

See [Self-hosting](SELF_HOSTING.md), [Federation](FEDERATION.md) and [Experimental Secure Net relay](SECURE_NET_RELAY.md).
