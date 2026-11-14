# Registries

Generated from [`registry.json`](registry.json) by `node scripts/standards.mjs --write`. Don't edit this
file: change `registry.json` through a SNIP (CVP-000, section 7), then regenerate it.

Release 0.5.0.

## Features

| Feature | Version | Part | Notes |
| --- | --- | --- | --- |
| `cvp.federation` | 2 | CVP-005 |  |
| `cvp.sealed-relay` | 1 | [CVP-015](CVP-015-quantum-resistance.md) |  |
| `cvp.pq-signatures` | 1 | [CVP-015](CVP-015-quantum-resistance.md) |  |
| `cvp.identity` | 2 | CVP-001 |  |
| `cvp.sessions` | 1 | [CVP-016](CVP-016-sessions.md) |  |
| `cvp.envelope` | 1 | CVP-003 |  |
| `cvp.commons-ledger` | 1 | [CVP-011](CVP-011-commons-ledger.md) |  |
| `cvp.governance` | 1 | [CVP-012](CVP-012-governance.md) |  |
| `cvp.tokens` | 1 | [CVP-013](CVP-013-tokens.md) |  |
| `cvp.personas` | 1 | CVP-001 |  |
| `cvp.consent` | 1 | CVP-014 |  |
| `cvp.extensions` | 1 | CVP-008 |  |
| `cvp.actors` | 1 | [CVP-017](CVP-017-actors.md) |  |
| `cvp.activities` | 1 | [CVP-018](CVP-018-activities.md) |  |
| `cvp.delivery` | 1 | [CVP-019](CVP-019-delivery.md) |  |
| `cvp.repos` | 1 | [CVP-020](CVP-020-repositories.md) |  |
| `cvp.lexicons` | 1 | [CVP-021](CVP-021-lexicons.md) |  |

## Record kinds

Signed with the label `secure-net/<kind>/v1` (CVP-002).

| Kind | Part | Notes |
| --- | --- | --- |
| `actor.document` | [CVP-017](CVP-017-actors.md) |  |
| `commons.block` | [CVP-011](CVP-011-commons-ledger.md) |  |
| `commons.host` | [CVP-011](CVP-011-commons-ledger.md) |  |
| `consent.capsule` | CVP-014 |  |
| `consent.revocation` | CVP-014 |  |
| `debate.argument` | [CVP-012](CVP-012-governance.md) |  |
| `debate.evidence` | [CVP-012](CVP-012-governance.md) |  |
| `debate.moderation` | [CVP-012](CVP-012-governance.md) |  |
| `debate.position` | [CVP-012](CVP-012-governance.md) |  |
| `debate.rebuttal` | [CVP-012](CVP-012-governance.md) |  |
| `debate.round` | [CVP-012](CVP-012-governance.md) |  |
| `extension.manifest` | CVP-008 |  |
| `governance.motion` | [CVP-012](CVP-012-governance.md) |  |
| `identity.migration` | CVP-001 |  |
| `identity.persona-link` | CVP-001 |  |
| `lexicon.schema` | [CVP-021](CVP-021-lexicons.md) |  |
| `repo.commit` | [CVP-020](CVP-020-repositories.md) |  |
| `session.device-list` | [CVP-016](CVP-016-sessions.md) |  |
| `session.prekey` | [CVP-016](CVP-016-sessions.md) |  |
| `social.activity` | [CVP-018](CVP-018-activities.md) |  |
| `theme.package` | CVP-008 |  |
| `vote.ballot` | [CVP-012](CVP-012-governance.md) |  |
| `vote.result` | [CVP-012](CVP-012-governance.md) |  |
| `vote.secret-ballot` | [CVP-012](CVP-012-governance.md) |  |

## Ledger events and capabilities

| Event | Capability needed | Part | Notes |
| --- | --- | --- | --- |
| `commons.genesis` | `authority` | [CVP-011](CVP-011-commons-ledger.md) |  |
| `keys.set` | `authority` | [CVP-011](CVP-011-commons-ledger.md) |  |
| `replicas.set` | `authority` | [CVP-011](CVP-011-commons-ledger.md) |  |
| `policy.set` | `authority` | [CVP-011](CVP-011-commons-ledger.md) |  |
| `host.move` | `authority` | [CVP-011](CVP-011-commons-ledger.md) |  |
| `governance.result` | `govern` | [CVP-012](CVP-012-governance.md) |  |
| `member.add` | `members` | CVP-004 |  |
| `member.remove` | `members` | CVP-004 |  |
| `role.set` | `roles` | CVP-004 |  |
| `ban.set` | `moderate` | CVP-004 |  |
| `channel.set` | `channels` | CVP-004 |  |
| `channel.remove` | `channels` | CVP-004 |  |
| `content.ref` | `content` | CVP-004 |  |
| `note` | `content` | [CVP-011](CVP-011-commons-ledger.md) | grandfathered: Registered before the naming rule; new events must be <area>.<name> |

| Capability | Part | Notes |
| --- | --- | --- |
| `authority` | [CVP-011](CVP-011-commons-ledger.md) | implies every other capability; authority events also need the community's threshold |
| `govern` | [CVP-012](CVP-012-governance.md) |  |
| `members` | CVP-004 |  |
| `roles` | CVP-004 |  |
| `moderate` | CVP-004 |  |
| `channels` | CVP-004 |  |
| `content` | CVP-004 |  |

## Extension execution models and permissions

| Execution | Permissions it may ask for | Part | Notes |
| --- | --- | --- | --- |
| `client-local` | `read.selected`, `read.channel`, `write.message`, `ui.panel`, `ui.command`, `storage.local` | CVP-008 |  |
| `server-side` | `read.metadata`, `read.ciphertext`, `write.ciphertext`, `queue`, `ratelimit` | CVP-008 | grandfathered: queue and ratelimit predate the <verb>.<object> rule |
| `external` | `send.selected`, `ui.panel` | CVP-008 |  |
| `public` | `read.public`, `publish.public` | CVP-008 |  |

## Consent actions and vote methods

| Consent action | Part |
| --- | --- |
| `read` | CVP-014 |
| `store` | CVP-014 |
| `replicate` | CVP-014 |
| `forward` | CVP-014 |
| `process` | CVP-014 |
| `publish` | CVP-014 |

| Vote method | Part |
| --- | --- |
| `majority` | [CVP-012](CVP-012-governance.md) |
| `supermajority` | [CVP-012](CVP-012-governance.md) |
| `approval` | [CVP-012](CVP-012-governance.md) |
| `ranked` | [CVP-012](CVP-012-governance.md) |

## Social vocabulary

ActivityStreams 2.0 names (CVP-018), carried as plain canonical JSON rather than JSON-LD.

| Actor type | Part | ActivityStreams |
| --- | --- | --- |
| `Person` | [CVP-017](CVP-017-actors.md) | https://www.w3.org/ns/activitystreams#Person |
| `Group` | [CVP-017](CVP-017-actors.md) | https://www.w3.org/ns/activitystreams#Group |
| `Organization` | [CVP-017](CVP-017-actors.md) | https://www.w3.org/ns/activitystreams#Organization |
| `Service` | [CVP-017](CVP-017-actors.md) | https://www.w3.org/ns/activitystreams#Service |
| `Application` | [CVP-017](CVP-017-actors.md) | https://www.w3.org/ns/activitystreams#Application |

| Activity type | Part | ActivityStreams |
| --- | --- | --- |
| `Create` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Create |
| `Update` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Update |
| `Delete` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Delete |
| `Follow` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Follow |
| `Accept` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Accept |
| `Reject` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Reject |
| `Undo` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Undo |
| `Like` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Like |
| `Announce` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Announce |
| `Add` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Add |
| `Remove` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Remove |
| `Block` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Block |
| `Flag` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Flag |
| `Join` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Join |
| `Leave` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Leave |
| `Invite` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Invite |
| `Move` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Move |

| Object type | Part | ActivityStreams |
| --- | --- | --- |
| `Note` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Note |
| `Article` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Article |
| `Image` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Image |
| `Video` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Video |
| `Audio` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Audio |
| `Document` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Document |
| `Page` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Page |
| `Event` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Event |
| `Place` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Place |
| `Question` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Question |
| `Tombstone` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Tombstone |

| Address | Part | ActivityStreams |
| --- | --- | --- |
| `public` | [CVP-018](CVP-018-activities.md) | https://www.w3.org/ns/activitystreams#Public |
| `followers` | [CVP-018](CVP-018-activities.md) | the actor's followers collection |

| Envelope mode | Part | What a site can read |
| --- | --- | --- |
| `public` | [CVP-019](CVP-019-delivery.md) | signed, readable |
| `direct` | [CVP-019](CVP-019-delivery.md) | CVP-016 session to one device |
| `audience` | [CVP-019](CVP-019-delivery.md) | CVP-016 sender key, one ciphertext for an audience |

| Lexicon field type | Part |
| --- | --- |
| `string` | [CVP-021](CVP-021-lexicons.md) |
| `integer` | [CVP-021](CVP-021-lexicons.md) |
| `boolean` | [CVP-021](CVP-021-lexicons.md) |
| `id` | [CVP-021](CVP-021-lexicons.md) |
| `actor` | [CVP-021](CVP-021-lexicons.md) |
| `array` | [CVP-021](CVP-021-lexicons.md) |

## Algorithm suites

| Suite | Used for | Part | Notes |
| --- | --- | --- | --- |
| `Ed25519` | classical signatures on signed records and site requests | [CVP-002](CVP-002-signed-records.md) |  |
| `Ed25519+ML-DSA-65` | quantum-resistant signatures on signed records; both must verify | [CVP-015](CVP-015-quantum-resistance.md) |  |
| `p256-mlkem768+mldsa65` | sealed relay between sites | [CVP-015](CVP-015-quantum-resistance.md) |  |
| `P256-SHA256` | RFC 9497 VOPRF tokens | [CVP-013](CVP-013-tokens.md) |  |
| `MLKEM768-P256` | hybrid sealing in the older envelope | CVP-003 |  |

## Labels

Every signature, hash and key derivation is separated by one of these. A label's meaning never changes;
a change means a new version (CVP-000, 4.4). `<...>` marks a variable part.

| Label | Used for | Part | Notes |
| --- | --- | --- | --- |
| `secure-net/<kind>/v1` | signed records: prefix of the signed bytes, followed by a newline | [CVP-002](CVP-002-signed-records.md) |  |
| `secure-net/relay/v1` | sealed relay key derivation | [CVP-015](CVP-015-quantum-resistance.md) |  |
| `secure-net/tokens/v1/<scope>` | VOPRF key derivation per scope | [CVP-013](CVP-013-tokens.md) |  |
| `secure-net/nullifier/v1` | token nullifiers | [CVP-013](CVP-013-tokens.md) |  |
| `secure-net/session/v1` | prefix of every session label below | [CVP-016](CVP-016-sessions.md) |  |
| `secure-net/session/v1/<purpose>` | how session/primitives.js builds the labels below; it refuses any purpose not registered here | [CVP-016](CVP-016-sessions.md) |  |
| `secure-net/session/v1/handshake` | handshake secret (HKDF info, followed by the transcript hash) | [CVP-016](CVP-016-sessions.md) |  |
| `secure-net/session/v1/transcript` | transcript hash prefix | [CVP-016](CVP-016-sessions.md) |  |
| `secure-net/session/v1/root` | root chain HKDF info | [CVP-016](CVP-016-sessions.md) |  |
| `secure-net/session/v1/message` | message key HKDF info | [CVP-016](CVP-016-sessions.md) |  |
| `secure-net/session/v1/group` | group message key HKDF info, and associated-data prefix | [CVP-016](CVP-016-sessions.md) |  |
| `secure-net/session/v1/group-sig` | group message signature prefix | [CVP-016](CVP-016-sessions.md) |  |
| `secure-net/session/v1/history` | history chunk HKDF info, and associated-data prefix | [CVP-016](CVP-016-sessions.md) |  |
| `secure-net/session/v1/history/<i>` | per-chunk key derivation | [CVP-016](CVP-016-sessions.md) |  |
| `secure-net/session/v1/link` | link code | [CVP-016](CVP-016-sessions.md) |  |
| `secure-net/session/v1/safety` | safety number | [CVP-016](CVP-016-sessions.md) |  |
| `commonveil-request/v1` | first line of a site request's signature base | CVP-005 |  |
| `commonveil/<context>` | older canonical signing contexts | CVP-001 |  |
| `commonveil/content/v1` | older envelope content binding | CVP-003 |  |
| `commonveil/key-commitment/v1` | older key commitments | CVP-003 |  |
| `commonveil/wrap/v1` | older key wrapping | CVP-003 |  |
| `commonveil/chain-digest/v1` | account key chain digests | CVP-001 |  |
| `commonveil/link-code/v2` | older link codes | CVP-001 | deprecated |
| `commonveil/link-code/v3` | older link codes with ML-KEM keys | CVP-001 |  |
| `commonveil/safety/v2` | older safety numbers | CVP-001 |  |
| `commonveil/kem-seal/v1` | older hybrid sealing salt | CVP-003 |  |
| `commonveil.keyring.v1` | older account keyring | CVP-003 |  |
| `commonveil/keyring-recovery/v1` | older keyring recovery | CVP-003 |  |
| `commonveil/keyring-to-device/v1` | older keyring delivery to devices | CVP-003 |  |
| `commonveil passcode check v1` | app lock passcode check | CVP-001 | grandfathered: Not in label form |
| `commonveil-lock:<purpose>` | app lock associated data | CVP-001 | grandfathered: Not in label form |
| `commonveil/owner/v1` | site owner proofs | CVP-005 |  |
| `commonveil-owner/v1` | site owner challenge | CVP-005 |  |
| `commonveil/recovery/v1` | recovery phrase derivation | CVP-001 |  |
| `commonveil/invite-preview/v1` | invite previews | CVP-003 |  |
| `commonveil/server-item-key/v1` | community item keys | CVP-003 |  |
| `commonveil/chain-commit/v1` | community key chain commitments | CVP-003 |  |
| `commonveil/key-grant/v1` | community key grants | CVP-003 |  |
| `commonveil/ratchet/v1` | community key ratchet | CVP-003 |  |
| `commonveil/server-content/v1` | community content binding | CVP-003 |  |
| `secure-net/social/v1/session` | session tag on direct envelopes (SHA-256 of this label, a newline and the session's handshake hash) | [CVP-019](CVP-019-delivery.md) |  |
| `secure-net/repo/v1/leaf` | Merkle leaf hash prefix (followed by a newline and the record id) | [CVP-020](CVP-020-repositories.md) |  |
| `secure-net/repo/v1/node` | Merkle node hash prefix (followed by a newline and the two child hashes) | [CVP-020](CVP-020-repositories.md) |  |
| `secure-net/repo/v1/empty` | root of an empty repository | [CVP-020](CVP-020-repositories.md) |  |

## Protocol identifiers

| Identifier | Used for | Part |
| --- | --- | --- |
| `commonveil/1` | the federation protocol identifier (wire/federation.js PROTOCOL) | CVP-005 |
| `secure-net` | the protocol named in a site document (wire/features.js describeSite) | CVP-008 |

## Endpoints

Defaults; a site may list others in its site document, except the site document itself.

| Name | Path | Part | Notes |
| --- | --- | --- | --- |
| site-document | `/.well-known/commonveil` | CVP-005 | fixed |
| act | `/cvp/v1/act` | CVP-005 |  |
| directory | `/cvp/v1/directory` | CVP-005 |  |
| inbox | `/cvp/v1/inbox` | CVP-005 |  |
| discover | `/cvp/v1/discover` | CVP-005 |  |
| actors | `/cvp/v1/actors/{name}/{room}` | CVP-005 |  |
| identity | `/.well-known/commonveil/identity` | CVP-001 |  |
| files | `/api/files` | CVP-006 |  |
| actor | `/.well-known/commonveil/actor` | [CVP-017](CVP-017-actors.md) |  |
| prekeys | `/cvp/v2/prekeys/{actor}/{device}` | [CVP-017](CVP-017-actors.md) |  |
| deliver | `/cvp/v2/deliver` | [CVP-019](CVP-019-delivery.md) |  |
| outbox | `/cvp/v2/outbox` | [CVP-019](CVP-019-delivery.md) |  |
| mailbox | `/cvp/v2/mailbox` | [CVP-019](CVP-019-delivery.md) |  |
| public | `/cvp/v2/public/{actor}` | [CVP-019](CVP-019-delivery.md) |  |
| repo | `/cvp/v2/repo/{actor}` | [CVP-020](CVP-020-repositories.md) |  |
| changes | `/cvp/v2/changes` | [CVP-020](CVP-020-repositories.md) |  |
| lexicon | `/cvp/v2/lexicon/{id}` | [CVP-021](CVP-021-lexicons.md) |  |

## HTTP headers

| Header | Carries | Part |
| --- | --- | --- |
| `CV-From` | sending site's host | CVP-005 |
| `CV-Date` | request time | CVP-005 |
| `CV-Nonce` | one-off request nonce | CVP-005 |
| `CV-Digest` | body digest (sha-256=<base64url>) | CVP-005 |
| `CV-User` | id of the person the request is made on behalf of (covered by the signature) | CVP-005 |
| `CV-Person` | base64 JSON profile card of that person, on actor connections; its id MUST equal CV-User | CVP-005 |
| `CV-Signature` | Ed25519 signature over the signature base | CVP-005 |
| `CV-PQ-Signature` | ML-DSA-65 signature over the signature base | [CVP-015](CVP-015-quantum-resistance.md) |
| `CV-Sealed` | marks a sealed request body | [CVP-015](CVP-015-quantum-resistance.md) |

## Conformance profiles

What each profile requires is in [CVP-010](CVP-010-conformance.md).

| Profile | Name | Parts | For |
| --- | --- | --- | --- |
| `core` | Core | [CVP-002](CVP-002-signed-records.md) | Anything that creates or checks signed records |
| `messaging` | Messaging app | [CVP-002](CVP-002-signed-records.md), [CVP-016](CVP-016-sessions.md) | Apps that send end-to-end encrypted messages |
| `site` | Federating site | [CVP-002](CVP-002-signed-records.md), CVP-005, CVP-008, [CVP-015](CVP-015-quantum-resistance.md) | Servers that talk to other sites |
| `community` | Community host or mirror | [CVP-002](CVP-002-signed-records.md), CVP-004, [CVP-011](CVP-011-commons-ledger.md) | Sites that host or mirror communities |
| `governance` | Governance | [CVP-002](CVP-002-signed-records.md), [CVP-011](CVP-011-commons-ledger.md), [CVP-012](CVP-012-governance.md), [CVP-013](CVP-013-tokens.md) | Motions, debates and ballots |
| `extensions` | Extensions and consent | [CVP-002](CVP-002-signed-records.md), CVP-008, CVP-014 | Hosts that run extensions or honour consent capsules |
| `commonveil-compatible` | Commonveil-compatible (older) | CVP-001, [CVP-002](CVP-002-signed-records.md), CVP-003, CVP-005 | Talking to today's Commonveil sites, before they move to CVP-016 |
| `social` | Social network site or app | [CVP-002](CVP-002-signed-records.md), CVP-005, [CVP-015](CVP-015-quantum-resistance.md), [CVP-016](CVP-016-sessions.md), [CVP-017](CVP-017-actors.md), [CVP-018](CVP-018-activities.md), [CVP-019](CVP-019-delivery.md), [CVP-020](CVP-020-repositories.md), [CVP-021](CVP-021-lexicons.md) | Federated social networking, end to end encrypted, with portable accounts and verifiable public data |
