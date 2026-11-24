import React from "react";
import { Link } from "react-router-dom";
import { ArrowRight, GitBranch, Globe2, Inbox, KeyRound, LockKeyhole } from "lucide-react";

/**
 * Public developer orientation, not a live protocol capability endpoint.
 * The Secure Net specification and its releases are governed independently
 * from Commonveil. No client-side crypto, account or transport is activated.
 */
const GITHUB = "https://github.com/Comutability/secure-net";
const CARDS = [
  {
    Icon: KeyRound,
    title: "Independent identities",
    text: "An actor's signing and encryption keys belong to its devices. A compatible application can create and verify them without asking Commonveil to issue an identity.",
  },
  {
    Icon: Inbox,
    title: "Inbox, outbox and relay",
    text: "Secure Net specifies how applications hand off sealed envelopes through their own site's outbox, authenticated site-to-site delivery and the destination's mailbox.",
  },
  {
    Icon: Globe2,
    title: "Any compatible application",
    text: "A developer can implement the published CVP contracts in another site or app. Commonveil is the first app adopting them, not a required server or authority.",
  },
  {
    Icon: LockKeyhole,
    title: "Encryption stays with users",
    text: "The sending device seals private messages for receiving devices. Relay operators still see necessary routing, size and timing metadata, but should not receive message decryption keys.",
  },
];

export default function SecureNet() {
  return (
    <div className="container-cv py-12 sm:py-16">
      <p className="eyebrow">Open protocol</p>
      <h1 className="mt-3 max-w-3xl text-4xl font-semibold sm:text-5xl">Secure Net is independent of Commonveil</h1>
      <p className="mt-5 max-w-3xl text-lg text-muted-foreground">
        Secure Net is a separate, community-led, open-source protocol for encrypted communication
        between compatible sites and applications. Commonveil is its first application.
        Developers can build their own software around Secure Net without creating a Commonveil
        account, operating a Commonveil instance or depending on Commonveil's product roadmap.
      </p>

      <div className="mt-8 grid gap-4 sm:grid-cols-2">
        {CARDS.map(({ Icon, title, text }) => (
          <section key={title} className="card-cv p-5">
            <Icon className="h-6 w-6 text-primary" aria-hidden="true" />
            <h2 className="mt-3 text-lg font-semibold">{title}</h2>
            <p className="mt-2 text-sm text-muted-foreground">{text}</p>
          </section>
        ))}
      </div>

      <section className="mt-10 rounded-xl border border-border p-6">
        <h2 className="text-2xl font-semibold">How messages cross applications</h2>
        <p className="mt-3 text-muted-foreground">
          One app encrypts an envelope for a recipient, then submits it to its own site's outbox.
          Its site can deliver through Secure Net's signed, post-quantum sealed relay protocol
          to the recipient site's inbox or mailbox. The recipient app verifies and decrypts it
          locally. Sites are responsible for authenticating senders, replay prevention, delivery,
          device lists, blocking and consent. A relay can delay or refuse traffic, and encryption
          does not hide all metadata.
        </p>
        <p className="mt-3 text-sm text-muted-foreground">
          There is no compulsory central Commonveil server in this design. Site-to-site
          interoperability depends on two real implementations advertising and negotiating
          compatible Secure Net features, not merely sharing a brand or a URL.
        </p>
      </section>

      <section className="mt-8 rounded-xl border border-border p-6">
        <h2 className="text-2xl font-semibold">Implementation status</h2>
        <p className="mt-3 text-muted-foreground">
          Secure Net's CVP-017 to CVP-022 specifications and Rust reference code include
          independent actors, encrypted delivery, inbox/outbox contracts and federation tests.
          Commonveil also has an older application-specific federation interface called
          commonveil/1. That older interface is not the same as the full Secure Net CVP-019
          third-party transport and must not be advertised as such.
        </p>
        <p className="mt-3 text-muted-foreground">
          The hosted Commonveil site does <strong>not yet offer verified public CVP-019
          cross-application inbox/outbox interoperation</strong>. The self-hosted Rust migration
          staging and signed recipient-consent experiments remain disabled by default in Docker.
          They do not migrate accounts, export history keys or transfer inbox ownership.
          No independent cryptographic audit has been completed.
        </p>
      </section>

      <section className="mt-8 rounded-xl border border-border p-6">
        <h2 className="text-2xl font-semibold">Build with Secure Net</h2>
        <p className="mt-3 text-muted-foreground">
          Start with the independent specification, the Rust reference examples, delivery
          conformance tests and public Secure Net Improvement Proposals (SNIPs). These are
          protocol resources, not Commonveil-only application APIs.
        </p>
        <div className="mt-5 flex flex-wrap gap-x-6 gap-y-3 text-sm font-medium">
          <a className="inline-flex items-center gap-2 text-primary hover:underline" href={GITHUB} target="_blank" rel="noopener noreferrer">
            <GitBranch className="h-4 w-4" aria-hidden="true" /> Secure Net source and docs
          </a>
          <a className="inline-flex items-center gap-2 text-primary hover:underline" href={GITHUB + "/blob/main/spec/CVP-019-delivery.md"} target="_blank" rel="noopener noreferrer">
            Delivery specification <ArrowRight className="h-4 w-4" aria-hidden="true" />
          </a>
          <a className="inline-flex items-center gap-2 text-primary hover:underline" href={GITHUB + "/tree/main/snips"} target="_blank" rel="noopener noreferrer">
            SNIPs and community review <ArrowRight className="h-4 w-4" aria-hidden="true" />
          </a>
          <Link className="inline-flex items-center gap-2 text-primary hover:underline" to="/security">
            Commonveil security and current limits <ArrowRight className="h-4 w-4" aria-hidden="true" />
          </Link>
        </div>
      </section>
    </div>
  );
}
