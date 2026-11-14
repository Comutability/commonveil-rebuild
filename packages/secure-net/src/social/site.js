// A reference site for CVP-017 and CVP-019, in memory: what a server must do, without any
// particular web framework or database. Commonveil's server is the production implementation;
// this one exists so the protocol can be tested end to end and read in one place.
//
// What a site does: serve actor documents and prekey bundles; take envelopes from its own users
// (the outbox) and deliver them, signed, to other sites; take signed deliveries from other sites
// (the delivery endpoint); and hold each local actor's mailbox until their devices collect it.
// It never needs, and never gets, a key that opens a direct or audience envelope.
//
// Not covered here: how a site authenticates its own users (any method will do), HTTP itself,
// and the sealed relay (CVP-015), which real sites MUST use between them.
import { ed25519 } from "@noble/curves/ed25519.js";
import { b64u } from "../core/bytes.js";
import { canonicalJson } from "../core/canonical.js";
import { signRequest, verifyRequest, digestOf, freshEnough, DEFAULT_ENDPOINTS, SOCIAL_ENDPOINTS, normHost } from "../wire/federation.js";
import { describeSite } from "../wire/features.js";
import { takeBundle } from "../session/keys.js";
import { SessionError } from "../session/primitives.js";
import { verifyActorDocument, parseHandle } from "./actor.js";
import { verifyActivity } from "./activity.js";
import { deliveryBody, readDeliveryBody, envelopeProblems } from "./delivery.js";
import { verifyRepo } from "./repo.js";
import { verifyLexicon } from "./lexicon.js";

const randomNonce = () => b64u(globalThis.crypto.getRandomValues(new Uint8Array(16)));

/** A network of sites that records everything sent across it (for tests and examples). */
export class MemoryNetwork {
  constructor() {
    this.sites = new Map();
    this.log = [];
  }
  add(site) {
    this.sites.set(site.host, site);
    site.network = this;
  }
  site(host) {
    const s = this.sites.get(host);
    if (!s) throw new SessionError("UNREACHABLE", `No site at ${host}`);
    return s;
  }
  /** Anything that crosses the network goes through here, and is kept. */
  record(what) {
    this.log.push(typeof what === "string" ? what : JSON.stringify(what));
    return what;
  }
}

export class ReferenceSite {
  constructor(host) {
    this.host = normHost(host);
    const { secretKey, publicKey } = ed25519.keygen();
    this.key = { secretKey: b64u(secretKey), publicKey: b64u(publicKey) };
    this.actors = new Map(); // actor id -> actor document record
    this.handles = new Map(); // name -> actor id
    this.prekeys = new Map(); // `${actor}/${device}` -> published prekeys
    this.mailboxes = new Map(); // actor id -> [{ envelope, from }]
    this.public = new Map(); // actor id -> [signed public activity]
    this.seenNonces = new Set();
    this.repos = new Map(); // actor id -> exported repository
    this.changeLog = []; // { actor, head }: every repository commit this site has accepted, in order
    this.moved = new Map(); // actor id or handle name -> newer actor document on another site
    this.lexicons = new Map(); // NSID -> lexicon record
  }

  /** The site document (CVP-005, CVP-008). */
  document() {
    return { ...describeSite(), host: this.host, public_key: this.key.publicKey, endpoints: { ...DEFAULT_ENDPOINTS, ...SOCIAL_ENDPOINTS } };
  }

  // ---- Discovery and keys (anyone may call) ----

  /** GET actor: by handle name or by id. */
  actor({ handle, id }) {
    const moved = this.moved.get(id ?? String(handle || "").toLowerCase());
    if (moved) return this.network.record({ moved });
    const actorId = id ?? this.handles.get(String(handle || "").toLowerCase());
    const r = actorId && this.actors.get(actorId);
    if (!r) throw new SessionError("NOT_FOUND", "No such actor here");
    return this.network ? this.network.record(r) : r;
  }

  /** POST prekeys/{actor}/{device}: one bundle, using up a one-time prekey. */
  bundle(actorId, device) {
    const doc = this.actors.get(actorId);
    const pub = this.prekeys.get(`${actorId}/${device}`);
    if (!doc || !pub) throw new SessionError("NOT_FOUND", "No prekeys for that device");
    const b = takeBundle(doc.body.devices, pub, device);
    return this.network ? this.network.record(b) : b;
  }

  /** GET public: an actor's public activities. */
  publicActivities(actorId) {
    return [...(this.public.get(actorId) || [])];
  }

  /** GET repo: an actor's repository (CVP-020). Anyone can check it with verifyRepo. */
  repo(actorId) {
    const r = this.repos.get(actorId);
    if (!r) throw new SessionError("NOT_FOUND", "No repository for that actor here");
    return this.network.record(r);
  }

  /** GET changes: repository commits accepted since a cursor, for mirrors and indexers (CVP-020). */
  changes(cursor = 0) {
    return { cursor: this.changeLog.length, commits: this.changeLog.slice(cursor) };
  }

  /** GET lexicon (CVP-021). */
  lexicon(id) {
    const r = this.lexicons.get(id);
    if (!r) throw new SessionError("NOT_FOUND", "No such lexicon here");
    return r;
  }

  // ---- Its own users (authenticated by the site's own means) ----

  publishRepo(exported) {
    const prev = this.repos.get(exported?.actor?.body?.id);
    const { actor, commit } = verifyRepo(exported, { minSeq: prev ? prev.head.body.seq + 1 : 0 });
    if (!this.actors.has(actor.id)) throw new SessionError("UNTRUSTED", "Not a local actor");
    this.repos.set(actor.id, exported);
    this.changeLog.push({ actor: actor.id, head: exported.head });
    return commit;
  }

  publishLexicon(record) {
    const author = this.actors.get(record?.sig?.kid);
    if (!author) throw new SessionError("UNTRUSTED", "Not a local actor");
    const l = verifyLexicon(record, author.body, { minRevision: (this.lexicons.get(record.body.id)?.body.revision ?? 0) + 1 });
    this.lexicons.set(l.id, record);
  }

  /**
   * An actor has moved to another site (CVP-017, "Moving"): given their newer actor document,
   * whose handle is elsewhere, stop hosting them and point lookups at it.
   */
  release(record) {
    const prev = this.actors.get(record?.body?.id);
    if (!prev) throw new SessionError("NOT_FOUND", "Not a local actor");
    const body = verifyActorDocument(record, { id: prev.body.id, minSeq: prev.body.seq + 1 });
    if (parseHandle(body.handle).host === this.host) throw new SessionError("BAD_INPUT", "That document is still for this site");
    const name = parseHandle(prev.body.handle).name;
    this.moved.set(name, record);
    this.moved.set(body.id, record);
    this.actors.delete(body.id);
    this.handles.delete(name);
    this.mailboxes.delete(body.id);
    this.repos.delete(body.id);
  }

  publishActor(record) {
    const prev = this.actors.get(record?.body?.id);
    const body = verifyActorDocument(record, { minSeq: prev ? prev.body.seq + 1 : 0 });
    const h = parseHandle(body.handle);
    if (h.host !== this.host) throw new SessionError("BAD_INPUT", "That handle belongs to another site");
    const holder = this.handles.get(h.name);
    // "lexicons" defines the domain's object types (CVP-021): a real site gives it to its operator only.
    if ((holder && holder !== body.id) || (this.moved.has(h.name) && this.moved.get(h.name).body.id !== body.id)) throw new SessionError("TAKEN", "That handle is taken");
    this.moved.delete(h.name);
    this.moved.delete(body.id);
    if (prev && prev.body.handle !== body.handle) this.handles.delete(parseHandle(prev.body.handle).name);
    this.actors.set(body.id, record);
    this.handles.set(h.name, body.id);
    if (!this.mailboxes.has(body.id)) this.mailboxes.set(body.id, []);
  }

  publishPrekeys(actorId, device, published) {
    const doc = this.actors.get(actorId);
    if (!doc?.body.devices.body.devices.some((d) => d.kid === device)) throw new SessionError("BAD_INPUT", "That device isn't on the actor's device list");
    this.prekeys.set(`${actorId}/${device}`, published);
  }

  /** Collect (and clear) an actor's mailbox. */
  collect(actorId) {
    const box = this.mailboxes.get(actorId) || [];
    this.mailboxes.set(actorId, []);
    return box;
  }

  /**
   * The outbox: items [{ host, to, envelope }] from a local actor. Local recipients get them
   * straight away; the rest go to their sites, one signed request per site.
   */
  async send(fromActor, items) {
    if (!this.actors.has(fromActor)) throw new SessionError("UNTRUSTED", "Not a local actor");
    const byHost = new Map();
    for (const it of items) {
      const host = normHost(it.host);
      if (!host) throw new SessionError("BAD_INPUT", "Bad host");
      if (!byHost.has(host)) byHost.set(host, []);
      byHost.get(host).push({ to: it.to, envelope: it.envelope });
    }
    for (const [host, list] of byHost) {
      for (const env of list.map((x) => x.envelope)) if (env.mode === "public") this.#keepPublic(env.activity);
      if (host === this.host) {
        for (const it of readDeliveryBody(deliveryBody(list))) this.#store(it, this.host);
        continue;
      }
      for (let i = 0; i < list.length; i += 100) await this.#deliver(host, list.slice(i, i + 100));
    }
  }

  async #deliver(host, items) {
    const text = canonicalJson(deliveryBody(items));
    const fields = { method: "POST", to: host, path: SOCIAL_ENDPOINTS.deliver, from: this.host, date: new Date().toUTCString(), nonce: randomNonce(), digest: digestOf(text) };
    const request = { ...fields, signature: signRequest(fields, this.key.secretKey), body: text };
    await this.network.site(host).receive(this.network.record(request));
  }

  // ---- Other sites ----

  /** POST deliver: a signed delivery from another site (CVP-019, "Site to site"). */
  async receive(request) {
    const { body, signature, ...fields } = request;
    if (fields.to !== this.host || fields.path !== SOCIAL_ENDPOINTS.deliver || fields.method !== "POST") throw new SessionError("BAD_REQUEST", "Not a delivery for this site");
    if (!freshEnough(fields.date)) throw new SessionError("BAD_TIME", "Request is too old or from the future");
    if (this.seenNonces.has(`${fields.from}/${fields.nonce}`)) throw new SessionError("REPLAY", "Request already received");
    if (digestOf(body) !== fields.digest) throw new SessionError("BAD_REQUEST", "Body doesn't match its digest");
    const sender = this.network.site(fields.from).document();
    if (!verifyRequest(fields, signature, sender.public_key)) throw new SessionError("UNTRUSTED", "Request signature doesn't match the sending site");
    this.seenNonces.add(`${fields.from}/${fields.nonce}`);
    const items = readDeliveryBody(JSON.parse(body));
    // Check everything before storing anything: a delivery is accepted whole or not at all.
    for (const it of items) if (it.envelope.mode === "public") this.#checkPublic(it.envelope.activity, fields.from);
    for (const it of items) this.#store(it, fields.from);
  }

  #checkPublic(activity, fromHost) {
    // A public activity arrives from its author's site, so it's checked against the actor
    // document that site serves for the author. A site that can't check one doesn't store it.
    const author = activity?.body?.actor;
    const doc = verifyActorDocument(this.network.site(fromHost).actor({ id: author }), { id: author });
    if (parseHandle(doc.handle).host !== fromHost) throw new SessionError("UNTRUSTED", "A public activity must come from its author's own site");
    verifyActivity(activity, doc);
  }

  #keepPublic(activity) {
    const list = this.public.get(activity.body.actor) || [];
    list.push(activity);
    this.public.set(activity.body.actor, list);
  }

  #store(item, fromHost) {
    if (envelopeProblems(item.envelope).length) throw new SessionError("BAD_MESSAGE", "Bad envelope");
    const box = this.mailboxes.get(item.to);
    if (!box) return; // no such local actor: dropped, as a real site would answer 404 for it
    box.push({ envelope: item.envelope, from: fromHost });
  }
}
