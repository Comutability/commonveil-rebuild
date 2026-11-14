// A complete, runnable walk through CVP-016: two people, three devices, one group and a new
// phone, talking through a relay that keeps a copy of everything it carries.
//
//   node examples/two-party.mjs
//
// At the end the relay's copy is searched for every plaintext: none of it is there.
import {
  createAccount, createDevice, devicePublic, signDeviceList, verifyDeviceList, approveLink, linkCode,
  safetyNumber, createPrekeys, takeBundle, initiate, respond, encrypt, decrypt, isInitial,
  createSenderKey, distribution, acceptDistribution, groupEncrypt, groupDecrypt, sealHistory, openHistory,
} from "../src/session/index.js";

const text = (b) => new TextDecoder().decode(b);
const log = (...a) => console.log(...a);

// ---- The relay: stores prekey bundles and passes messages on. It is not trusted with anything. ----
const relay = {
  seen: [],
  bundles: new Map(), // device kid -> { list, published }
  inbox: new Map(), // device kid -> messages
  publish(list, kid, published) {
    this.bundles.set(kid, { list, published });
  },
  bundle(kid) {
    const b = this.bundles.get(kid);
    return takeBundle(b.list, b.published, kid); // hands each one-time prekey out once
  },
  send(to, payload) {
    this.seen.push(JSON.stringify(payload));
    if (!this.inbox.has(to)) this.inbox.set(to, []);
    this.inbox.get(to).push(payload);
  },
  receive(kid) {
    const m = this.inbox.get(kid) || [];
    this.inbox.set(kid, []);
    return m;
  },
};

// ---- Accounts and devices ----
function newPerson(name, deviceNames) {
  const account = createAccount();
  const devices = deviceNames.map((d) => ({ name: `${name}'s ${d}`, ...createDevice() }));
  const list = signDeviceList(account, devices, { seq: 1 });
  const p = { name, account, devices, list, secrets: {}, sessions: {}, trusted: {} };
  for (const d of devices) {
    const { secrets, published } = createPrekeys(d, { oneTime: 5, pqOneTime: 5 });
    p.secrets[d.kid] = secrets;
    p.sessions[d.kid] = {};
    relay.publish(list, d.kid, published);
  }
  return p;
}

const alice = newPerson("Alice", ["laptop"]);
const bob = newPerson("Bob", ["phone", "laptop"]);
// Each pins the other's account key (in a real app: on first contact, then checked in person).
alice.trusted[bob.account.publicKey] = true;
bob.trusted[alice.account.publicKey] = true;
log("Safety number Alice and Bob compare:", safetyNumber(alice.account.publicKey, bob.account.publicKey));

const me = (p, d) => ({ device: d, deviceList: p.list, prekeys: p.secrets[d.kid] });

/** Send from one device to every device of a person, starting sessions where needed. */
async function sendToPerson(from, fromDev, to, plaintext) {
  const list = verifyDeviceList(to.list, { accountKey: to.account.publicKey });
  for (const d of list.devices) {
    let s = from.sessions[fromDev.kid][d.kid];
    if (!s) s = initiate({ me: me(from, fromDev), bundle: relay.bundle(d.kid), accountKey: to.account.publicKey });
    const out = await encrypt(s, plaintext);
    from.sessions[fromDev.kid][d.kid] = out.state;
    relay.send(d.kid, { from: fromDev.kid, account: from.account.publicKey, message: out.message });
  }
}

/** Read everything waiting for a device. */
async function readAll(p, dev) {
  const out = [];
  for (const { from, account, message } of relay.receive(dev.kid)) {
    if (!p.trusted[account]) throw new Error("message from an account we haven't pinned");
    let r;
    const s = p.sessions[dev.kid][from];
    if (isInitial(message) && !s) {
      r = await respond({ me: me(p, dev), message, accountKey: account });
      p.secrets[dev.kid] = r.prekeys;
    } else {
      r = await decrypt(s, message);
    }
    p.sessions[dev.kid][from] = r.state;
    out.push(text(r.plaintext));
  }
  return out;
}

// ---- 1. One to one, to all of Bob's devices ----
const [laptop] = alice.devices;
const [bobPhone, bobLaptop] = bob.devices;
await sendToPerson(alice, laptop, bob, "Hi Bob, is this thing on?");
await sendToPerson(alice, laptop, bob, "It should be quantum-resistant now.");
log("Bob's phone got:", await readAll(bob, bobPhone));
log("Bob's laptop got:", await readAll(bob, bobLaptop));
await sendToPerson(bob, bobPhone, alice, "Loud and clear.");
log("Alice got:", await readAll(alice, laptop));

// ---- 2. A group: Alice's sender key goes to each of Bob's devices over their sessions ----
let aliceSender = createSenderKey("book-club");
await sendToPerson(alice, laptop, bob, JSON.stringify(distribution(aliceSender)));
const views = {};
for (const d of bob.devices) views[d.kid] = acceptDistribution(JSON.parse((await readAll(bob, d))[0]), { from: laptop.kid });
const g = await groupEncrypt(aliceSender, "Book club is on Thursday.");
aliceSender = g.key;
for (const d of bob.devices) relay.send(d.kid, { group: g.message });
for (const d of bob.devices) {
  const [{ group }] = relay.receive(d.kid);
  const r = await groupDecrypt(views[d.kid], group);
  views[d.kid] = r.state;
  log(`${d.name} got group message:`, text(r.plaintext));
}

// ---- 3. Bob gets a new tablet: link it, then copy history from his phone ----
const tablet = { name: "Bob's tablet", ...createDevice() };
log("Tablet shows link code:   ", linkCode(devicePublic(tablet)));
log("Phone computes link code: ", linkCode(devicePublic(tablet)), "(Bob checks they match)");
bob.list = approveLink(bob.account, verifyDeviceList(bob.list, { accountKey: bob.account.publicKey }), tablet);
const tabletKeys = createPrekeys(tablet, { oneTime: 2, pqOneTime: 2 });
bob.secrets[tablet.kid] = tabletKeys.secrets;
bob.sessions[tablet.kid] = {};
relay.publish(bob.list, tablet.kid, tabletKeys.published);

const phoneHistory = [
  { from: "Alice", text: "Hi Bob, is this thing on?" },
  { from: "Alice", text: "It should be quantum-resistant now." },
  { from: "Bob", text: "Loud and clear." },
];
const { offer, chunks } = await sealHistory(phoneHistory, { chunkSize: 64 });
relay.seen.push(JSON.stringify(chunks)); // the chunks can sit on any store
let s = initiate({ me: me(bob, bobPhone), bundle: relay.bundle(tablet.kid), accountKey: bob.account.publicKey });
const out = await encrypt(s, JSON.stringify(offer));
relay.send(tablet.kid, { from: bobPhone.kid, account: bob.account.publicKey, message: out.message });
bob.trusted[bob.account.publicKey] = true;
const [offerJson] = await readAll(bob, tablet);
log("Tablet restored history:", (await openHistory(JSON.parse(offerJson), chunks)).map((m) => `${m.from}: ${m.text}`));

// ---- What the relay saw ----
const everything = relay.seen.join("\n");
const secrets = ["is this thing on", "quantum-resistant now", "Loud and clear", "Thursday", "Book club"];
const leaked = secrets.filter((t) => everything.includes(t));
log(`\nThe relay carried ${relay.seen.length} items (${everything.length.toLocaleString("en-GB")} characters). Plaintext found in them: ${leaked.length ? leaked.join(", ") : "none"}.`);
if (leaked.length) process.exit(1);
