// The social protocol (CVP-017 to 021) end to end: three sites and four people. Public posts,
// follows, followers-only posts, a direct message, a like, an unfollow, a verifiable repository,
// a new object type from a lexicon, and a move to another site, all over a network that keeps a
// copy of everything it carries.
//
//   node examples/social.mjs
//
// At the end the network's copy is searched: public posts should be there (they're public), and
// nothing private should be.
import { MemoryNetwork, ReferenceSite, SocialClient, verifyRepo, createLexicon, verifyLexicon, extensionProblems } from "../src/social/index.js";
import { safetyNumber } from "../src/session/keys.js";

const net = new MemoryNetwork();
net.add(new ReferenceSite("a.example"));
net.add(new ReferenceSite("b.example"));
net.add(new ReferenceSite("c.example"));

const alice = new SocialClient({ handle: "alice@a.example", network: net, name: "Alice" }).register();
const bob = new SocialClient({ handle: "bob@b.example", network: net, name: "Bob" }).register();
const carol = new SocialClient({ handle: "carol@b.example", network: net, name: "Carol" }).register();

const show = (who, items) => {
  for (const i of items) {
    if (i.kind === "post") console.log(`  ${who} sees ${i.how} ${i.type === "Note" ? "post" : i.type} from ${i.from}: "${i.content}"`);
    else if (i.kind === "unreadable" || i.kind === "refused") console.log(`  ${who} can't read one envelope (${i.reason})`);
    else if (i.kind !== "keys") console.log(`  ${who}: ${i.kind} ${i.from ?? ""}`);
  }
};
const syncAll = async () => {
  show("Alice", await alice.sync());
  show("Bob", await bob.sync());
  show("Carol", await carol.sync());
};
const step = (s) => console.log(`\n${s}`);

step("1. Alice posts publicly, and Bob follows her (the follow itself is end-to-end encrypted)");
await alice.post("Hello from a.example. This one is public.", { to: "public" });
await bob.follow("@alice@a.example");
await syncAll();
await syncAll();
console.log(`  Safety number Alice and Bob can compare: ${safetyNumber(alice.account.publicKey, bob.account.publicKey)}`);

step("2. Alice posts to her followers only");
await alice.post("Followers only: the meetup is on Thursday.");
await syncAll();

step("3. Alice messages Bob directly; Bob likes her followers-only post");
await alice.post("Bob, are you coming on Thursday?", { to: [bob.id] });
await syncAll();
const meetup = bob.timeline.find((p) => p.content.startsWith("Followers only"));
await bob.like(meetup.id, alice.id);
await syncAll();
console.log(`  Likes on Alice's followers-only post: ${alice.likes.get(meetup.id)?.size ?? 0}`);

step("4. Carol follows too, and only sees what Alice posts after that");
await carol.follow("@alice@a.example");
await syncAll();
await syncAll();
await alice.post("Followers only: bring snacks.");
await syncAll();

step("5. Bob unfollows. Alice's next followers-only post goes to Carol, with a key Bob never gets");
await bob.unfollow(alice.id);
await syncAll();
await syncAll();
await alice.post("Followers only: Bob has left, so he can't read this.");
await syncAll();
// Even if a site handed Bob that envelope, he couldn't open it.
const deliveries = net.log.map((l) => JSON.parse(l)).filter((r) => typeof r.body === "string").map((r) => JSON.parse(r.body));
const env = deliveries.flatMap((d) => d.items).filter((i) => i.envelope.mode === "audience").at(-1).envelope;
bob.site.mailboxes.get(bob.id).push({ envelope: env, from: "a.example" });
show("Bob (given the envelope anyway)", await bob.sync());

step("6. Alice posts publicly again: her followers get it, signed and readable");
await alice.post("Public again: everyone welcome on Thursday.", { to: "public" });
await syncAll();

step("7. Anyone can check Alice's public repository, from any copy (like an AT Protocol repository)");
const copy = JSON.parse(JSON.stringify(net.site("a.example").repo(alice.id))); // a mirror's copy
const repo = verifyRepo(copy, { id: alice.id });
console.log(`  A mirror's copy verifies: ${repo.records.length} public records, commit ${repo.commit.seq}, signed by Alice's device`);
copy.records.pop();
let caught = "";
try {
  verifyRepo(copy, { id: alice.id });
} catch (e) {
  caught = e.code;
}
console.log(`  The same copy with one record dropped: refused (${caught})`);
console.log(`  a.example's change feed for indexers: ${net.site("a.example").changes().commits.length} commits`);

step("8. A new kind of post, defined by a lexicon on its own domain, with no change to the standard");
const chef = new SocialClient({ handle: "lexicons@c.example", network: net, name: "c.example types" }).register();
const lexicon = createLexicon(chef.account, { id: "example.c.recipe", revision: 1, fields: { serves: { type: "integer", min: 1, required: true }, ingredients: { type: "array", items: { type: "string" }, required: true } } });
net.site("c.example").publishLexicon(lexicon);
await alice.post(null, { object: { type: "example.c.recipe", name: "Dal for Thursday", content: "Simmer the lentils with onion.", serves: 6, ingredients: ["lentils", "onion"] } });
await syncAll();
const known = verifyLexicon(net.site("c.example").lexicon("example.c.recipe"), chef.lookup("lexicons@c.example"));
const recipe = carol.timeline.at(-1);
console.log(`  Carol's app doesn't know recipes and shows it as a post. An app that does checks it: ${extensionProblems(recipe.object, known).length === 0 ? "valid recipe" : "invalid"}`);

step("9. Alice moves to c.example and keeps her identity, followers, keys and history");
const idBefore = alice.id;
await alice.migrate("alice@c.example");
await syncAll();
await alice.post("Followers only: same me, new home.");
await syncAll();
const moved = verifyRepo(net.site("c.example").repo(alice.id), { id: alice.id });
console.log(`  Same actor id: ${alice.id === idBefore}. Public history at the new site: ${moved.records.length} records, still verifying`);
console.log(`  Bob looks up the old handle and is sent to: @${bob.lookup("alice@a.example").handle}`);

// ---- What the network saw ----
const everything = net.log.join("\n");
const privateTexts = ["meetup is on Thursday", "are you coming", "bring snacks", "Bob has left", "same me, new home", 'type\\":\\"Follow', 'type\\":\\"Like', 'type\\":\\"Undo'];
const leaked = privateTexts.filter((t) => everything.includes(t));
// Public posts: the one sent to followers crossed the network readable; both are in Alice's
// site's public collection, which anyone may fetch.
const collection = JSON.stringify(moved.records);
const missing = [];
if (!everything.includes("everyone welcome")) missing.push("the public post sent to followers");
for (const t of ["This one is public", "everyone welcome"]) if (!collection.includes(t)) missing.push(`"${t}" in Alice's repository`);
console.log(`\nThe network carried ${net.log.length} items (${everything.length.toLocaleString("en-GB")} characters).`);
console.log(`Private text or activity types found in them: ${leaked.length ? leaked.join(", ") : "none"}.`);
console.log(`Public posts readable, as they should be: ${missing.length ? `missing ${missing.join(", ")}` : "yes (on the network and in Alice's repository)"}.`);
if (leaked.length || missing.length) process.exit(1);
