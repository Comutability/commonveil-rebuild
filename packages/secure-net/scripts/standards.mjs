// Keeps the standard and the code in step (CVP-000, sections 3 and 7).
//
//   node scripts/standards.mjs           check; exit 1 on any problem
//   node scripts/standards.mjs --write   also rewrite spec/REGISTRIES.md and the index in spec/README.md
//
// It checks the registries are well formed, that every name the reference code uses (features,
// record kinds, ledger events, permissions, suites, endpoints, labels) is registered and every
// registered name the code defines is really there, that part documents carry the header and
// sections CVP-000 requires, and that the generated documents are up to date.
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const spec = (f) => path.join(root, "spec", f);
const KIND = /^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$/;
const PART_ID = /^CVP-\d{3}$/;
const FEATURE = /^cvp\.[a-z][a-z0-9-]*$/;
const load = (rel) => import(pathToFileURL(path.join(root, rel)).href);
const sameSet = (a, b) => a.length === b.length && [...a].sort().join("\n") === [...b].sort().join("\n");
const diff = (a, b) => [...new Set(a)].filter((x) => !new Set(b).has(x));
const placeholders = (s) => s.replace(/<[^>]*>/g, "<>");

function walk(dir) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else if (p.endsWith(".js")) out.push(p);
  }
  return out;
}

/** Labels written in the code: string and template literals starting secure-net/ or commonveil. */
function labelsInCode(sessionLabel) {
  const found = new Map();
  for (const file of walk(path.join(root, "src"))) {
    const text = fs.readFileSync(file, "utf8").replaceAll("${LABEL}", sessionLabel);
    for (const m of text.matchAll(/`((?:secure-net|commonveil)[^`]*)`|"((?:secure-net|commonveil)[^"\n]*)"|'((?:secure-net|commonveil)[^'\n]*)'/g)) {
      const raw = (m[1] ?? m[2] ?? m[3]).replace(/\$\{[^}]*\}/g, "<x>");
      const cut = raw.split(/\\n|\n|\|/)[0];
      if (!found.has(cut)) found.set(cut, path.relative(root, file));
    }
  }
  return found;
}

function docHeader(text) {
  const row = (name) => text.match(new RegExp(`^\\|\\s*${name}\\s*\\|\\s*([^|]*?)\\s*\\|`, "m"))?.[1];
  const headings = [...text.matchAll(/^#{2,3} (.*)$/gm)].map((m) => m[1].toLowerCase());
  return { status: row("Status"), version: row("Version"), headings };
}

export async function checkStandards() {
  const problems = [];
  const warnings = [];
  const bad = (msg) => problems.push(msg);
  const reg = JSON.parse(fs.readFileSync(spec("registry.json"), "utf8"));

  // ---- The registries themselves ----
  const parts = new Map(reg.parts.map((p) => [p.id, p]));
  const unique = (list, key, what) => {
    const seen = new Set();
    for (const e of list) {
      if (seen.has(e[key])) bad(`${what} "${e[key]}" is registered twice`);
      seen.add(e[key]);
    }
  };
  unique(reg.parts, "id", "Part");
  for (const [name, key] of [["features", "name"], ["recordKinds", "name"], ["ledgerEvents", "name"], ["capabilities", "name"], ["extensionExecution", "name"], ["consentActions", "name"], ["voteMethods", "name"], ["suites", "name"], ["labels", "label"], ["identifiers", "name"], ["endpoints", "name"], ["headers", "name"], ["profiles", "name"], ["actorTypes", "name"], ["activityTypes", "name"], ["objectTypes", "name"], ["addresses", "name"], ["envelopeModes", "name"], ["lexiconFieldTypes", "name"]]) {
    unique(reg[name], key, name);
    for (const e of reg[name]) {
      if (e.part && !parts.has(e.part)) bad(`${name} "${e[key]}" names unknown part ${e.part}`);
      if (e.status && !reg.entryStatuses.includes(e.status)) bad(`${name} "${e[key]}" has unknown status "${e.status}"`);
    }
  }
  for (const p of reg.parts) {
    if (!PART_ID.test(p.id)) bad(`"${p.id}" isn't a part id`);
    if (!reg.partStatuses.includes(p.status)) bad(`${p.id} has unknown status "${p.status}"`);
    if (!Number.isSafeInteger(p.version) || p.version < (p.status === "Reserved" ? 0 : 1)) bad(`${p.id} has a bad version`);
    for (const d of p.dependsOn) if (!parts.has(d)) bad(`${p.id} depends on unknown part ${d}`);
    for (const v of p.vectors) if (!fs.existsSync(spec(v))) bad(`${p.id}: vectors ${v} don't exist`);
    for (const f of p.features) if (!reg.features.some((x) => x.name === f && x.part === p.id)) bad(`${p.id} lists feature ${f}, but the feature doesn't name it`);
    if (p.status !== "Reserved" && !p.doc) warnings.push(`${p.id} (${p.title}) has no part document yet`);
    if (p.doc) {
      if (!fs.existsSync(spec(p.doc))) {
        bad(`${p.id}: ${p.doc} doesn't exist`);
        continue;
      }
      const h = docHeader(fs.readFileSync(spec(p.doc), "utf8"));
      if (!h.status?.startsWith(p.status)) bad(`${p.doc}: Status should start "${p.status}" (the registry), not "${h.status ?? "missing"}"`);
      if (String(p.version) !== h.version) bad(`${p.doc}: Version should be ${p.version} (the registry), not "${h.version ?? "missing"}"`);
      for (const [need, re] of [["security and privacy", /secur|protect/], ["conformance", /conformance/], ["changes", /^changes$/]]) {
        if (!h.headings.some((x) => re.test(x))) bad(`${p.doc} has no ${need} section (CVP-000, 3.1)`);
      }
    }
  }
  for (const f of reg.features) {
    if (!FEATURE.test(f.name)) bad(`Feature "${f.name}" doesn't follow cvp.<name>`);
    if (!parts.get(f.part)?.features.includes(f.name)) bad(`Feature ${f.name} names ${f.part}, but that part doesn't list it`);
  }
  for (const k of [...reg.recordKinds, ...reg.ledgerEvents]) if (!KIND.test(k.name) && !k.grandfathered) bad(`"${k.name}" doesn't follow <area>.<name>`);
  for (const l of reg.labels) if (!l.label.startsWith("secure-net/") && !l.label.startsWith("commonveil")) bad(`Label "${l.label}" must start secure-net/`);
  for (const pr of reg.profiles) {
    for (const id of pr.parts) {
      if (!parts.has(id)) bad(`Profile ${pr.name} needs unknown part ${id}`);
      else if (parts.get(id).status === "Reserved") bad(`Profile ${pr.name} needs ${id}, which has no specification`);
    }
  }

  // ---- The registries against the reference code ----
  const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const features = await load("src/wire/features.js");
  if (pkg.version !== reg.release) bad(`registry release ${reg.release} isn't package.json's ${pkg.version}`);
  if (features.SECURE_NET_VERSION !== pkg.version) bad(`SECURE_NET_VERSION ${features.SECURE_NET_VERSION} isn't package.json's ${pkg.version}`);
  const activeFeatures = Object.fromEntries(reg.features.filter((f) => f.status !== "removed").map((f) => [f.name, f.version]));
  for (const [n, v] of Object.entries(features.FEATURES)) if (activeFeatures[n] !== v) bad(`Feature ${n} ${v} in wire/features.js isn't registered at that version`);
  for (const n of diff(Object.keys(activeFeatures), Object.keys(features.FEATURES))) bad(`Feature ${n} is registered but wire/features.js doesn't announce it`);
  if (features.describeSite().protocol !== "secure-net" || !reg.identifiers.some((i) => i.name === features.describeSite().protocol)) bad("The site document's protocol name isn't registered");

  // Record kinds: exported constants and arrays, plus literals passed straight to sign().
  const kinds = new Set();
  for (const file of walk(path.join(root, "src")).filter((f) => !f.includes(`${path.sep}crypto${path.sep}`))) {
    const mod = await import(pathToFileURL(file).href);
    for (const [name, v] of Object.entries(mod)) {
      if (name === "EVENT_CAPS") continue;
      if (typeof v === "string" && KIND.test(v)) kinds.add(v);
      if (Array.isArray(v) && v.length && v.every((x) => typeof x === "string" && KIND.test(x))) v.forEach((x) => kinds.add(x));
    }
    for (const m of fs.readFileSync(file, "utf8").matchAll(/\bsign\(\s*"([^"]+)"/g)) kinds.add(m[1]);
  }
  const regKinds = reg.recordKinds.filter((k) => k.status !== "removed").map((k) => k.name);
  for (const k of diff(kinds, regKinds)) bad(`Record kind "${k}" is used in the code but not registered`);
  for (const k of diff(regKinds, kinds)) bad(`Record kind "${k}" is registered but the code never defines it`);

  const ledger = await load("src/commons/ledger.js");
  const regEvents = Object.fromEntries(reg.ledgerEvents.filter((e) => e.status !== "removed").map((e) => [e.name, e.capability]));
  for (const [e, cap] of Object.entries(ledger.EVENT_CAPS)) if (regEvents[e] !== cap) bad(`Ledger event ${e} (needs ${cap}) isn't registered that way`);
  for (const e of diff(Object.keys(regEvents), Object.keys(ledger.EVENT_CAPS))) bad(`Ledger event ${e} is registered but the ledger doesn't know it`);
  if (!sameSet(ledger.CAPS, reg.capabilities.map((c) => c.name))) bad(`Capabilities differ: code ${ledger.CAPS.join(", ")}`);

  const ext = await load("src/extensions/manifest.js");
  const regExec = Object.fromEntries(reg.extensionExecution.map((e) => [e.name, e.permissions]));
  if (!sameSet(Object.keys(ext.EXECUTION), Object.keys(regExec))) bad("Extension execution models differ from the registry");
  for (const [n, perms] of Object.entries(ext.EXECUTION)) if (!regExec[n] || !sameSet(perms, regExec[n])) bad(`Permissions for ${n} extensions differ from the registry`);
  if (!sameSet((await load("src/consent/capsule.js")).ACTIONS, reg.consentActions.map((a) => a.name))) bad("Consent actions differ from the registry");
  if (!sameSet((await load("src/governance/vote.js")).METHODS, reg.voteMethods.map((a) => a.name))) bad("Vote methods differ from the registry");

  const vocab = await load("src/social/vocabulary.js");
  const delivery = await load("src/social/delivery.js");
  for (const [name, code, list] of [["Actor types", vocab.ACTOR_TYPES, reg.actorTypes], ["Activity types", vocab.ACTIVITY_TYPES, reg.activityTypes], ["Object types", vocab.OBJECT_TYPES, reg.objectTypes], ["Addresses", [vocab.PUBLIC, vocab.FOLLOWERS], reg.addresses], ["Envelope modes", delivery.MODES, reg.envelopeModes], ["Lexicon field types", (await load("src/social/lexicon.js")).FIELD_TYPES, reg.lexiconFieldTypes]]) {
    const names = list.map((x) => x.name);
    for (const n of diff(code, names)) bad(`${name}: "${n}" is in the code but not registered`);
    for (const n of diff(names, code)) bad(`${name}: "${n}" is registered but not in the code`);
  }

  for (const s of reg.suites) {
    const [file, name] = s.code.split(" ");
    const v = (await load(`src/${file}`))[name];
    if (v !== s.name) bad(`Suite ${s.name}: src/${file} ${name} is "${v}"`);
  }
  const fed = await load("src/wire/federation.js");
  if (!reg.identifiers.some((i) => i.name === fed.PROTOCOL)) bad(`Protocol identifier ${fed.PROTOCOL} isn't registered`);
  const regPaths = Object.fromEntries(reg.endpoints.map((e) => [e.name, e.path]));
  if (regPaths["site-document"] !== fed.SITE_DOCUMENT) bad("The site document path differs from the registry");
  const codeEndpoints = { ...fed.DEFAULT_ENDPOINTS, ...fed.SOCIAL_ENDPOINTS };
  for (const n of Object.keys(fed.SOCIAL_ENDPOINTS)) if (n in fed.DEFAULT_ENDPOINTS) bad(`Endpoint ${n} is in both endpoint lists`);
  for (const [n, p] of Object.entries(codeEndpoints)) if (regPaths[n] !== p) bad(`Endpoint ${n} (${p}) isn't registered at that path`);
  for (const n of diff(Object.keys(regPaths), ["site-document", ...Object.keys(codeEndpoints)])) bad(`Endpoint ${n} is registered but the code doesn't define it`);

  // Labels: everything written in the code, and every purpose session/primitives derives under.
  const session = await load("src/session/primitives.js");
  const inCode = labelsInCode(session.LABEL);
  for (const p of session.PURPOSES) inCode.set(`${session.LABEL}/${p}`, "src/session/primitives.js");
  const skip = new Set(reg.identifiers.map((i) => i.name));
  const regLabels = new Map(reg.labels.filter((l) => l.status !== "removed").map((l) => [placeholders(l.label), l.label]));
  for (const [l, file] of inCode) if (!skip.has(l) && !regLabels.has(placeholders(l))) bad(`Label "${l}" in ${file} isn't registered`);
  const codeLabels = new Set([...inCode.keys()].map(placeholders));
  for (const [norm, l] of regLabels) if (!codeLabels.has(norm)) bad(`Label "${l}" is registered but the code never uses it`);

  // The reference implementation's conformance statement (CVP-010, section 5) must stay true.
  const stmt = JSON.parse(fs.readFileSync(path.join(root, "secure-net-conformance.json"), "utf8"));
  if (stmt.release !== reg.release || stmt.version !== pkg.version) bad("secure-net-conformance.json names a different release");
  if (JSON.stringify(Object.entries(stmt.features).sort()) !== JSON.stringify(Object.entries(features.FEATURES).sort())) bad("secure-net-conformance.json lists different features from wire/features.js");
  for (const name of stmt.profiles) {
    const prof = reg.profiles.find((x) => x.name === name);
    if (!prof) bad(`secure-net-conformance.json claims unknown profile ${name}`);
    else for (const id of prof.parts) if (!stmt.parts[id]) bad(`secure-net-conformance.json claims ${name} but doesn't list ${id}`);
  }
  for (const [id, entry] of Object.entries(stmt.parts)) for (const v of entry.vectors || []) if (!parts.get(id)?.vectors.includes(`vectors/${v}`)) bad(`secure-net-conformance.json: ${id} has no vectors ${v}`);

  // ---- Generated documents ----
  for (const [file, text] of Object.entries(generated(reg, warnings))) {
    if (fs.readFileSync(spec(file), "utf8") !== text) bad(`spec/${file} is out of date: run node scripts/standards.mjs --write`);
  }
  return { problems, warnings, registry: reg };
}

// ---- What the script writes ----

const table = (head, rows) => [`| ${head.join(" | ")} |`, `| ${head.map(() => "---").join(" | ")} |`, ...rows.map((r) => `| ${r.map((c) => String(c ?? "").replaceAll("|", "\\|")).join(" | ")} |`)].join("\n");
const code = (s) => `\`${s}\``;
const note = (e) => [e.status && e.status !== "active" ? e.status : "", e.grandfathered ? `grandfathered: ${e.grandfathered}` : "", e.note || ""].filter(Boolean).join("; ");
const partLink = (reg, id) => {
  const p = reg.parts.find((x) => x.id === id);
  return p?.doc ? `[${id}](${p.doc})` : id;
};

function generated(reg, warnings) {
  const L = (id) => partLink(reg, id);
  const reg_md = [
    "# Registries",
    "",
    "Generated from [`registry.json`](registry.json) by `node scripts/standards.mjs --write`. Don't edit this",
    "file: change `registry.json` through a SNIP (CVP-000, section 7), then regenerate it.",
    "",
    `Release ${reg.release}.`,
    "",
    "## Features",
    "",
    table(["Feature", "Version", "Part", "Notes"], reg.features.map((f) => [code(f.name), f.version, L(f.part), note(f)])),
    "",
    "## Record kinds",
    "",
    "Signed with the label `secure-net/<kind>/v1` (CVP-002).",
    "",
    table(["Kind", "Part", "Notes"], reg.recordKinds.map((k) => [code(k.name), L(k.part), note(k)])),
    "",
    "## Ledger events and capabilities",
    "",
    table(["Event", "Capability needed", "Part", "Notes"], reg.ledgerEvents.map((e) => [code(e.name), code(e.capability), L(e.part), note(e)])),
    "",
    table(["Capability", "Part", "Notes"], reg.capabilities.map((c) => [code(c.name), L(c.part), note(c)])),
    "",
    "## Extension execution models and permissions",
    "",
    table(["Execution", "Permissions it may ask for", "Part", "Notes"], reg.extensionExecution.map((e) => [code(e.name), e.permissions.map(code).join(", "), L(e.part), note(e)])),
    "",
    "## Consent actions and vote methods",
    "",
    table(["Consent action", "Part"], reg.consentActions.map((a) => [code(a.name), L(a.part)])),
    "",
    table(["Vote method", "Part"], reg.voteMethods.map((a) => [code(a.name), L(a.part)])),
    "",
    "## Social vocabulary",
    "",
    "ActivityStreams 2.0 names (CVP-018), carried as plain canonical JSON rather than JSON-LD.",
    "",
    table(["Actor type", "Part", "ActivityStreams"], reg.actorTypes.map((t) => [code(t.name), L(t.part), t.as2])),
    "",
    table(["Activity type", "Part", "ActivityStreams"], reg.activityTypes.map((t) => [code(t.name), L(t.part), t.as2])),
    "",
    table(["Object type", "Part", "ActivityStreams"], reg.objectTypes.map((t) => [code(t.name), L(t.part), t.as2])),
    "",
    table(["Address", "Part", "ActivityStreams"], reg.addresses.map((t) => [code(t.name), L(t.part), t.as2])),
    "",
    table(["Envelope mode", "Part", "What a site can read"], reg.envelopeModes.map((t) => [code(t.name), L(t.part), t.note])),
    "",
    table(["Lexicon field type", "Part"], reg.lexiconFieldTypes.map((t) => [code(t.name), L(t.part)])),
    "",
    "## Algorithm suites",
    "",
    table(["Suite", "Used for", "Part", "Notes"], reg.suites.map((s) => [code(s.name), s.use, L(s.part), note(s)])),
    "",
    "## Labels",
    "",
    "Every signature, hash and key derivation is separated by one of these. A label's meaning never changes;",
    "a change means a new version (CVP-000, 4.4). `<...>` marks a variable part.",
    "",
    table(["Label", "Used for", "Part", "Notes"], reg.labels.map((l) => [code(l.label), l.use, L(l.part), note(l)])),
    "",
    "## Protocol identifiers",
    "",
    table(["Identifier", "Used for", "Part"], reg.identifiers.map((i) => [code(i.name), i.use, L(i.part)])),
    "",
    "## Endpoints",
    "",
    "Defaults; a site may list others in its site document, except the site document itself.",
    "",
    table(["Name", "Path", "Part", "Notes"], reg.endpoints.map((e) => [e.name, code(e.path), L(e.part), e.fixed ? "fixed" : ""])),
    "",
    "## HTTP headers",
    "",
    table(["Header", "Carries", "Part"], reg.headers.map((h) => [code(h.name), h.use, L(h.part)])),
    "",
    "## Conformance profiles",
    "",
    "What each profile requires is in [CVP-010](CVP-010-conformance.md).",
    "",
    table(["Profile", "Name", "Parts", "For"], reg.profiles.map((p) => [code(p.name), p.title, p.parts.map(L).join(", "), p.for])),
    "",
  ].join("\n");

  const index = [
    "<!-- index:start (generated by node scripts/standards.mjs --write from registry.json; don't edit) -->",
    table(["Part", "Subject", "Status", "Version", "Features", "Code"], reg.parts.map((p) => [L(p.id), p.title, p.status, p.version || "", p.features.map(code).join(", "), p.code.map(code).join(", ")])),
    "",
    warnings.length ? `**Documentation still to write:** ${reg.parts.filter((p) => p.status !== "Reserved" && !p.doc).map((p) => p.id).join(", ")}. These parts are implemented and tested, but so far the code is their only specification.` : "Every part has a document.",
    "<!-- index:end -->",
  ].join("\n");
  const readme = fs.readFileSync(spec("README.md"), "utf8");
  const at = readme.indexOf("<!-- index:start");
  const end = readme.indexOf("<!-- index:end -->");
  const nextReadme = at >= 0 && end > at ? readme.slice(0, at) + index + readme.slice(end + "<!-- index:end -->".length) : readme;
  return { "REGISTRIES.md": reg_md, "README.md": nextReadme };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.includes("--write")) {
    const reg = JSON.parse(fs.readFileSync(spec("registry.json"), "utf8"));
    const { warnings } = await checkStandards();
    for (const [file, text] of Object.entries(generated(reg, warnings))) fs.writeFileSync(spec(file), text);
  }
  const { problems, warnings } = await checkStandards();
  for (const w of warnings) console.log(`note: ${w}`);
  for (const p of problems) console.error(`problem: ${p}`);
  console.log(problems.length ? `\n${problems.length} problem(s)` : "\nThe code, registries and documents agree.");
  process.exit(problems.length ? 1 : 0);
}
