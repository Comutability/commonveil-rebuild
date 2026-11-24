import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = (file) => readFileSync(new URL("../" + file, import.meta.url), "utf8");

test("Commonveil clearly distinguishes its own legacy federation from independent Secure Net", () => {
  const legacy = source("docs/FEDERATION.md");
  const guide = source("docs/SECURE_NET_INTEGRATION.md");
  assert.match(legacy, /Commonveil legacy federation/);
  assert.match(legacy, /NOT Secure Net's independent/);
  assert.match(guide, /Commonveil is its first adopting application/i);
  assert.match(guide, /no compulsory central Commonveil relay/i);
  assert.match(guide, /\/cvp\/v2\/outbox/);
  assert.match(guide, /\/cvp\/v2\/deliver/);
  assert.match(guide, /\/cvp\/v2\/mailbox/);
  assert.match(guide, /other-vendor CVP-019 exchange/i);
});

test("public website exposes independent protocol information without enabling unsupported transport", () => {
  const routes = source("src/App.jsx");
  const page = source("src/pages/site/SecureNet.jsx");
  const home = source("src/pages/site/Home.jsx");
  const settings = source("src/components/identity/ProtocolIdentitySettings.jsx");
  assert.match(routes, /path="secure-net" element=\{<SecureNet/);
  assert.match(home, /to="\/secure-net"/);
  assert.match(settings, /to="\/secure-net"/);
  assert.match(page, /independent of Commonveil/i);
  assert.match(page, /not yet offer verified public CVP-019/i);
  assert.match(page, /not a required server or authority/i);
});

test("Docker identifies application role, pins one Secure Net commit and defaults to safe gates", () => {
  const cargo = source("rust/Cargo.toml");
  const docker = source("Dockerfile");
  const compose = source("deploy/docker-compose.yml");
  const workflow = source(".github/workflows/test.yml");
  const revs = [...cargo.matchAll(/rev = "([a-f0-9]{40})"/g)].map((x) => x[1]);
  assert.equal(revs.length, 3);
  assert.equal(new Set(revs).size, 1);
  assert.match(docker, /commonveil-application-not-generic-cvp-relay/);
  assert.match(workflow, /commonveil-application-not-generic-cvp-relay/);
  for (const flag of ["EXPERIMENTAL_TRANSFER_STAGING", "EXPERIMENTAL_RECIPIENT_CONSENT"]) {
    assert.ok(compose.includes(flag + ": " + "$" + "{" + flag + ":-false}"));
    assert.ok(workflow.includes("c.services.app.environment." + flag + '!=="false"'));
  }
});
