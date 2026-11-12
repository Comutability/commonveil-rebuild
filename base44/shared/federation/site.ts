// The hosted site's own federation settings (docs/FEDERATION.md, "The hosted site").
//
// enabled: whether the hosted site talks to other sites at all. Off until its key is published.
// host: the address other sites know it by. Handles are <username>.<host>.
// public_key: the site's Ed25519 public key, as published in /.well-known/commonveil (a static
//   file the build writes from this). The private half never leaves the FedKey table. To set up:
//   deploy, call the fedidentity function with ?site=1, and copy the key it reports here.
export const SITE = {
  enabled: true,
  host: "commonveil-rebuild-71d823fd.base44.app",
  name: "Commonveil",
  public_key: "s-gk8goe9oIRNtXkJfPANc1lgYyFF-3fKeCRWDM9MH8",
};

/** Where the hosted site's endpoints are: one function each (the platform has no sub-paths). */
export const HOSTED_ENDPOINTS = {
  act: "/functions/fedact",
  directory: "/functions/feddirectory",
  inbox: "/functions/fedinbox",
  discover: "/functions/feddiscover",
  identity: "/functions/fedidentity",
};

/** The hosted site's site document. */
export function siteDocument(site = SITE, version = "") {
  return {
    protocol: "commonveil/1",
    host: site.host,
    name: site.name,
    software: { name: "commonveil", version },
    handle_domain: site.host,
    key: { alg: "Ed25519", public: site.public_key },
    endpoints: { ...HOSTED_ENDPOINTS },
    // What this site can't do with others, so they can say so instead of failing oddly.
    limits: { actors: false, files: false, holds: false },
  };
}
