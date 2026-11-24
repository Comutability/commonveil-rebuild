// Site-wide policy source of truth on self-hosted Node, stored in the normal
// SitePolicy and SiteDomainRule backend-only entities (same as Base44/Rust).
// Does not require or inspect plaintext encrypted messages.
import { policyOf, siteDecision } from "../base44/shared/sitePolicy.ts";

function rows(store,entity,limit=301) {
  const values=store.db.prepare("SELECT data FROM records WHERE entity = ? ORDER BY seq DESC LIMIT ?").all(entity,limit);
  return values.map(r=>JSON.parse(r.data));
}
export function sitePolicy(store) {
  const row=rows(store,"SitePolicy",10).find(r=>r.scope==="site")||null;
  return policyOf(row);
}
export function siteDomainRule(store,host) {
  return rows(store,"SiteDomainRule").find(r=>r.domain===host)||null;
}
export function siteVerdict(store,host) {
  return siteDecision(sitePolicy(store),siteDomainRule(store,host));
}
export function publicSiteRules(store) {
  const policy=sitePolicy(store);
  return {rules:policy.public_rules,contact:policy.contact,
    registration_open:policy.registration_open,federation_mode:policy.federation_mode,
    domain_blocks:policy.show_domain_blocks ? rows(store,"SiteDomainRule")
      .filter(r=>r.severity==="suspend"||r.severity==="limit")
      .map(r=>({domain:r.domain,severity:r.severity,reason:r.public_reason||""})) : []};
}
