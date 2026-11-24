// Site-wide policy: not community-server membership permissions. Only the
// *site* admin role can edit; owner-only federation/signup controls are stricter.
import { ApiError, type Actions } from "../http.ts";
import { cleanDomain, policyOf, validatePolicy, validateDomainRule } from "../sitePolicy.ts";

const manager=(user:any)=>{
  if(!user||user.role!=="admin")throw new ApiError(403,"FORBIDDEN","Site administrators only.");
  return user.site_owner===true;
};
const MAX_DOMAINS=300;
async function find(sr:any) {
  const items=await sr.entities.SitePolicy.filter({scope:"site"},"created_date",2);
  return items[0]||null;
}
const list=async(sr:any)=>{
  const policy=await find(sr);
  const domains=await sr.entities.SiteDomainRule.list("created_date",MAX_DOMAINS);
  return {policy:policyOf(policy),domains:domains.map((d:any)=>({
    domain:d.domain,severity:d.severity,public_reason:d.public_reason||"",private_note:d.private_note||"",updated_at:d.updated_at,
  }))};
};
export const sitePolicyActions:Actions={
  async site_policy_get({sr,user}) {
    const owner=manager(user);
    return {...(await list(sr)),owner,admin:true};
  },
  async site_policy_save({sr,user,body,now}) {
    const owner=manager(user);
    const current=await find(sr);
    const clean=validatePolicy(body.policy,current,owner);
    const data={...clean,scope:"site",updated_by:user.id,updated_at:now.toISOString()};
    if(current)await sr.entities.SitePolicy.update(current.id,data);
    else await sr.entities.SitePolicy.create(data);
    return {policy:clean};
  },
  async site_domain_upsert({sr,user,body,now}) {
    manager(user);
    const data=validateDomainRule(body.rule);
    const existing=await sr.entities.SiteDomainRule.filter({domain:data.domain},"created_date",5);
    if(!existing.length && (await sr.entities.SiteDomainRule.list("created_date",MAX_DOMAINS+1)).length>=MAX_DOMAINS){
      throw new ApiError(409,"DOMAIN_LIMIT","This site has reached its domain-rule limit.");
    }
    const row={...data,updated_by:user.id,updated_at:now.toISOString()};
    if(existing.length)await sr.entities.SiteDomainRule.update(existing[0].id,row);
    else await sr.entities.SiteDomainRule.create(row);
    return {...(await list(sr)),saved:data.domain};
  },
  async site_domain_remove({sr,user,body}) {
    manager(user);
    const domain=cleanDomain(body.domain);
    const rows=await sr.entities.SiteDomainRule.filter({domain},"created_date",5);
    for(const row of rows)await sr.entities.SiteDomainRule.delete(row.id);
    return {...(await list(sr)),removed:domain};
  },
};

export async function publicSiteRules(sr:any) {
  const policy=policyOf(await find(sr));
  const domains=policy.show_domain_blocks
    ? (await sr.entities.SiteDomainRule.list("created_date",MAX_DOMAINS)).filter((d:any)=>d.severity==="suspend"||d.severity==="limit")
      .map((d:any)=>({domain:d.domain,severity:d.severity,reason:d.public_reason||""}))
    : [];
  return {rules:policy.public_rules,contact:policy.contact,registration_open:policy.registration_open,
    federation_mode:policy.federation_mode,domain_blocks:domains};
}
