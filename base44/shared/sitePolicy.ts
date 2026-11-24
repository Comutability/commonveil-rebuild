// A Mastodon-style LOCAL policy for an independently operated Commonveil site.
// It applies to site-to-site transport metadata, not plaintext E2E message content.
import { ApiError } from "./http.ts";

export const POLICY_DEFAULT = Object.freeze({
  public_rules: [] as string[],
  contact: "",
  federation_mode: "open" as "open" | "allowlist" | "off",
  registration_open: true,
  allow_remote_discovery: true,
  show_domain_blocks: false,
});
export const SEVERITIES = Object.freeze(["suspend","limit","reject_media","allow"]);
export const MAX_RULES=20;

export function cleanDomain(value:unknown):string {
  if (typeof value!=="string") throw new ApiError(400,"BAD_DOMAIN","Enter a site hostname, without a URL or path.");
  const v=value.trim().toLowerCase();
  if (v.length>253||!v.includes(".")||v.includes(":")||v.includes("/")||v.endsWith(".")||
      !v.split(".").every(part=>part.length>0&&part.length<=63&&/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part)) ||
      /^[0-9.]+$/.test(v)) {
    throw new ApiError(400,"BAD_DOMAIN","Enter an exact public DNS site hostname.");
  }
  return v;
}
export function policyOf(v:any) {
  if(!v) return {...POLICY_DEFAULT,public_rules:[]};
  return {...POLICY_DEFAULT,
    public_rules:Array.isArray(v.public_rules)?v.public_rules.filter((s:unknown):s is string=>typeof s==="string").slice(0,MAX_RULES):[],
    contact:typeof v.contact==="string"?v.contact:"",
    federation_mode:["open","allowlist","off"].includes(v.federation_mode)?v.federation_mode:"open",
    registration_open:v.registration_open!==false,
    allow_remote_discovery:v.allow_remote_discovery!==false,
    show_domain_blocks:v.show_domain_blocks===true,
  };
}
export function validatePolicy(value:any,current:any,owner:boolean) {
  if (!value||typeof value!=="object"||Array.isArray(value)) throw new ApiError(400,"BAD_POLICY","Invalid policy.");
  const obj={...policyOf(current)};
  if(Object.hasOwn(value,"public_rules")){
    if(!Array.isArray(value.public_rules)||value.public_rules.length>MAX_RULES||
       value.public_rules.some((r:unknown)=>typeof r!=="string"||r.trim().length<3||r.trim().length>500)){
       throw new ApiError(400,"BAD_RULES","Use at most 20 clear rules, 3 to 500 characters each.");
    }
    obj.public_rules=value.public_rules.map((r:string)=>r.trim());
  }
  if(Object.hasOwn(value,"contact")){
    if(typeof value.contact!=="string"||value.contact.length>200)throw new ApiError(400,"BAD_CONTACT","Contact information is too long.");
    obj.contact=value.contact.trim();
  }
  for(const k of ["registration_open","allow_remote_discovery","show_domain_blocks"] as const){
    if(Object.hasOwn(value,k)){
      if(typeof value[k]!=="boolean") throw new ApiError(400,"BAD_POLICY","Invalid "+k);
      if(k==="registration_open"&&!owner)throw new ApiError(403,"OWNER_ONLY","Only the host owner may change registration.");
      obj[k]=value[k];
    }
  }
  if(Object.hasOwn(value,"federation_mode")){
    if(!owner)throw new ApiError(403,"OWNER_ONLY","Only the host owner may change federation mode.");
    if(!["open","allowlist","off"].includes(value.federation_mode))throw new ApiError(400,"BAD_POLICY","Invalid federation mode.");
    obj.federation_mode=value.federation_mode;
  }
  const allowed=["public_rules","contact","registration_open","allow_remote_discovery","show_domain_blocks","federation_mode"];
  if(Object.keys(value).some(k=>!allowed.includes(k)))throw new ApiError(400,"BAD_POLICY","Unexpected policy field.");
  return obj;
}
export function validateDomainRule(value:any) {
  if(!value||typeof value!=="object"||Array.isArray(value))throw new ApiError(400,"BAD_RULE","Invalid domain rule.");
  const domain=cleanDomain(value.domain);
  const severity=value.severity;
  if(!SEVERITIES.includes(severity))throw new ApiError(400,"BAD_SEVERITY","Choose suspend, limit, reject media or allow.");
  const reason=(v:unknown,max:number)=> {
    if(typeof v!=="string"&&v!==undefined)return null;
    const s=String(v||"").trim();
    return s.length<=max?s:null;
  };
  const public_reason=reason(value.public_reason,500),private_note=reason(value.private_note,1000);
  if(public_reason===null||private_note===null)throw new ApiError(400,"BAD_REASON","The reason is too long.");
  if(Object.keys(value).some(k=>!["domain","severity","public_reason","private_note"].includes(k)))throw new ApiError(400,"BAD_RULE","Unexpected field.");
  return {domain,severity,public_reason,private_note};
}
export function siteDecision(policy:any,rule:any) {
  const p=policyOf(policy);
  const severity=rule?.severity||"";
  if(severity==="suspend")return "suspend";
  if(p.federation_mode==="off")return "suspend";
  if(p.federation_mode==="allowlist"&&severity!=="allow")return "suspend";
  return severity||"open";
}
