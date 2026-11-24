import test from "node:test";
import assert from "node:assert/strict";
import { FakeWorld } from "./support/fakeBase44.mjs";
import { runAction } from "../base44/shared/http.ts";
import { adminActions } from "../base44/shared/handlers/safety.ts";
import { disclosureActions } from "../base44/shared/handlers/disclosure.ts";
import { cleanDomain, siteDecision, policyOf, validatePolicy } from "../base44/shared/sitePolicy.ts";

const context=()=>{
 const world=new FakeWorld();
 const users={
   owner:{id:world.newId(),email:"owner@example.test",role:"admin",site_owner:true},
   admin:{id:world.newId(),email:"moderator@example.test",role:"admin",site_owner:false},
   guest:{id:world.newId(),email:"guest@example.test",role:"user",site_owner:false},
 };
 const call=async(user,fn,body)=>{
  const response=await runAction(world.clientFor(user),
    JSON.stringify(body),fn==="admin"?adminActions:disclosureActions,
    {allowAnonymous:fn==="disclose",trustPlatformUser:true});
  return {status:response.status,data:await response.json()};
 };
 return {world,users,call};
};
test("Mastodon-like site policy is owner-controlled but delegated site admins can moderate domains",async()=>{
 const {world,users,call}=context();
 const get=async user=>call(user,"admin",{action:"site_policy_get"});
 assert.equal((await get(users.guest)).status,403);
 assert.equal((await get(users.admin)).status,200);
 assert.equal((await call(users.admin,"admin",{action:"site_policy_save",policy:{federation_mode:"off"}})).status,403);
 assert.equal((await call(users.admin,"admin",{action:"site_policy_save",policy:{registration_open:false}})).status,403);
 const r=await call(users.owner,"admin",{action:"site_policy_save",policy:{
   public_rules:["No threatening behaviour","Respect other people"],
   federation_mode:"allowlist",registration_open:false,allow_remote_discovery:false,
   contact:"https://chat.example/contact",show_domain_blocks:true}});
 assert.equal(r.status,200,JSON.stringify(r.data));
 assert.equal(r.data.policy.registration_open,false);
 assert.equal((await get(users.admin)).data.policy.federation_mode,"allowlist");
 assert.equal((await call(users.guest,"admin",{action:"site_domain_upsert",rule:{domain:"bad.example",severity:"suspend"}})).status,403);
 assert.equal((await call(users.admin,"admin",{action:"site_domain_upsert",rule:{
   domain:"bad.example",severity:"suspend",public_reason:"Repeated spam",
   private_note:"Internal case report #123"}})).status,200);
 assert.equal((await call(users.admin,"admin",{action:"site_domain_upsert",rule:{
   domain:"friend.example",severity:"allow",private_note:"Trusted"}})).status,200);
 const rows=world.rows("SiteDomainRule");
 assert.equal(rows.length,2);
 assert.equal(siteDecision(r.data.policy,rows.find(v=>v.domain==="bad.example")),"suspend");
 assert.equal(siteDecision(r.data.policy,rows.find(v=>v.domain==="friend.example")),"allow");
 assert.equal(siteDecision(r.data.policy,null),"suspend");
 const pub=await call(null,"disclose",{action:"site_rules"});
 assert.equal(pub.status,200,JSON.stringify(pub.data));
 assert.deepEqual(pub.data.rules,["No threatening behaviour","Respect other people"]);
 assert.equal(pub.data.domain_blocks.length,1);
 assert.equal(pub.data.domain_blocks[0].reason,"Repeated spam");
 assert.equal(JSON.stringify(pub.data).includes("Internal case report"),false);
 assert.equal(JSON.stringify(pub.data).includes("Trusted"),false);
 assert.equal((await call(users.admin,"admin",{action:"site_domain_remove",domain:"bad.example"})).status,200);
 assert.equal(world.rows("SiteDomainRule").length,1);
});
test("policies fail closed for invalid hosts, malformed rules and unsafe owner transitions",async()=>{
 const {users,call}=context();
 for(const domain of ["localhost","127.0.0.1","http://bad.example","bad.example/anything","bad..example","-bad.example","bad.example:443","bad_.example"]){
   assert.throws(()=>cleanDomain(domain),{code:"BAD_DOMAIN"});
 }
 assert.equal(cleanDomain("MiXeD.ExAmPlE"),"mixed.example");
 for(const invalid of [{domain:"bad.example",severity:"silent"},
                        {domain:"bad.example",severity:"suspend",private_note:{hidden:1}},
                        {domain:"bad.example",severity:"suspend",public_reason:"a".repeat(501)}]){
   assert.equal((await call(users.admin,"admin",{action:"site_domain_upsert",rule:invalid})).status,400);
 }
 assert.equal((await call(users.owner,"admin",{action:"site_policy_save",policy:{public_rules:Array(21).fill("one rule")}})).status,400);
 assert.equal((await call(users.owner,"admin",{action:"site_policy_save",policy:{irrelevant:true}})).status,400);
 assert.equal((await call(users.owner,"admin",{action:"site_policy_save",policy:{federation_mode:"anything"}})).status,400);
 assert.equal(validatePolicy({federation_mode:"open"},policyOf(null),true).federation_mode,"open");
});
