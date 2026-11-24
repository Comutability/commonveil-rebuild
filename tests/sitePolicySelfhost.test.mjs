import test from "node:test";
import assert from "node:assert/strict";
import {startSites,http} from "./support/selfhost.mjs";
import {Person} from "./support/person.mjs";

test("two self-hosted sites: owner and staff domain rules gate outgoing and incoming federation, preserving encryption",async()=>{
 const net=await startSites(["policy-alpha.test","policy-beta.test"]);
 try{
  const alpha=net.sites["policy-alpha.test"];
  const beta=net.sites["policy-beta.test"];
  const alice=await new Person(alpha,"alice").setup();
  const bob=await new Person(beta,"bob").setup();
  await alpha.app.store.entities.Person.update(alice.id,{role:"admin",site_owner:true});
  const save=async(action,payload={})=>http(alpha,"/api/functions/admin",{method:"POST",token:alice.token,body:{action,...payload}});
  assert.equal((await save("site_policy_get")).status,200);
  const policy=await save("site_policy_save",{policy:{
    public_rules:["Respect the privacy of others","No harassment or spam"],
    contact:"https://policy-alpha.test/appeals",show_domain_blocks:true,
    allow_remote_discovery:true}});
  assert.equal(policy.status,200,JSON.stringify(policy.data));
  const publicRules=await http(alpha,"/api/site/rules");
  assert.equal(publicRules.status,200,JSON.stringify(publicRules.data));
  assert.equal(publicRules.data.rules.length,2);
  const first=await alpha.app.federation.signer.siteDoc("policy-beta.test");
  assert.equal(first.host,"policy-beta.test");
  const block=await save("site_domain_upsert",{rule:{
    domain:"policy-beta.test",severity:"suspend",
    public_reason:"Repeated unsolicited spam",private_note:"Internal investigation #7"}});
  assert.equal(block.status,200,JSON.stringify(block.data));
  assert.equal(block.data.domains.find(d=>d.domain==="policy-beta.test").severity,"suspend");
  assert.equal(JSON.stringify((await http(alpha,"/api/site/rules")).data).includes("Internal investigation"),false);
  await assert.rejects(()=>alpha.app.federation.signer.siteDoc("policy-beta.test"),e=>e.code==="SITE_BLOCKED");
  await assert.rejects(()=>alpha.app.federation.signer.send("policy-beta.test","inbox",{type:"ping"}),e=>e.code==="SITE_BLOCKED");
  const unblock=await save("site_domain_remove",{domain:"policy-beta.test"});
  assert.equal(unblock.status,200,JSON.stringify(unblock.data));
  assert.equal((await alpha.app.federation.signer.siteDoc("policy-beta.test")).host,"policy-beta.test");

  const off=await save("site_policy_save",{policy:{federation_mode:"allowlist"}});
  assert.equal(off.status,200,JSON.stringify(off.data));
  await assert.rejects(()=>alpha.app.federation.signer.siteDoc("policy-beta.test"),e=>e.code==="SITE_BLOCKED");
  assert.equal((await save("site_domain_upsert",{rule:{domain:"policy-beta.test",severity:"allow"}})).status,200);
  assert.equal((await alpha.app.federation.signer.siteDoc("policy-beta.test")).host,"policy-beta.test");

  const closed=await save("site_policy_save",{policy:{registration_open:false,allow_remote_discovery:false}});
  assert.equal(closed.status,200,JSON.stringify(closed.data));
  const signup=await http(alpha,"/api/functions/identity",{method:"POST",body:{
    action:"register",username:"late_visitor",password:"long enough password",age_confirmed:true}});
  assert.deepEqual([signup.status,signup.data.code],[403,"REGISTRATION_CLOSED"]);
  const directory=await http(alpha,"/cvp/v1/discover");
  assert.equal(directory.status,403);
  assert.equal(directory.data.code,"DISCOVERY_DISABLED");
 }finally{await net.close()}
});
