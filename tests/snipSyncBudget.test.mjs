import test from "node:test";
import assert from "node:assert/strict";
import { planSnipSync, runSnipSync, MAX_STEPS, snipThreadId, snipClosedNoteId } from "../src/lib/secure/snipForum.js";

const mk = (n) => ({
  id: "SNIP-" + String(n).padStart(4, "0"),
  title: "Example proposal",
  status: "Draft",
  where: "main",
  closure: "merged_to_main",
  closed: true,
  url: "https://github.com/Comutability/secure-net",
});

test("rate-limited batches prioritise missing proposals over closures", () => {
  assert.equal(MAX_STEPS, 1);
  const report = {
    enabled:true, manager:true, stale:false, channel:{id:"forum"},
    snips: Array.from({length:8},(_,i)=>mk(i+1)),
    threads:Object.fromEntries(Array.from({length:6},(_,i)=>[mk(i+1).id, {locked:i===0}])),
    notes:{},
  };
  const first=planSnipSync(report);
  assert.deepEqual(first.map(v=>v.snip.id),["SNIP-0007"]);
  assert.deepEqual(planSnipSync(report,Number.MAX_SAFE_INTEGER).map(v=>v.snip.id),
    ["SNIP-0007","SNIP-0008","SNIP-0002","SNIP-0003","SNIP-0004","SNIP-0005","SNIP-0006"]);
  assert.deepEqual(planSnipSync({...report,stale:true}),[]);
});

test("a failure after encrypted posting resumes the closing lock without duplicating a thread or note", async () => {
  const posted = new Set();
  const locked = new Set();
  let failOnce=true;
  const snip=mk(7);
  const status=async () => ({
    enabled:true, manager:true, stale:false,
    channel:{id:"forum"}, snips:[snip],
    threads:posted.has(snipThreadId(snip.id))? {[snip.id]:{locked:locked.has(snipThreadId(snip.id))}}:{},
    notes:posted.has(snipClosedNoteId(snip.id))?{[snip.id]:true}:{},
  });
  const io={
    status,
    channelOf:async()=>({id:"forum"}),
    post:async (_channel,_payload,opts)=>{
      if(posted.has(opts.itemId))throw Object.assign(new Error("duplicate"),{code:"DUPLICATE_ID"});
      posted.add(opts.itemId);
    },
    lock:async(_channel,id)=>{
      if(failOnce) {failOnce=false;throw Object.assign(new Error("service busy"),{code:"UPSTREAM_BUSY"})}
      locked.add(id);
    },
  };
  await assert.rejects(()=>runSnipSync(io),{code:"UPSTREAM_BUSY"});
  assert.deepEqual([...posted].sort(),[snipClosedNoteId(snip.id),snipThreadId(snip.id)].sort());
  assert.deepEqual(await runSnipSync(io),{forum:false,posted:[],closed:[snip.id]});
  assert.deepEqual(await runSnipSync(io),{forum:false,posted:[],closed:[]});
  assert.equal(posted.size,2);
  assert.equal(locked.has(snipThreadId(snip.id)),true);
});
