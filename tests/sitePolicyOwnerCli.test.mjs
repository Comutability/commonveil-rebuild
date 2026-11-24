import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {DatabaseSync} from "node:sqlite";
import {runCli} from "../server/cli.mjs";
test("only the operator console can transfer owner role, and keeps one owner",async()=>{
  const folder=mkdtempSync(join(tmpdir(),"commonveil-owner-cli-"));
  const dbFile=join(folder,"site.db");
  try {
    const db=new DatabaseSync(dbFile);
    db.exec("CREATE TABLE records (entity TEXT,id TEXT,seq INTEGER,data TEXT,PRIMARY KEY(entity,id))");
    const put=db.prepare("INSERT INTO records(entity,id,seq,data) VALUES(?,?,?,?)");
    put.run("Person","first_account",1,JSON.stringify({id:"first_account",role:"admin",site_owner:true}));
    put.run("Person","second_account",2,JSON.stringify({id:"second_account",role:"user",site_owner:false}));
    put.run("Profile","first_profile",3,JSON.stringify({username_key:"first",user_id:"first_account"}));
    put.run("Profile","second_profile",4,JSON.stringify({username_key:"second",user_id:"second_account"}));
    db.close();
    assert.equal(await runCli({dbFile,version:"test"} ,["make-owner","second"]),0);
    const opened=new DatabaseSync(dbFile);
    const people=opened.prepare("SELECT data FROM records WHERE entity='Person' ORDER BY seq").all()
       .map(row=>JSON.parse(row.data));
    assert.equal(people[0].site_owner,false);
    assert.equal(people[1].site_owner,true);
    assert.equal(people[1].role,"admin");
    opened.close();
    assert.equal(await runCli({dbFile,version:"test"},["make-owner","missing"]),1);
  }finally {rmSync(folder,{recursive:true,force:true})}
});
