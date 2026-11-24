import React, {useEffect,useState} from "react";
import {Link} from "react-router-dom";
import {callFn} from "@/lib/api";
import {PageHeader} from "@/components/site/bits";

export default function SiteRules(){
  const [data,setData]=useState(null);
  const [error,setError]=useState("");
  useEffect(()=>{let alive=true;callFn("disclose",{action:"site_rules"})
    .then(v=>alive&&setData(v)).catch(e=>alive&&setError(e.message));return()=>{alive=false}},[]);
  return <>
    <PageHeader eyebrow="Community safety" title="Site rules and federation policy"
      intro="Every Commonveil host chooses its own rules and which other sites it communicates with. Rules are separate from community-server permissions."/>
    <div className="container-cv max-w-3xl space-y-8 py-12">
      {error?<p role="alert">{error}</p>:!data?<p>Loading site rules…</p>:<>
        <section className="space-y-3">
          <h2 className="text-xl font-semibold">Rules on this site</h2>
          {data.rules?.length?<ol className="list-decimal space-y-3 pl-6">{data.rules.map((r,i)=><li key={i} className="whitespace-pre-wrap">{r}</li>)}</ol>:<p className="text-muted-foreground">The site owner has not published additional local rules. General terms and applicable laws still apply.</p>}
          {data.contact?<p className="text-sm">Contact or appeals: <span className="break-all">{data.contact}</span></p>:null}
        </section>
        <section className="space-y-3">
          <h2 className="text-xl font-semibold">Federation and access</h2>
          <p>New accounts: {data.registration_open?"accepted under the site's sign-up controls":"registration closed"}.</p>
          <p>Federation policy: {data.federation_mode==="allowlist"?"approved sites only":data.federation_mode==="off"?"disabled by the owner":"open to compatible sites, subject to moderation"}.</p>
          {data.domain_blocks?.length?<ul className="space-y-2">{data.domain_blocks.map(d=><li key={d.domain}><strong>{d.domain}</strong>: {d.severity==="suspend"?"Suspended":"Limited"}{d.reason?". "+d.reason:""}</li>)}</ul>:null}
        </section>
        <p className="text-sm text-muted-foreground">Moderators cannot inspect the plaintext of end-to-end encrypted private conversations. Federation decisions restrict site traffic and local delivery, not what another independent operator can publish.</p>
      </>}
      <Link className="text-primary underline" to="/terms">Read the Terms of Use</Link>
    </div>
  </>;
}
