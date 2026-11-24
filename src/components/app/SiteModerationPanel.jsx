import React, { useCallback, useEffect, useState } from "react";
import { Globe2, ShieldCheck, ShieldOff, RefreshCw, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { NativeSelect } from "@/components/ui/native-select";
import { ErrorNote } from "@/components/site/bits";
import { callFn } from "@/lib/api";

const policyDefaults={public_rules:[],contact:"",federation_mode:"open",
  registration_open:true,allow_remote_discovery:true,show_domain_blocks:false};
const newDomain={domain:"",severity:"suspend",public_reason:"",private_note:""};
export default function SiteModerationPanel(){
  const [policy,setPolicy]=useState(policyDefaults);
  const [domains,setDomains]=useState([]);
  const [owner,setOwner]=useState(false);
  const [draftRules,setDraftRules]=useState("");
  const [entry,setEntry]=useState(newDomain);
  const [working,setWorking]=useState("");
  const [error,setError]=useState("");
  const [success,setSuccess]=useState("");
  const [loaded,setLoaded]=useState(false);
  const refresh=useCallback(async()=>{
    try {
      const data=await callFn("admin",{action:"site_policy_get"});
      setPolicy(data.policy||policyDefaults);
      setDomains(data.domains||[]);
      setOwner(data.owner===true);
      setDraftRules((data.policy?.public_rules||[]).join("\n"));
      setLoaded(true);
      setError("");
    } catch(e){setError(e.message)}
  },[]);
  useEffect(()=>{refresh()},[refresh]);
  const act=async(name,body)=>{
    setWorking(name);setError("");setSuccess("");
    try {
      const result=await callFn("admin",{action:name,...body});
      if(result.policy)setPolicy(result.policy);
      if(result.domains)setDomains(result.domains);
      setSuccess("Site policy saved.");
      return true;
    }catch(e){setError(e.message);return false}
    finally{setWorking("")}
  };
  const change=(key,val)=>setPolicy(p=>({...p,[key]:val}));
  return <div className="space-y-7">
    <div className="rounded-lg border bg-card p-4 text-sm">
      <div className="flex items-center gap-2 font-semibold"><ShieldCheck size={18} aria-hidden="true"/> Site-wide controls</div>
      <p className="mt-2 text-muted-foreground">These are your host's rules, separate from the permissions and encrypted content of individual community servers. Site administrators may manage local rules and other domains. The host owner controls sign-ups and whether federation is open, restricted or disabled.</p>
      <p className="mt-2 text-muted-foreground">Like Mastodon, a domain can be suspended, limited or have its remote media rejected. Encrypted private messages are not scanned for inappropriate content. Decisions must be based on reports, visible metadata and evidence that participants choose to provide.</p>
    </div>
    {error?<ErrorNote>{error}</ErrorNote>:null}
    {success?<p role="status" className="text-sm text-primary">{success}</p>:null}
    {!loaded?<p className="text-sm text-muted-foreground">Loading site policy…</p>:<>
      <section className="space-y-4 rounded-lg border p-4">
        <div className="flex items-center justify-between"><h3 className="font-semibold">Public site rules</h3><Button size="sm" variant="ghost" onClick={refresh}><RefreshCw size={16} aria-hidden="true"/> Refresh</Button></div>
        <p className="text-xs text-muted-foreground">One rule per line, up to 20 rules of 500 characters each. These are visible to everyone at the site's Rules page. Do not include private member details.</p>
        <Label htmlFor="public-site-rules">Rules for everyone using this host</Label>
        <Textarea id="public-site-rules" rows={7} value={draftRules} onChange={e=>setDraftRules(e.target.value)} placeholder={"No harassment or threats\nNo spam or scams\nRespect consent and privacy"}/>
        <Label htmlFor="public-site-contact">Moderation contact or appeals URL (optional)</Label>
        <Input id="public-site-contact" maxLength={200} value={policy.contact||""} onChange={e=>change("contact",e.target.value)} placeholder="https://your-site.example/contact"/>
        <div className="flex items-center gap-2"><Checkbox id="show-domain-reasons" checked={policy.show_domain_blocks===true} onCheckedChange={v=>change("show_domain_blocks",v===true)}/><Label htmlFor="show-domain-reasons">Publish domain suspensions and their public reasons</Label></div>
        <Button disabled={Boolean(working)} onClick={()=>act("site_policy_save",{policy:{public_rules:draftRules.split(/\r?\n/).map(x=>x.trim()).filter(Boolean),contact:policy.contact,show_domain_blocks:policy.show_domain_blocks}})}>Save rules</Button>
      </section>

      <section className="space-y-4 rounded-lg border p-4">
        <h3 className="font-semibold">Host configuration</h3>
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="space-y-1.5 text-sm"><span className="font-medium">Federation mode</span>
            <NativeSelect aria-label="Federation mode" disabled={!owner||Boolean(working)} value={policy.federation_mode} onChange={e=>change("federation_mode",e.target.value)}>
              <option value="open">Open federation</option><option value="allowlist">Approved sites only</option><option value="off">No site-to-site federation</option>
            </NativeSelect>
          </label>
          <div className="space-y-3 text-sm">
            <label className="flex items-center gap-2"><Checkbox disabled={!owner||Boolean(working)} checked={policy.registration_open} onCheckedChange={v=>change("registration_open",v===true)}/> Allow new account registration</label>
            <label className="flex items-center gap-2"><Checkbox checked={policy.allow_remote_discovery} onCheckedChange={v=>change("allow_remote_discovery",v===true)}/> Allow remote site directory discovery</label>
          </div>
        </div>
        <p className="text-xs text-muted-foreground">Approved sites only requires exact domains with the Allow action below. Turning off registration in this panel cannot override a stricter Docker OPEN_REGISTRATION=false setting. Turning off federation does not erase past encrypted messages. Use the Docker FEDERATION=false flag to disable the federation subsystem entirely.</p>
        <Button disabled={Boolean(working)} onClick={()=>act("site_policy_save",{policy:owner?{registration_open:policy.registration_open,federation_mode:policy.federation_mode,allow_remote_discovery:policy.allow_remote_discovery}:{allow_remote_discovery:policy.allow_remote_discovery}})}>Save host settings</Button>
      </section>

      <section className="space-y-4 rounded-lg border p-4">
        <div className="flex items-center gap-2"><Globe2 size={18} aria-hidden="true"/><h3 className="font-semibold">Domain moderation and approved sites</h3></div>
        <p className="text-xs text-muted-foreground">Exact hostnames only. Suspend rejects authenticated remote federation in both directions. Limit rejects new remote relationships and discovery while preserving existing encrypted conversations. Reject media blocks proxying files from that domain. Allow places a site on the list for restricted federation. Each action applies to this host only.</p>
        <form className="space-y-3" onSubmit={async e=>{
          e.preventDefault();
          if(await act("site_domain_upsert",{rule:entry}))setEntry(newDomain);
        }}>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="space-y-1.5 text-sm"><span className="font-medium">Remote domain</span>
              <Input required value={entry.domain} onChange={e=>setEntry(v=>({...v,domain:e.target.value}))} placeholder="another-site.example" maxLength={253}/>
            </label>
            <label className="space-y-1.5 text-sm"><span className="font-medium">Action</span>
              <NativeSelect value={entry.severity} onChange={e=>setEntry(v=>({...v,severity:e.target.value}))} aria-label="Domain action">
                <option value="suspend">Suspend federation</option>
                <option value="limit">Limit new interactions</option>
                <option value="reject_media">Reject remote media</option>
                <option value="allow">Allow in restricted federation</option>
              </NativeSelect>
            </label>
          </div>
          <label className="block space-y-1.5 text-sm"><span className="font-medium">Public reason (optional)</span><Textarea rows={2} maxLength={500} value={entry.public_reason} onChange={e=>setEntry(v=>({...v,public_reason:e.target.value}))} placeholder="Repeated unsolicited spam, confirmed by reports"/></label>
          <label className="block space-y-1.5 text-sm"><span className="font-medium">Private admin note (optional)</span><Textarea rows={2} maxLength={1000} value={entry.private_note} onChange={e=>setEntry(v=>({...v,private_note:e.target.value}))} placeholder="Internal evidence or moderation review reference, no private message content"/></label>
          <Button type="submit" disabled={!entry.domain||Boolean(working)}>Save domain rule</Button>
        </form>
        {domains.length?(
          <ul className="divide-y rounded-md border">
            {domains.map(d=><li key={d.domain} className="flex flex-wrap gap-3 p-3 text-sm">
              <div className="min-w-0 flex-1 space-y-1"><p className="font-semibold">{d.domain} <span className="ml-2 font-normal text-muted-foreground">({d.severity.replace("_"," ")})</span></p>
                {d.public_reason?<p className="text-muted-foreground">Public: {d.public_reason}</p>:null}
                {d.private_note?<p className="text-xs text-muted-foreground">Private staff note: {d.private_note}</p>:null}
              </div>
              <Button size="sm" variant="outline" onClick={()=>setEntry({domain:d.domain,severity:d.severity,public_reason:d.public_reason||"",private_note:d.private_note||""})}>Edit</Button>
              <Button size="sm" variant="outline" disabled={Boolean(working)} onClick={()=>act("site_domain_remove",{domain:d.domain})} aria-label={"Remove domain policy for "+d.domain}><Trash2 size={16} aria-hidden="true"/> Remove</Button>
            </li>)}
          </ul>
        ):<p className="text-xs text-muted-foreground">No custom domain rules yet. Remote sites are treated according to your federation mode.</p>}
      </section>
      <p className="flex items-center gap-2 text-xs text-muted-foreground"><ShieldOff size={16} aria-hidden="true"/> Local policy does not govern or censor other independently operated sites. Hosting choices and site appeals remain the responsibility of each operator.</p>
    </>}
  </div>;
}
