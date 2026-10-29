import React, { useState } from "react";
import { Link } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { ErrorNote, PageHeader } from "@/components/site/bits";
import { callFn } from "@/lib/api";

export default function ReportSecurityIssue() {
  const [summary, setSummary] = useState("");
  const [details, setDetails] = useState("");
  const [contact, setContact] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [sent, setSent] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await callFn("disclose", { action: "submit", summary, details, contact });
      setSent(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader
        eyebrow="Security"
        title="Report a security problem"
        intro="If you've found a way to read messages you shouldn't, act as someone else, or get around Commonveil's protections, please tell us here first."
      />
      <div className="container-cv grid gap-10 py-12 lg:grid-cols-[1.4fr_1fr]">
        {sent ? (
          <div className="card-cv flex items-start gap-4 p-6" role="status">
            <ShieldCheck className="mt-1 h-6 w-6 shrink-0 text-primary" aria-hidden="true" />
            <div>
              <h2 className="text-xl font-semibold">Thank you. Your report is with our staff.</h2>
              <p className="mt-2 text-muted-foreground">
                If you left a way to reach you, we'll reply there. Please keep the details private until it's fixed.
              </p>
              <Link to="/security" className="mt-4 inline-block text-primary underline">Back to Security</Link>
            </div>
          </div>
        ) : (
          <form onSubmit={submit} className="space-y-5">
            <div className="space-y-1.5">
              <Label htmlFor="sr-summary">What's the problem?</Label>
              <Input id="sr-summary" value={summary} onChange={(e) => setSummary(e.target.value)} maxLength={200} required placeholder="A one-line summary" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="sr-details">Details</Label>
              <Textarea
                id="sr-details"
                value={details}
                onChange={(e) => setDetails(e.target.value)}
                maxLength={8000}
                rows={10}
                required
                placeholder="What you found, the steps to reproduce it, and what someone could do with it."
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="sr-contact">How can we reach you? <span className="font-normal text-muted-foreground">(optional)</span></Label>
              <Input id="sr-contact" value={contact} onChange={(e) => setContact(e.target.value)} maxLength={300} placeholder="An email address, a Commonveil username, or leave blank" />
            </div>
            <ErrorNote>{error}</ErrorNote>
            <Button type="submit" disabled={busy || summary.trim().length < 5 || details.trim().length < 20}>{busy ? "Sending…" : "Send report"}</Button>
          </form>
        )}
        <aside className="card-cv h-fit space-y-3 p-6 text-sm text-muted-foreground">
          <h2 className="text-lg font-semibold text-foreground">Before you send</h2>
          <ul className="list-disc space-y-2 pl-5">
            <li>You don't need an account. Reports go only to Commonveil's staff.</li>
            <li>Test against your own accounts. Please don't access other people's data or disrupt the service.</li>
            <li>Give us a reasonable chance to fix a problem before you talk about it publicly.</li>
            <li>Don't include anyone else's personal information.</li>
          </ul>
        </aside>
      </div>
    </>
  );
}
