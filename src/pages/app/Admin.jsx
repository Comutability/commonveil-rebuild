import React, { useEffect, useMemo, useState } from "react";
import { Link, Navigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Bug, FileText, Flag, Plus } from "lucide-react";
import { base44 } from "@/api/base44Client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ErrorNote, Loading, Pill, formatDate } from "@/components/site/bits";
import Markdown from "@/components/site/Markdown";
import { callFn } from "@/lib/api";
import { useAuth } from "@/lib/AuthContext";
import { LogoMark } from "@/components/site/Logo";

// ---------- Reports ----------

function ReportRow({ r, onSaved }) {
  const [status, setStatus] = useState(r.status);
  const [note, setNote] = useState(r.resolution_note);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <li className="card-cv space-y-3 p-4">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Pill tone="warn">{r.reason}</Pill>
        <span><strong>@{r.reporter}</strong> reported <strong>@{r.reported}</strong></span>
        <span className="text-muted-foreground">{formatDate(r.created_date)}</span>
      </div>
      {r.details ? <p className="whitespace-pre-wrap rounded-md bg-muted p-3 text-sm">{r.details}</p> : <p className="text-sm text-muted-foreground">No details given.</p>}
      <div className="grid gap-2 sm:grid-cols-[180px_1fr_auto]">
        <Select value={status} onValueChange={setStatus}>
          <SelectTrigger aria-label="Status"><SelectValue /></SelectTrigger>
          <SelectContent>
            {["open", "reviewing", "resolved", "dismissed"].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
          </SelectContent>
        </Select>
        <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Note (staff only)" aria-label="Resolution note" />
        <Button
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            setError("");
            try {
              await callFn("admin", { action: "update_report", report_id: r.id, status, resolution_note: note });
              onSaved();
            } catch (err) {
              setError(err.message);
            } finally {
              setBusy(false);
            }
          }}
        >
          Save
        </Button>
      </div>
      <ErrorNote>{error}</ErrorNote>
    </li>
  );
}

function Reports() {
  const [filter, setFilter] = useState("open");
  const q = useQuery({ queryKey: ["admin-reports", filter], queryFn: () => callFn("admin", { action: "list_reports", status: filter === "all" ? undefined : filter }) });
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Label>Show</Label>
        <Select value={filter} onValueChange={setFilter}>
          <SelectTrigger className="w-44" aria-label="Filter reports"><SelectValue /></SelectTrigger>
          <SelectContent>
            {["open", "reviewing", "resolved", "dismissed", "all"].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>
      {q.isLoading ? <Loading /> : q.error ? <ErrorNote>{q.error.message}</ErrorNote> : q.data.reports.length === 0 ? (
        <p className="text-muted-foreground">Nothing here.</p>
      ) : (
        <ul className="space-y-3">{q.data.reports.map((r) => <ReportRow key={r.id} r={r} onSaved={() => q.refetch()} />)}</ul>
      )}
    </div>
  );
}

// ---------- Security reports ----------

const SECURITY_STATUSES = ["new", "triaged", "fixed", "closed"];

function SecurityReportRow({ r, onSaved }) {
  const [status, setStatus] = useState(r.status);
  const [note, setNote] = useState(r.staff_note);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <li className="card-cv space-y-3 p-4">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Pill tone={r.status === "new" ? "warn" : "muted"}>{r.status}</Pill>
        <strong className="min-w-0 break-words">{r.summary}</strong>
        <span className="text-muted-foreground">{formatDate(r.created_date)}</span>
      </div>
      {/* Reports come from the public, so they're shown as plain text: never Markdown, never links. */}
      <p className="whitespace-pre-wrap break-words rounded-md bg-muted p-3 text-sm">{r.details}</p>
      <p className="text-sm text-muted-foreground">
        {r.reporter ? <>From member <strong>@{r.reporter}</strong>. </> : <>Sent without signing in. </>}
        {r.contact ? <>Contact: <span className="break-all text-foreground">{r.contact}</span></> : "No contact given."}
      </p>
      <div className="grid gap-2 sm:grid-cols-[180px_1fr_auto]">
        <Select value={status} onValueChange={setStatus}>
          <SelectTrigger aria-label="Status"><SelectValue /></SelectTrigger>
          <SelectContent>
            {SECURITY_STATUSES.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
          </SelectContent>
        </Select>
        <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Note (staff only)" aria-label="Staff note" />
        <Button
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            setError("");
            try {
              await callFn("admin", { action: "update_security_report", report_id: r.id, status, staff_note: note });
              onSaved();
            } catch (err) {
              setError(err.message);
            } finally {
              setBusy(false);
            }
          }}
        >
          Save
        </Button>
      </div>
      <ErrorNote>{error}</ErrorNote>
    </li>
  );
}

function SecurityReports() {
  const [filter, setFilter] = useState("new");
  const q = useQuery({
    queryKey: ["admin-security-reports", filter],
    queryFn: () => callFn("admin", { action: "list_security_reports", status: filter === "all" ? undefined : filter }),
  });
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Label>Show</Label>
        <Select value={filter} onValueChange={setFilter}>
          <SelectTrigger className="w-44" aria-label="Filter security reports"><SelectValue /></SelectTrigger>
          <SelectContent>
            {[...SECURITY_STATUSES, "all"].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>
      {q.isLoading ? <Loading /> : q.error ? <ErrorNote>{q.error.message}</ErrorNote> : q.data.reports.length === 0 ? (
        <p className="text-muted-foreground">Nothing here.</p>
      ) : (
        <ul className="space-y-3">{q.data.reports.map((r) => <SecurityReportRow key={r.id} r={r} onSaved={() => q.refetch()} />)}</ul>
      )}
    </div>
  );
}

// ---------- Content ----------

const TYPES = {
  BlogPost: {
    label: "Blog posts",
    titleField: "title",
    fields: [
      ["title", "Title"], ["slug", "Slug"], ["excerpt", "Excerpt", "textarea"], ["category", "Category"], ["author_name", "Author"],
      ["reading_time", "Reading time"], ["cover_image", "Cover image URL"], ["published_at", "Published date (YYYY-MM-DD)"],
      ["tags", "Tags (comma separated)", "list"], ["featured", "Featured", "bool"], ["body", "Body (Markdown)", "markdown"],
    ],
  },
  Guide: {
    label: "Guides",
    titleField: "title",
    fields: [
      ["title", "Title"], ["slug", "Slug"], ["summary", "Summary", "textarea"], ["category", "Category"],
      ["difficulty", "Difficulty", "select", ["Beginner", "Intermediate", "Advanced"]], ["estimated_time", "Time needed"],
      ["os_version", "Works on"], ["last_tested", "Last tested (YYYY-MM-DD)"], ["requirements", "You'll need (one per line)", "lines"],
      ["prerequisites", "Before you start (one per line)", "lines"], ["author_name", "Author"], ["body", "Body (Markdown)", "markdown"],
    ],
  },
  LearningPath: {
    label: "Learning paths",
    titleField: "title",
    fields: [
      ["title", "Title"], ["slug", "Slug"], ["summary", "Summary", "textarea"], ["description", "Description", "textarea"],
      ["category", "Category"], ["difficulty", "Difficulty", "select", ["Beginner", "Intermediate", "Advanced"]],
      ["estimated_time", "Time needed"], ["guide_slugs", "Guide slugs, in order (one per line)", "lines"],
    ],
  },
  Resource: {
    label: "Resources",
    titleField: "name",
    fields: [
      ["name", "Name"], ["website", "Website"], ["description", "Description", "textarea"], ["category", "Category"],
      ["open_source", "Open source", "select", ["Yes", "Partly", "No", "Unknown"]], ["self_hostable", "Self-hostable", "bool"],
      ["platforms", "Platforms (comma separated)", "list"], ["pricing_summary", "Pricing"], ["privacy_notes", "Privacy notes", "textarea"],
      ["last_reviewed", "Last reviewed (YYYY-MM-DD)"],
    ],
  },
  WikiPage: {
    label: "Wiki pages",
    titleField: "title",
    fields: [["title", "Title"], ["slug", "Slug"], ["summary", "Summary", "textarea"], ["category", "Category"], ["body", "Body (Markdown)", "markdown"]],
  },
};

const slugify = (s) => String(s || "").toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80);

function toForm(type, record) {
  const out = { status: record?.status || "draft" };
  for (const [key, , kind] of TYPES[type].fields) {
    const v = record?.[key];
    out[key] = kind === "list" ? (v || []).join(", ") : kind === "lines" ? (v || []).join("\n") : kind === "bool" ? Boolean(v) : v ?? "";
  }
  return out;
}

function fromForm(type, form) {
  const out = { status: form.status };
  for (const [key, , kind] of TYPES[type].fields) {
    const v = form[key];
    if (kind === "list") out[key] = String(v || "").split(",").map((x) => x.trim()).filter(Boolean);
    else if (kind === "lines") out[key] = String(v || "").split("\n").map((x) => x.trim()).filter(Boolean);
    else if (kind === "bool") out[key] = Boolean(v);
    else out[key] = String(v || "").trim();
  }
  if (!out.slug && out[TYPES[type].titleField]) out.slug = slugify(out[TYPES[type].titleField]);
  return out;
}

function Editor({ type, record, onClose }) {
  const qc = useQueryClient();
  const [form, setForm] = useState(() => toForm(type, record));
  const [preview, setPreview] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));

  const save = async () => {
    setBusy(true);
    setError("");
    try {
      const data = fromForm(type, form);
      if (record?.id) await base44.entities[type].update(record.id, data);
      else await base44.entities[type].create(data);
      qc.invalidateQueries({ queryKey: ["admin-content", type] });
      qc.invalidateQueries({ queryKey: ["content", type] });
      onClose();
    } catch (err) {
      setError(err.message || "Couldn't save.");
      setBusy(false);
    }
  };

  const remove = async () => {
    if (!record?.id || !window.confirm("Delete this permanently?")) return;
    setBusy(true);
    try {
      await base44.entities[type].delete(record.id);
      qc.invalidateQueries({ queryKey: ["admin-content", type] });
      qc.invalidateQueries({ queryKey: ["content", type] });
      onClose();
    } catch (err) {
      setError(err.message || "Couldn't delete.");
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="ghost" onClick={onClose}>← Back</Button>
        <span className="flex-1" />
        <Select value={form.status} onValueChange={(v) => set("status", v)}>
          <SelectTrigger className="w-36" aria-label="Status"><SelectValue /></SelectTrigger>
          <SelectContent><SelectItem value="draft">Draft</SelectItem><SelectItem value="published">Published</SelectItem></SelectContent>
        </Select>
        {record?.id && <Button variant="outline" className="text-destructive" onClick={remove} disabled={busy}>Delete</Button>}
        <Button onClick={save} disabled={busy}>{busy ? "Saving…" : "Save"}</Button>
      </div>
      <ErrorNote>{error}</ErrorNote>
      <div className="grid gap-4 sm:grid-cols-2">
        {TYPES[type].fields.map(([key, label, kind, options]) => {
          const id = `f-${key}`;
          if (kind === "markdown") {
            return (
              <div key={key} className="space-y-1.5 sm:col-span-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor={id}>{label}</Label>
                  <button type="button" className="text-sm text-primary hover:underline" onClick={() => setPreview((p) => !p)}>{preview ? "Edit" : "Preview"}</button>
                </div>
                {preview ? <div className="card-cv p-5"><Markdown>{form[key]}</Markdown></div> : (
                  <Textarea id={id} value={form[key]} onChange={(e) => set(key, e.target.value)} rows={18} className="mono text-sm" />
                )}
              </div>
            );
          }
          if (kind === "bool") {
            return (
              <label key={key} className="flex items-center gap-2 text-sm">
                <Checkbox checked={Boolean(form[key])} onCheckedChange={(v) => set(key, Boolean(v))} /> {label}
              </label>
            );
          }
          if (kind === "select") {
            return (
              <div key={key} className="space-y-1.5">
                <Label>{label}</Label>
                <Select value={form[key] || options[0]} onValueChange={(v) => set(key, v)}>
                  <SelectTrigger aria-label={label}><SelectValue /></SelectTrigger>
                  <SelectContent>{options.map((o) => <SelectItem key={o} value={o}>{o}</SelectItem>)}</SelectContent>
                </Select>
              </div>
            );
          }
          const area = kind === "textarea" || kind === "lines";
          return (
            <div key={key} className={`space-y-1.5 ${area ? "sm:col-span-2" : ""}`}>
              <Label htmlFor={id}>{label}</Label>
              {area ? <Textarea id={id} value={form[key]} onChange={(e) => set(key, e.target.value)} rows={3} /> : <Input id={id} value={form[key]} onChange={(e) => set(key, e.target.value)} />}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function Content() {
  const [type, setType] = useState("BlogPost");
  const [editing, setEditing] = useState(null);
  const q = useQuery({ queryKey: ["admin-content", type], queryFn: () => base44.entities[type].list("-updated_date", 500) });
  const titleField = TYPES[type].titleField;
  const rows = useMemo(() => q.data || [], [q.data]);

  useEffect(() => setEditing(null), [type]);

  if (editing) return <Editor key={editing.id || "new"} type={type} record={editing.id ? editing : null} onClose={() => setEditing(null)} />;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Select value={type} onValueChange={setType}>
          <SelectTrigger className="w-48" aria-label="Content type"><SelectValue /></SelectTrigger>
          <SelectContent>{Object.entries(TYPES).map(([k, v]) => <SelectItem key={k} value={k}>{v.label}</SelectItem>)}</SelectContent>
        </Select>
        <Button onClick={() => setEditing({})}><Plus className="mr-1 h-4 w-4" aria-hidden="true" /> New</Button>
      </div>
      {q.isLoading ? <Loading /> : (
        <ul className="divide-y divide-border rounded-xl border border-border">
          {rows.map((r) => (
            <li key={r.id}>
              <button type="button" onClick={() => setEditing(r)} className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-muted/50">
                <span className="min-w-0 flex-1 truncate font-medium">{r[titleField]}</span>
                <Pill tone={r.status === "published" ? "accent" : "muted"}>{r.status}</Pill>
                <span className="hidden text-xs text-muted-foreground sm:inline">{formatDate(r.updated_date)}</span>
              </button>
            </li>
          ))}
          {rows.length === 0 && <li className="px-4 py-6 text-center text-sm text-muted-foreground">Nothing yet.</li>}
        </ul>
      )}
    </div>
  );
}

/**
 * Staff area. Deliberately outside the encrypted-messaging gate: managing content and
 * reports needs the admin role, not encryption keys, and staff never see message content.
 */
export default function Admin() {
  const { user } = useAuth();
  if (user?.role !== "admin") return <Navigate to="/" replace />;
  return (
    <div className="min-h-[100dvh]">
      <header className="border-b border-border">
        <div className="mx-auto flex h-14 max-w-5xl items-center justify-between px-4">
          <Link to="/" className="flex items-center gap-2">
            <LogoMark className="h-7 w-7 text-primary-foreground" />
            <span className="font-heading text-lg font-semibold">Commonveil admin</span>
          </Link>
          <nav className="flex gap-4 text-sm text-muted-foreground">
            <Link to="/app" className="hover:text-foreground">Messages</Link>
            <Link to="/" className="hover:text-foreground">Site</Link>
          </nav>
        </div>
      </header>
      <main className="mx-auto w-full max-w-5xl px-4 py-8">
        <h1 className="text-3xl font-semibold">Admin</h1>
        <Tabs defaultValue="reports" className="mt-6">
          <TabsList>
            <TabsTrigger value="reports"><Flag className="mr-1.5 h-4 w-4" aria-hidden="true" /> Reports</TabsTrigger>
            <TabsTrigger value="security"><Bug className="mr-1.5 h-4 w-4" aria-hidden="true" /> Security</TabsTrigger>
            <TabsTrigger value="content"><FileText className="mr-1.5 h-4 w-4" aria-hidden="true" /> Content</TabsTrigger>
          </TabsList>
          <TabsContent value="reports" className="pt-4"><Reports /></TabsContent>
          <TabsContent value="security" className="pt-4"><SecurityReports /></TabsContent>
          <TabsContent value="content" className="pt-4"><Content /></TabsContent>
        </Tabs>
      </main>
    </div>
  );
}
