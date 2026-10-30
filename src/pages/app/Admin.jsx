import React, { useEffect, useMemo, useState } from "react";
import { Link, Navigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Bug, FileText, Flag, Plus, UserX } from "lucide-react";
import { base44 } from "@/api/base44Client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { NativeSelect } from "@/components/ui/native-select";
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
        <NativeSelect value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
          {["open", "reviewing", "resolved", "dismissed"].map((s) => <option key={s} value={s}>{s}</option>)}
        </NativeSelect>
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
        <NativeSelect className="w-44" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter reports">
          {["open", "reviewing", "resolved", "dismissed", "all"].map((s) => <option key={s} value={s}>{s}</option>)}
        </NativeSelect>
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
        <NativeSelect value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
          {SECURITY_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
        </NativeSelect>
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
        <NativeSelect className="w-44" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter security reports">
          {[...SECURITY_STATUSES, "all"].map((s) => <option key={s} value={s}>{s}</option>)}
        </NativeSelect>
      </div>
      {q.isLoading ? <Loading /> : q.error ? <ErrorNote>{q.error.message}</ErrorNote> : q.data.reports.length === 0 ? (
        <p className="text-muted-foreground">Nothing here.</p>
      ) : (
        <ul className="space-y-3">{q.data.reports.map((r) => <SecurityReportRow key={r.id} r={r} onSaved={() => q.refetch()} />)}</ul>
      )}
    </div>
  );
}

// ---------- Removed accounts ----------

function RemovedAccountRow({ account, onErased }) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const inputId = `erase-${account.user_id}`;
  const erase = async () => {
    setBusy(true);
    setError("");
    try {
      // A big account takes more than one call; each picks up where the last stopped.
      for (let i = 0; i < 40; i += 1) {
        const res = await callFn("admin", { action: "erase_removed_account", user_id: account.user_id, confirm: "ERASE" });
        if (res.done) {
          onErased();
          return;
        }
      }
      setError("This is taking a while. Press the button again to carry on.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <li className="card-cv space-y-3 p-4">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <strong>@{account.username}</strong>
        {account.display_name && account.display_name !== account.username && <span>{account.display_name}</span>}
        <span className="text-muted-foreground">joined {formatDate(account.created_date)}</span>
      </div>
      <div className="flex flex-wrap items-end gap-2">
        <div className="space-y-1.5">
          <Label htmlFor={inputId}>Type ERASE to confirm</Label>
          <Input id={inputId} className="w-40" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
        </div>
        <Button variant="destructive" disabled={busy || typed !== "ERASE"} onClick={erase}>
          {busy ? "Erasing…" : "Erase what they left"}
        </Button>
      </div>
      <ErrorNote>{error}</ErrorNote>
    </li>
  );
}

function RemovedAccounts() {
  const q = useQuery({ queryKey: ["admin-removed-accounts"], queryFn: () => callFn("admin", { action: "list_removed_accounts" }) });
  return (
    <div className="space-y-4">
      <p className="max-w-3xl text-sm text-muted-foreground">
        Members delete their own accounts in Settings. If someone's sign-in is removed in Base44 instead, their profile, keys and the
        messages they sent stay here until you erase them. Erasing works exactly like a member deleting their own account: their direct
        conversations go for the other person too, they leave their groups, and their username can't be used again.
      </p>
      {q.isLoading ? <Loading /> : q.error ? <ErrorNote>{q.error.message}</ErrorNote> : q.data.accounts.length === 0 ? (
        <p className="text-muted-foreground">No removed sign-ins have left anything here.</p>
      ) : (
        <ul className="space-y-3">
          {q.data.accounts.map((a) => <RemovedAccountRow key={a.user_id} account={a} onErased={() => q.refetch()} />)}
        </ul>
      )}
      {q.data && !q.data.complete && <p className="text-sm text-muted-foreground">Only the first 5,000 accounts were checked.</p>}
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
        <NativeSelect className="w-36" value={form.status} onChange={(e) => set("status", e.target.value)} aria-label="Status">
          <option value="draft">Draft</option>
          <option value="published">Published</option>
        </NativeSelect>
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
                <Label htmlFor={id}>{label}</Label>
                <NativeSelect id={id} value={form[key] || options[0]} onChange={(e) => set(key, e.target.value)}>
                  {options.map((o) => <option key={o} value={o}>{o}</option>)}
                </NativeSelect>
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
        <NativeSelect className="w-48" value={type} onChange={(e) => setType(e.target.value)} aria-label="Content type">
          {Object.entries(TYPES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
        </NativeSelect>
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
          <TabsList className="h-auto flex-wrap justify-start">
            <TabsTrigger value="reports"><Flag className="mr-1.5 h-4 w-4" aria-hidden="true" /> Reports</TabsTrigger>
            <TabsTrigger value="security"><Bug className="mr-1.5 h-4 w-4" aria-hidden="true" /> Security</TabsTrigger>
            <TabsTrigger value="accounts"><UserX className="mr-1.5 h-4 w-4" aria-hidden="true" /> Accounts</TabsTrigger>
            <TabsTrigger value="content"><FileText className="mr-1.5 h-4 w-4" aria-hidden="true" /> Content</TabsTrigger>
          </TabsList>
          <TabsContent value="reports" className="pt-4"><Reports /></TabsContent>
          <TabsContent value="security" className="pt-4"><SecurityReports /></TabsContent>
          <TabsContent value="accounts" className="pt-4"><RemovedAccounts /></TabsContent>
          <TabsContent value="content" className="pt-4"><Content /></TabsContent>
        </Tabs>
      </main>
    </div>
  );
}
