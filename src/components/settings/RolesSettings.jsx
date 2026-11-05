import React, { useEffect, useMemo, useState } from "react";
import { ArrowDown, ArrowUp, Plus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { ErrorNote } from "@/components/site/bits";
import { useServers } from "@/lib/secure/ServerContext";
import { PERMISSION_INFO, P, has } from "@/lib/secure/permissions";
import { ColorPicker } from "@/components/servers/CreateServerDialog";
import ConfirmDialog from "@/components/app/ConfirmDialog";
import { SettingsTitle } from "./SettingsLayout";

function RoleEditor({ serverId, role, myPerms, canEdit, onDeleted }) {
  const { roleName, roleColor, updateRole, act } = useServers();
  const [name, setName] = useState(roleName(role));
  const [color, setColor] = useState(roleColor(role));
  const [perms, setPerms] = useState(role.permissions);
  const [hoist, setHoist] = useState(role.hoist);
  const [mentionable, setMentionable] = useState(role.mentionable);
  const [state, setState] = useState({ busy: false, msg: "", error: "" });
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    setName(roleName(role));
    setColor(roleColor(role));
    setPerms(role.permissions);
    setHoist(role.hoist);
    setMentionable(role.mentionable);
    setState({ busy: false, msg: "", error: "" });
    // Reset when another role is chosen, not whenever names decrypt.
     
  }, [role.id]);

  const dirty = perms !== role.permissions || hoist !== role.hoist || mentionable !== role.mentionable || (!role.is_everyone && (name !== roleName(role) || color !== roleColor(role)));
  const save = async () => {
    setState({ busy: true, msg: "", error: "" });
    try {
      const changes = {};
      if (perms !== role.permissions) changes.permissions = perms;
      if (hoist !== role.hoist) changes.hoist = hoist;
      if (mentionable !== role.mentionable) changes.mentionable = mentionable;
      if (!role.is_everyone && (name !== roleName(role) || color !== roleColor(role))) Object.assign(changes, { name: name.trim() || "Role", color });
      await updateRole(serverId, role, changes);
      setState({ busy: false, msg: "Saved.", error: "" });
    } catch (err) {
      setState({ busy: false, msg: "", error: err.message });
    }
  };

  const groups = useMemo(() => {
    const out = [];
    for (const info of PERMISSION_INFO) {
      let g = out.find((x) => x.group === info.group);
      if (!g) out.push((g = { group: info.group, items: [] }));
      g.items.push(info);
    }
    return out;
  }, []);

  return (
    <div className="space-y-6">
      {!role.is_everyone && (
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="role-name">Role name</Label>
            <Input id="role-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={60} disabled={!canEdit} />
            <p className="text-xs text-muted-foreground">Encrypted: only members can read it.</p>
          </div>
          <div className="space-y-1.5">
            <Label>Colour</Label>
            <ColorPicker value={color} onChange={(c) => canEdit && setColor(c)} />
          </div>
        </div>
      )}
      {!role.is_everyone && (
        <div className="space-y-3">
          <label className="flex items-center justify-between gap-4">
            <span className="text-sm">
              <span className="block font-medium">Show separately in the member list</span>
              <span className="block text-xs text-muted-foreground">People with this role are always listed, under its name.</span>
            </span>
            <Switch checked={hoist} onCheckedChange={setHoist} disabled={!canEdit} />
          </label>
          <label className="flex items-center justify-between gap-4">
            <span className="text-sm">
              <span className="block font-medium">Anyone can @mention it</span>
              <span className="block text-xs text-muted-foreground">Works when the role's name is one word.</span>
            </span>
            <Switch checked={mentionable} onCheckedChange={setMentionable} disabled={!canEdit} />
          </label>
        </div>
      )}
      <div>
        <h3 className="font-heading text-lg font-semibold">Permissions</h3>
        {role.is_everyone && <p className="mt-1 text-sm text-muted-foreground">What everyone in the server can do, unless a channel says otherwise.</p>}
        {groups.map((g) => (
          <fieldset key={g.group} className="mt-4" disabled={!canEdit}>
            <legend className="text-xs font-semibold text-muted-foreground">{g.group}</legend>
            <ul className="mt-1 divide-y divide-border">
              {g.items.map((info) => {
                const on = has(perms, info.bit);
                const allowed = has(myPerms, info.bit);
                return (
                  <li key={info.bit} className="flex items-center justify-between gap-4 py-2.5">
                    <span className="text-sm">
                      <span className="block font-medium">{info.label}</span>
                      <span className="block text-xs text-muted-foreground">{info.help}{!allowed && !on ? " (You can't give a permission you don't have.)" : ""}</span>
                    </span>
                    <Switch checked={on} disabled={!canEdit || (!allowed && !on)} onCheckedChange={(v) => setPerms((p) => (v ? p | info.bit : p & ~info.bit))} aria-label={info.label} />
                  </li>
                );
              })}
            </ul>
          </fieldset>
        ))}
      </div>
      <ErrorNote>{state.error}</ErrorNote>
      {canEdit && (
        <div className="sticky bottom-0 flex flex-wrap items-center gap-3 border-t border-border bg-chat py-3">
          <Button onClick={save} disabled={!dirty || state.busy}>{state.busy ? "Saving…" : "Save changes"}</Button>
          {state.msg && !dirty && <span className="text-sm text-primary">{state.msg}</span>}
          {!role.is_everyone && (
            <Button variant="ghost" className="ml-auto text-destructive" onClick={() => setDeleting(true)}>
              <Trash2 className="mr-1.5 h-4 w-4" aria-hidden="true" /> Delete role
            </Button>
          )}
        </div>
      )}
      <ConfirmDialog
        open={deleting}
        onOpenChange={setDeleting}
        title={`Delete the ${roleName(role)} role?`}
        confirmLabel="Delete role"
        onConfirm={async () => {
          await act(serverId, "delete_role", { role_id: role.id });
          onDeleted();
        }}
      >
        <p>Everyone who has it loses it, along with anything it let them see. Private channels it opened get new keys.</p>
      </ConfirmDialog>
    </div>
  );
}

export default function RolesSettings({ serverId }) {
  const { servers, roleName, roleColor, createRole, permsFor, myTop, act } = useServers();
  const e = servers[serverId];
  const [selected, setSelected] = useState(null);
  const [state, setState] = useState({ busy: false, error: "" });
  if (!e?.roles) return null;
  const roles = [...e.roles].sort((a, b) => b.position - a.position);
  const everyone = roles.find((r) => r.is_everyone);
  const others = roles.filter((r) => !r.is_everyone);
  const top = myTop(serverId);
  const myPerms = permsFor(serverId);
  const current = roles.find((r) => r.id === selected) || null;
  const canEditRole = (r) => has(myPerms, P.MANAGE_ROLES) && (r.is_everyone || r.position < top);

  const add = async () => {
    setState({ busy: true, error: "" });
    try {
      const res = await createRole(serverId, { name: "New role", color: "", permissions: 0 });
      setSelected(res.role.id);
      setState({ busy: false, error: "" });
    } catch (err) {
      setState({ busy: false, error: err.message });
    }
  };

  const move = async (role, dir) => {
    const i = others.findIndex((r) => r.id === role.id);
    const other = others[i + (dir === "up" ? -1 : 1)];
    if (!other || other.position >= top || role.position >= top) return;
    setState({ busy: true, error: "" });
    try {
      await act(serverId, "reorder_roles", { order: [{ id: role.id, position: other.position }, { id: other.id, position: role.position }] });
      setState({ busy: false, error: "" });
    } catch (err) {
      setState({ busy: false, error: err.message });
    }
  };

  return (
    <>
      <SettingsTitle intro="Roles group permissions. People can only manage roles below their own highest one. Role names are encrypted.">Roles</SettingsTitle>
      <div className="grid gap-6 lg:grid-cols-[14rem_1fr]">
        <div>
          <Button size="sm" onClick={add} disabled={state.busy} className="mb-3 w-full"><Plus className="mr-1 h-4 w-4" aria-hidden="true" /> Create role</Button>
          <ul className="space-y-0.5">
            {others.map((r, i) => (
              <li key={r.id} className="group flex items-center">
                <button type="button" onClick={() => setSelected(r.id)} aria-current={selected === r.id ? "page" : undefined} className="panel-item flex-1">
                  <span className="h-3 w-3 shrink-0 rounded-full" style={{ backgroundColor: roleColor(r) || "hsl(var(--muted-foreground))" }} aria-hidden="true" />
                  <span className="truncate">{roleName(r)}</span>
                </button>
                {canEditRole(r) && (
                  <span className="flex opacity-0 group-hover:opacity-100 focus-within:opacity-100">
                    <button type="button" disabled={i === 0 || others[i - 1].position >= top} onClick={() => move(r, "up")} className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-30" aria-label={`Move ${roleName(r)} up`}><ArrowUp className="h-3.5 w-3.5" aria-hidden="true" /></button>
                    <button type="button" disabled={i === others.length - 1} onClick={() => move(r, "down")} className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-30" aria-label={`Move ${roleName(r)} down`}><ArrowDown className="h-3.5 w-3.5" aria-hidden="true" /></button>
                  </span>
                )}
              </li>
            ))}
            {everyone && (
              <li>
                <button type="button" onClick={() => setSelected(everyone.id)} aria-current={selected === everyone.id ? "page" : undefined} className="panel-item">
                  <span className="h-3 w-3 shrink-0 rounded-full bg-muted-foreground/40" aria-hidden="true" /> @everyone
                </button>
              </li>
            )}
          </ul>
          <ErrorNote>{state.error}</ErrorNote>
        </div>
        <div>
          {current ? (
            <RoleEditor key={current.id} serverId={serverId} role={current} myPerms={myPerms} canEdit={canEditRole(current)} onDeleted={() => setSelected(null)} />
          ) : (
            <p className="text-sm text-muted-foreground">Choose a role to edit it, or create one.</p>
          )}
        </div>
      </div>
    </>
  );
}
