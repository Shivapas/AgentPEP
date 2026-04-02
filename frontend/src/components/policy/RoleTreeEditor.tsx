/**
 * APEP-113: Role hierarchy tree editor with visual drag-and-drop role
 * inheritance management.
 *
 * Renders the role DAG as a nested tree. Each node can be dragged onto another
 * node to re-parent it. Roles can be created, renamed, and deleted inline.
 */

import { useState, useCallback, type DragEvent } from "react";
import type { AgentRole } from "@/types/policy";
import { cn } from "@/lib/utils";

// ---------- helpers ----------

function buildTree(roles: AgentRole[]): Map<string, string[]> {
  const children = new Map<string, string[]>();
  for (const r of roles) {
    if (!children.has(r.role_id)) children.set(r.role_id, []);
    for (const pid of r.parent_roles) {
      const list = children.get(pid) ?? [];
      list.push(r.role_id);
      children.set(pid, list);
    }
  }
  return children;
}

function rootRoles(roles: AgentRole[]): AgentRole[] {
  return roles.filter((r) => r.parent_roles.length === 0);
}

// ---------- sub-components ----------

interface TreeNodeProps {
  role: AgentRole;
  rolesMap: Map<string, AgentRole>;
  childrenMap: Map<string, string[]>;
  depth: number;
  dragOverId: string | null;
  onDragStartNode: (id: string) => (e: DragEvent) => void;
  onDragOverNode: (id: string) => (e: DragEvent) => void;
  onDropNode: (targetId: string) => (e: DragEvent) => void;
  onEdit: (role: AgentRole) => void;
  onDelete: (roleId: string) => void;
}

function TreeNode({
  role,
  rolesMap,
  childrenMap,
  depth,
  dragOverId,
  onDragStartNode,
  onDragOverNode,
  onDropNode,
  onEdit,
  onDelete,
}: TreeNodeProps) {
  const kids = childrenMap.get(role.role_id) ?? [];

  return (
    <div className="select-none" style={{ marginLeft: depth * 20 }}>
      <div
        draggable
        onDragStart={onDragStartNode(role.role_id)}
        onDragOver={onDragOverNode(role.role_id)}
        onDrop={onDropNode(role.role_id)}
        className={cn(
          "group flex items-center gap-2 rounded px-3 py-1.5 text-sm cursor-grab",
          "hover:bg-secondary",
          dragOverId === role.role_id && "ring-2 ring-primary bg-accent",
        )}
      >
        <span className="font-mono text-xs text-muted-foreground">
          {kids.length > 0 ? "▾" : "•"}
        </span>
        <span className="font-medium">{role.name}</span>
        <span className="text-xs text-muted-foreground">({role.role_id})</span>
        <span className="ml-auto flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
          <button
            onClick={() => onEdit(role)}
            className="rounded px-1.5 py-0.5 text-xs hover:bg-accent"
          >
            Edit
          </button>
          <button
            onClick={() => onDelete(role.role_id)}
            className="rounded px-1.5 py-0.5 text-xs text-destructive hover:bg-destructive/10"
          >
            Delete
          </button>
        </span>
      </div>

      {kids.map((kidId) => {
        const kidRole = rolesMap.get(kidId);
        if (!kidRole) return null;
        return (
          <TreeNode
            key={kidId}
            role={kidRole}
            rolesMap={rolesMap}
            childrenMap={childrenMap}
            depth={depth + 1}
            dragOverId={dragOverId}
            onDragStartNode={onDragStartNode}
            onDragOverNode={onDragOverNode}
            onDropNode={onDropNode}
            onEdit={onEdit}
            onDelete={onDelete}
          />
        );
      })}
    </div>
  );
}

// ---------- Role Edit Modal ----------

interface RoleFormProps {
  role: Partial<AgentRole>;
  allRoles: AgentRole[];
  onSave: (role: Partial<AgentRole>) => void;
  onCancel: () => void;
}

function RoleForm({ role, allRoles, onSave, onCancel }: RoleFormProps) {
  const [form, setForm] = useState<Partial<AgentRole>>({
    role_id: "",
    name: "",
    parent_roles: [],
    allowed_tools: [],
    denied_tools: [],
    max_risk_threshold: 1.0,
    enabled: true,
    ...role,
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave(form);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-lg rounded-lg border border-border bg-card p-6 shadow-lg space-y-4"
      >
        <h3 className="text-lg font-semibold">
          {role.role_id ? "Edit Role" : "New Role"}
        </h3>

        <label className="block text-sm">
          Role ID
          <input
            required
            disabled={!!role.role_id}
            value={form.role_id ?? ""}
            onChange={(e) => setForm({ ...form, role_id: e.target.value })}
            className="mt-1 block w-full rounded border border-border bg-background px-3 py-1.5 text-sm"
          />
        </label>

        <label className="block text-sm">
          Name
          <input
            required
            value={form.name ?? ""}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            className="mt-1 block w-full rounded border border-border bg-background px-3 py-1.5 text-sm"
          />
        </label>

        <label className="block text-sm">
          Parent Roles
          <select
            multiple
            value={form.parent_roles ?? []}
            onChange={(e) =>
              setForm({
                ...form,
                parent_roles: Array.from(
                  e.target.selectedOptions,
                  (o) => o.value,
                ),
              })
            }
            className="mt-1 block w-full rounded border border-border bg-background px-3 py-1.5 text-sm h-24"
          >
            {allRoles
              .filter((r) => r.role_id !== form.role_id)
              .map((r) => (
                <option key={r.role_id} value={r.role_id}>
                  {r.name} ({r.role_id})
                </option>
              ))}
          </select>
        </label>

        <label className="block text-sm">
          Allowed Tools (comma-separated globs)
          <input
            value={(form.allowed_tools ?? []).join(", ")}
            onChange={(e) =>
              setForm({
                ...form,
                allowed_tools: e.target.value
                  .split(",")
                  .map((s) => s.trim())
                  .filter(Boolean),
              })
            }
            className="mt-1 block w-full rounded border border-border bg-background px-3 py-1.5 text-sm"
          />
        </label>

        <label className="block text-sm">
          Denied Tools (comma-separated globs)
          <input
            value={(form.denied_tools ?? []).join(", ")}
            onChange={(e) =>
              setForm({
                ...form,
                denied_tools: e.target.value
                  .split(",")
                  .map((s) => s.trim())
                  .filter(Boolean),
              })
            }
            className="mt-1 block w-full rounded border border-border bg-background px-3 py-1.5 text-sm"
          />
        </label>

        <label className="block text-sm">
          Max Risk Threshold
          <input
            type="number"
            min={0}
            max={1}
            step={0.05}
            value={form.max_risk_threshold ?? 1}
            onChange={(e) =>
              setForm({ ...form, max_risk_threshold: +e.target.value })
            }
            className="mt-1 block w-full rounded border border-border bg-background px-3 py-1.5 text-sm"
          />
        </label>

        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onCancel}
            className="rounded border border-border px-4 py-1.5 text-sm hover:bg-secondary"
          >
            Cancel
          </button>
          <button
            type="submit"
            className="rounded bg-primary px-4 py-1.5 text-sm text-primary-foreground hover:opacity-90"
          >
            Save
          </button>
        </div>
      </form>
    </div>
  );
}

// ---------- main component ----------

interface RoleTreeEditorProps {
  roles: AgentRole[];
  onCreateRole: (role: Partial<AgentRole>) => void;
  onUpdateRole: (roleId: string, patch: Partial<AgentRole>) => void;
  onDeleteRole: (roleId: string) => void;
}

export function RoleTreeEditor({
  roles,
  onCreateRole,
  onUpdateRole,
  onDeleteRole,
}: RoleTreeEditorProps) {
  const [editingRole, setEditingRole] = useState<Partial<AgentRole> | null>(
    null,
  );
  const [dragSourceId, setDragSourceId] = useState<string | null>(null);
  const [dragOverId, setDragOverId] = useState<string | null>(null);

  const rolesMap = new Map(roles.map((r) => [r.role_id, r]));
  const childrenMap = buildTree(roles);
  const roots = rootRoles(roles);

  const onDragStartNode = useCallback(
    (id: string) => (e: DragEvent) => {
      setDragSourceId(id);
      e.dataTransfer.effectAllowed = "move";
    },
    [],
  );

  const onDragOverNode = useCallback(
    (id: string) => (e: DragEvent) => {
      e.preventDefault();
      setDragOverId(id);
    },
    [],
  );

  const onDropNode = useCallback(
    (targetId: string) => (e: DragEvent) => {
      e.preventDefault();
      if (dragSourceId && dragSourceId !== targetId) {
        onUpdateRole(dragSourceId, { parent_roles: [targetId] });
      }
      setDragSourceId(null);
      setDragOverId(null);
    },
    [dragSourceId, onUpdateRole],
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Role Hierarchy</h2>
        <button
          onClick={() => setEditingRole({})}
          className="rounded bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:opacity-90"
        >
          + New Role
        </button>
      </div>

      <p className="text-xs text-muted-foreground">
        Drag a role onto another to re-parent it. Hover to edit or delete.
      </p>

      <div
        className="rounded-lg border border-border bg-card p-4"
        onDragOver={(e) => {
          e.preventDefault();
          setDragOverId(null);
        }}
        onDrop={(e) => {
          e.preventDefault();
          if (dragSourceId) {
            onUpdateRole(dragSourceId, { parent_roles: [] });
          }
          setDragSourceId(null);
          setDragOverId(null);
        }}
      >
        {roots.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No roles defined. Create one to get started.
          </p>
        )}
        {roots.map((role) => (
          <TreeNode
            key={role.role_id}
            role={role}
            rolesMap={rolesMap}
            childrenMap={childrenMap}
            depth={0}
            dragOverId={dragOverId}
            onDragStartNode={onDragStartNode}
            onDragOverNode={onDragOverNode}
            onDropNode={onDropNode}
            onEdit={(r) => setEditingRole(r)}
            onDelete={onDeleteRole}
          />
        ))}
      </div>

      {editingRole !== null && (
        <RoleForm
          role={editingRole}
          allRoles={roles}
          onSave={(r) => {
            if (editingRole.role_id) {
              onUpdateRole(editingRole.role_id, r);
            } else {
              onCreateRole(r);
            }
            setEditingRole(null);
          }}
          onCancel={() => setEditingRole(null)}
        />
      )}
    </div>
  );
}
