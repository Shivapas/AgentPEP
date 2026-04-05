/**
 * Sprint 14 — Policy Console — Policy Authoring.
 *
 * Main page that composes all Sprint 14 components:
 * - Role tree editor (APEP-113)
 * - Rule builder form (APEP-114)
 * - Rule priority list (APEP-115)
 * - YAML import/export (APEP-116)
 * - Version history + diff (APEP-117)
 * - Peer review workflow (APEP-118)
 * - Conflict detector (APEP-119)
 */

import { useState, useEffect, useCallback } from "react";
import type {
  AgentRole,
  PolicyRule,
  PolicyVersion,
  ReviewStatus,
} from "@/types/policy";
import * as api from "@/api/policyApi";
import { RoleTreeEditor } from "./RoleTreeEditor";
import { RuleBuilderForm } from "./RuleBuilderForm";
import { RulePriorityList } from "./RulePriorityList";
import { YamlImportExport } from "./YamlImportExport";
import { PolicyVersionHistory } from "./PolicyVersionHistory";
import { PeerReviewWorkflow } from "./PeerReviewWorkflow";
import { PolicyConflictDetector } from "./PolicyConflictDetector";

type Tab =
  | "roles"
  | "rules"
  | "priority"
  | "yaml"
  | "versions"
  | "review"
  | "conflicts";

const TABS: { key: Tab; label: string }[] = [
  { key: "roles", label: "Roles" },
  { key: "rules", label: "Rules" },
  { key: "priority", label: "Priority" },
  { key: "yaml", label: "YAML" },
  { key: "versions", label: "Versions" },
  { key: "review", label: "Review" },
  { key: "conflicts", label: "Conflicts" },
];

export function PolicyAuthoringPage() {
  const [tab, setTab] = useState<Tab>("roles");
  const [roles, setRoles] = useState<AgentRole[]>([]);
  const [rules, setRules] = useState<PolicyRule[]>([]);
  const [versions, setVersions] = useState<PolicyVersion[]>([]);
  const [editingRule, setEditingRule] = useState<Partial<PolicyRule> | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);

  // --- data fetching ---

  const loadData = useCallback(async () => {
    try {
      const [fetchedRoles, fetchedRules, policySets] = await Promise.all([
        api.fetchRoles().catch(() => [] as AgentRole[]),
        api.fetchRules().catch(() => [] as PolicyRule[]),
        api.fetchPolicySets().catch(() => []),
      ]);
      setRoles(fetchedRoles);
      setRules(fetchedRules);
      if (policySets.length > 0) {
        setVersions(policySets[0]!.versions);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load data");
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  // --- role handlers ---

  const handleCreateRole = useCallback(
    async (role: Partial<AgentRole>) => {
      try {
        await api.createRole(role);
        await loadData();
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to create role");
      }
    },
    [loadData],
  );

  const handleUpdateRole = useCallback(
    async (roleId: string, patch: Partial<AgentRole>) => {
      try {
        await api.updateRole(roleId, patch);
        await loadData();
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to update role");
      }
    },
    [loadData],
  );

  const handleDeleteRole = useCallback(
    async (roleId: string) => {
      try {
        await api.deleteRole(roleId);
        await loadData();
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to delete role");
      }
    },
    [loadData],
  );

  // --- rule handlers ---

  const handleSaveRule = useCallback(
    async (rule: Partial<PolicyRule>) => {
      try {
        if (editingRule?.rule_id) {
          await api.updateRule(editingRule.rule_id, rule);
        } else {
          await api.createRule(rule);
        }
        setEditingRule(null);
        await loadData();
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to save rule");
      }
    },
    [editingRule, loadData],
  );

  const handleDeleteRule = useCallback(
    async (ruleId: string) => {
      try {
        await api.deleteRule(ruleId);
        await loadData();
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to delete rule");
      }
    },
    [loadData],
  );

  const handleReorderRules = useCallback(
    async (ruleIds: string[]) => {
      try {
        await api.reorderRules(ruleIds);
        await loadData();
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to reorder rules",
        );
      }
    },
    [loadData],
  );

  // --- version handlers ---

  const handleRestore = useCallback(
    async (versionId: string) => {
      try {
        await api.restoreVersion("default", versionId);
        await loadData();
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to restore version",
        );
      }
    },
    [loadData],
  );

  const handleTransition = useCallback(
    async (versionId: string, newStatus: ReviewStatus) => {
      try {
        await api.updateVersionStatus("default", versionId, newStatus);
        await loadData();
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to update status",
        );
      }
    },
    [loadData],
  );

  // --- import handler ---

  const handleImport = useCallback(
    (data: { rules: PolicyRule[]; roles: AgentRole[] }) => {
      setRoles(data.roles);
      setRules(data.rules);
    },
    [],
  );

  // --- current version for review ---

  const latestVersion: PolicyVersion | null =
    versions.length > 0
      ? [...versions].sort((a, b) => b.version - a.version)[0]!
      : null;

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">Policy Authoring</h2>

      {error && (
        <div className="rounded border border-destructive bg-destructive/10 px-4 py-2 text-sm text-destructive flex justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-xs underline">
            Dismiss
          </button>
        </div>
      )}

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-border">
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === t.key
                ? "border-primary text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div>
        {tab === "roles" && (
          <RoleTreeEditor
            roles={roles}
            onCreateRole={handleCreateRole}
            onUpdateRole={handleUpdateRole}
            onDeleteRole={handleDeleteRole}
          />
        )}

        {tab === "rules" && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">Policy Rules</h2>
              <button
                onClick={() => setEditingRule({})}
                className="rounded bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:opacity-90"
              >
                + New Rule
              </button>
            </div>
            {editingRule !== null ? (
              <div className="rounded-lg border border-border bg-card p-4">
                <RuleBuilderForm
                  initial={editingRule}
                  availableRoles={roles.map((r) => r.role_id)}
                  onSave={handleSaveRule}
                  onCancel={() => setEditingRule(null)}
                />
              </div>
            ) : (
              <RulePriorityList
                rules={rules}
                onReorder={handleReorderRules}
                onEdit={(r) => setEditingRule(r)}
                onDelete={handleDeleteRule}
              />
            )}
          </div>
        )}

        {tab === "priority" && (
          <RulePriorityList
            rules={rules}
            onReorder={handleReorderRules}
            onEdit={(r) => {
              setEditingRule(r);
              setTab("rules");
            }}
            onDelete={handleDeleteRule}
          />
        )}

        {tab === "yaml" && (
          <YamlImportExport
            rules={rules}
            roles={roles}
            policySetName="default"
            onImport={handleImport}
          />
        )}

        {tab === "versions" && (
          <PolicyVersionHistory
            versions={versions}
            onRestore={handleRestore}
          />
        )}

        {tab === "review" && latestVersion && (
          <PeerReviewWorkflow
            version={latestVersion}
            onTransition={handleTransition}
          />
        )}
        {tab === "review" && !latestVersion && (
          <p className="text-sm text-muted-foreground">
            No versions available for review.
          </p>
        )}

        {tab === "conflicts" && <PolicyConflictDetector rules={rules} />}
      </div>
    </div>
  );
}
