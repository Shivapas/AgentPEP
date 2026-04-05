/**
 * APEP-116: YAML import/export for policy sets.
 *
 * Provides an Export button that downloads the current policy set as YAML
 * and an Import dropzone / file picker that reads a YAML file and calls
 * the import API.
 */

import { useState, useCallback, useRef } from "react";
import yaml from "js-yaml";
import type { PolicyRule, AgentRole } from "@/types/policy";

interface YamlImportExportProps {
  rules: PolicyRule[];
  roles: AgentRole[];
  policySetName: string;
  onImport: (data: { rules: PolicyRule[]; roles: AgentRole[] }) => void;
}

export function YamlImportExport({
  rules,
  roles,
  policySetName,
  onImport,
}: YamlImportExportProps) {
  const [importError, setImportError] = useState<string | null>(null);
  const [importPreview, setImportPreview] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  // --- Export ---
  const handleExport = useCallback(() => {
    const doc = {
      policy_set: policySetName,
      exported_at: new Date().toISOString(),
      roles: roles.map(({ role_id, name, parent_roles, allowed_tools, denied_tools, max_risk_threshold, enabled }) => ({
        role_id,
        name,
        parent_roles,
        allowed_tools,
        denied_tools,
        max_risk_threshold,
        enabled,
      })),
      rules: rules.map(({ rule_id, name, agent_role, tool_pattern, action, taint_check, risk_threshold, rate_limit, arg_validators, priority, enabled }) => ({
        rule_id,
        name,
        agent_role,
        tool_pattern,
        action,
        taint_check,
        risk_threshold,
        rate_limit,
        arg_validators,
        priority,
        enabled,
      })),
    };
    const yamlStr = yaml.dump(doc, { sortKeys: false, lineWidth: 120 });
    const blob = new Blob([yamlStr], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${policySetName.replace(/\s+/g, "_")}_policy.yaml`;
    a.click();
    URL.revokeObjectURL(url);
  }, [rules, roles, policySetName]);

  // --- Import ---
  const parseYaml = useCallback(
    (text: string) => {
      try {
        const parsed = yaml.load(text) as Record<string, unknown>;
        if (!parsed || typeof parsed !== "object") {
          setImportError("Invalid YAML: expected a mapping at the top level.");
          return;
        }
        const importedRules = (parsed.rules ?? []) as PolicyRule[];
        const importedRoles = (parsed.roles ?? []) as AgentRole[];
        setImportError(null);
        setImportPreview(
          `Found ${importedRoles.length} roles, ${importedRules.length} rules`,
        );
        onImport({ rules: importedRules, roles: importedRoles });
      } catch (err) {
        setImportError(
          `YAML parse error: ${err instanceof Error ? err.message : String(err)}`,
        );
        setImportPreview(null);
      }
    },
    [onImport],
  );

  const handleFile = useCallback(
    (file: File) => {
      const reader = new FileReader();
      reader.onload = () => parseYaml(reader.result as string);
      reader.readAsText(file);
    },
    [parseYaml],
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">YAML Import / Export</h2>
      </div>

      <div className="flex gap-4">
        {/* Export */}
        <button
          onClick={handleExport}
          className="rounded bg-primary px-4 py-1.5 text-sm text-primary-foreground hover:opacity-90"
        >
          Export YAML
        </button>

        {/* Import */}
        <button
          onClick={() => fileRef.current?.click()}
          className="rounded border border-border px-4 py-1.5 text-sm hover:bg-secondary"
        >
          Import YAML
        </button>
        <input
          ref={fileRef}
          type="file"
          accept=".yaml,.yml"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleFile(file);
          }}
        />
      </div>

      {/* Drop zone */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          e.stopPropagation();
        }}
        onDrop={(e) => {
          e.preventDefault();
          e.stopPropagation();
          const file = e.dataTransfer.files[0];
          if (file) handleFile(file);
        }}
        className="rounded-lg border-2 border-dashed border-border p-6 text-center text-sm text-muted-foreground"
      >
        Drop a YAML file here to import
      </div>

      {importError && (
        <p className="text-sm text-destructive">{importError}</p>
      )}
      {importPreview && (
        <p className="text-sm text-green-600">{importPreview}</p>
      )}
    </div>
  );
}
