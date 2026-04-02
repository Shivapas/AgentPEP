/**
 * APEP-114: Rule builder form — tool pattern, action, taint check, risk
 * threshold, and argument validators.
 */

import { useState, type FormEvent } from "react";
import type {
  PolicyRule,
  Decision,
  ArgValidator,
  RateLimit,
  FieldError,
} from "@/types/policy";
import { validateRule } from "@/lib/ruleValidation";

const DECISIONS: Decision[] = ["ALLOW", "DENY", "ESCALATE", "DRY_RUN"];

interface RuleBuilderFormProps {
  initial?: Partial<PolicyRule>;
  availableRoles: string[];
  onSave: (rule: Partial<PolicyRule>) => void;
  onCancel: () => void;
}

export function RuleBuilderForm({
  initial,
  availableRoles,
  onSave,
  onCancel,
}: RuleBuilderFormProps) {
  const [form, setForm] = useState<Partial<PolicyRule>>({
    name: "",
    agent_role: [],
    tool_pattern: "",
    action: "DENY",
    taint_check: false,
    risk_threshold: 1.0,
    rate_limit: null,
    arg_validators: [],
    priority: 100,
    enabled: true,
    ...initial,
  });

  const [errors, setErrors] = useState<FieldError[]>([]);
  const [showValidators, setShowValidators] = useState(
    (form.arg_validators ?? []).length > 0,
  );
  const [showRateLimit, setShowRateLimit] = useState(form.rate_limit !== null);

  const fieldError = (field: string) =>
    errors.find((e) => e.field === field)?.message;

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    const validation = validateRule(form);
    if (validation.length > 0) {
      setErrors(validation);
      return;
    }
    setErrors([]);
    onSave(form);
  };

  const updateValidator = (idx: number, patch: Partial<ArgValidator>) => {
    const validators = [...(form.arg_validators ?? [])];
    validators[idx] = { ...validators[idx]!, ...patch };
    setForm({ ...form, arg_validators: validators });
  };

  const addValidator = () => {
    setForm({
      ...form,
      arg_validators: [
        ...(form.arg_validators ?? []),
        { arg_name: "", regex_pattern: null, allowlist: null, blocklist: null },
      ],
    });
    setShowValidators(true);
  };

  const removeValidator = (idx: number) => {
    const validators = [...(form.arg_validators ?? [])];
    validators.splice(idx, 1);
    setForm({ ...form, arg_validators: validators });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <h3 className="text-lg font-semibold">
        {initial?.rule_id ? "Edit Rule" : "New Rule"}
      </h3>

      {/* Name */}
      <label className="block text-sm">
        Rule Name
        <input
          required
          value={form.name ?? ""}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          className="mt-1 block w-full rounded border border-border bg-background px-3 py-1.5 text-sm"
        />
        {fieldError("name") && (
          <span className="text-xs text-destructive">{fieldError("name")}</span>
        )}
      </label>

      {/* Agent Roles */}
      <label className="block text-sm">
        Agent Roles
        <select
          multiple
          value={form.agent_role ?? []}
          onChange={(e) =>
            setForm({
              ...form,
              agent_role: Array.from(e.target.selectedOptions, (o) => o.value),
            })
          }
          className="mt-1 block w-full rounded border border-border bg-background px-3 py-1.5 text-sm h-20"
        >
          {availableRoles.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        {fieldError("agent_role") && (
          <span className="text-xs text-destructive">
            {fieldError("agent_role")}
          </span>
        )}
      </label>

      {/* Tool Pattern */}
      <label className="block text-sm">
        Tool Pattern (glob or regex)
        <input
          required
          value={form.tool_pattern ?? ""}
          onChange={(e) => setForm({ ...form, tool_pattern: e.target.value })}
          placeholder="e.g. file_* or .*_write"
          className="mt-1 block w-full rounded border border-border bg-background px-3 py-1.5 text-sm font-mono"
        />
        {fieldError("tool_pattern") && (
          <span className="text-xs text-destructive">
            {fieldError("tool_pattern")}
          </span>
        )}
      </label>

      {/* Action */}
      <label className="block text-sm">
        Action
        <select
          value={form.action ?? "DENY"}
          onChange={(e) =>
            setForm({ ...form, action: e.target.value as Decision })
          }
          className="mt-1 block w-full rounded border border-border bg-background px-3 py-1.5 text-sm"
        >
          {DECISIONS.map((d) => (
            <option key={d} value={d}>
              {d}
            </option>
          ))}
        </select>
      </label>

      {/* Taint Check & Risk Threshold row */}
      <div className="flex gap-4">
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={form.taint_check ?? false}
            onChange={(e) => setForm({ ...form, taint_check: e.target.checked })}
          />
          Require Taint Check
        </label>
        <label className="block text-sm flex-1">
          Risk Threshold
          <input
            type="number"
            min={0}
            max={1}
            step={0.05}
            value={form.risk_threshold ?? 1}
            onChange={(e) =>
              setForm({ ...form, risk_threshold: +e.target.value })
            }
            className="mt-1 block w-full rounded border border-border bg-background px-3 py-1.5 text-sm"
          />
          {fieldError("risk_threshold") && (
            <span className="text-xs text-destructive">
              {fieldError("risk_threshold")}
            </span>
          )}
        </label>
      </div>

      {/* Priority */}
      <label className="block text-sm">
        Priority (lower = higher priority)
        <input
          type="number"
          min={0}
          value={form.priority ?? 100}
          onChange={(e) => setForm({ ...form, priority: +e.target.value })}
          className="mt-1 block w-full rounded border border-border bg-background px-3 py-1.5 text-sm"
        />
        {fieldError("priority") && (
          <span className="text-xs text-destructive">
            {fieldError("priority")}
          </span>
        )}
      </label>

      {/* Rate Limit */}
      <div className="space-y-2">
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={showRateLimit}
            onChange={(e) => {
              setShowRateLimit(e.target.checked);
              if (!e.target.checked) setForm({ ...form, rate_limit: null });
            }}
          />
          Rate Limit
        </label>
        {showRateLimit && (
          <div className="flex gap-4 pl-6">
            <label className="block text-sm flex-1">
              Count
              <input
                type="number"
                min={1}
                value={form.rate_limit?.count ?? 10}
                onChange={(e) =>
                  setForm({
                    ...form,
                    rate_limit: {
                      count: +e.target.value,
                      window_s: form.rate_limit?.window_s ?? 60,
                    } as RateLimit,
                  })
                }
                className="mt-1 block w-full rounded border border-border bg-background px-3 py-1.5 text-sm"
              />
            </label>
            <label className="block text-sm flex-1">
              Window (seconds)
              <input
                type="number"
                min={1}
                value={form.rate_limit?.window_s ?? 60}
                onChange={(e) =>
                  setForm({
                    ...form,
                    rate_limit: {
                      count: form.rate_limit?.count ?? 10,
                      window_s: +e.target.value,
                    } as RateLimit,
                  })
                }
                className="mt-1 block w-full rounded border border-border bg-background px-3 py-1.5 text-sm"
              />
            </label>
          </div>
        )}
      </div>

      {/* Arg Validators */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={showValidators}
              onChange={(e) => setShowValidators(e.target.checked)}
            />
            Argument Validators
          </label>
          {showValidators && (
            <button
              type="button"
              onClick={addValidator}
              className="text-xs text-primary hover:underline"
            >
              + Add Validator
            </button>
          )}
        </div>
        {showValidators &&
          (form.arg_validators ?? []).map((v, idx) => (
            <div
              key={idx}
              className="flex gap-2 items-end pl-6 rounded border border-border p-2"
            >
              <label className="block text-xs flex-1">
                Arg Name
                <input
                  value={v.arg_name}
                  onChange={(e) =>
                    updateValidator(idx, { arg_name: e.target.value })
                  }
                  className="mt-1 block w-full rounded border border-border bg-background px-2 py-1 text-xs"
                />
              </label>
              <label className="block text-xs flex-1">
                Regex
                <input
                  value={v.regex_pattern ?? ""}
                  onChange={(e) =>
                    updateValidator(idx, {
                      regex_pattern: e.target.value || null,
                    })
                  }
                  className="mt-1 block w-full rounded border border-border bg-background px-2 py-1 text-xs font-mono"
                />
              </label>
              <label className="block text-xs flex-1">
                Allowlist (comma-sep)
                <input
                  value={(v.allowlist ?? []).join(", ")}
                  onChange={(e) =>
                    updateValidator(idx, {
                      allowlist: e.target.value
                        ? e.target.value.split(",").map((s) => s.trim())
                        : null,
                    })
                  }
                  className="mt-1 block w-full rounded border border-border bg-background px-2 py-1 text-xs"
                />
              </label>
              <button
                type="button"
                onClick={() => removeValidator(idx)}
                className="text-xs text-destructive hover:underline"
              >
                Remove
              </button>
            </div>
          ))}
      </div>

      {/* Submit */}
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
          Save Rule
        </button>
      </div>
    </form>
  );
}
