"""AgentPEP CLI — command-line tool for policy management and testing.

Sprint 34 — APEP-267: Build ``agentpep-cli`` with subcommands:
  - ``agentpep policy validate`` — validate YAML policy against schema
  - ``agentpep policy diff`` — diff two YAML policy files
  - ``agentpep simulate`` — simulate tool call against offline policy
  - ``agentpep redteam generate`` — auto-generate adversarial payloads (APEP-268)
  - ``agentpep redteam run`` — execute adversarial suite (APEP-269)
  - ``agentpep policy migrate`` — upgrade policy YAML schema versions (APEP-271)
  - ``agentpep receipt verify`` — batch-verify signed receipts (APEP-273)
  - ``agentpep health`` — check server connectivity and health (APEP-274)

Usage::

    agentpep policy validate policy.yaml
    agentpep policy diff old.yaml new.yaml
    agentpep policy migrate policy.yaml --target-version 2.0
    agentpep simulate policy.yaml --agent-id bot --tool-name file.read
    agentpep redteam generate policy.yaml -o adversarial.json
    agentpep redteam run policy.yaml --suite adversarial.json
    agentpep receipt verify --receipts-file receipts.jsonl --key-file key.pem
    agentpep health --base-url http://localhost:8000
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _load_yaml(path: str) -> dict[str, Any]:
    """Load and parse a YAML file."""
    import yaml

    p = Path(path)
    if not p.is_file():
        print(f"ERROR: File not found: {path}", file=sys.stderr)
        sys.exit(1)
    return yaml.safe_load(p.read_text())  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# policy validate
# ---------------------------------------------------------------------------


def cmd_policy_validate(args: argparse.Namespace) -> int:
    """Validate a YAML policy file against the AgentPEP schema."""
    from agentpep.policy_bundle import PolicyBundle

    path = Path(args.file)
    if not path.exists():
        print(f"ERROR: File not found: {args.file}", file=sys.stderr)
        return 1

    errors: list[str] = []

    # Parse YAML
    try:
        if path.is_dir():
            bundle = PolicyBundle.from_yaml_directory(path)
        else:
            bundle = PolicyBundle.from_yaml_file(path)
    except Exception as exc:
        errors.append(f"Parse error: {exc}")
        for e in errors:
            print(f"  FAIL: {e}", file=sys.stderr)
        return 1

    # Validate structure
    if not bundle.rules:
        errors.append("No rules defined in policy")

    # Validate role references in rules
    known_roles = {r.role_id for r in bundle.roles}
    for rule in bundle.rules:
        for role_ref in rule.agent_roles:
            if role_ref != "*" and role_ref not in known_roles:
                errors.append(
                    f"Rule '{rule.name}' references unknown role '{role_ref}'"
                )

    # Validate parent role references
    for role in bundle.roles:
        for parent in role.parent_roles:
            if parent not in known_roles:
                errors.append(
                    f"Role '{role.role_id}' references unknown parent role '{parent}'"
                )

    # Check for duplicate role IDs
    role_ids = [r.role_id for r in bundle.roles]
    seen: set[str] = set()
    for rid in role_ids:
        if rid in seen:
            errors.append(f"Duplicate role_id: '{rid}'")
        seen.add(rid)

    # Check for duplicate rule names
    rule_names = [r.name for r in bundle.rules]
    seen_names: set[str] = set()
    for name in rule_names:
        if name in seen_names:
            errors.append(f"Duplicate rule name: '{name}'")
        seen_names.add(name)

    # Risk config validation
    if bundle.risk_config.escalation_threshold < 0 or bundle.risk_config.escalation_threshold > 1:
        errors.append(
            f"Invalid escalation_threshold: {bundle.risk_config.escalation_threshold}"
        )

    if errors:
        print(f"INVALID: {len(errors)} error(s) found in {args.file}")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(f"VALID: {args.file}")
    print(f"  Roles: {len(bundle.roles)}")
    print(f"  Rules: {len(bundle.rules)}")
    print(f"  Schema version: {bundle.schema_version}")
    print(f"  Injection patterns: {len(bundle.injection_patterns)}")
    return 0


# ---------------------------------------------------------------------------
# policy diff
# ---------------------------------------------------------------------------


def cmd_policy_diff(args: argparse.Namespace) -> int:
    """Diff two YAML policy files and show structured changes."""
    from agentpep.policy_bundle import PolicyBundle

    path_a = Path(args.file_a)
    path_b = Path(args.file_b)

    for p, label in [(path_a, "file_a"), (path_b, "file_b")]:
        if not p.exists():
            print(f"ERROR: {label} not found: {p}", file=sys.stderr)
            return 1

    try:
        bundle_a = (
            PolicyBundle.from_yaml_directory(path_a)
            if path_a.is_dir()
            else PolicyBundle.from_yaml_file(path_a)
        )
        bundle_b = (
            PolicyBundle.from_yaml_directory(path_b)
            if path_b.is_dir()
            else PolicyBundle.from_yaml_file(path_b)
        )
    except Exception as exc:
        print(f"ERROR: Failed to parse policies: {exc}", file=sys.stderr)
        return 1

    diff = _diff_bundles(bundle_a, bundle_b)

    if not diff["entries"]:
        print("No changes detected.")
        return 0

    print(f"Changes: {diff['summary']['added']} added, "
          f"{diff['summary']['removed']} removed, "
          f"{diff['summary']['changed']} changed")

    for entry in diff["entries"]:
        marker = {"ADDED": "+", "REMOVED": "-", "CHANGED": "~"}[entry["change_type"]]
        print(f"  [{marker}] {entry['section']}/{entry['identifier']}: {entry['change_type']}")
        if entry.get("changed_fields"):
            print(f"      Changed fields: {', '.join(entry['changed_fields'])}")

    if args.json:
        print("\n--- JSON Output ---")
        print(json.dumps(diff, indent=2, default=str))

    return 0


def _diff_bundles(
    bundle_a: Any, bundle_b: Any
) -> dict[str, Any]:
    """Compute structured diff between two PolicyBundles."""
    entries: list[dict[str, Any]] = []

    # Diff roles
    _diff_section(
        section="roles",
        old_items={r.role_id: _role_dict(r) for r in bundle_a.roles},
        new_items={r.role_id: _role_dict(r) for r in bundle_b.roles},
        entries=entries,
    )

    # Diff rules
    _diff_section(
        section="rules",
        old_items={r.name: _rule_dict(r) for r in bundle_a.rules},
        new_items={r.name: _rule_dict(r) for r in bundle_b.rules},
        entries=entries,
    )

    # Diff risk config
    old_risk = {
        "escalation_threshold": bundle_a.risk_config.escalation_threshold,
        "weights": bundle_a.risk_config.weights,
    }
    new_risk = {
        "escalation_threshold": bundle_b.risk_config.escalation_threshold,
        "weights": bundle_b.risk_config.weights,
    }
    if old_risk != new_risk:
        changed = [k for k in old_risk if old_risk[k] != new_risk.get(k)]
        entries.append({
            "section": "risk",
            "change_type": "CHANGED",
            "identifier": "risk_config",
            "old_value": old_risk,
            "new_value": new_risk,
            "changed_fields": changed,
        })

    # Diff taint
    old_taint = {
        "max_hop_depth": bundle_a.taint_policy.max_hop_depth,
        "quarantine_on_injection": bundle_a.taint_policy.quarantine_on_injection,
    }
    new_taint = {
        "max_hop_depth": bundle_b.taint_policy.max_hop_depth,
        "quarantine_on_injection": bundle_b.taint_policy.quarantine_on_injection,
    }
    if old_taint != new_taint:
        changed = [k for k in old_taint if old_taint[k] != new_taint.get(k)]
        entries.append({
            "section": "taint",
            "change_type": "CHANGED",
            "identifier": "taint_policy",
            "old_value": old_taint,
            "new_value": new_taint,
            "changed_fields": changed,
        })

    added = sum(1 for e in entries if e["change_type"] == "ADDED")
    removed = sum(1 for e in entries if e["change_type"] == "REMOVED")
    changed = sum(1 for e in entries if e["change_type"] == "CHANGED")

    return {
        "has_changes": len(entries) > 0,
        "summary": {
            "added": added,
            "removed": removed,
            "changed": changed,
            "total": len(entries),
        },
        "entries": entries,
    }


def _role_dict(r: Any) -> dict[str, Any]:
    return {
        "role_id": r.role_id,
        "name": r.name,
        "parent_roles": r.parent_roles,
        "allowed_tools": r.allowed_tools,
        "denied_tools": r.denied_tools,
        "max_risk_threshold": r.max_risk_threshold,
        "enabled": r.enabled,
    }


def _rule_dict(r: Any) -> dict[str, Any]:
    return {
        "name": r.name,
        "tool_pattern": r.tool_pattern,
        "action": r.action,
        "agent_roles": r.agent_roles,
        "taint_check": r.taint_check,
        "risk_threshold": r.risk_threshold,
        "priority": r.priority,
        "enabled": r.enabled,
    }


def _diff_section(
    *,
    section: str,
    old_items: dict[str, dict[str, Any]],
    new_items: dict[str, dict[str, Any]],
    entries: list[dict[str, Any]],
) -> None:
    """Diff a named section by identifier key."""
    old_keys = set(old_items.keys())
    new_keys = set(new_items.keys())

    for key in sorted(new_keys - old_keys):
        entries.append({
            "section": section,
            "change_type": "ADDED",
            "identifier": key,
            "new_value": new_items[key],
        })

    for key in sorted(old_keys - new_keys):
        entries.append({
            "section": section,
            "change_type": "REMOVED",
            "identifier": key,
            "old_value": old_items[key],
        })

    for key in sorted(old_keys & new_keys):
        old_d = old_items[key]
        new_d = new_items[key]
        changed_fields = [k for k in old_d if old_d.get(k) != new_d.get(k)]
        if changed_fields:
            entries.append({
                "section": section,
                "change_type": "CHANGED",
                "identifier": key,
                "old_value": old_d,
                "new_value": new_d,
                "changed_fields": changed_fields,
            })


# ---------------------------------------------------------------------------
# simulate
# ---------------------------------------------------------------------------


def cmd_simulate(args: argparse.Namespace) -> int:
    """Simulate a tool call against an offline policy stack."""
    from agentpep.offline import OfflineEvaluator
    from agentpep.models import PolicyDecision

    path = Path(args.policy_file)
    if not path.exists():
        print(f"ERROR: Policy file not found: {args.policy_file}", file=sys.stderr)
        return 1

    try:
        if path.is_dir():
            evaluator = OfflineEvaluator.from_yaml_directory(path)
        else:
            evaluator = OfflineEvaluator.from_yaml_file(path)
    except Exception as exc:
        print(f"ERROR: Failed to load policy: {exc}", file=sys.stderr)
        return 1

    tool_args: dict[str, Any] = {}
    if args.tool_args:
        try:
            tool_args = json.loads(args.tool_args)
        except json.JSONDecodeError as exc:
            print(f"ERROR: Invalid JSON in --tool-args: {exc}", file=sys.stderr)
            return 1

    taint_flags = args.taint_flags.split(",") if args.taint_flags else None
    delegation_chain = args.delegation_chain.split(",") if args.delegation_chain else None

    result = evaluator.evaluate(
        agent_id=args.agent_id,
        tool_name=args.tool_name,
        tool_args=tool_args,
        role=args.role,
        taint_flags=taint_flags,
        delegation_chain=delegation_chain,
    )

    # Output
    output = {
        "decision": result.decision.value,
        "reason": result.reason,
        "risk_score": result.risk_score,
        "taint_flags": result.taint_flags,
    }

    if args.json:
        print(json.dumps(output, indent=2, default=str))
    else:
        icon = {
            PolicyDecision.ALLOW: "ALLOW",
            PolicyDecision.DENY: "DENY",
            PolicyDecision.ESCALATE: "ESCALATE",
        }.get(result.decision, result.decision.value)
        print(f"Decision: {icon}")
        print(f"Reason: {result.reason}")
        print(f"Risk score: {result.risk_score:.4f}")
        if result.taint_flags:
            print(f"Taint flags: {', '.join(result.taint_flags)}")

    return 0 if result.decision == PolicyDecision.ALLOW else 1


# ---------------------------------------------------------------------------
# redteam generate
# ---------------------------------------------------------------------------


def cmd_redteam_generate(args: argparse.Namespace) -> int:
    """Auto-generate adversarial tool call payloads from policy definitions."""
    from agentpep.redteam import RedTeamGenerator

    path = Path(args.policy_file)
    if not path.exists():
        print(f"ERROR: Policy file not found: {args.policy_file}", file=sys.stderr)
        return 1

    try:
        generator = RedTeamGenerator.from_policy_file(path)
    except Exception as exc:
        print(f"ERROR: Failed to load policy: {exc}", file=sys.stderr)
        return 1

    vectors = generator.generate(
        categories=args.categories.split(",") if args.categories else None,
        count=args.count,
    )

    output = [v.to_dict() for v in vectors]

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(output, indent=2, default=str))
        print(f"Generated {len(vectors)} adversarial vectors -> {args.output}")
    else:
        print(json.dumps(output, indent=2, default=str))

    return 0


# ---------------------------------------------------------------------------
# redteam run
# ---------------------------------------------------------------------------


def cmd_redteam_run(args: argparse.Namespace) -> int:
    """Execute an adversarial suite against the policy stack."""
    from agentpep.redteam import RedTeamRunner

    path = Path(args.policy_file)
    if not path.exists():
        print(f"ERROR: Policy file not found: {args.policy_file}", file=sys.stderr)
        return 1

    suite_vectors = None
    if args.suite:
        suite_path = Path(args.suite)
        if not suite_path.is_file():
            print(f"ERROR: Suite file not found: {args.suite}", file=sys.stderr)
            return 1
        try:
            suite_vectors = json.loads(suite_path.read_text())
        except json.JSONDecodeError as exc:
            print(f"ERROR: Invalid JSON in suite file: {exc}", file=sys.stderr)
            return 1

    try:
        runner = RedTeamRunner.from_policy_file(path)
    except Exception as exc:
        print(f"ERROR: Failed to load policy: {exc}", file=sys.stderr)
        return 1

    report = runner.run(vectors=suite_vectors)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, default=str))
    else:
        print(f"Red Team Report: {report.passed}/{report.total} passed, "
              f"{report.failed} failed")
        for result in report.results:
            status = "PASS" if result["passed"] else "FAIL"
            print(f"  [{status}] {result['vector_id']}: {result['name']}")
            if not result["passed"]:
                print(f"         Expected: {result['expected']}, Got: {result['actual']}")

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(report.to_dict(), indent=2, default=str))
        print(f"\nReport saved to: {args.output}")

    return 0 if report.failed == 0 else 1


# ---------------------------------------------------------------------------
# policy migrate
# ---------------------------------------------------------------------------


def cmd_policy_migrate(args: argparse.Namespace) -> int:
    """Migrate a YAML policy file to a new schema version."""
    from agentpep.policy_migration import PolicyMigrator

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: File not found: {args.file}", file=sys.stderr)
        return 1

    migrator = PolicyMigrator()

    try:
        result = migrator.migrate_file(
            path, target_version=args.target_version
        )
    except Exception as exc:
        print(f"ERROR: Migration failed: {exc}", file=sys.stderr)
        return 1

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(result.yaml_output)
        print(f"Migrated {args.file} -> {args.output} "
              f"(v{result.source_version} -> v{result.target_version})")
    else:
        print(result.yaml_output)

    if result.warnings:
        print("\nWarnings:", file=sys.stderr)
        for w in result.warnings:
            print(f"  - {w}", file=sys.stderr)

    return 0


# ---------------------------------------------------------------------------
# receipt verify
# ---------------------------------------------------------------------------


def cmd_receipt_verify(args: argparse.Namespace) -> int:
    """Batch-verify signed receipts from audit export files."""
    from agentpep.receipt_verify import batch_verify_receipts

    return batch_verify_receipts(
        receipts_file=args.receipts_file,
        key_file=args.key_file,
        key_id=args.key_id,
        verbose=args.verbose,
    )


def cmd_receipt_verify_chain(args: argparse.Namespace) -> int:
    """Verify per-receipt Ed25519 signatures and receipt chain integrity."""
    from agentpep.receipt_verify import verify_chain_cli

    return verify_chain_cli(
        plan_id=args.plan,
        receipts_file=getattr(args, "receipts_file", None),
        key_file=getattr(args, "key_file", None),
        export_path=getattr(args, "export", None),
        base_url=args.base_url,
        verbose=args.verbose,
    )


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------


def cmd_health(args: argparse.Namespace) -> int:
    """Check server connectivity and backend health."""
    from agentpep.health_check import check_health

    return check_health(
        base_url=args.base_url,
        api_key=args.api_key,
        timeout=args.timeout,
        verbose=args.verbose,
    )


# ---------------------------------------------------------------------------
# scope compile (Sprint 38 — APEP-305)
# ---------------------------------------------------------------------------


def cmd_scope_compile(args: argparse.Namespace) -> int:
    """Compile a scope pattern to RBAC tool-name globs."""
    import re

    # Reuse the same validation logic as the backend without importing it
    VALID_VERBS = {"read", "write", "delete", "execute", "send", "*"}
    VALID_NAMESPACES = {"public", "secret", "internal", "external", "*"}
    RESOURCE_RE = re.compile(r"^[\w\*\?\.\-/]+$")

    VERB_PREFIXES = {
        "read": ["file.read", "db.read", "api.get", "read"],
        "write": ["file.write", "db.write", "api.post", "api.put", "write"],
        "delete": ["file.delete", "db.drop", "db.delete", "api.delete", "delete"],
        "execute": ["exec", "shell", "deploy", "execute"],
        "send": ["email.send", "slack.send", "notify", "send"],
        "*": ["*"],
    }
    NAMESPACE_SEGMENTS = {
        "public": ["public"],
        "secret": ["secret", "credential"],
        "internal": ["internal", "admin"],
        "external": ["external", "api"],
        "*": ["*"],
    }

    pattern = args.pattern
    parts = pattern.split(":")
    if len(parts) != 3:
        print(
            f"ERROR: Invalid scope pattern '{pattern}': "
            f"expected 'verb:namespace:resource'",
            file=sys.stderr,
        )
        return 1

    verb, namespace, resource = parts
    verb = verb.lower()
    namespace = namespace.lower()

    if verb not in VALID_VERBS:
        print(f"ERROR: Invalid verb '{verb}'. Valid: {', '.join(sorted(VALID_VERBS))}", file=sys.stderr)
        return 1
    if namespace not in VALID_NAMESPACES:
        print(f"ERROR: Invalid namespace '{namespace}'. Valid: {', '.join(sorted(VALID_NAMESPACES))}", file=sys.stderr)
        return 1
    if not resource or not RESOURCE_RE.match(resource):
        print(f"ERROR: Invalid resource glob '{resource}'", file=sys.stderr)
        return 1

    # Compile to RBAC patterns
    if verb == "*" and namespace == "*" and resource == "*":
        rbac_patterns = ["*"]
    else:
        rbac_patterns = []
        prefixes = VERB_PREFIXES.get(verb, [verb])
        segments = NAMESPACE_SEGMENTS.get(namespace, [namespace])
        for prefix in prefixes:
            for segment in segments:
                if prefix == "*":
                    if segment == "*":
                        rbac_patterns.append(f"*.{resource}")
                    else:
                        rbac_patterns.append(f"*.{segment}.{resource}")
                elif segment == "*":
                    rbac_patterns.append(f"{prefix}.*.{resource}")
                else:
                    rbac_patterns.append(f"{prefix}.{segment}.{resource}")

    # Deduplicate
    seen: set[str] = set()
    unique: list[str] = []
    for p in rbac_patterns:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    rbac_patterns = unique

    if args.json:
        output = {
            "scope_pattern": f"{verb}:{namespace}:{resource}",
            "verb": verb,
            "namespace": namespace,
            "resource_glob": resource,
            "rbac_patterns": rbac_patterns,
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"Scope pattern: {verb}:{namespace}:{resource}")
        print(f"  Verb:      {verb}")
        print(f"  Namespace: {namespace}")
        print(f"  Resource:  {resource}")
        print(f"  RBAC patterns ({len(rbac_patterns)}):")
        for p in rbac_patterns:
            print(f"    - {p}")

    return 0


# ---------------------------------------------------------------------------
# scope validate (Sprint 38 — APEP-306)
# ---------------------------------------------------------------------------


def cmd_scope_validate(args: argparse.Namespace) -> int:
    """Validate scope patterns in a plan YAML file."""
    import re

    import yaml

    VALID_VERBS = {"read", "write", "delete", "execute", "send", "*"}
    VALID_NAMESPACES = {"public", "secret", "internal", "external", "*"}
    RESOURCE_RE = re.compile(r"^[\w\*\?\.\-/]+$")

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: File not found: {args.file}", file=sys.stderr)
        return 1

    try:
        data = yaml.safe_load(path.read_text())
    except Exception as exc:
        print(f"ERROR: Failed to parse YAML: {exc}", file=sys.stderr)
        return 1

    if not isinstance(data, dict):
        print("ERROR: Plan YAML must be a mapping", file=sys.stderr)
        return 1

    # Collect scope patterns from known fields
    scope_patterns: list[str] = []
    for field in ("scope", "requires_checkpoint"):
        value = data.get(field, [])
        if isinstance(value, list):
            scope_patterns.extend(value)

    if not scope_patterns:
        print("No scope patterns found in plan YAML.")
        return 0

    errors: list[str] = []
    valid_count = 0

    for pattern in scope_patterns:
        parts = pattern.split(":")
        if len(parts) != 3:
            errors.append(
                f"'{pattern}': expected 'verb:namespace:resource', "
                f"got {len(parts)} part(s)"
            )
            continue

        verb, namespace, resource = parts
        verb = verb.lower()
        namespace = namespace.lower()

        if verb not in VALID_VERBS:
            errors.append(f"'{pattern}': invalid verb '{verb}'")
            continue
        if namespace not in VALID_NAMESPACES:
            errors.append(f"'{pattern}': invalid namespace '{namespace}'")
            continue
        if not resource or not RESOURCE_RE.match(resource):
            errors.append(f"'{pattern}': invalid resource glob '{resource}'")
            continue

        valid_count += 1

    total = len(scope_patterns)
    invalid_count = len(errors)
    all_valid = invalid_count == 0

    if args.json:
        output = {
            "valid": all_valid,
            "total_patterns": total,
            "valid_patterns": valid_count,
            "invalid_patterns": invalid_count,
            "errors": errors,
        }
        print(json.dumps(output, indent=2))
    else:
        status = "VALID" if all_valid else "INVALID"
        print(f"{status}: {args.file}")
        print(f"  Total patterns: {total}")
        print(f"  Valid: {valid_count}")
        print(f"  Invalid: {invalid_count}")
        if errors:
            print("  Errors:")
            for e in errors:
                print(f"    - {e}")

    return 0 if all_valid else 1


# ---------------------------------------------------------------------------
# scope simulate (Sprint 43 — APEP-341)
# ---------------------------------------------------------------------------


def cmd_scope_simulate(args: argparse.Namespace) -> int:
    """Simulate tool calls against plan scope patterns offline."""
    import re

    import yaml

    VALID_VERBS = {"read", "write", "delete", "execute", "send", "*"}
    VALID_NAMESPACES = {"public", "secret", "internal", "external", "*"}
    RESOURCE_RE = re.compile(r"^[\w\*\?\.\-/]+$")

    scope_patterns: list[str] = list(args.scope) if args.scope else []
    checkpoint_patterns: list[str] = list(args.checkpoint) if args.checkpoint else []

    # Load patterns from plan YAML if provided
    if args.plan_file:
        path = Path(args.plan_file)
        if not path.is_file():
            print(f"ERROR: Plan file not found: {args.plan_file}", file=sys.stderr)
            return 1
        try:
            data = yaml.safe_load(path.read_text())
        except Exception as exc:
            print(f"ERROR: Failed to parse YAML: {exc}", file=sys.stderr)
            return 1

        if isinstance(data, dict):
            scope_patterns.extend(data.get("scope", []))
            checkpoint_patterns.extend(data.get("requires_checkpoint", []))

    if not scope_patterns:
        print("ERROR: No scope patterns provided. Use --scope or --plan.", file=sys.stderr)
        return 1

    # Validate scope patterns
    errors: list[str] = []
    for pattern in scope_patterns + checkpoint_patterns:
        parts = pattern.split(":")
        if len(parts) != 3:
            errors.append(f"'{pattern}': expected verb:namespace:resource")
            continue
        verb, namespace, resource = parts
        if verb.lower() not in VALID_VERBS:
            errors.append(f"'{pattern}': invalid verb '{verb}'")
        if namespace.lower() not in VALID_NAMESPACES:
            errors.append(f"'{pattern}': invalid namespace '{namespace}'")
        if not resource or not RESOURCE_RE.match(resource):
            errors.append(f"'{pattern}': invalid resource '{resource}'")

    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # Build RBAC mappings inline (reuse same logic as cmd_scope_compile)
    VERB_PREFIXES = {
        "read": ["file.read", "db.read", "api.get", "read"],
        "write": ["file.write", "db.write", "api.post", "api.put", "write"],
        "delete": ["file.delete", "db.drop", "db.delete", "api.delete", "delete"],
        "execute": ["exec", "shell", "deploy", "execute"],
        "send": ["email.send", "slack.send", "notify", "send"],
        "*": ["*"],
    }
    NAMESPACE_SEGMENTS = {
        "public": ["public"],
        "secret": ["secret", "credential"],
        "internal": ["internal", "admin"],
        "external": ["external", "api"],
        "*": ["*"],
    }

    import fnmatch as _fnmatch

    def compile_pattern(pattern: str) -> list[str]:
        parts = pattern.split(":")
        if len(parts) != 3:
            return []
        verb, namespace, resource = parts
        verb = verb.lower()
        namespace = namespace.lower()
        if verb == "*" and namespace == "*" and resource == "*":
            return ["*"]
        rbac: list[str] = []
        for prefix in VERB_PREFIXES.get(verb, [verb]):
            for segment in NAMESPACE_SEGMENTS.get(namespace, [namespace]):
                if prefix == "*":
                    rbac.append(f"*.{segment}.{resource}" if segment != "*" else f"*.{resource}")
                elif segment == "*":
                    rbac.append(f"{prefix}.*.{resource}")
                else:
                    rbac.append(f"{prefix}.{segment}.{resource}")
        return list(dict.fromkeys(rbac))

    def check_match(patterns: list[str], tool_name: str) -> str | None:
        for pattern in patterns:
            for rbac_glob in compile_pattern(pattern):
                if _fnmatch.fnmatch(tool_name, rbac_glob):
                    return pattern
        return None

    results: list[dict[str, object]] = []
    for tool_name in args.tool_names:
        scope_match = check_match(scope_patterns, tool_name)
        scope_allowed = scope_match is not None if scope_patterns else True
        checkpoint_match = check_match(checkpoint_patterns, tool_name)
        checkpoint_triggered = checkpoint_match is not None

        if not scope_allowed:
            effective = "DENY"
        elif checkpoint_triggered:
            effective = "ESCALATE"
        else:
            effective = "ALLOW"

        results.append({
            "tool_name": tool_name,
            "action": args.action,
            "scope_allowed": scope_allowed,
            "scope_matched_pattern": scope_match,
            "checkpoint_triggered": checkpoint_triggered,
            "checkpoint_matched_pattern": checkpoint_match,
            "effective_decision": effective,
        })

    if args.json:
        output = results if len(results) > 1 else results[0]
        print(json.dumps(output, indent=2, default=str))
    else:
        for r in results:
            icon = {"ALLOW": "ALLOW", "DENY": "DENY", "ESCALATE": "ESCALATE"}[
                str(r["effective_decision"])
            ]
            print(f"Tool: {r['tool_name']}")
            print(f"  Decision: {icon}")
            print(f"  Scope allowed: {r['scope_allowed']}")
            if r["scope_matched_pattern"]:
                print(f"  Scope match: {r['scope_matched_pattern']}")
            print(f"  Checkpoint: {r['checkpoint_triggered']}")
            if r["checkpoint_matched_pattern"]:
                print(f"  Checkpoint match: {r['checkpoint_matched_pattern']}")
            print()

    has_failure = any(r["effective_decision"] != "ALLOW" for r in results)
    return 1 if has_failure else 0


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="agentpep",
        description="AgentPEP CLI — policy management, testing, and simulation",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- policy ---
    policy_parser = subparsers.add_parser("policy", help="Policy management commands")
    policy_sub = policy_parser.add_subparsers(dest="policy_command")

    # policy validate
    validate_p = policy_sub.add_parser("validate", help="Validate a YAML policy file")
    validate_p.add_argument("file", help="Path to YAML policy file or directory")

    # policy diff
    diff_p = policy_sub.add_parser("diff", help="Diff two YAML policy files")
    diff_p.add_argument("file_a", help="Path to first policy file")
    diff_p.add_argument("file_b", help="Path to second policy file")
    diff_p.add_argument("--json", action="store_true", help="Output as JSON")

    # policy migrate
    migrate_p = policy_sub.add_parser("migrate", help="Migrate YAML policy schema version")
    migrate_p.add_argument("file", help="Path to YAML policy file")
    migrate_p.add_argument(
        "--target-version", default="2.0",
        help="Target schema version (default: 2.0)",
    )
    migrate_p.add_argument("-o", "--output", help="Output file path (default: stdout)")

    # --- simulate ---
    sim_p = subparsers.add_parser("simulate", help="Simulate a tool call offline")
    sim_p.add_argument("policy_file", help="Path to YAML policy file or directory")
    sim_p.add_argument("--agent-id", required=True, help="Agent identifier")
    sim_p.add_argument("--tool-name", required=True, help="Tool name to simulate")
    sim_p.add_argument("--tool-args", help="Tool arguments as JSON string")
    sim_p.add_argument("--role", default="*", help="Agent role (default: *)")
    sim_p.add_argument("--taint-flags", help="Comma-separated taint flags")
    sim_p.add_argument("--delegation-chain", help="Comma-separated delegation chain")
    sim_p.add_argument("--json", action="store_true", help="Output as JSON")

    # --- redteam ---
    redteam_parser = subparsers.add_parser("redteam", help="Red team testing commands")
    redteam_sub = redteam_parser.add_subparsers(dest="redteam_command")

    # redteam generate
    gen_p = redteam_sub.add_parser("generate", help="Generate adversarial payloads")
    gen_p.add_argument("policy_file", help="Path to YAML policy file")
    gen_p.add_argument("-o", "--output", help="Output file path")
    gen_p.add_argument(
        "--categories",
        help="Comma-separated categories: privilege_escalation,injection,"
        "data_exfiltration,confused_deputy,taint_bypass",
    )
    gen_p.add_argument("--count", type=int, default=10, help="Number of vectors per category")

    # redteam run
    run_p = redteam_sub.add_parser("run", help="Execute adversarial test suite")
    run_p.add_argument("policy_file", help="Path to YAML policy file")
    run_p.add_argument("--suite", help="Path to JSON test suite file")
    run_p.add_argument("-o", "--output", help="Save report to file")
    run_p.add_argument("--json", action="store_true", help="Output as JSON")

    # --- receipt ---
    receipt_parser = subparsers.add_parser("receipt", help="Receipt management commands")
    receipt_sub = receipt_parser.add_subparsers(dest="receipt_command")

    verify_p = receipt_sub.add_parser("verify", help="Batch-verify signed receipts")
    verify_p.add_argument(
        "--receipts-file", required=True,
        help="Path to JSONL file with receipt+record pairs",
    )
    verify_p.add_argument(
        "--key-file", required=True,
        help="Path to verify key file (format: algorithm:base64_key)",
    )
    verify_p.add_argument("--key-id", default="default", help="Key ID")
    verify_p.add_argument("--verbose", action="store_true")

    # Sprint 39 — APEP-314: receipt verify-chain
    verify_chain_p = receipt_sub.add_parser(
        "verify-chain",
        help="Verify per-receipt Ed25519 signatures and chain integrity",
    )
    verify_chain_p.add_argument(
        "--plan", required=True,
        help="MissionPlan UUID to verify",
    )
    verify_chain_p.add_argument(
        "--receipts-file",
        help="Path to exported receipt chain JSON (skip server fetch)",
    )
    verify_chain_p.add_argument(
        "--key-file",
        help="Path to Ed25519 verify key file (ed25519:base64_key)",
    )
    verify_chain_p.add_argument(
        "--export",
        help="Export fetched receipt chain to this JSON file",
    )
    verify_chain_p.add_argument(
        "--base-url", default="http://localhost:8000",
        help="AgentPEP server URL (default: http://localhost:8000)",
    )
    verify_chain_p.add_argument("--verbose", action="store_true")

    # --- scope (Sprint 38 — APEP-305/306) ---
    scope_parser = subparsers.add_parser("scope", help="Scope pattern commands")
    scope_sub = scope_parser.add_subparsers(dest="scope_command")

    # scope compile
    compile_p = scope_sub.add_parser(
        "compile",
        help="Compile a scope pattern to RBAC tool-name globs",
    )
    compile_p.add_argument("pattern", help="Scope pattern (verb:namespace:resource)")
    compile_p.add_argument("--json", action="store_true", help="Output as JSON")

    # scope validate
    validate_scope_p = scope_sub.add_parser(
        "validate",
        help="Validate scope patterns in a plan YAML file",
    )
    validate_scope_p.add_argument("file", help="Path to plan YAML file")
    validate_scope_p.add_argument("--json", action="store_true", help="Output as JSON")

    # scope simulate (Sprint 43 — APEP-341)
    simulate_scope_p = scope_sub.add_parser(
        "simulate",
        help="Simulate a tool call against plan scope patterns",
    )
    simulate_scope_p.add_argument(
        "--plan", dest="plan_file",
        help="Path to plan YAML file containing scope and requires_checkpoint",
    )
    simulate_scope_p.add_argument(
        "--scope", nargs="*", default=[],
        help="Inline scope patterns (verb:namespace:resource)",
    )
    simulate_scope_p.add_argument(
        "--checkpoint", nargs="*", default=[],
        help="Inline requires_checkpoint patterns",
    )
    simulate_scope_p.add_argument(
        "--action", default="",
        help="Human-readable action description for the simulation",
    )
    simulate_scope_p.add_argument(
        "--tool-name", dest="tool_names", nargs="+", required=True,
        help="One or more tool names to simulate",
    )
    simulate_scope_p.add_argument("--json", action="store_true", help="Output as JSON")

    # --- health ---
    health_p = subparsers.add_parser("health", help="Check server health")
    health_p.add_argument(
        "--base-url", default="http://localhost:8000",
        help="AgentPEP server URL",
    )
    health_p.add_argument("--api-key", help="API key for authentication")
    health_p.add_argument("--timeout", type=float, default=5.0, help="Request timeout")
    health_p.add_argument("--verbose", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "policy":
        if not hasattr(args, "policy_command") or args.policy_command is None:
            parser.parse_args(["policy", "--help"])
            return 0
        if args.policy_command == "validate":
            return cmd_policy_validate(args)
        elif args.policy_command == "diff":
            return cmd_policy_diff(args)
        elif args.policy_command == "migrate":
            return cmd_policy_migrate(args)

    elif args.command == "simulate":
        return cmd_simulate(args)

    elif args.command == "redteam":
        if not hasattr(args, "redteam_command") or args.redteam_command is None:
            parser.parse_args(["redteam", "--help"])
            return 0
        if args.redteam_command == "generate":
            return cmd_redteam_generate(args)
        elif args.redteam_command == "run":
            return cmd_redteam_run(args)

    elif args.command == "receipt":
        if not hasattr(args, "receipt_command") or args.receipt_command is None:
            parser.parse_args(["receipt", "--help"])
            return 0
        if args.receipt_command == "verify":
            return cmd_receipt_verify(args)
        elif args.receipt_command == "verify-chain":
            return cmd_receipt_verify_chain(args)

    elif args.command == "scope":
        if not hasattr(args, "scope_command") or args.scope_command is None:
            parser.parse_args(["scope", "--help"])
            return 0
        if args.scope_command == "compile":
            return cmd_scope_compile(args)
        elif args.scope_command == "validate":
            return cmd_scope_validate(args)
        elif args.scope_command == "simulate":
            return cmd_scope_simulate(args)

    elif args.command == "health":
        return cmd_health(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
