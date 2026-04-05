"""Validator Pipeline — sequential argument validation with full error collection.

APEP-093: JSON schema argument validator.
APEP-094: Regex validator — per-arg regex patterns.
APEP-095: Allowlist/blocklist string validator — per-arg value matching.
APEP-096: Pipeline runs all configured validators in sequence; any FAIL → DENY.
"""

import logging
import re
from typing import Any

import jsonschema

from app.models.policy import ArgValidator, ValidationFailure, ValidationResult

logger = logging.getLogger(__name__)


class ValidatorPipeline:
    """Runs all configured argument validators in sequence.

    Unlike the legacy validate_args in RuleMatcher (which early-exits on first
    failure and skips the rule), this pipeline:
    1. Runs ALL validators for ALL arguments — never short-circuits.
    2. Collects every failure into a ValidationResult.
    3. Any failure means the overall result is DENY.
    """

    def validate(
        self,
        tool_args: dict[str, Any],
        validators: list[ArgValidator],
    ) -> ValidationResult:
        """Run the full validator pipeline on tool arguments.

        Each ArgValidator may define one or more of: json_schema, regex_pattern,
        allowlist, blocklist. All checks run for every validator — failures are
        collected, not short-circuited.
        """
        failures: list[ValidationFailure] = []

        for validator in validators:
            arg_value = tool_args.get(validator.arg_name)

            # --- JSON Schema validation (APEP-093) ---
            if validator.json_schema is not None:
                failures.extend(
                    self._validate_json_schema(
                        validator.arg_name, arg_value, validator.json_schema
                    )
                )

            if arg_value is None:
                continue

            arg_str = str(arg_value)

            # --- Blocklist check (APEP-095) ---
            if validator.blocklist is not None:
                failures.extend(
                    self._validate_blocklist(
                        validator.arg_name, arg_str, validator.blocklist
                    )
                )

            # --- Allowlist check (APEP-095) ---
            if validator.allowlist is not None:
                failures.extend(
                    self._validate_allowlist(
                        validator.arg_name, arg_str, validator.allowlist
                    )
                )

            # --- Regex pattern check (APEP-094) ---
            if validator.regex_pattern is not None:
                failures.extend(
                    self._validate_regex(
                        validator.arg_name, arg_str, validator.regex_pattern
                    )
                )

        return ValidationResult(
            passed=len(failures) == 0,
            failures=failures,
        )

    @staticmethod
    def _validate_json_schema(
        arg_name: str, arg_value: Any, schema: dict[str, Any]
    ) -> list[ValidationFailure]:
        """Validate a single argument against a JSON schema (APEP-093)."""
        try:
            jsonschema.validate(instance=arg_value, schema=schema)
            return []
        except jsonschema.ValidationError as e:
            return [
                ValidationFailure(
                    validator_type="json_schema",
                    arg_name=arg_name,
                    reason=e.message,
                )
            ]
        except jsonschema.SchemaError as e:
            logger.warning("Invalid JSON schema for arg '%s': %s", arg_name, e.message)
            return [
                ValidationFailure(
                    validator_type="json_schema",
                    arg_name=arg_name,
                    reason=f"Invalid schema: {e.message}",
                )
            ]

    @staticmethod
    def _validate_regex(
        arg_name: str, arg_str: str, pattern: str
    ) -> list[ValidationFailure]:
        """Validate an argument string against a regex pattern (APEP-094)."""
        try:
            if not re.fullmatch(pattern, arg_str):
                return [
                    ValidationFailure(
                        validator_type="regex",
                        arg_name=arg_name,
                        reason=f"Value does not match pattern '{pattern}'",
                    )
                ]
            return []
        except re.error as e:
            return [
                ValidationFailure(
                    validator_type="regex",
                    arg_name=arg_name,
                    reason=f"Invalid regex pattern: {e}",
                )
            ]

    @staticmethod
    def _validate_allowlist(
        arg_name: str, arg_str: str, allowlist: list[str]
    ) -> list[ValidationFailure]:
        """Validate an argument is in the allowlist (APEP-095)."""
        if arg_str not in allowlist:
            return [
                ValidationFailure(
                    validator_type="allowlist",
                    arg_name=arg_name,
                    reason=f"Value '{arg_str}' not in allowlist",
                )
            ]
        return []

    @staticmethod
    def _validate_blocklist(
        arg_name: str, arg_str: str, blocklist: list[str]
    ) -> list[ValidationFailure]:
        """Validate an argument is NOT in the blocklist (APEP-095)."""
        if arg_str in blocklist:
            return [
                ValidationFailure(
                    validator_type="blocklist",
                    arg_name=arg_name,
                    reason=f"Value '{arg_str}' is in blocklist",
                )
            ]
        return []


# Module-level singleton
validator_pipeline = ValidatorPipeline()
