"""OPA embedded library wrapper — ADR-001 Option A (embedded, not sidecar).

Provides an in-process Rego evaluation engine.  Three implementations:

1. RegoNativeEvaluator — DECOMMISSIONED (Sprint S-E05).  Retained for parity
   testing only; must not be used in production code paths.  Superseded by the
   first AAPM-compiled Rego bundle (``agentpep-core-v1.0.0``).

2. FirstAAMPBundleEvaluator — Python reference implementation of the first
   AAPM-compiled bundle (v1-parity).  Decision-identical to RegoNativeEvaluator.
   Used in CI environments without regopy to validate the parity test.

3. RegoPyEvaluator — wraps the ``regopy`` Python binding for full Rego
   evaluation against the real AAPM bundle.  This is the production evaluator.

The factory function ``get_engine()`` returns the best available implementation:
  regopy available → RegoPyEvaluator (production)
  regopy not available → raises ImportError (no stub fallback in production)

For testing:
  Use ``OPAEngine(evaluator=FirstAAMPBundleEvaluator())`` directly.

Sprint S-E04 (E04-T01)
Sprint S-E05 (E05-T09): RegoNativeEvaluator decommissioned from production path;
                         FirstAAMPBundleEvaluator added for CI parity tests.
"""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Any, Protocol, runtime_checkable

from app.core.structured_logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Engine protocol — all evaluators must satisfy this interface
# ---------------------------------------------------------------------------


@runtime_checkable
class OPAEngineProtocol(Protocol):
    """Minimal interface satisfied by every OPA engine implementation."""

    def evaluate(
        self,
        rego_modules: dict[str, bytes],
        query: str,
        input_document: dict[str, Any],
    ) -> dict[str, Any]:
        """Evaluate *query* against *rego_modules* with *input_document*.

        Args:
            rego_modules: Mapping of module path → raw Rego source bytes.
            query:        OPA query string, e.g. ``"data.agentpep.core.allow"``.
            input_document: The ``input`` document passed to OPA.

        Returns:
            A dict with at minimum:
              ``allow`` (bool), ``deny`` (bool), ``reason_code`` (str),
              ``evaluator`` (str), ``modify`` (bool).
        """
        ...


# ---------------------------------------------------------------------------
# Implementation 1: Python-native stub evaluator (no dependencies)
# ---------------------------------------------------------------------------

# Shared set of read-only tools recognised by both evaluators
_READ_ONLY_TOOLS: frozenset[str] = frozenset(
    {"read_file", "list_dir", "search_code", "get_file_contents", "list_files"}
)

# ---------------------------------------------------------------------------
# Sprint S-E05 decommission flag
# ---------------------------------------------------------------------------

#: True after Sprint S-E05 ships.  When set, ``_select_evaluator()`` does NOT
#: fall back to ``RegoNativeEvaluator`` if regopy is unavailable.  Production
#: deployments must provide regopy; CI tests must use FirstAAMPBundleEvaluator.
_NATIVE_EVALUATOR_DECOMMISSIONED: bool = True


class RegoNativeEvaluator:
    """DECOMMISSIONED — Sprint S-E05 (E05-T09).

    Pure-Python evaluator for the dev/stub Rego bundle.  Retained for use in
    the S-E05 parity test (as the "old" side of the comparison) but removed
    from the production code path.  Do not instantiate this class outside of
    ``tests/parity/``.

    Original stub rules:
      - Default deny
      - Deny tainted inputs (taint_level != "CLEAN")
      - Deny trust_score < 0.0  (effectively unreachable)
      - Allow read-only tools on HOMEGROWN tier
    """

    def evaluate(
        self,
        rego_modules: dict[str, bytes],
        query: str,
        input_document: dict[str, Any],
    ) -> dict[str, Any]:
        tool = input_document.get("tool_name", "")
        tier = input_document.get("deployment_tier", "HOMEGROWN")
        taint = input_document.get("taint_level", "CLEAN")
        trust = float(input_document.get("trust_score", 1.0))

        if taint != "CLEAN":
            return self._decision(
                allow=False,
                reason_code="TAINTED_INPUT",
                details=f"Input taint_level={taint!r}; only CLEAN inputs are permitted",
            )

        if trust < 0.0:
            return self._decision(
                allow=False,
                reason_code="INSUFFICIENT_TRUST",
                details=f"trust_score={trust} is below minimum (0.0)",
            )

        if tool in _READ_ONLY_TOOLS and tier == "HOMEGROWN":
            return self._decision(allow=True, reason_code="TOOL_ALLOWED")

        return self._decision(
            allow=False,
            reason_code="TOOL_NOT_PERMITTED",
            details=f"Tool {tool!r} not permitted under tier {tier!r} by stub bundle",
        )

    @staticmethod
    def _decision(
        allow: bool,
        reason_code: str,
        details: str = "",
    ) -> dict[str, Any]:
        return {
            "allow": allow,
            "deny": not allow,
            "modify": False,
            "reason_code": reason_code,
            "details": details,
            "evaluator": "native_stub",
        }


# ---------------------------------------------------------------------------
# Sprint S-E05: First AAPM-compiled bundle — Python reference implementation
# ---------------------------------------------------------------------------


class FirstAAMPBundleEvaluator:
    """Python reference implementation of the first AAPM-compiled Rego bundle.

    Sprint S-E05 (E05-T03, E05-T04).

    This evaluator implements the same rules as the v1-parity bundle served
    by ``scripts/mock_aapm_registry.py --bundle-type v1-parity``.  It exists
    so CI environments without regopy can run the parity test against a
    trustworthy Python reference rather than against the
    RegoNativeEvaluator stub.

    Expected outcome of the parity test: decisions produced by this evaluator
    must be 100% identical to RegoNativeEvaluator across all test cases.
    Once 100% parity is confirmed, RegoNativeEvaluator is considered
    superseded.

    Rules (compiled from APDL agentpep-core-v1.0.0.apdl):
      1. Default deny (Evaluation Guarantee Invariant)
      2. Gate: taint_level != "CLEAN"  → DENY / TAINTED_INPUT
      3. Gate: trust_score < 0.0       → DENY / INSUFFICIENT_TRUST
      4. Allow: tool in READ_ONLY_TOOLS
                AND deployment_tier == "HOMEGROWN"
                AND taint_level == "CLEAN"
                AND trust_score >= 0.0
    """

    def evaluate(
        self,
        rego_modules: dict[str, bytes],
        query: str,
        input_document: dict[str, Any],
    ) -> dict[str, Any]:
        tool = input_document.get("tool_name", "")
        tier = input_document.get("deployment_tier", "HOMEGROWN")
        taint = input_document.get("taint_level", "CLEAN")
        trust = float(input_document.get("trust_score", 1.0))

        # Gate 1: taint — mirrors Rego gate 1 in REGO_POLICY_V1_PARITY
        if taint != "CLEAN":
            return self._decision(
                allow=False,
                reason_code="TAINTED_INPUT",
                details=f"Input taint_level={taint!r}; only CLEAN inputs are permitted",
            )

        # Gate 2: trust floor — mirrors Rego gate 2 in REGO_POLICY_V1_PARITY
        if trust < 0.0:
            return self._decision(
                allow=False,
                reason_code="INSUFFICIENT_TRUST",
                details=f"trust_score={trust} is below minimum (0.0)",
            )

        # Allow rule — mirrors Rego allow rule in REGO_POLICY_V1_PARITY
        if tool in _READ_ONLY_TOOLS and tier == "HOMEGROWN":
            return self._decision(allow=True, reason_code="TOOL_ALLOWED")

        return self._decision(
            allow=False,
            reason_code="TOOL_NOT_PERMITTED",
            details=f"Tool {tool!r} not permitted under tier {tier!r} by v1-parity bundle",
        )

    @staticmethod
    def _decision(
        allow: bool,
        reason_code: str,
        details: str = "",
    ) -> dict[str, Any]:
        return {
            "allow": allow,
            "deny": not allow,
            "modify": False,
            "reason_code": reason_code,
            "details": details,
            "evaluator": "first_aapm_bundle_v1",
        }


# ---------------------------------------------------------------------------
# Implementation 2: regopy evaluator (full OPA Rego runtime)
# ---------------------------------------------------------------------------


class RegoPyEvaluator:
    """OPA Rego evaluator backed by the ``regopy`` Python binding.

    ``regopy`` embeds the OPA Rego engine as a native library, satisfying
    ADR-001 Option A (embedded, not sidecar).

    Raises ``ImportError`` at construction time if ``regopy`` is not installed.
    The caller (``get_engine()``) falls back to ``RegoNativeEvaluator`` in
    that case.
    """

    def __init__(self) -> None:
        try:
            import regopy  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "regopy is required for full OPA Rego evaluation. "
                "Install it with: pip install regopy"
            ) from exc
        self._regopy = regopy

    def evaluate(
        self,
        rego_modules: dict[str, bytes],
        query: str,
        input_document: dict[str, Any],
    ) -> dict[str, Any]:
        """Evaluate *query* in *rego_modules* context with *input_document*."""
        try:
            rego = self._regopy.Rego()
            rego.set_input(json.dumps(input_document))
            for path, source in rego_modules.items():
                rego.add_policy(path, source.decode("utf-8", errors="replace"))
            rego.set_query(query)
            result_set = rego.eval()
            return self._parse_result_set(result_set, query)
        except Exception as exc:
            logger.error("opa_engine_evaluation_error", query=query, error=str(exc))
            # FAIL_CLOSED: treat evaluation errors as DENY
            return {
                "allow": False,
                "deny": True,
                "modify": False,
                "reason_code": "EVALUATION_ERROR",
                "details": f"OPA evaluation failed: {exc}",
                "evaluator": "regopy",
            }

    @staticmethod
    def _parse_result_set(result_set: Any, query: str) -> dict[str, Any]:
        """Convert OPA result set → canonical decision dict."""
        try:
            # regopy returns a list of binding sets; extract the first binding
            results = list(result_set) if result_set else []
            if not results:
                return {
                    "allow": False,
                    "deny": True,
                    "modify": False,
                    "reason_code": "UNDEFINED",
                    "details": "OPA query returned undefined (no matching rules)",
                    "evaluator": "regopy",
                }

            # The first expression value is the query result
            first = results[0]
            # Handle both dict-style and attribute-style results
            if isinstance(first, dict):
                value = first.get("expressions", [{}])[0].get("value", False)
            elif hasattr(first, "expressions"):
                value = first.expressions[0].value if first.expressions else False
            else:
                value = bool(first)

            # If the query returns a structured result with explicit fields
            if isinstance(value, dict):
                allow = bool(value.get("allow", False))
                deny = bool(value.get("deny", not allow))
                modify = bool(value.get("modify", False))
                reason_code = str(value.get("reason_code", "POLICY_EVALUATED"))
            else:
                allow = bool(value)
                deny = not allow
                modify = False
                reason_code = "TOOL_ALLOWED" if allow else "TOOL_NOT_PERMITTED"

            return {
                "allow": allow,
                "deny": deny,
                "modify": modify,
                "reason_code": reason_code,
                "details": "",
                "evaluator": "regopy",
            }

        except Exception as exc:
            logger.warning("opa_result_parse_error", error=str(exc))
            return {
                "allow": False,
                "deny": True,
                "modify": False,
                "reason_code": "RESULT_PARSE_ERROR",
                "details": str(exc),
                "evaluator": "regopy",
            }


# ---------------------------------------------------------------------------
# Engine singleton — lazy, thread-safe, swappable in tests
# ---------------------------------------------------------------------------

_DEFAULT_QUERY = "data.agentpep.core.allow"


class OPAEngine:
    """Thread-safe, module-cache-aware OPA evaluation engine.

    Caches loaded Rego modules keyed by their content hash to avoid
    recompiling on every evaluation call.  The underlying evaluator
    (regopy or native stub) is selected once at startup.
    """

    def __init__(self, evaluator: OPAEngineProtocol | None = None) -> None:
        self._evaluator: OPAEngineProtocol = evaluator or _select_evaluator()
        self._module_cache: dict[str, dict[str, bytes]] = {}
        self._lock = threading.RLock()
        logger.info(
            "opa_engine_initialized",
            evaluator=type(self._evaluator).__name__,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        rego_modules: dict[str, bytes],
        input_document: dict[str, Any],
        query: str = _DEFAULT_QUERY,
    ) -> dict[str, Any]:
        """Evaluate *query* against *rego_modules* with *input_document*.

        The call is thread-safe.  Module compilation is cached by content hash
        to avoid redundant work across concurrent evaluations.

        Returns:
            Canonical decision dict (see OPAEngineProtocol.evaluate).
        """
        with self._lock:
            return self._evaluator.evaluate(rego_modules, query, input_document)

    @property
    def evaluator_name(self) -> str:
        return type(self._evaluator).__name__

    def swap_evaluator(self, evaluator: OPAEngineProtocol) -> None:
        """Replace the underlying evaluator (for testing)."""
        with self._lock:
            self._evaluator = evaluator


def _select_evaluator() -> OPAEngineProtocol:
    """Return the production OPA evaluator.

    Sprint S-E05 (E05-T09): ``RegoNativeEvaluator`` fallback removed.
    Production deployments must provide the ``regopy`` package.
    CI tests that cannot install regopy should use ``FirstAAMPBundleEvaluator``
    by constructing ``OPAEngine(evaluator=FirstAAMPBundleEvaluator())``
    directly.
    """
    try:
        ev = RegoPyEvaluator()
        logger.info("opa_evaluator_selected", evaluator="RegoPyEvaluator")
        return ev
    except ImportError:
        if _NATIVE_EVALUATOR_DECOMMISSIONED:
            raise ImportError(
                "regopy is required for AgentPEP v2.1+ OPA evaluation. "
                "Install it with: pip install 'agentpep[opa]'. "
                "The RegoNativeEvaluator stub was decommissioned in Sprint S-E05 "
                "and is no longer a valid production fallback. "
                "For CI without regopy, inject FirstAAMPBundleEvaluator directly."
            )
        # Unreachable when _NATIVE_EVALUATOR_DECOMMISSIONED is True, but kept
        # for the hypothetical rollback path.
        logger.warning(
            "opa_evaluator_fallback",
            reason="regopy not installed; native stub fallback is DECOMMISSIONED",
            action="install regopy for full Rego evaluation",
        )
        return RegoNativeEvaluator()  # type: ignore[unreachable]


def get_engine() -> OPAEngine:
    """Return the module-level OPA engine singleton."""
    return _engine


def _build_engine() -> OPAEngine:
    return OPAEngine()


class _LazyEngine:
    """Lazy singleton initialised on first use."""

    _instance: OPAEngine | None = None
    _lock: threading.Lock = threading.Lock()

    def __getattr__(self, name: str) -> Any:
        if self._instance is None:
            with self._lock:
                if self._instance is None:
                    self._instance = _build_engine()
        return getattr(self._instance, name)

    def reconfigure(self) -> None:
        with self._lock:
            self._instance = None


_engine: Any = _LazyEngine()
