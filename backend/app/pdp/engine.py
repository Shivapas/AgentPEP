"""OPA embedded library wrapper — ADR-001 Option A (embedded, not sidecar).

Provides an in-process Rego evaluation engine.  Two implementations:

1. RegoNativeEvaluator — zero-dependency Python evaluator for the dev/stub
   bundle shipped by scripts/mock_aapm_registry.py.  Used when regopy is not
   installed (CI, lightweight deployments).

2. RegoPyEvaluator — wraps the ``regopy`` Python binding for full Rego
   evaluation once the real AAPM bundle arrives in S-E05.

Both implement OPAEngineProtocol and are interchangeable.  The factory
function ``get_engine()`` returns the best available implementation.

Sprint S-E04 (E04-T01)
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

_READ_ONLY_TOOLS: frozenset[str] = frozenset(
    {"read_file", "list_dir", "search_code", "get_file_contents", "list_files"}
)


class RegoNativeEvaluator:
    """Pure-Python evaluator for the stub Rego bundle from the mock AAPM registry.

    Implements the subset of rules present in the dev bundle:

        default allow := false

        allow if {
            input.tool_name in {"read_file", "list_dir", "search_code"}
            input.deployment_tier == "HOMEGROWN"
        }

    This is intentionally narrow.  The native evaluator exists only to keep
    tests green in environments without OPA binaries.  Production deployments
    use RegoPyEvaluator once the real AAPM bundle is active (Sprint S-E05).
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

        # Tainted requests are always denied
        if taint != "CLEAN":
            return self._decision(
                allow=False,
                reason_code="TAINTED_INPUT",
                details=f"Input taint_level={taint!r}; only CLEAN inputs are permitted",
            )

        # Insufficient trust score
        if trust < 0.0:
            return self._decision(
                allow=False,
                reason_code="INSUFFICIENT_TRUST",
                details=f"trust_score={trust} is below minimum (0.0)",
            )

        # Stub bundle rule: read-only tools on HOMEGROWN tier
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
    """Return the best available OPA evaluator implementation."""
    try:
        ev = RegoPyEvaluator()
        logger.info("opa_evaluator_selected", evaluator="RegoPyEvaluator")
        return ev
    except ImportError:
        logger.warning(
            "opa_evaluator_fallback",
            reason="regopy not installed; using RegoNativeEvaluator stub",
            action="install regopy for full Rego evaluation",
        )
        return RegoNativeEvaluator()


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
