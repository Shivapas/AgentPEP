"""Trust score calculator — linear decay per delegation hop.

Implements the trust degradation model defined in PRD v2.1 FEATURE-04:

    trust_score(n) = (1 - decay_rate) ^ n

where n is the number of delegation hops from the root principal (hop 0 = root,
full trust score 1.0).

Default parameters (PRD v2.1 baseline):
  decay_rate           = 0.15   (15% decay per hop)
  min_trust_threshold  = 0.10   (chain terminates if score falls below this)
  max_hop_count        = 10     (hard cap regardless of computed score)

Sprint S-E06 (E06-T02)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.trust.delegation_context import DelegationContext


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustScoreConfig:
    """Operator-configurable trust score parameters.

    All fields have PRD v2.1 defaults.  Operators may tighten (increase
    decay_rate, raise min_trust_threshold) but the FAIL_CLOSED behaviour —
    chain termination when below threshold or hop limit exceeded — is not
    configurable away.
    """

    decay_rate: float = 0.15
    min_trust_threshold: float = 0.10
    max_hop_count: int = 10

    def __post_init__(self) -> None:
        if not (0.0 < self.decay_rate < 1.0):
            raise ValueError(
                f"decay_rate must be in (0, 1), got {self.decay_rate!r}"
            )
        if not (0.0 <= self.min_trust_threshold < 1.0):
            raise ValueError(
                f"min_trust_threshold must be in [0, 1), got {self.min_trust_threshold!r}"
            )
        if self.max_hop_count < 1:
            raise ValueError(
                f"max_hop_count must be >= 1, got {self.max_hop_count!r}"
            )


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustScore:
    """Result of a single trust score calculation.

    Attributes:
        score:              Computed trust score in [0.0, 1.0].
        hop_count:          Number of delegation hops used in the calculation.
        below_threshold:    True if score < min_trust_threshold.
        max_hops_exceeded:  True if hop_count > max_hop_count.
    """

    score: float
    hop_count: int
    below_threshold: bool
    max_hops_exceeded: bool

    @property
    def chain_must_terminate(self) -> bool:
        """True when trust enforcement must block further delegation or tool use."""
        return self.below_threshold or self.max_hops_exceeded


# ---------------------------------------------------------------------------
# Calculator
# ---------------------------------------------------------------------------


class TrustScoreCalculator:
    """Computes degraded trust scores for delegation chains.

    Formula:  score(n) = max(0.0, min(1.0, (1 - decay_rate) ^ hop_count))

    A score of 1.0 is only possible at hop_count == 0 (root principal).
    """

    def __init__(self, config: TrustScoreConfig | None = None) -> None:
        self._config = config or TrustScoreConfig()

    @property
    def config(self) -> TrustScoreConfig:
        return self._config

    def calculate(self, hop_count: int) -> TrustScore:
        """Calculate the trust score for a given hop count.

        Args:
            hop_count: Number of delegation hops (0 = root principal, full trust).

        Returns:
            TrustScore with computed score and termination flags.

        Raises:
            ValueError: If hop_count is negative.
        """
        if hop_count < 0:
            raise ValueError(f"hop_count must be >= 0, got {hop_count!r}")

        raw = (1.0 - self._config.decay_rate) ** hop_count
        score = max(0.0, min(1.0, raw))

        return TrustScore(
            score=score,
            hop_count=hop_count,
            below_threshold=score < self._config.min_trust_threshold,
            max_hops_exceeded=hop_count > self._config.max_hop_count,
        )

    def from_context(self, ctx: "DelegationContext") -> TrustScore:
        """Calculate trust score directly from a DelegationContext."""
        return self.calculate(ctx.hop_count)

    def hops_until_termination(self) -> int:
        """Return the first hop count at which the chain must terminate.

        The chain terminates when either:
          - score < min_trust_threshold, or
          - hop_count > max_hop_count

        Useful for operator documentation and LangGraph workflow validation.
        """
        for n in range(self._config.max_hop_count + 2):
            score = (1.0 - self._config.decay_rate) ** n
            if score < self._config.min_trust_threshold:
                return n
        return self._config.max_hop_count + 1


# ---------------------------------------------------------------------------
# Module-level singleton (default PRD v2.1 config)
# ---------------------------------------------------------------------------

trust_score_calculator = TrustScoreCalculator()
