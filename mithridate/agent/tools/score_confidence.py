"""Confidence scoring tool — adjusts IOC and technique confidence based on context.

Factors: source trust tier, screening score (higher = less trustworthy),
initial extractor confidence, and per-type heuristics.
"""

from __future__ import annotations

from mithridate.models import (
    IOC,
    ScoreConfidenceInput,
    ScoreConfidenceOutput,
    TechniqueMapping,
    TrustTier,
)

_TRUST_TIER_MULTIPLIER: dict[TrustTier, float] = {
    "high": 1.0,
    "medium": 0.85,
    "low": 0.65,
}


def score_confidence(input_data: ScoreConfidenceInput) -> ScoreConfidenceOutput:
    """Adjust confidence scores based on source trust tier and screening result."""
    tier_mult = _TRUST_TIER_MULTIPLIER.get(input_data.trust_tier, 0.65)

    # Screening score is injection likelihood — penalize if > 0
    screening_penalty = input_data.screening_score * 0.3

    iocs_scored: list[IOC] = []
    for ioc in input_data.iocs:
        adjusted = ioc.confidence * tier_mult * (1.0 - screening_penalty)
        adjusted = max(0.0, min(1.0, adjusted))
        iocs_scored.append(ioc.model_copy(update={"confidence": round(adjusted, 4)}))

    techs_scored: list[TechniqueMapping] = []
    for tech in input_data.techniques:
        adjusted = tech.confidence * tier_mult * (1.0 - screening_penalty)
        adjusted = max(0.0, min(1.0, adjusted))
        techs_scored.append(tech.model_copy(update={"confidence": round(adjusted, 4)}))

    return ScoreConfidenceOutput(iocs=iocs_scored, techniques=techs_scored)
