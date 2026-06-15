"""ATT&CK mapping tool — validates technique IDs against the bundled matrix.

Any technique ID not present in the bundled matrix is dropped and logged as
a hallucination event, incrementing the hallucinated-indicator metric (§7.4, A6).
"""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path

from mithridate.models import MapAttackInput, MapAttackOutput, TechniqueMapping

logger = logging.getLogger(__name__)

_DATA_PATH = Path(__file__).parent.parent.parent / "data" / "attack_techniques.json"


@lru_cache(maxsize=1)
def _load_matrix() -> dict[str, str]:
    """Load and cache the bundled ATT&CK technique matrix."""
    if not _DATA_PATH.exists():
        logger.warning("ATT&CK matrix not found at %s — technique validation disabled", _DATA_PATH)
        return {}
    data = json.loads(_DATA_PATH.read_text())
    return {k.upper(): v for k, v in data.get("techniques", {}).items()}


def map_attack(input_data: MapAttackInput) -> MapAttackOutput:
    """Validate candidate ATT&CK technique IDs against the bundled matrix.

    Security: this is the output-validation gate for ATT&CK IDs (§7.4, A6 defense).
    Any technique ID absent from the bundled matrix is considered hallucinated,
    dropped, and logged.
    """
    matrix = _load_matrix()
    mappings: list[TechniqueMapping] = []
    hallucinated: list[str] = []

    for technique_id in input_data.candidate_ids:
        normalized_id = technique_id.upper().strip()

        if matrix and normalized_id not in matrix:
            logger.warning(
                "Hallucinated ATT&CK technique %r from doc %s — dropping",
                technique_id,
                input_data.source_doc_id,
            )
            hallucinated.append(technique_id)
            continue

        technique_name = matrix.get(normalized_id, "Unknown Technique")
        rationale = input_data.rationales.get(technique_id, input_data.rationales.get(normalized_id, ""))

        try:
            mapping = TechniqueMapping(
                technique_id=normalized_id,
                technique_name=technique_name,
                confidence=0.7,  # default; overridden by score_confidence tool
                rationale=rationale,
            )
            mappings.append(mapping)
        except Exception as exc:
            logger.warning("Failed to create TechniqueMapping for %r: %s", technique_id, exc)
            hallucinated.append(technique_id)

    if hallucinated:
        logger.info("Hallucinated technique count from doc %s: %d", input_data.source_doc_id, len(hallucinated))

    return MapAttackOutput(mappings=mappings, hallucinated=hallucinated)


def is_valid_technique(technique_id: str) -> bool:
    """Check whether a technique ID exists in the bundled matrix."""
    matrix = _load_matrix()
    return not matrix or technique_id.upper() in matrix
