"""Deduplication tool — filters IOCs and techniques already in the store.

Prevents re-adding existing intel on subsequent runs.
Store lookup is injected to keep this testable and the tool pure.
"""

from __future__ import annotations

from collections.abc import Callable

from mithridate.models import IOC, DedupeCheckInput, DedupeCheckOutput, TechniqueMapping


def dedupe_check(
    input_data: DedupeCheckInput,
    ioc_exists: Callable[[str, str], bool],
) -> DedupeCheckOutput:
    """Return only IOCs and techniques not already in the store.

    Args:
        input_data: candidates to check
        ioc_exists: callable(type, value) -> bool — injected store lookup
    """
    new_iocs: list[IOC] = []
    dup_count = 0
    for ioc in input_data.iocs:
        if ioc_exists(ioc.type, ioc.value):
            dup_count += 1
        else:
            new_iocs.append(ioc)

    # Techniques: dedupe by technique_id (allow same tech from different docs)
    seen_ids: set[str] = set()
    new_techs: list[TechniqueMapping] = []
    dup_tech_count = 0
    for tech in input_data.techniques:
        if tech.technique_id in seen_ids:
            dup_tech_count += 1
        else:
            seen_ids.add(tech.technique_id)
            new_techs.append(tech)

    return DedupeCheckOutput(
        new_iocs=new_iocs,
        duplicate_ioc_count=dup_count,
        new_techniques=new_techs,
        duplicate_technique_count=dup_tech_count,
    )
