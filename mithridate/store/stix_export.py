"""STIX 2.1 export — converts intel records to a STIX bundle.

Emits: Indicator (IOCs), AttackPattern (techniques), Relationship objects.
STIX makes the output consumable by real threat-intel tools (OpenCTI, MISP, etc.).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from mithridate.models import IOC, IntelRecord, TechniqueMapping

logger = logging.getLogger(__name__)

_STIX_IOC_TYPE: dict[str, str] = {
    "ipv4": "ipv4-addr",
    "ipv6": "ipv6-addr",
    "domain": "domain-name",
    "url": "url",
    "md5": "file",
    "sha1": "file",
    "sha256": "file",
    "email": "email-addr",
    "cve": "vulnerability",
}

_STIX_PATTERN_TEMPLATE: dict[str, str] = {
    "ipv4": "[ipv4-addr:value = '{value}']",
    "ipv6": "[ipv6-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
    "md5": "[file:hashes.MD5 = '{value}']",
    "sha1": "[file:hashes.'SHA-1' = '{value}']",
    "sha256": "[file:hashes.'SHA-256' = '{value}']",
    "email": "[email-addr:value = '{value}']",
    "cve": "[vulnerability:name = '{value}']",
}


def _make_id(obj_type: str, value: str) -> str:
    import hashlib
    digest = hashlib.sha256(f"{obj_type}:{value}".encode()).hexdigest()
    return f"{obj_type}--{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def ioc_to_stix_indicator(ioc: IOC) -> dict[str, Any]:
    pattern_tmpl = _STIX_PATTERN_TEMPLATE.get(ioc.type, "[unknown:value = '{value}']")
    pattern = pattern_tmpl.format(value=ioc.value)
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _make_id("indicator", f"{ioc.type}:{ioc.value}"),
        "name": f"{ioc.type.upper()}: {ioc.value}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": ioc.first_seen.isoformat() + "Z",
        "confidence": int(ioc.confidence * 100),
        "labels": [ioc.type],
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
    }


def technique_to_stix_attack_pattern(mapping: TechniqueMapping) -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": _make_id("attack-pattern", mapping.technique_id),
        "name": mapping.technique_name,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": mapping.technique_id,
                "url": f"https://attack.mitre.org/techniques/{mapping.technique_id.replace('.', '/')}",
            }
        ],
        "confidence": int(mapping.confidence * 100),
        "description": mapping.rationale,
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
    }


def make_relationship(source_id: str, target_id: str, relationship_type: str) -> dict[str, Any]:
    rel_key = f"{source_id}:{target_id}:{relationship_type}"
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": _make_id("relationship", rel_key),
        "relationship_type": relationship_type,
        "source_ref": source_id,
        "target_ref": target_id,
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
    }


def records_to_stix_bundle(records: list[IntelRecord]) -> dict[str, Any]:
    """Convert a list of IntelRecords to a STIX 2.1 bundle."""
    objects: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    indicator_ids: list[str] = []
    attack_pattern_ids: list[str] = []

    for record in records:
        for ioc in record.iocs:
            stix_obj = ioc_to_stix_indicator(ioc)
            if stix_obj["id"] not in seen_ids:
                objects.append(stix_obj)
                seen_ids.add(stix_obj["id"])
                indicator_ids.append(stix_obj["id"])

        for tech in record.techniques:
            stix_obj = technique_to_stix_attack_pattern(tech)
            if stix_obj["id"] not in seen_ids:
                objects.append(stix_obj)
                seen_ids.add(stix_obj["id"])
                attack_pattern_ids.append(stix_obj["id"])

    # Link each indicator to each technique via 'indicates' relationship
    for ind_id in indicator_ids:
        for ap_id in attack_pattern_ids:
            rel = make_relationship(ind_id, ap_id, "indicates")
            if rel["id"] not in seen_ids:
                objects.append(rel)
                seen_ids.add(rel["id"])

    bundle_id = _make_id("bundle", f"mithridate-{datetime.utcnow().isoformat()}")
    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects,
    }


def export_to_file(records: list[IntelRecord], output_path: Path) -> None:
    bundle = records_to_stix_bundle(records)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bundle, indent=2))
    logger.info("Exported %d STIX objects to %s", len(bundle["objects"]), output_path)
