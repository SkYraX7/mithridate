"""Heuristic injection detector — deterministic rule/regex layer.

Every rule that fires records a signal string for the audit log.
No LLM calls here — this layer must be fully deterministic and auditable.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Rule patterns — ordered from most specific to least specific
# ---------------------------------------------------------------------------

# Classic direct injection phrases
_DIRECT_INJECTION = [
    (re.compile(r"\bignore\s+(all\s+)?previous\s+instructions?\b", re.I), "injection:ignore_previous"),
    (re.compile(r"\bdisregard\s+(all\s+)?prior\s+instructions?\b", re.I), "injection:disregard_prior"),
    (re.compile(r"\bforget\s+everything\s+(you\s+)?(were\s+)?told\b", re.I), "injection:forget_everything"),
    (re.compile(r"\byou\s+are\s+now\s+(a|an|the)\b", re.I), "injection:role_reassignment"),
    (re.compile(r"\byour\s+new\s+(role|task|instructions?|job)\b", re.I), "injection:new_role"),
    (re.compile(r"\bact\s+as\s+(a|an|the)\b", re.I), "injection:act_as"),
    (re.compile(r"\bpretend\s+(you\s+are|to\s+be)\b", re.I), "injection:pretend"),
    (re.compile(r"\boverride\s+(all\s+)?(previous\s+|prior\s+)?instructions?\b", re.I), "injection:override"),
    (re.compile(r"\binstructions?\s+override\b", re.I), "injection:instructions_override"),
]

# System-prompt-style markers often used to inject fake context
_SYSTEM_PROMPT_MARKERS = [
    (re.compile(r"\[SYSTEM\]", re.I), "injection:system_marker"),
    (re.compile(r"<\s*system\s*>", re.I), "injection:system_tag"),
    (re.compile(r"\[INST\]", re.I), "injection:inst_marker"),
    (re.compile(r"<\s*\|?im_start\|?\s*>", re.I), "injection:im_start_tag"),
    (re.compile(r"###\s*(Instructions?|System|Human|Assistant)\s*:", re.I), "injection:header_marker"),
    (re.compile(r"<\s*instructions?\s*>", re.I), "injection:instructions_tag"),
]

# Tool-call mimicry — content attempting to look like a tool invocation
_TOOL_COERCION = [
    (re.compile(r"\bcall\s+(the\s+)?(tool|function|api|endpoint)\b", re.I), "injection:tool_call"),
    (re.compile(r"\bexecute\s+(the\s+)?(tool|function|command)\b", re.I), "injection:execute_tool"),
    (re.compile(r"\bdelete[_\s]all[_\s](records?|entries?|data)\b", re.I), "injection:delete_all"),
    (re.compile(r"\bdrop\s+(table|database|collection)\b", re.I), "injection:drop_table"),
    (re.compile(r'"tool"\s*:\s*"[^"]{1,100}"', re.I), "injection:json_tool_field"),
    (re.compile(r'"function"\s*:\s*"[^"]{1,100}"', re.I), "injection:json_function_field"),
]

# Confidence/classification override attempts
_VERDICT_OVERRIDE = [
    (re.compile(r"\bmark\s+(?:this\s+)?(?:it|document|doc|report|file)\s+as\s+(benign|clean|safe|trusted)\b", re.I), "injection:verdict_override"),
    (re.compile(r"\bclassify\s+(this|it)\s+as\s+(benign|safe|clean|not\s+malicious)\b", re.I), "injection:classify_benign"),
    (re.compile(r"\b(confidence|score)\s*[:=]\s*1\.0\b", re.I), "injection:force_confidence_1"),
    (re.compile(r"\bset\s+(confidence|score)\s+to\s+(1\.?0?|100%?)\b", re.I), "injection:set_confidence_max"),
    (re.compile(r"\bthis\s+(document|report|file)\s+is\s+(safe|benign|clean|trusted)\b", re.I), "injection:claim_benign"),
]

# Multilingual injection patterns — same semantics in other languages
_MULTILINGUAL = [
    # Spanish
    (re.compile(r"\bignorar?\s+(todas\s+las\s+)?instrucciones?\s+anteriores?\b", re.I), "injection:es_ignore_previous"),
    (re.compile(r"\bolvidar?\s+todo\b", re.I), "injection:es_forget_everything"),
    # French
    (re.compile(r"\bignorer?\s+(toutes\s+les\s+)?instructions?\s+précédentes?\b", re.I), "injection:fr_ignore_previous"),
    # German
    (re.compile(r"\bignoriere?\s+(alle\s+)?vorherigen\s+Anweisungen\b", re.I), "injection:de_ignore_previous"),
    # Russian (transliterated)
    (re.compile(r"\bпроигнорируй\s+(все\s+)?предыдущие\s+инструкции\b", re.I), "injection:ru_ignore_previous"),
    (re.compile(r"\bзабудь\s+всё\b", re.I), "injection:ru_forget_everything"),
    # Chinese simplified
    (re.compile(r"忽略.*指令|忘记.*一切", re.I), "injection:zh_ignore_instructions"),
]

# Role-play preamble patterns
_ROLEPLAY = [
    (re.compile(r"\bDAN\b"), "injection:DAN_jailbreak"),
    (re.compile(r"\bjailbreak\b", re.I), "injection:jailbreak"),
    (re.compile(r"\bDeveloper\s+Mode\b", re.I), "injection:developer_mode"),
    (re.compile(r"\bgodmode\b", re.I), "injection:godmode"),
    (re.compile(r"\bunrestricted\s+(AI|assistant|mode)\b", re.I), "injection:unrestricted_mode"),
]

# IOC flooding heuristic — a single document with suspiciously many unique IPs
_IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

IOC_FLOOD_THRESHOLD = 100
"""Documents containing more than this many unique IPs are flagged as potential flooding (A3)."""

ALL_RULE_GROUPS = [
    _DIRECT_INJECTION,
    _SYSTEM_PROMPT_MARKERS,
    _TOOL_COERCION,
    _VERDICT_OVERRIDE,
    _MULTILINGUAL,
    _ROLEPLAY,
]


def detect(text: str) -> tuple[list[str], float]:
    """Run all heuristic detectors against the normalized text.

    Returns:
        (signals, score) — signals is the list of rule IDs that fired;
        score is a rough injection likelihood in [0, 1].
    """
    signals: list[str] = []

    for rule_group in ALL_RULE_GROUPS:
        for pattern, signal_name in rule_group:
            if pattern.search(text):
                signals.append(signal_name)

    # IOC flooding check
    unique_ips = set(_IP_PATTERN.findall(text))
    if len(unique_ips) > IOC_FLOOD_THRESHOLD:
        signals.append(f"ioc_flood:unique_ips={len(unique_ips)}")

    # Compute a simple score: weighted by severity
    high_severity = sum(
        1
        for s in signals
        if any(
            s.startswith(p)
            for p in ("injection:ignore", "injection:disregard", "injection:forget", "injection:override")
        )
    )
    medium_severity = len(signals) - high_severity

    score = min(1.0, (high_severity * 0.4 + medium_severity * 0.15))
    return signals, score
