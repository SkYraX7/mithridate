"""Text normalization — applied before any screening or LLM call.

Normalizes Unicode, strips hostile control characters, detects homoglyphs,
and extracts decoded_segments from base64 blobs for re-screening.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

# Control and zero-width characters that can be used to obscure injection payloads
_ZERO_WIDTH = re.compile(
    r"[​‌‍\u200E\u200F\u202A-\u202E⁠-⁯﻿]"
)
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Patterns for base64 blobs likely to contain encoded content (min 40 chars)
_BASE64_BLOB = re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

# Common homoglyph substitutions (Cyrillic/Greek look-alikes for Latin)
_HOMOGLYPH_MAP: dict[str, str] = {
    "а": "a",  # Cyrillic small a
    "е": "e",  # Cyrillic small ie
    "о": "o",  # Cyrillic small o
    "р": "p",  # Cyrillic small er
    "с": "c",  # Cyrillic small es
    "х": "x",  # Cyrillic small ha
    "і": "i",  # Cyrillic small i (Ukrainian)
    "Α": "A",  # Greek capital Alpha
    "Β": "B",  # Greek capital Beta
    "Ε": "E",  # Greek capital Epsilon
    "Ζ": "Z",  # Greek capital Zeta
    "Η": "H",  # Greek capital Eta
    "Ι": "I",  # Greek capital Iota
    "Κ": "K",  # Greek capital Kappa
    "Μ": "M",  # Greek capital Mu
    "Ν": "N",  # Greek capital Nu
    "Ο": "O",  # Greek capital Omicron
    "Ρ": "P",  # Greek capital Rho
    "Τ": "T",  # Greek capital Tau
    "Υ": "Y",  # Greek capital Upsilon
    "Χ": "X",  # Greek capital Chi
}


def normalize(text: str) -> tuple[str, list[str], list[str]]:
    """Normalize text for safe processing.

    Returns:
        (normalized_text, decoded_segments, homoglyph_signals)
        decoded_segments: any base64 blobs decoded and extracted for re-screening
        homoglyph_signals: descriptions of homoglyphs detected
    """
    signals: list[str] = []
    decoded_segments: list[str] = []

    # Step 1: NFKC normalization collapses many lookalike forms
    normalized = unicodedata.normalize("NFKC", text)

    # Step 2: Detect and flag homoglyphs before stripping (they may indicate evasion)
    homoglyphs_found = []
    for char, replacement in _HOMOGLYPH_MAP.items():
        if char in normalized:
            homoglyphs_found.append(f"homoglyph U+{ord(char):04X} ({char!r} → {replacement!r})")
            normalized = normalized.replace(char, replacement)
    if homoglyphs_found:
        signals.extend(homoglyphs_found)

    # Step 3: Strip zero-width and control characters
    if _ZERO_WIDTH.search(normalized):
        signals.append("zero_width_chars_stripped")
    normalized = _ZERO_WIDTH.sub("", normalized)

    if _CONTROL_CHARS.search(normalized):
        signals.append("control_chars_stripped")
    normalized = _CONTROL_CHARS.sub("", normalized)

    # Step 4: Detect and extract base64 blobs for re-screening
    for match in _BASE64_BLOB.finditer(normalized):
        blob = match.group(0)
        try:
            decoded_bytes = base64.b64decode(blob + "==")  # add padding if missing
            decoded_text = decoded_bytes.decode("utf-8", errors="ignore").strip()
            if len(decoded_text) >= 20 and decoded_text.isprintable():
                decoded_segments.append(decoded_text)
                signals.append(f"base64_blob_decoded (len={len(blob)})")
        except (binascii.Error, UnicodeDecodeError):
            pass

    return normalized, decoded_segments, signals
