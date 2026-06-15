"""Unit tests for Pydantic schemas — schemas are a security control."""

from __future__ import annotations

from datetime import datetime

import pytest
from mithridate.models import (
    IOC,
    Provenance,
    RawDocument,
    TechniqueMapping,
    _refang,
)

# ---------------------------------------------------------------------------
# IOC validation
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.utcnow()


def _make_ioc(**kwargs: object) -> IOC:
    defaults: dict[str, object] = {"confidence": 0.9, "source_doc": "test", "first_seen": _now()}
    defaults.update(kwargs)  # type: ignore[arg-type]
    return IOC(**defaults)  # type: ignore[arg-type]


class TestIOCValidation:
    def test_valid_ipv4(self) -> None:
        ioc = _make_ioc(type="ipv4", value="198.51.100.42")
        assert ioc.value == "198.51.100.42"

    def test_invalid_ipv4_rejects(self) -> None:
        with pytest.raises((ValueError, Exception)):  # pydantic raises ValidationError (subclass of ValueError)
            _make_ioc(type="ipv4", value="999.0.0.1")

    def test_valid_domain(self) -> None:
        ioc = _make_ioc(type="domain", value="evil-c2.example.com")
        assert ioc.value == "evil-c2.example.com"

    def test_invalid_domain_rejects(self) -> None:
        with pytest.raises((ValueError, Exception)):  # pydantic raises ValidationError (subclass of ValueError)
            _make_ioc(type="domain", value="not a domain!")

    def test_valid_sha256(self) -> None:
        sha = "a" * 64
        ioc = _make_ioc(type="sha256", value=sha)
        assert ioc.value == sha

    def test_invalid_sha256_wrong_length(self) -> None:
        with pytest.raises((ValueError, Exception)):  # pydantic raises ValidationError (subclass of ValueError)
            _make_ioc(type="sha256", value="a" * 63)

    def test_valid_md5(self) -> None:
        ioc = _make_ioc(type="md5", value="d" * 32)
        assert ioc.value == "d" * 32

    def test_valid_cve(self) -> None:
        ioc = _make_ioc(type="cve", value="CVE-2023-44487")
        assert ioc.value == "CVE-2023-44487"

    def test_invalid_cve_format(self) -> None:
        with pytest.raises((ValueError, Exception)):  # pydantic raises ValidationError (subclass of ValueError)
            _make_ioc(type="cve", value="CVE-2023-123")  # too few digits

    def test_valid_email(self) -> None:
        ioc = _make_ioc(type="email", value="threat@actor.net")
        assert ioc.value == "threat@actor.net"

    def test_defanged_ip_refanged(self) -> None:
        ioc = _make_ioc(type="ipv4", value="198.51.100[.]42")
        assert ioc.value == "198.51.100.42"

    def test_defanged_url_refanged(self) -> None:
        ioc = _make_ioc(type="url", value="hxxps://evil.example.com/path")
        assert ioc.value == "https://evil.example.com/path"

    def test_confidence_clamped(self) -> None:
        ioc = _make_ioc(type="ipv4", value="198.51.100.1", confidence=1.5)
        assert ioc.confidence <= 1.0

    def test_valid_url(self) -> None:
        ioc = _make_ioc(type="url", value="https://c2.example.com/beacon?id=abc")
        assert "https" in ioc.value


class TestTechniqueMapping:
    def test_valid_technique(self) -> None:
        m = TechniqueMapping(
            technique_id="T1059.001",
            technique_name="PowerShell",
            confidence=0.8,
            rationale="PowerShell commands observed",
        )
        assert m.technique_id == "T1059.001"

    def test_uppercase_normalized(self) -> None:
        m = TechniqueMapping(
            technique_id="t1059",
            technique_name="Command Interpreter",
            confidence=0.8,
            rationale="test",
        )
        assert m.technique_id == "T1059"

    def test_invalid_id_format_rejected(self) -> None:
        with pytest.raises((ValueError, Exception)):  # pydantic raises ValidationError (subclass of ValueError)
            TechniqueMapping(
                technique_id="INVALID",
                technique_name="Fake",
                confidence=0.8,
                rationale="test",
            )

    def test_fake_id_format_accepted_at_schema_level(self) -> None:
        """Schema only checks format — ATT&CK matrix validation is in map_attack tool."""
        m = TechniqueMapping(
            technique_id="T9999.999",
            technique_name="Fake",
            confidence=0.8,
            rationale="test",
        )
        assert m.technique_id == "T9999.999"


class TestRawDocument:
    def test_from_text_hashes_content(self) -> None:
        prov = Provenance(
            source_id="test", url=None, fetched_at=datetime.utcnow(), trust_tier="medium"
        )
        doc1 = RawDocument.from_text("same text", prov)
        doc2 = RawDocument.from_text("same text", prov)
        assert doc1.id == doc2.id

    def test_different_content_different_id(self) -> None:
        prov = Provenance(
            source_id="test", url=None, fetched_at=datetime.utcnow(), trust_tier="medium"
        )
        doc1 = RawDocument.from_text("text A", prov)
        doc2 = RawDocument.from_text("text B", prov)
        assert doc1.id != doc2.id


class TestRefang:
    def test_hxxp(self) -> None:
        assert _refang("hxxp://evil.com") == "http://evil.com"

    def test_bracketed_dot(self) -> None:
        assert _refang("192[.]168[.]1[.]1") == "192.168.1.1"

    def test_at_bracket(self) -> None:
        assert _refang("user[at]domain.com") == "user@domain.com"
