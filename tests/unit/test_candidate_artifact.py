"""`CandidateArtifactV1` — validated evidence, not a free hex string.

The load-bearing test is `test_agreeing_independent_readings_are_admitted`:
every refusal below would pass trivially if nothing could ever be built.
"""

from __future__ import annotations

import pytest

from dotmac_deployment_control.candidate_artifact import (
    CANDIDATE_ARTIFACT_ALGORITHM,
    CANDIDATE_ARTIFACT_SCHEMA,
    CANDIDATE_ARTIFACT_SUBJECT,
    CANDIDATE_ARTIFACT_VERSION,
    CandidateArtifactV1,
)
from dotmac_deployment_control.digests import FoundationArtifactDigestV1
from dotmac_deployment_control.ports import CandidateArtifactRefusedError

_BUILD_DIGEST = "sha256:" + "1" * 64
_HOST_DIGEST_SAME = "sha256:" + "1" * 64
_HOST_DIGEST_DIFFERENT = "sha256:" + "2" * 64


def _document(**overrides: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "schema": CANDIDATE_ARTIFACT_SCHEMA,
        "version": CANDIDATE_ARTIFACT_VERSION,
        "repository": "michaelayoade/dotmac_starter_mt",
        "run_id": "33780438726",
        "artifact_id": "9903418260",
        "foundation_artifact_digest": _BUILD_DIGEST,
        "host_observed_digest": _HOST_DIGEST_SAME,
    }
    fields.update(overrides)
    return fields


# ── the admit control ────────────────────────────────────────────────────────


def test_agreeing_independent_readings_are_admitted() -> None:
    """NON-VACUITY. Two independent readings that AGREE build the type."""
    evidence = CandidateArtifactV1.parse(_document())
    assert evidence.repository == "michaelayoade/dotmac_starter_mt"
    assert evidence.run_id == "33780438726"
    assert evidence.artifact_id == "9903418260"
    assert evidence.foundation_artifact_digest == FoundationArtifactDigestV1.parse(
        _BUILD_DIGEST
    )


def test_the_subject_and_algorithm_are_named_explicitly() -> None:
    """Michael's ruling: the subject is part of the type's meaning."""
    assert "wheel" in CANDIDATE_ARTIFACT_SUBJECT.lower()
    assert "foundation" in CANDIDATE_ARTIFACT_SUBJECT.lower()
    assert CANDIDATE_ARTIFACT_ALGORITHM == "sha256"


# ── the independent PEP 610 comparison is EXERCISED, not merely available ──


def test_disagreeing_independent_readings_are_refused_and_named() -> None:
    """PLANT THE DEFECT: the build's own digest and HostSource's PEP 610
    reading name different bytes. This is exactly the case a caller who
    hand-typed one side (and left the other as whatever the real build
    produced) would trigger, and it must be NAMED, not silently accepted."""
    with pytest.raises(CandidateArtifactRefusedError) as refused:
        CandidateArtifactV1.parse(
            _document(host_observed_digest=_HOST_DIGEST_DIFFERENT)
        )
    message = str(refused.value)
    assert _BUILD_DIGEST in message
    assert _HOST_DIGEST_DIFFERENT in message


def test_agreeing_readings_are_the_near_miss_that_stays_silent() -> None:
    """NEAR MISS, permanent negative control for the test above.

    Two readings that agree — even on a value that is not the real Foundation
    wheel's digest, since this module cannot tell a wheel digest from any
    other well-formed sha256 by inspection alone — must NOT be refused for
    disagreeing, because they do not disagree. This is what proves the
    refusal above is about AGREEMENT, not about the particular digest value.
    """
    evidence = CandidateArtifactV1.parse(
        _document(
            foundation_artifact_digest="sha256:" + "9" * 64,
            host_observed_digest="sha256:" + "9" * 64,
        )
    )
    assert evidence.foundation_artifact_digest == FoundationArtifactDigestV1.parse(
        "sha256:" + "9" * 64
    )


# ── malformed and incomplete evidence ───────────────────────────────────────


def test_a_non_mapping_is_refused() -> None:
    with pytest.raises(CandidateArtifactRefusedError):
        CandidateArtifactV1.parse("not-a-mapping")


def test_the_wrong_schema_is_refused() -> None:
    with pytest.raises(CandidateArtifactRefusedError) as refused:
        CandidateArtifactV1.parse(_document(schema="something.else"))
    assert "something.else" in str(refused.value)


def test_the_wrong_version_is_refused() -> None:
    with pytest.raises(CandidateArtifactRefusedError):
        CandidateArtifactV1.parse(_document(version=2))


@pytest.mark.parametrize(
    "missing",
    [
        "repository",
        "run_id",
        "artifact_id",
        "foundation_artifact_digest",
        "host_observed_digest",
    ],
)
def test_a_missing_required_field_is_refused(missing: str) -> None:
    document = _document()
    del document[missing]
    with pytest.raises(CandidateArtifactRefusedError) as refused:
        CandidateArtifactV1.parse(document)
    assert missing in str(refused.value)


@pytest.mark.parametrize("field", ["repository", "run_id", "artifact_id"])
def test_a_blank_locating_field_is_refused(field: str) -> None:
    with pytest.raises(CandidateArtifactRefusedError):
        CandidateArtifactV1.parse(_document(**{field: "   "}))


def test_a_malformed_digest_reading_is_refused_before_agreement_is_checked() -> None:
    """An encoding fault is refused as such, not folded into "disagreement"."""
    with pytest.raises(CandidateArtifactRefusedError) as refused:
        CandidateArtifactV1.parse(_document(foundation_artifact_digest="not-a-digest"))
    assert "foundation_artifact_digest" in str(refused.value)


def test_the_only_constructor_is_parse() -> None:
    """No other function anywhere returns a `CandidateArtifactV1` — the
    typed-accessor requirement is enforceable only because of this."""
    import dotmac_deployment_control.candidate_artifact as module

    producers = [
        name
        for name, value in vars(module).items()
        if callable(value)
        and getattr(value, "__module__", None) == module.__name__
        and name != "CandidateArtifactV1"
    ]
    assert producers == [], (
        f"unexpected top-level callable(s) in candidate_artifact.py: "
        f"{producers}; CandidateArtifactV1.parse must stay the only route"
    )
