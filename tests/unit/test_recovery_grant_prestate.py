"""The prestate discriminator: six conditions, each planted on its own.

Control signs `incumbent_prestate_digest` and computes nothing. Until Foundation
published a canonicalizer for `FailedSystemObservationV1`, NOTHING produced that
value on either side -- the term existed in a signed contract, was compared, and
was refused on mismatch, with no authority behind it. The first real recovery
would have reached a comparison neither side could satisfy.

`incumbent_prestate_discriminator` is Foundation's identity for the rules that
turned the observation into bytes. Control stores it, requires it, and defines
nothing about it.

## Why every case is planted separately

A single fixture that varied several terms at once would refuse -- and could not
show WHICH condition each refusal detects. Three refusals send an operator to
three different places: a historical row nobody can execute, a version this
deployment does not have, and a host holding a different incumbent. A suite that
cannot tell them apart is a suite that would have passed while they were
interchangeable.

## Latent, not live

Nothing here misbehaves today. All the digest terms are opaque caller-supplied
strings with no second encoding in play, so a text comparison is correct
precisely because neither side canonicalizes. It becomes the `0.1.0a4` defect --
bare hex against `sha256:`-prefixed, a formatting bug wearing a tampering
refusal -- the moment a canonically encoded digest meets the other spelling.
Which is this change. These cases close the window this work opens.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from dotmac_deployment_control.recovery_grant import (
    KNOWN_PRESTATE_DISCRIMINATORS,
    PRESTATE_DISCRIMINATOR,
    RecoveryGrantRefusalCode,
    RecoveryGrantRefusedError,
    RecoveryGrantV1,
    issue_recovery_grant,
    verify_recovery_grant,
)
from tests.unit.test_recovery_grant import _Signer, _statement, _Verifier

NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)

#: The spelling Foundation RETIRED. It named Control's field rather than the
#: document being digested, and was renamed before anything pinned it.
#:
#: Reconstructed from the naming rule, never aliased and never imported: there
#: is deliberately no name in Control or Foundation that resolves to it. It is
#: here only so a test can prove it is REFUSED. An alias would give one contract
#: two valid spellings, which is the defect the rename removed.
OBSOLETE_DISCRIMINATOR = "dotmac.deployment_foundation.incumbent_prestate.v1"


def _grant(**overrides: object) -> dict[str, object]:
    return issue_recovery_grant(_statement(**overrides), signer=_Signer()).as_mapping()


def _refusal(grant: dict[str, object], subject_overrides: dict[str, object]):
    subject = _statement(**subject_overrides).subject
    with pytest.raises(RecoveryGrantRefusedError) as refused:
        verify_recovery_grant(
            grant, verifier=_Verifier(), subject=subject, at=NOW - timedelta(minutes=1)
        )
    return refused.value


# ── the admitting case, first ───────────────────────────────────────────────


def test_a_correctly_discriminated_grant_is_admitted() -> None:
    """NON-VACUITY. Six refusals prove nothing if nothing can be built."""
    statement = _statement()
    verified = verify_recovery_grant(
        _grant(),
        verifier=_Verifier(),
        subject=statement.subject,
        at=NOW - timedelta(minutes=1),
    )
    assert verified.statement.incumbent_prestate_discriminator == (
        PRESTATE_DISCRIMINATOR
    )


def test_the_discriminator_is_inside_the_signature() -> None:
    """Storing it beside the digest is not enough: an unsigned discriminator
    could be edited to make any digest look accounted for."""
    mapping = _grant()
    statement = mapping["statement"]
    assert statement["incumbent_prestate_discriminator"] == (  # type: ignore[index]
        PRESTATE_DISCRIMINATOR
    )


# ── 1. missing discriminator ────────────────────────────────────────────────


def test_a_grant_with_no_discriminator_is_historical_and_unexecutable() -> None:
    """A row predating the term. Refused, never backfilled.

    Its digest was not produced under rules anyone can name, and assuming the
    current identity would MANUFACTURE PROVENANCE for a value whose missing
    provenance is the entire defect. `NOT NULL` on the digest column cannot
    catch this -- it proves only that a string exists -- which is why the
    discriminator column is nullable and why absence is the detectable thing.
    """
    refusal = _refusal(
        _grant(incumbent_prestate_discriminator=""),
        {"incumbent_prestate_discriminator": ""},
    )
    assert refusal.code is RecoveryGrantRefusalCode.PRESTATE_UNDISCRIMINATED
    assert "never backfilled" in str(refusal).lower() or "backfill" in str(refusal)


def test_whitespace_is_not_a_discriminator() -> None:
    """A blank-looking value is absence wearing a string, and the column being
    nullable does not stop a writer putting spaces in it."""
    refusal = _refusal(
        _grant(incumbent_prestate_discriminator="   "),
        {"incumbent_prestate_discriminator": "   "},
    )
    assert refusal.code is RecoveryGrantRefusalCode.PRESTATE_UNDISCRIMINATED


def _without_the_discriminator() -> dict[str, object]:
    """A stored envelope from before the term existed: the KEY is missing, not
    empty. Built by removal because nothing can issue one any more -- which is
    the point, since the rows this refusal is for were written by a Control
    that had no such field."""
    grant = _grant()
    statement = dict(grant["statement"])  # type: ignore[arg-type]
    del statement["incumbent_prestate_discriminator"]
    return {"statement": statement, "signature": grant["signature"]}


def test_a_statement_that_never_carried_the_key_is_read_then_refused() -> None:
    """READABLE AND REFUSABLE, which is one property and not two.

    The key check compares the statement's key SET, so a term named in neither
    the required set nor an optional one is not tolerated -- it is FORBIDDEN,
    in the direction nobody thinks about. Absence and presence therefore need
    separate cases: the whole suite above exercises presence, and this is the
    only place absence is stated at all.

    The verdict, not merely the raising, is what is asserted. `MALFORMED` here
    would send an operator to look for a corrupted envelope; the row is intact
    and its provenance is what is missing, which is a different destination.
    """
    historical = _without_the_discriminator()

    parsed = RecoveryGrantV1.parse(historical)
    assert parsed.statement.incumbent_prestate_discriminator == ""

    with pytest.raises(RecoveryGrantRefusedError) as refused:
        verify_recovery_grant(
            historical,
            verifier=_Verifier(),
            subject=_statement().subject,
            at=NOW - timedelta(minutes=1),
        )
    assert refused.value.code is RecoveryGrantRefusalCode.PRESTATE_UNDISCRIMINATED
    assert refused.value.code is not RecoveryGrantRefusalCode.MALFORMED


def test_naming_one_optional_key_did_not_open_the_statement_to_others() -> None:
    """SENSITIVITY for the case above. "Absence is tolerated" is one edit away
    from "anything is tolerated", and a statement that accepted unknown keys
    would let a document carry a term this version compares against nothing.
    """
    grant = _without_the_discriminator()
    statement = dict(grant["statement"])  # type: ignore[arg-type]
    statement["operation"] = "deploy"

    with pytest.raises(RecoveryGrantRefusedError) as refused:
        RecoveryGrantV1.parse({"statement": statement, "signature": grant["signature"]})
    assert refused.value.code is RecoveryGrantRefusalCode.MALFORMED
    assert "operation" in str(refused.value)


# ── 2. unknown discriminator version, including the retired spelling ────────


def test_the_obsolete_spelling_is_refused_and_not_aliased() -> None:
    """The rename, proven active.

    The retired identity named Control's FIELD; the current one names the
    DOCUMENT it digests. Accepting both would give one contract two valid
    spellings -- exactly what the rename removed -- so the old string is refused
    like any other unknown encoding, and no alias exists anywhere.
    """
    assert OBSOLETE_DISCRIMINATOR not in KNOWN_PRESTATE_DISCRIMINATORS
    refusal = _refusal(
        _grant(incumbent_prestate_discriminator=OBSOLETE_DISCRIMINATOR),
        {"incumbent_prestate_discriminator": OBSOLETE_DISCRIMINATOR},
    )
    assert refusal.code is RecoveryGrantRefusalCode.PRESTATE_UNKNOWN_DISCRIMINATOR


def test_a_future_version_is_refused_as_a_version_not_a_mismatch() -> None:
    """The repair is a VERSION, not a re-observation. Reporting this as a
    mismatch would send someone to re-capture a prestate that was correct."""
    refusal = _refusal(
        _grant(
            incumbent_prestate_discriminator=(
                "dotmac.deployment_foundation.failed_system_observation.v2"
            )
        ),
        {
            "incumbent_prestate_discriminator": (
                "dotmac.deployment_foundation.failed_system_observation.v2"
            )
        },
    )
    assert refusal.code is RecoveryGrantRefusalCode.PRESTATE_UNKNOWN_DISCRIMINATOR
    assert refusal.code is not RecoveryGrantRefusalCode.PRESTATE_MISMATCH


# ── 3. correct discriminator, wrong digest ──────────────────────────────────


def test_a_correct_discriminator_does_not_excuse_a_wrong_digest() -> None:
    """The discriminator says which rules produced the value; it says nothing
    about WHICH value. A check that stopped at the identity would authorize a
    recovery against any incumbent so long as its encoding was named."""
    refusal = _refusal(_grant(), {"incumbent_prestate_digest": "sha256:" + "d" * 64})
    assert refusal.code is RecoveryGrantRefusalCode.PRESTATE_MISMATCH


# ── 4. correct digest paired with another observation ───────────────────────


def test_a_correct_digest_for_a_different_target_does_not_authorize_this_one() -> None:
    """CROSS-TARGET, and it is the case most easily omitted.

    A grant that is valid in every other respect -- signed, in window, correctly
    discriminated, digest matching its own prestate -- must not authorize a
    recovery of a DIFFERENT target. Binding is by comparison, never by presence:
    carrying a prestate digest is not being a grant FOR this system.
    """
    refusal = _refusal(_grant(), {"target_id": "t-2", "target_ref": "other-prod"})
    assert refusal.code is RecoveryGrantRefusalCode.TARGET_MISMATCH


def test_the_same_digest_under_another_product_is_refused() -> None:
    """The other half of pairing: one observation's digest reused beneath a
    different product is a different fact about a different system."""
    refusal = _refusal(_grant(), {"product_code": "dotmac-sub"})
    assert refusal.code is RecoveryGrantRefusalCode.PRODUCT_MISMATCH


# ── 5. every bound observation field mutated independently ──────────────────


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("product_code", "dotmac-sub", RecoveryGrantRefusalCode.PRODUCT_MISMATCH),
        ("target_id", "t-9", RecoveryGrantRefusalCode.TARGET_MISMATCH),
        ("target_ref", "elsewhere", RecoveryGrantRefusalCode.TARGET_MISMATCH),
        ("environment", "staging", RecoveryGrantRefusalCode.ENVIRONMENT_MISMATCH),
        (
            "recovery_execution_plan_digest",
            "sha256:" + "e" * 64,
            RecoveryGrantRefusalCode.RECOVERY_PLAN_MISMATCH,
        ),
        (
            "recovery_bundle_digest",
            "sha256:" + "f" * 64,
            RecoveryGrantRefusalCode.BUNDLE_MISMATCH,
        ),
        (
            "incumbent_prestate_digest",
            "sha256:" + "0" * 64,
            RecoveryGrantRefusalCode.PRESTATE_MISMATCH,
        ),
    ],
)
def test_each_bound_term_refuses_on_its_own(
    field: str, value: str, code: RecoveryGrantRefusalCode
) -> None:
    """ONE field moved per case, each with its OWN code.

    An aggregate refusal would send an operator round the loop once per field,
    during an incident, which is the worst moment available for it. Parametrized
    rather than looped inside one test so a single broken term is one red case
    naming itself, not one red test naming the first thing it hit.
    """
    assert _refusal(_grant(), {field: value}).code is code


def test_the_mutation_harness_is_not_refusing_everything() -> None:
    """SENSITIVITY for the parametrization above. Seven refusals are equally
    consistent with a subject builder that produces something unusable."""
    statement = _statement()
    verified = verify_recovery_grant(
        _grant(),
        verifier=_Verifier(),
        subject=statement.subject,
        at=NOW - timedelta(minutes=1),
    )
    assert verified.statement.grant_id == statement.grant_id


# ── 6. a revoked grant, and the window ──────────────────────────────────────


def test_a_revoked_grant_does_not_authorize_however_well_discriminated() -> None:
    """Revocation outranks a perfect prestate binding. A withdrawn grant whose
    every term still matches is exactly the case where a check ordered wrongly
    would authorize."""
    grant = _grant()
    statement = _statement()
    with pytest.raises(RecoveryGrantRefusedError) as refused:
        verify_recovery_grant(
            grant,
            verifier=_Verifier(),
            subject=statement.subject,
            at=NOW - timedelta(minutes=1),
            revoked_grant_ids=frozenset({"g-1"}),
        )
    assert refused.value.code is RecoveryGrantRefusalCode.REVOKED
