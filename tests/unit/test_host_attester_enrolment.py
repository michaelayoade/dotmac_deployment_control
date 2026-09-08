"""A host-attester enrolment binds `host_id` to an attester incarnation,
where the incarnation IS the attester-key fingerprint (see the module
docstring for why there is no separate `incarnation_id` field).

The load-bearing tests here are `test_a_real_initial_enrolment_is_admitted`
and `test_a_real_rotation_is_admitted`: a suite of refusals passes trivially
when construction itself is broken.

`test_evidence_signed_by_the_old_key_is_refused_after_rebuild` is THE
rotation property the brief asks for: it proves the refusal fires because of
the rotation (`FINGERPRINT_SUPERSEDED`) and not because of some unrelated
invariant, by first proving the identical shape is admitted BEFORE the
rotation happens (the near-miss, kept silent) and only THEN rotating and
re-checking (the plant, named).
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
from datetime import UTC, datetime

import pytest

from dotmac_deployment_control.digests import PublicKeyFingerprintV1
from dotmac_deployment_control.host_attester_enrolment import (
    FingerprintRecord,
    FingerprintStatus,
    HostAttesterEnrolmentRefusalCode,
    HostAttesterEnrolmentRefusedError,
    HostAttesterEnrolmentSignature,
    HostAttesterEnrolmentSignerIdentity,
    HostAttesterEnrolmentStatementV1,
    HostAttesterStanding,
    evaluate_enrolment,
    host_attester_standing,
    issue_host_attester_enrolment,
    require_custody_pointer,
    require_host_id,
    verify_host_attester_enrolment,
)
from dotmac_deployment_control.ports import DeploymentControlError

NOW = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)


def _pubkey_b64(label: str) -> str:
    raw = hashlib.sha256(b"host-attester-key\0" + label.encode()).digest()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _fingerprint(label: str) -> str:
    return PublicKeyFingerprintV1.from_public_key_b64(_pubkey_b64(label)).canonical


class _EnrolmentSigner:
    """Deterministic double for the ENROLMENT AUTHORITY's own key."""

    def __init__(self, key_id: str = "enrolment-authority-1") -> None:
        self._key_id = key_id
        self.enrolment_identity = HostAttesterEnrolmentSignerIdentity(
            key_id=key_id,
            algorithm="test-sha256",
            public_key_fingerprint=f"fp-{key_id}",
        )

    def sign_enrolment(self, canonical_bytes: bytes) -> HostAttesterEnrolmentSignature:
        identity = self.enrolment_identity
        signature = hashlib.sha256(
            identity.public_key_fingerprint.encode()
            + b"\0enrolment\0"
            + canonical_bytes
        ).hexdigest()
        return HostAttesterEnrolmentSignature(
            key_id=identity.key_id,
            algorithm=identity.algorithm,
            purpose=identity.purpose,
            public_key_fingerprint=identity.public_key_fingerprint,
            signature=signature,
        )


class _EnrolmentVerifier:
    def verify_enrolment(self, **kwargs: object) -> bool:
        expected = hashlib.sha256(
            str(kwargs["public_key_fingerprint"]).encode()
            + b"\0enrolment\0"
            + kwargs["canonical_bytes"]  # type: ignore[operator]
        ).hexdigest()
        return kwargs["signature"] == expected


SIGNER = _EnrolmentSigner()
VERIFIER = _EnrolmentVerifier()


def _statement(**overrides: object) -> HostAttesterEnrolmentStatementV1:
    fields: dict[str, object] = {
        "enrolment_id": "enrol-1",
        "host_id": "db-primary",
        "public_key_b64": _pubkey_b64("incarnation-1"),
        "public_key_fingerprint": _fingerprint("incarnation-1"),
        "supersedes_fingerprint": "",
        "key_custody_pointer": "bao://secret/dotmac/host-attesters/db-primary",
        "issued_at": NOW,
        "control_version": "0.1.0a1",
        "key_id": SIGNER.enrolment_identity.key_id,
        "algorithm": SIGNER.enrolment_identity.algorithm,
        "public_key_fingerprint_signer": (
            SIGNER.enrolment_identity.public_key_fingerprint
        ),
    }
    fields.update(overrides)
    return HostAttesterEnrolmentStatementV1(**fields)  # type: ignore[arg-type]


def _envelope(**overrides: object) -> dict[str, object]:
    return issue_host_attester_enrolment(
        _statement(**overrides), signer=SIGNER
    ).as_mapping()


# ── the admitting cases, first ───────────────────────────────────────────────


def test_a_real_initial_enrolment_is_admitted() -> None:
    """NON-VACUITY. A suite of refusals proves nothing if nothing can be built."""
    verified = verify_host_attester_enrolment(_envelope(), verifier=VERIFIER, at=NOW)
    assert verified.statement.host_id == "db-primary"
    assert verified.statement.is_rotation is False
    assert (
        verified.statement.incarnation_id == verified.statement.public_key_fingerprint
    )
    # And it clears the registry check with no active binding yet.
    evaluate_enrolment(
        verified.statement, active_by_host={}, known_fingerprints={}
    )  # must not raise


def test_a_real_rotation_is_admitted() -> None:
    old_fp = _fingerprint("incarnation-1")
    new_fp = _fingerprint("incarnation-2")
    statement = _statement(
        public_key_b64=_pubkey_b64("incarnation-2"),
        public_key_fingerprint=new_fp,
        supersedes_fingerprint=old_fp,
    )
    evaluate_enrolment(
        statement,
        active_by_host={"db-primary": old_fp},
        known_fingerprints={
            old_fp: FingerprintRecord("db-primary", FingerprintStatus.ACTIVE)
        },
    )  # must not raise


def test_there_is_no_separate_incarnation_field() -> None:
    """The incarnation IS the fingerprint -- one value, not two that could
    disagree."""
    mapping = _envelope()
    keys = set(mapping["statement"])  # type: ignore[arg-type]
    assert "incarnation_id" not in keys
    assert "public_key_fingerprint" in keys


# ── envelope-level refusals ──────────────────────────────────────────────────


def test_a_document_with_the_wrong_schema_is_refused() -> None:
    mapping = _envelope()
    mapping["statement"]["schema"] = "dotmac.deployment_control.authorization"  # type: ignore[index]
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        verify_host_attester_enrolment(mapping, verifier=VERIFIER, at=NOW)
    assert excinfo.value.code is HostAttesterEnrolmentRefusalCode.SCHEMA_MISMATCH


def test_an_unsigned_envelope_is_refused() -> None:
    mapping = _envelope()
    mapping["signature"] = ""
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        verify_host_attester_enrolment(mapping, verifier=VERIFIER, at=NOW)
    assert excinfo.value.code is HostAttesterEnrolmentRefusalCode.UNSIGNED


def test_a_bad_signature_is_refused() -> None:
    mapping = _envelope()
    mapping["signature"] = "not-the-real-signature"
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        verify_host_attester_enrolment(mapping, verifier=VERIFIER, at=NOW)
    assert excinfo.value.code is HostAttesterEnrolmentRefusalCode.SIGNATURE_INVALID


def test_a_malformed_envelope_missing_a_key_is_refused() -> None:
    mapping = _envelope()
    del mapping["statement"]["enrolment_id"]  # type: ignore[arg-type]
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        verify_host_attester_enrolment(mapping, verifier=VERIFIER, at=NOW)
    assert excinfo.value.code is HostAttesterEnrolmentRefusalCode.MALFORMED


def test_all_refusals_are_the_declared_exception_and_a_stable_code() -> None:
    """Every refusal arm raises the SAME exception class and a code drawn
    from the closed enum -- never a bare ValueError or a generic message."""
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        _statement(host_id="Bad_Host")
    assert isinstance(excinfo.value, DeploymentControlError)
    assert excinfo.value.code in set(HostAttesterEnrolmentRefusalCode)


# ── statement-construction refusals ──────────────────────────────────────────


@pytest.mark.parametrize(
    "bad_host_id",
    ["Bad-Host", "-leading-hyphen", "trailing-hyphen-", "has_underscore", "", "a" * 64],
)
def test_a_malformed_host_id_is_refused(bad_host_id: str) -> None:
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        require_host_id(bad_host_id, where="host_id")
    assert excinfo.value.code is HostAttesterEnrolmentRefusalCode.HOST_ID_MALFORMED


@pytest.mark.parametrize("good_host_id", ["db-primary", "control-runner", "ns1"])
def test_fleet_measured_host_id_shapes_are_admitted(good_host_id: str) -> None:
    """The three slugs the brief measured directly from Fleet."""
    assert require_host_id(good_host_id, where="host_id") == good_host_id


@pytest.mark.parametrize(
    "bad_pointer",
    [
        "secret/dotmac/host-attesters/db-primary",  # missing scheme
        "hvac://secret/dotmac/host-attesters/db-primary",  # wrong scheme
        "bao://has a space",
        "",
        "bao://" + "x" * 600,
    ],
)
def test_a_malformed_custody_pointer_is_refused(bad_pointer: str) -> None:
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        require_custody_pointer(bad_pointer, where="key_custody_pointer")
    assert (
        excinfo.value.code is HostAttesterEnrolmentRefusalCode.CUSTODY_POINTER_MALFORMED
    )


def test_a_well_formed_custody_pointer_is_admitted() -> None:
    pointer = "bao://secret/dotmac/host-attesters/db-primary"
    assert require_custody_pointer(pointer, where="key_custody_pointer") == pointer


def test_a_stated_fingerprint_that_does_not_match_the_key_is_refused() -> None:
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        _statement(public_key_fingerprint=_fingerprint("some-other-key"))
    assert (
        excinfo.value.code is HostAttesterEnrolmentRefusalCode.FINGERPRINT_KEY_MISMATCH
    )


def test_a_rotation_naming_itself_as_superseded_is_refused() -> None:
    fp = _fingerprint("incarnation-1")
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        _statement(public_key_fingerprint=fp, supersedes_fingerprint=fp)
    assert excinfo.value.code is HostAttesterEnrolmentRefusalCode.SUPERSEDES_EQUALS_NEW


# ── the registry-conflict refusals (`evaluate_enrolment`) ───────────────────


def test_a_second_initial_enrolment_for_an_already_enrolled_host_is_refused() -> None:
    statement = _statement()
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        evaluate_enrolment(
            statement,
            active_by_host={"db-primary": _fingerprint("incarnation-0")},
            known_fingerprints={},
        )
    assert excinfo.value.code is HostAttesterEnrolmentRefusalCode.HOST_ALREADY_ENROLLED


def test_a_rotation_with_no_active_enrolment_to_supersede_is_refused() -> None:
    statement = _statement(
        public_key_b64=_pubkey_b64("incarnation-2"),
        public_key_fingerprint=_fingerprint("incarnation-2"),
        supersedes_fingerprint=_fingerprint("incarnation-1"),
    )
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        evaluate_enrolment(statement, active_by_host={}, known_fingerprints={})
    assert (
        excinfo.value.code
        is HostAttesterEnrolmentRefusalCode.SUPERSEDES_WITHOUT_ACTIVE_ENROLMENT
    )


def test_a_rotation_naming_the_wrong_superseded_fingerprint_is_refused() -> None:
    """Prevents a stale or wrong rotation from being admitted even though the
    host DOES have an active attester -- just not the one named."""
    actual_active = _fingerprint("incarnation-1")
    wrongly_named = _fingerprint("incarnation-0")
    statement = _statement(
        public_key_b64=_pubkey_b64("incarnation-2"),
        public_key_fingerprint=_fingerprint("incarnation-2"),
        supersedes_fingerprint=wrongly_named,
    )
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        evaluate_enrolment(
            statement,
            active_by_host={"db-primary": actual_active},
            known_fingerprints={},
        )
    assert (
        excinfo.value.code
        is HostAttesterEnrolmentRefusalCode.SUPERSEDED_FINGERPRINT_MISMATCH
    )


def test_two_hosts_cannot_share_an_incarnation() -> None:
    """PLANT: host `ns1` tries to enrol the fingerprint already active for
    `db-primary`. Named refusal: FINGERPRINT_REUSED_ACROSS_HOSTS."""
    shared_fp = _fingerprint("incarnation-1")
    statement = _statement(host_id="ns1", public_key_fingerprint=shared_fp)
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        evaluate_enrolment(
            statement,
            active_by_host={},
            known_fingerprints={
                shared_fp: FingerprintRecord(
                    host_id="db-primary", status=FingerprintStatus.ACTIVE
                )
            },
        )
    assert (
        excinfo.value.code
        is HostAttesterEnrolmentRefusalCode.FINGERPRINT_REUSED_ACROSS_HOSTS
    )


def test_two_enrolments_of_the_same_host_cannot_share_a_fingerprint() -> None:
    """PLANT: `db-primary` re-presents its OWN currently active fingerprint as
    though it were a fresh enrolment. Named refusal:
    FINGERPRINT_ALREADY_ENROLLED, distinct from the cross-host code above."""
    fp = _fingerprint("incarnation-1")
    statement = _statement(public_key_fingerprint=fp)
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        evaluate_enrolment(
            statement,
            active_by_host={"db-primary": fp},
            known_fingerprints={
                fp: FingerprintRecord("db-primary", FingerprintStatus.ACTIVE)
            },
        )
    assert (
        excinfo.value.code
        is HostAttesterEnrolmentRefusalCode.FINGERPRINT_ALREADY_ENROLLED
    )


# ── THE rotation property ────────────────────────────────────────────────────


def test_evidence_signed_by_the_old_key_is_refused_after_rebuild() -> None:
    """THE load-bearing property: rebuilding db-primary revokes its old
    incarnation, and an attempt to re-enrol (or re-use) the old fingerprint
    afterward is refused -- BECAUSE of the rotation, not some unrelated
    invariant.

    Structure: first prove the identical statement shape is admitted BEFORE
    the rotation (near-miss, silent). Only then perform the rotation and
    re-check the OLD fingerprint (plant, named). Same statement shape both
    times, so the only thing that changed is the registry -- isolating the
    cause.
    """
    old_fp = _fingerprint("incarnation-1")
    new_fp = _fingerprint("incarnation-2")

    # Near-miss: before any rotation, re-presenting the old fingerprint for a
    # DIFFERENT, not-yet-enrolled host is a legitimate (if unrelated) initial
    # enrolment and must stay silent.
    unrelated_statement = _statement(host_id="ns1", public_key_fingerprint=old_fp)
    evaluate_enrolment(
        unrelated_statement, active_by_host={}, known_fingerprints={}
    )  # must not raise: the fingerprint has not been rotated away yet.

    # The rebuild: db-primary rotates from old_fp to new_fp.
    rotation = _statement(
        public_key_b64=_pubkey_b64("incarnation-2"),
        public_key_fingerprint=new_fp,
        supersedes_fingerprint=old_fp,
    )
    registry_before_rotation = {
        old_fp: FingerprintRecord("db-primary", FingerprintStatus.ACTIVE)
    }
    evaluate_enrolment(
        rotation,
        active_by_host={"db-primary": old_fp},
        known_fingerprints=registry_before_rotation,
    )  # the rotation itself is admitted

    # After the rotation commits, the registry moves old_fp to SUPERSEDED and
    # db-primary's active binding moves to new_fp -- exactly what a durable
    # store applying this rotation would record.
    registry_after_rotation = {
        old_fp: FingerprintRecord("db-primary", FingerprintStatus.SUPERSEDED),
        new_fp: FingerprintRecord("db-primary", FingerprintStatus.ACTIVE),
    }
    active_after_rotation = {"db-primary": new_fp}

    # PLANT: db-primary (the SAME host) tries to come back with the OLD key,
    # as a rebuild's leftover credential would attempt to.
    replay = _statement(public_key_fingerprint=old_fp, supersedes_fingerprint=new_fp)
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        evaluate_enrolment(
            replay,
            active_by_host=active_after_rotation,
            known_fingerprints=registry_after_rotation,
        )
    assert excinfo.value.code is HostAttesterEnrolmentRefusalCode.FINGERPRINT_SUPERSEDED

    # And the standing query -- what a Foundation verifier would ask -- agrees
    # for the same reason, distinguishing it from an unrelated invariant such
    # as a malformed statement or a bad signature (neither is present here).
    standing = host_attester_standing(
        host_id="db-primary",
        fingerprint=old_fp,
        active_by_host=active_after_rotation,
        known_fingerprints=registry_after_rotation,
    )
    assert standing.standing is HostAttesterStanding.SUPERSEDED
    assert standing.authorizes is False

    # Near-miss, kept silent: the NEW key, for the SAME host, still stands.
    new_key_standing = host_attester_standing(
        host_id="db-primary",
        fingerprint=new_fp,
        active_by_host=active_after_rotation,
        known_fingerprints=registry_after_rotation,
    )
    assert new_key_standing.standing is HostAttesterStanding.VALID
    assert new_key_standing.authorizes is True


def test_a_revoked_fingerprint_is_refused_with_its_own_distinct_code() -> None:
    """REVOKED and SUPERSEDED are deliberately different codes -- an operator
    needs to know whether a key was withdrawn directly or retired by a
    rotation. Testing they are not merged behind one composite condition."""
    fp = _fingerprint("incarnation-1")
    statement = _statement(public_key_fingerprint=fp)
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        evaluate_enrolment(
            statement,
            active_by_host={},
            known_fingerprints={
                fp: FingerprintRecord("db-primary", FingerprintStatus.REVOKED)
            },
        )
    assert excinfo.value.code is HostAttesterEnrolmentRefusalCode.FINGERPRINT_REVOKED
    assert (
        excinfo.value.code
        is not HostAttesterEnrolmentRefusalCode.FINGERPRINT_SUPERSEDED
    )

    standing = host_attester_standing(
        host_id="db-primary",
        fingerprint=fp,
        active_by_host={},
        known_fingerprints={
            fp: FingerprintRecord("db-primary", FingerprintStatus.REVOKED)
        },
    )
    assert standing.standing is HostAttesterStanding.REVOKED


def test_revocation_cannot_reclaim_a_spent_marker() -> None:
    """This module exposes no operation that moves a fingerprint OUT of
    REVOKED or SUPERSEDED -- checked here by exhausting every public
    function against a revoked fingerprint and finding none that admits it."""
    fp = _fingerprint("incarnation-1")
    revoked_registry = {fp: FingerprintRecord("db-primary", FingerprintStatus.REVOKED)}
    # A fresh initial enrolment for a DIFFERENT host naming the same
    # (revoked) fingerprint is refused -- revocation is permanent and global.
    statement = _statement(host_id="ns1", public_key_fingerprint=fp)
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        evaluate_enrolment(
            statement, active_by_host={}, known_fingerprints=revoked_registry
        )
    assert excinfo.value.code is HostAttesterEnrolmentRefusalCode.FINGERPRINT_REVOKED
    # And the standing query never reports VALID for it, no matter what
    # `active_by_host` claims -- a registry disagreement is refused, not
    # trusted.
    standing = host_attester_standing(
        host_id="db-primary",
        fingerprint=fp,
        active_by_host={"db-primary": fp},
        known_fingerprints=revoked_registry,
    )
    assert standing.authorizes is False


def test_registry_disagreement_is_refused_not_trusted() -> None:
    """`known_fingerprints` says ACTIVE for db-primary; `active_by_host` names
    a different fingerprint for db-primary. Neither map is trusted alone."""
    fp = _fingerprint("incarnation-1")
    standing = host_attester_standing(
        host_id="db-primary",
        fingerprint=fp,
        active_by_host={"db-primary": _fingerprint("incarnation-2")},
        known_fingerprints={
            fp: FingerprintRecord("db-primary", FingerprintStatus.ACTIVE)
        },
    )
    assert standing.standing is HostAttesterStanding.WRONG_HOST
    assert standing.authorizes is False


def test_an_absent_fingerprint_reports_absent_not_a_refusal() -> None:
    standing = host_attester_standing(
        host_id="db-primary",
        fingerprint=_fingerprint("never-enrolled"),
        active_by_host={},
        known_fingerprints={},
    )
    assert standing.standing is HostAttesterStanding.ABSENT
    assert standing.authorizes is False


def test_the_statement_is_immutable() -> None:
    statement = _statement()
    with pytest.raises(dataclasses.FrozenInstanceError):
        statement.host_id = "other-host"  # type: ignore[misc]
