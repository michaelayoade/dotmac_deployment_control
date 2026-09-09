"""A host-attester enrolment binds `host_id` to an attester incarnation,
where the incarnation IS the attester-key fingerprint (see the module
docstring for why there is no separate `incarnation_id` field).

The load-bearing tests here are `test_a_real_initial_enrolment_is_admitted`
and `test_a_real_rotation_is_admitted`: a suite of refusals passes trivially
when construction itself is broken.

`test_a_superseded_fingerprint_is_refused_for_re_enrolment_and_standing` is
THE rotation property the brief asks for: it proves the refusal fires
because of the rotation (`FINGERPRINT_SUPERSEDED`) and not because of some
unrelated invariant, by first proving a legitimate use of the fingerprint is
admitted BEFORE the rotation (the near-miss, kept silent) and only THEN
rotating and re-checking the exact old fingerprint (the plant, named). Two
of the near-miss statement's three varying inputs (`host_id`,
`supersedes_fingerprint`) differ from the plant's -- see that test's
docstring for exactly what is and is not held constant.

`test_a_rotation_cannot_retire_another_hosts_key` is the second serious
property: `_evaluate_enrolment` must not trust `active_by_host` alone for the
most destructive operation this module can request.

`_evaluate_enrolment` and `_host_attester_standing` are PRIVATE (leading
underscore, absent from `__all__`) as of the durable attestation trust
registry: nothing outside this module may call them, because a caller
supplying its own `active_by_host`/`known_fingerprints` mapping is exactly
the "the caller supplies the registry that decides whether the caller's key
is trusted" defect the registry closes. `attestation_trust_registry`'s
`enrol_root`/`rotate_root`/`revoke_root`/`fingerprint_standing`/
`resolve_current_root` are the ONE remaining path a real caller has for these
decisions -- they reach the same admission and standing answers this file's
pure functions compute, but against Control's own durable tables (unique
constraints, the fingerprint-closures ledger, the current-root projection)
rather than a mapping the caller assembled itself. This file still exercises
`_evaluate_enrolment`/`_host_attester_standing` directly, by their private
names, purely as coverage of the evaluation-order logic itself;
`tests/architecture/test_host_attester_enrolment_is_private.py` is the
structural proof that the public surface no longer exposes a caller-supplied
path to either decision.
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
    _evaluate_enrolment,
    _host_attester_standing,
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
    verified = verify_host_attester_enrolment(_envelope(), verifier=VERIFIER)
    assert verified.statement.host_id == "db-primary"
    assert verified.statement.is_rotation is False
    assert (
        verified.statement.incarnation_id == verified.statement.public_key_fingerprint
    )
    # And it clears the registry check with no active binding yet.
    _evaluate_enrolment(
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
    _evaluate_enrolment(
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
        verify_host_attester_enrolment(mapping, verifier=VERIFIER)
    assert excinfo.value.code is HostAttesterEnrolmentRefusalCode.SCHEMA_MISMATCH


def test_an_unsigned_envelope_is_refused() -> None:
    mapping = _envelope()
    mapping["signature"] = ""
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        verify_host_attester_enrolment(mapping, verifier=VERIFIER)
    assert excinfo.value.code is HostAttesterEnrolmentRefusalCode.UNSIGNED


def test_a_bad_signature_is_refused() -> None:
    mapping = _envelope()
    mapping["signature"] = "not-the-real-signature"
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        verify_host_attester_enrolment(mapping, verifier=VERIFIER)
    assert excinfo.value.code is HostAttesterEnrolmentRefusalCode.SIGNATURE_INVALID


def test_a_malformed_envelope_missing_a_key_is_refused() -> None:
    mapping = _envelope()
    del mapping["statement"]["enrolment_id"]  # type: ignore[arg-type]
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        verify_host_attester_enrolment(mapping, verifier=VERIFIER)
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


# ── the registry-conflict refusals (`_evaluate_enrolment`) ───────────────────


def test_a_second_initial_enrolment_for_an_already_enrolled_host_is_refused() -> None:
    statement = _statement()
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        _evaluate_enrolment(
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
        _evaluate_enrolment(statement, active_by_host={}, known_fingerprints={})
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
        _evaluate_enrolment(
            statement,
            active_by_host={"db-primary": actual_active},
            known_fingerprints={},
        )
    assert (
        excinfo.value.code
        is HostAttesterEnrolmentRefusalCode.SUPERSEDED_FINGERPRINT_MISMATCH
    )


def test_a_rotation_cannot_retire_another_hosts_key() -> None:
    """THE serious property: `active_by_host` alone is never trusted for the
    most destructive operation this module can request.

    PLANT: `active_by_host` (bugged, or attacker-influenced) claims host
    `ns1`'s active fingerprint is `fp_a` -- but `known_fingerprints`, the
    permanent record, says `fp_a` belongs to `db-primary`. A rotation for
    `ns1` naming `fp_a` as superseded must be refused rather than admitted
    and later applied as "retire db-primary's key", which `active_by_host`
    agreeing with the (wrong) claim would otherwise let through."""
    fp_a = _fingerprint("incarnation-1")  # db-primary's real active key
    fp_new = _fingerprint("incarnation-2")  # ns1's proposed new key
    rotation = _statement(
        host_id="ns1",
        public_key_b64=_pubkey_b64("incarnation-2"),
        public_key_fingerprint=fp_new,
        supersedes_fingerprint=fp_a,
    )
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        _evaluate_enrolment(
            rotation,
            active_by_host={"ns1": fp_a},  # the bugged/attacker claim
            known_fingerprints={
                fp_a: FingerprintRecord("db-primary", FingerprintStatus.ACTIVE)
            },
        )
    assert (
        excinfo.value.code
        is HostAttesterEnrolmentRefusalCode.SUPERSEDES_FINGERPRINT_WRONG_HOST
    )

    # Near-miss, kept silent: the identical rotation for the fingerprint's
    # TRUE owner, db-primary, is admitted.
    legitimate = _statement(
        public_key_b64=_pubkey_b64("incarnation-2"),
        public_key_fingerprint=fp_new,
        supersedes_fingerprint=fp_a,
    )
    _evaluate_enrolment(
        legitimate,
        active_by_host={"db-primary": fp_a},
        known_fingerprints={
            fp_a: FingerprintRecord("db-primary", FingerprintStatus.ACTIVE)
        },
    )  # must not raise


def test_supersedes_fingerprint_unknown_is_refused() -> None:
    """`active_by_host` names a fingerprint as this host's active attester,
    but `known_fingerprints` has never heard of it -- refused rather than
    trusting `active_by_host` alone."""
    fp = _fingerprint("incarnation-1")
    rotation = _statement(
        public_key_b64=_pubkey_b64("incarnation-2"),
        public_key_fingerprint=_fingerprint("incarnation-2"),
        supersedes_fingerprint=fp,
    )
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        _evaluate_enrolment(
            rotation, active_by_host={"db-primary": fp}, known_fingerprints={}
        )
    assert (
        excinfo.value.code
        is HostAttesterEnrolmentRefusalCode.SUPERSEDES_FINGERPRINT_UNKNOWN
    )


def test_supersedes_fingerprint_not_active_is_refused() -> None:
    """`active_by_host` and `known_fingerprints` agree on WHICH fingerprint,
    but the registry already records it as SUPERSEDED (not ACTIVE) -- a
    contradiction refused rather than admitted a second time."""
    fp = _fingerprint("incarnation-1")
    rotation = _statement(
        public_key_b64=_pubkey_b64("incarnation-2"),
        public_key_fingerprint=_fingerprint("incarnation-2"),
        supersedes_fingerprint=fp,
    )
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        _evaluate_enrolment(
            rotation,
            active_by_host={"db-primary": fp},
            known_fingerprints={
                fp: FingerprintRecord("db-primary", FingerprintStatus.SUPERSEDED)
            },
        )
    assert (
        excinfo.value.code
        is HostAttesterEnrolmentRefusalCode.SUPERSEDES_FINGERPRINT_NOT_ACTIVE
    )


def test_two_hosts_cannot_share_an_incarnation() -> None:
    """PLANT: host `ns1` tries to enrol the fingerprint already active for
    `db-primary`. Named refusal: FINGERPRINT_REUSED_ACROSS_HOSTS."""
    shared_fp = _fingerprint("incarnation-1")
    statement = _statement(host_id="ns1", public_key_fingerprint=shared_fp)
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        _evaluate_enrolment(
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


def test_a_superseded_fingerprint_is_also_refused_across_hosts() -> None:
    """Companion to the REVOKED cross-host case: `ns1` tries to enrol a
    fingerprint `known_fingerprints` records as SUPERSEDED for
    `db-primary`. The permanent-namespace rule applies regardless of WHICH
    permanent status the fingerprint carries."""
    superseded_fp = _fingerprint("incarnation-1")
    statement = _statement(host_id="ns1", public_key_fingerprint=superseded_fp)
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        _evaluate_enrolment(
            statement,
            active_by_host={},
            known_fingerprints={
                superseded_fp: FingerprintRecord(
                    "db-primary", FingerprintStatus.SUPERSEDED
                )
            },
        )
    assert excinfo.value.code is HostAttesterEnrolmentRefusalCode.FINGERPRINT_SUPERSEDED


def test_two_enrolments_of_the_same_host_cannot_share_a_fingerprint() -> None:
    """PLANT: `db-primary` re-presents its OWN currently active fingerprint as
    though it were a fresh enrolment. Named refusal:
    FINGERPRINT_ALREADY_ENROLLED, distinct from the cross-host code above.

    This case is reachable only because `_evaluate_enrolment` judges the
    fingerprint's own status BEFORE the host's binding -- if the host block
    ran first it would report `HOST_ALREADY_ENROLLED` and this code would be
    unreachable. `test_a_revoked_fingerprint_is_reported_before_the_host_block`
    below is the companion proof for the REVOKED case."""
    fp = _fingerprint("incarnation-1")
    statement = _statement(public_key_fingerprint=fp)
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        _evaluate_enrolment(
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


def test_a_revoked_fingerprint_is_reported_before_the_host_block() -> None:
    """A REVOKED fingerprint presented as a fresh enrolment for an
    ALREADY-enrolled host reports FINGERPRINT_REVOKED -- never
    HOST_ALREADY_ENROLLED, which would be true but would never mention the
    revocation, the more urgent fact. `db-primary` already has an active
    attester (a THIRD fingerprint, unrelated to the revoked one), so a host
    block that ran first would report HOST_ALREADY_ENROLLED instead."""
    revoked_fp = _fingerprint("some-other-key")
    host_active_fp = _fingerprint("incarnation-9")
    statement = _statement(
        public_key_b64=_pubkey_b64("some-other-key"),
        public_key_fingerprint=revoked_fp,
    )
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        _evaluate_enrolment(
            statement,
            active_by_host={"db-primary": host_active_fp},
            known_fingerprints={
                revoked_fp: FingerprintRecord(
                    "some-other-host", FingerprintStatus.REVOKED
                )
            },
        )
    assert excinfo.value.code is HostAttesterEnrolmentRefusalCode.FINGERPRINT_REVOKED


# ── THE rotation property ────────────────────────────────────────────────────


def test_a_superseded_fingerprint_is_refused_for_re_enrolment_and_standing() -> None:
    """THE load-bearing property: rebuilding db-primary supersedes its old
    incarnation, and an attempt to re-enrol (or query the standing of) the
    old fingerprint afterward is refused -- BECAUSE of the rotation, not some
    unrelated invariant. This module has no signed-evidence verification
    path of its own (that is Foundation's, built elsewhere); what it
    exercises is RE-ENROLMENT (`_evaluate_enrolment`) and a STANDING query
    (`_host_attester_standing`) of the retired fingerprint.

    Structure: first prove a legitimate, UNRELATED use of the fingerprint is
    admitted BEFORE the rotation (near-miss, silent) -- a different host
    (`host_id`) with no `supersedes_fingerprint`, i.e. two of the near-miss
    statement's three varying inputs differ from the later plant's. Only
    THEN perform the rotation and re-check the exact old fingerprint for the
    ORIGINAL host (plant, named). The isolation this proves is narrower than
    "only the registry changed": it is that `FINGERPRINT_SUPERSEDED` is
    raised in exactly one place in `_evaluate_enrolment`, so its appearance
    here can only be that branch, not a malformed statement, a bad
    signature, or any of the other refusal codes -- none of which this test
    triggers along the way.
    """
    old_fp = _fingerprint("incarnation-1")
    new_fp = _fingerprint("incarnation-2")

    # Near-miss: before any rotation, re-presenting the old fingerprint for a
    # DIFFERENT, not-yet-enrolled host is a legitimate (if unrelated) initial
    # enrolment and must stay silent.
    unrelated_statement = _statement(host_id="ns1", public_key_fingerprint=old_fp)
    _evaluate_enrolment(
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
    _evaluate_enrolment(
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
        _evaluate_enrolment(
            replay,
            active_by_host=active_after_rotation,
            known_fingerprints=registry_after_rotation,
        )
    assert excinfo.value.code is HostAttesterEnrolmentRefusalCode.FINGERPRINT_SUPERSEDED

    # And the standing query -- what a Foundation verifier would ask -- agrees
    # for the same reason, distinguishing it from an unrelated invariant such
    # as a malformed statement or a bad signature (neither is present here).
    standing = _host_attester_standing(
        host_id="db-primary",
        fingerprint=old_fp,
        active_by_host=active_after_rotation,
        known_fingerprints=registry_after_rotation,
    )
    assert standing.standing is HostAttesterStanding.SUPERSEDED
    assert standing.authorizes is False

    # Near-miss, kept silent: the NEW key, for the SAME host, still stands.
    new_key_standing = _host_attester_standing(
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
        _evaluate_enrolment(
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

    standing = _host_attester_standing(
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
    REVOKED or SUPERSEDED -- checked here against this module's two
    (now-private) evaluation functions, `_evaluate_enrolment` (the write
    path) and `_host_attester_standing` (the read path), and finding neither
    admits a revoked fingerprint. Not a claim of exhaustive coverage of every
    public function: `issue_host_attester_enrolment` and
    `verify_host_attester_enrolment` do not consult the registry at all (see
    their own docstrings), so they have nothing to exercise here."""
    fp = _fingerprint("incarnation-1")
    revoked_registry = {fp: FingerprintRecord("db-primary", FingerprintStatus.REVOKED)}
    # A fresh initial enrolment for a DIFFERENT host naming the same
    # (revoked) fingerprint is refused -- revocation is permanent and global.
    statement = _statement(host_id="ns1", public_key_fingerprint=fp)
    with pytest.raises(HostAttesterEnrolmentRefusedError) as excinfo:
        _evaluate_enrolment(
            statement, active_by_host={}, known_fingerprints=revoked_registry
        )
    assert excinfo.value.code is HostAttesterEnrolmentRefusalCode.FINGERPRINT_REVOKED
    # And the standing query never reports VALID for it, no matter what
    # `active_by_host` claims -- a registry disagreement is refused, not
    # trusted.
    standing = _host_attester_standing(
        host_id="db-primary",
        fingerprint=fp,
        active_by_host={"db-primary": fp},
        known_fingerprints=revoked_registry,
    )
    assert standing.authorizes is False


def test_registry_disagreement_is_refused_not_trusted() -> None:
    """`known_fingerprints` says ACTIVE for db-primary; `active_by_host` names
    a DIFFERENT fingerprint for db-primary. Neither map is trusted alone, and
    the code is REGISTRY_DISAGREEMENT -- distinct from WRONG_HOST (the
    fingerprint belongs to a different host entirely) and from
    NOT_ACTIVE_FOR_HOST (the host has no entry at all)."""
    fp = _fingerprint("incarnation-1")
    standing = _host_attester_standing(
        host_id="db-primary",
        fingerprint=fp,
        active_by_host={"db-primary": _fingerprint("incarnation-2")},
        known_fingerprints={
            fp: FingerprintRecord("db-primary", FingerprintStatus.ACTIVE)
        },
    )
    assert standing.standing is HostAttesterStanding.REGISTRY_DISAGREEMENT
    assert standing.authorizes is False


def test_a_fingerprint_active_for_this_host_with_no_active_by_host_entry() -> None:
    """`known_fingerprints` says this fingerprint is ACTIVE for db-primary,
    but `active_by_host` has no entry for db-primary at all -- distinct from
    REGISTRY_DISAGREEMENT (which requires a CONTRADICTING entry, not a
    missing one)."""
    fp = _fingerprint("incarnation-1")
    standing = _host_attester_standing(
        host_id="db-primary",
        fingerprint=fp,
        active_by_host={},
        known_fingerprints={
            fp: FingerprintRecord("db-primary", FingerprintStatus.ACTIVE)
        },
    )
    assert standing.standing is HostAttesterStanding.NOT_ACTIVE_FOR_HOST
    assert standing.authorizes is False


def test_wrong_host_is_distinct_from_registry_disagreement() -> None:
    """`known_fingerprints` says this fingerprint is ACTIVE for a DIFFERENT
    host than the one asked about -- WRONG_HOST, never REGISTRY_DISAGREEMENT
    or NOT_ACTIVE_FOR_HOST, which are about the ASKED host's own maps."""
    fp = _fingerprint("incarnation-1")
    standing = _host_attester_standing(
        host_id="ns1",
        fingerprint=fp,
        active_by_host={"db-primary": fp},
        known_fingerprints={
            fp: FingerprintRecord("db-primary", FingerprintStatus.ACTIVE)
        },
    )
    assert standing.standing is HostAttesterStanding.WRONG_HOST
    assert standing.authorizes is False


def test_an_absent_fingerprint_reports_absent_not_a_refusal() -> None:
    standing = _host_attester_standing(
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
