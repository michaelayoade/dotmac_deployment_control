"""Deterministic, non-cryptographic doubles for V3 health-evidence tests.

**FIXTURE-SHAPED, named as such.** `build_evidence_bytes` MIRRORS the
canonicalization `dotmac_platform_health.evidence.canonical_health_evidence_bytes`
documents (Starter PR #665, branch `feat/platform-health-canonical-evidence`) —
sort_keys, fixed-width UTC timestamps, components re-sorted by
`component_code` — on the same terms `rehearsal_grant.FOUNDATION_STEP_KINDS`
mirrors Foundation's published step vocabulary: a VALUE mirror, not an import,
because `dotmac-platform-health` is independently released and Control must
not depend on it (see `SIBLING_ROOTS` in
`tests/architecture/test_deployment_control_module.py`).

This mirror exists ONLY so these unit tests can construct realistic evidence
bytes without importing the producer. It is not a claim that a real,
end-to-end signed `DeploymentHealthEvidence.v1` document has ever been
produced against these fixtures — that genuine integration proof is a later
step (Foundation is frozen and built once, downstream), and every test that
uses this module says so in its own docstring rather than presenting the
result as end-to-end.

`TestHealthEvidenceVerifier` models "only Platform Health holds the real
key": it accepts a signature ONLY if it was produced by
`sign_evidence_bytes` under `REAL_HEALTH_EVIDENCE_KEY_ID` with the shared
test secret. A signature over identical bytes with any other key id, or any
hand-typed signature, is refused — this is what makes the one-caller
negative control test non-trivial: a caller can freely choose the CONTENT of
`required_component_roster` and evidence bytes, but cannot forge acceptance
from the verifier without also holding the secret this double treats as
"only Platform Health's".
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime

REAL_HEALTH_EVIDENCE_KEY_ID = "test-platform-health-key"
_REAL_SECRET = b"only-platform-health-holds-this-test-secret"
DEPLOYMENT_HEALTH_EVIDENCE_SCHEMA = "DeploymentHealthEvidence.v1"


def _canonical_instant(value: datetime) -> str:
    if value.utcoffset() is None:
        raise ValueError("evidence timestamps must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def build_component(
    code: str,
    *,
    state: str = "healthy",
    freshness: str = "fresh",
    observation_id: str | None = "3d3f6d0e-3b9a-4a34-9c8e-000000000001",
    observed_at: datetime | None = None,
) -> dict[str, object]:
    return {
        "component_code": code,
        "observation_id": observation_id,
        "observed_at": _canonical_instant(observed_at) if observed_at else None,
        "state": state,
        "freshness": freshness,
    }


def build_evidence_bytes(
    *,
    evaluated_at: datetime,
    valid_until: datetime,
    components: list[dict[str, object]],
) -> bytes:
    """Mirror of `canonical_health_evidence_bytes`. See module docstring."""
    payload = {
        "schema": DEPLOYMENT_HEALTH_EVIDENCE_SCHEMA,
        "evaluated_at": _canonical_instant(evaluated_at),
        "valid_until": _canonical_instant(valid_until),
        "components": sorted(components, key=lambda c: c["component_code"]),
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sign_evidence_bytes(canonical_bytes: bytes, *, key_id: str) -> bytes:
    """The double's own signing function. `key_id` decides whose 'key' this is."""
    return hmac.new(
        _REAL_SECRET + key_id.encode(), canonical_bytes, hashlib.sha256
    ).digest()


def build_signed_health_evidence_document(
    *,
    evaluated_at: datetime,
    valid_until: datetime,
    components: list[dict[str, object]],
    key_id: str = REAL_HEALTH_EVIDENCE_KEY_ID,
    signature_override: bytes | None = None,
) -> dict[str, object]:
    """Control's OWN wire shape — see
    `authorization_v3.parse_signed_health_evidence_document`.
    """
    canonical_bytes = build_evidence_bytes(
        evaluated_at=evaluated_at, valid_until=valid_until, components=components
    )
    signature = (
        signature_override
        if signature_override is not None
        else sign_evidence_bytes(canonical_bytes, key_id=key_id)
    )
    return {
        "canonical_bytes": base64.b64encode(canonical_bytes).decode("ascii"),
        "signature": {
            "key_id": key_id,
            "algorithm": "ed25519",
            "signature": base64.b64encode(signature).decode("ascii"),
        },
    }


class TestHealthEvidenceVerifier:
    """Accepts ONLY a signature genuinely produced under
    `REAL_HEALTH_EVIDENCE_KEY_ID`.
    """

    __test__ = False

    def verify_health_evidence(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        canonical_bytes: bytes,
        signature: bytes,
    ) -> bool:
        if key_id != REAL_HEALTH_EVIDENCE_KEY_ID or algorithm != "ed25519":
            return False
        expected = sign_evidence_bytes(canonical_bytes, key_id=key_id)
        return hmac.compare_digest(signature, expected)


HEALTH_EVIDENCE_VERIFIER = TestHealthEvidenceVerifier()
