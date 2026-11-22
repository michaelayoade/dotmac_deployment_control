"""Verify a release's deploy descriptor from assembly-supplied evidence.

Control does not own releases (`release_ref` is opaque, ADR-0006 D1). The
assembly implements `ReleaseDescriptorSource` over whatever vouches for the
release; this module is what Control does with the answer, on EVERY path that
acts on a descriptor (set desired state, the typed params form, propose):

1. resolve the evidence (a failure is `ReleaseDescriptorUnavailableError`);
2. check it is about the release, product and path that were asked for;
3. RECOMPUTE `DeployUnitDigestV1` over the bytes and refuse a difference from
   the attested digest (`descriptor_digest_mismatch`);
4. parse the descriptor (companion-path and default-deny legacy rules apply) and
   refuse a descriptor for another product;
5. validate params, and pin the image: the digest param is taken from the
   evidence, the repository param must be the evidence's own repository or its
   loopback form, never another (`release_image_mismatch`).

Only the digest and the image pins are kept. The bytes are used here and
dropped; no table, column or input holds descriptor text.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from dotmac_deployment_control.deploy_unit import (
    DeployUnit,
    parse_deploy_unit,
    validate_params,
)
from dotmac_deployment_control.digests import DeployUnitDigestV1, is_canonical_digest
from dotmac_deployment_control.image_policy import (
    ImagePolicyRefusedError,
    PullAllowlist,
    check_planned_image,
)
from dotmac_deployment_control.ports import (
    ReleaseDescriptorEvidence,
    ReleaseDescriptorRefusedError,
    ReleaseDescriptorSource,
    ReleaseDescriptorUnavailableError,
)

_E = ReleaseDescriptorRefusedError


@dataclass(frozen=True, slots=True)
class VerifiedDescriptor:
    unit: DeployUnit
    evidence: ReleaseDescriptorEvidence
    #: Recomputed by Control; equal to the attested digest or we never get here.
    digest: str


def verify_release_descriptor(
    source: ReleaseDescriptorSource | None,
    *,
    release_ref: str,
    product_code: str,
    descriptor_path: str,
    legacy_allowed: frozenset[str],
) -> VerifiedDescriptor:
    if source is None:
        raise ReleaseDescriptorUnavailableError(
            "no release descriptor source is configured; a descriptor is never "
            "taken from the caller"
        )
    evidence = source.resolve(
        release_ref, product_code=product_code, descriptor_path=descriptor_path
    )
    if (evidence.release_ref, evidence.descriptor_path) != (
        release_ref,
        descriptor_path,
    ):
        raise _E(
            _E.EVIDENCE_MISMATCH,
            "the evidence is about a different release or descriptor path",
        )
    if evidence.product_code != product_code:
        raise _E(_E.PRODUCT_MISMATCH, "the evidence is for another product")
    if not isinstance(evidence.deploy_unit_bytes, bytes) or not is_canonical_digest(
        evidence.attested_digest
    ):
        raise _E(_E.DIGEST_MISMATCH, "the attested digest is not canonical")
    recomputed = DeployUnitDigestV1.over_bytes(evidence.deploy_unit_bytes).canonical
    if recomputed != evidence.attested_digest:
        raise _E(
            _E.DIGEST_MISMATCH,
            "the descriptor bytes do not hash to the attested digest",
        )
    for label, value in (
        ("digest", evidence.image_digest),
        ("repository", evidence.image_repository),
    ):
        if not value:
            raise _E(_E.IMAGE_MISMATCH, f"the evidence carries no image {label}")
    if not is_canonical_digest(evidence.image_digest):
        raise _E(_E.IMAGE_MISMATCH, "the evidence image digest is not canonical")
    try:
        unit = parse_deploy_unit(
            evidence.deploy_unit_bytes.decode("utf-8"),
            descriptor_path=descriptor_path,
            legacy_allowed=legacy_allowed,
        )
    except UnicodeDecodeError:
        raise _E(_E.DIGEST_MISMATCH, "the descriptor is not UTF-8") from None
    if unit.product != product_code:
        raise _E(_E.PRODUCT_MISMATCH, "the descriptor declares another product")
    return VerifiedDescriptor(unit=unit, evidence=evidence, digest=recomputed)


def pin_params(
    verified: VerifiedDescriptor,
    values: Mapping[str, Any],
    *,
    environment: str,
    allowlist: PullAllowlist,
) -> dict[str, str]:
    """Validate values and pin the image params from the same evidence."""
    unit, evidence = verified.unit, verified.evidence
    merged = dict(values)
    for name, spec in unit.params.items():
        if spec.type == "image_digest":
            if name in merged and merged[name] != evidence.image_digest:
                raise _E(_E.IMAGE_MISMATCH, f"{name} differs from the release image")
            merged[name] = evidence.image_digest
    rendered = validate_params(unit, merged, environment=environment)
    for name, spec in unit.params.items():
        if spec.type == "image_repository" and name in rendered:
            try:
                check_planned_image(
                    source=unit.image_source,
                    release_repository=evidence.image_repository,
                    release_digest=evidence.image_digest,
                    planned_repository=rendered[name],
                    planned_digest=evidence.image_digest,
                    allowlist=allowlist,
                )
            except ImagePolicyRefusedError as exc:
                raise _E(_E.IMAGE_MISMATCH, f"{name}: {exc}") from None
    return rendered


def image_pin(verified: VerifiedDescriptor) -> dict[str, str]:
    """The authorized image this release pins: product as service, from evidence."""
    return {
        "service": verified.unit.product,
        "repository": verified.evidence.image_repository,
        "digest": verified.evidence.image_digest,
    }
