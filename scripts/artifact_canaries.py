"""Behavioural canaries that run against the INSTALLED distribution.

## Why this file is not a test

`tests/` runs against the source tree. That is the right place for almost
everything, and it is exactly why `0.1.0a4` shipped a wheel whose
`__version__` said `0.1.0a2`: every check that could have caught it was reading
`src/`, where the two literals were equally wrong and equally invisible. A
proof about an ARTIFACT has to execute the artifact.

So this is a standalone script, run by the interpreter of an environment that
has the wheel installed and does not have this repository importable:

    /path/to/venv/bin/python scripts/artifact_canaries.py --expect-version 0.1.0a5

It imports no pytest, because the environment being proven contains only the
distribution's real runtime dependencies. Adding a test framework to that
environment would change the thing under test.

## The first canary is the one that makes the rest mean anything

`installed_not_source` proves the module under test came out of the
environment's `site-packages` and not out of a checkout. Without it every
canary below could pass while reading the working tree, and the suite would be
a slower copy of the unit tests wearing a stronger claim. ADR-0018's first
failure mode, in the place it would do the most damage.

## What each canary corresponds to

Every one of these is a property `0.1.0a4` got wrong, or a property whose
absence let a4's defect survive publication:

* `installed_not_source`      — the proof is about the artifact.
* `version_agreement`         — `__version__`, wheel METADATA and the declared
                                version are one fact. a4 had two, disagreeing.
* `propose_emits_canonical`   — `propose_plan` freezes `sha256:<64 hex>`, not
                                bare hex.
* `exact_digest_approves`     — the digest Control emits, handed straight back,
                                authorizes. The happy path a4 also passed, kept
                                because the fix must not break it.
* `a4_bare_hex_still_binds`   — a4's encoding still authorizes, normalized
                                INSIDE Control. This is the sensitivity proof:
                                a string-comparing implementation fails it.
* `encoding_fault_is_not_a_mutation` — an unreadable digest raises
                                `DigestEncodingError` and never says the plan
                                changed. The defect itself.
* `mutation_after_authorization_is_refused` — and the refusal a4 was reaching
                                for still happens, on a real change.

## The two canaries `0.1.0a6` added, and the different defect they answer

`0.1.0a5` passed every canary above, against the wheel the registry served, and
still could not run in its consuming assembly. It imports
`dotmac_kernel.transactions` (`service.py:73`), first shipped in kernel `a98`,
while declaring `dotmac-kernel >=0.1.0a77` — **under-constrained by 21 alphas**.
Resolution succeeded, the lock wrote cleanly, the artifacts matched their
published hashes byte-for-byte, and the failure appeared at container boot.

Nothing above could have caught it, and the reason is worth being precise
about: the canaries ran in an environment where a compatible kernel HAPPENED to
be installed. That proves the wheel imports. It does not prove the wheel's
DECLARED FLOOR is honest, because nothing in the run ever installed that floor.

* `declared_kernel_floor`  — the kernel in this environment satisfies the floor
                             the ARTIFACT'S OWN `Requires-Dist` declares, and
                             every kernel submodule that bounds this artifact
                             resolves out of `site-packages`. The floor has
                             since moved on to
                             `dotmac_kernel.product_database_catalog` (kernel
                             `a100`). With `--expect-kernel` the
                             equality is exact, which is how `ci.yml`'s floor
                             lane pins the declared minimum literally rather
                             than accepting whatever the resolver chose.
The a6 `conflict_savepoint_executes` canary is retired in a10 because the
service no longer imports or calls that kernel mechanism: target-row
serialization makes two absent-receipt writers unreachable. Its replacement is
the installed-wheel signed-observation canary, which drives acceptance, exact
replay, changed-byte conflict, enrolled-key verification and purpose separation.

## The catalogue canaries `0.1.0a8` added, and the portable a9 canary

`0.1.0a7`'s headline is a source-owned `ModuleDatabaseCatalogContributionV1`
publishing `mod_deploy`'s exact seven platform tables and 95 columns — the
extent below is the POST-`dc_0008` one, eight tables and 133 columns, because
this literal describes the tree it ships with rather than the last release. It
was
published, tagged and VERIFIED on seven release properties and nine behavioural
canaries — **a6's exact set**. a7 added none, so no canary drove the catalogue
and the artifact proved nothing about the contract the artifact exists to ship.
That is the a4 shape one level up: a proof of one question (does the SOURCE
declare the right structure?) read as a proof of another (does the ARTIFACT
carry it?). a7's own record says so, and
`test_a7s_record_says_what_the_canaries_do_NOT_cover` pins the sentence.

* `database_catalogue_as_published` — the installed distribution publishes the
                             exact catalogue: module identity, all eight table
                             identities, all 133 columns by name, ordinal, type
                             identity and rendered spelling, nullability,
                             generation and default, and every table's plane and
                             owner. Compared element-by-element against literals
                             in this file, because `len(tables) == 8 and
                             len(columns) == 133` passes on eight wrong tables.
* `catalogue_digest_binds`  — the canonical digest is the sha256 of the document
                             the artifact serialises, the bytes round-trip, and
                             a one-byte change is REFUSED against that digest.
                             A digest a consumer adopts by has to bind.

The a10 signed-observation canary closes the former replay exclusion: it drives
exact-byte replay and a changed signed envelope under the same report id. The
receipt digest is independently derived inside Control, while byte identity is
decided from the stored canonical payload itself.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import sys
import sysconfig
import tempfile
import traceback
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

DISTRIBUTION = "dotmac-deployment-control"
IMPORT_NAME = "dotmac_deployment_control"
KERNEL_DISTRIBUTION = "dotmac-kernel"
KERNEL_IMPORT_NAME = "dotmac_kernel"
CANONICAL_DIGEST = re.compile(r"\Asha256:[0-9a-f]{64}\Z")

#: `0.1.0a100`, and nothing else. The same narrow shape `scripts/release_guard
#: .py` and `scripts/kernel_floor.py` accept, repeated here rather than
#: imported because this script runs in an environment that has the wheel
#: installed and does NOT have this repository importable — importing a
#: sibling script would be the one thing these canaries exist to refuse.
_ALPHA = re.compile(r"\A(\d+)\.(\d+)\.(\d+)a(\d+)\Z")

#: `dotmac-kernel (>=0.1.0a100)` and `dotmac-kernel>=0.1.0a100` are both seen in
#: the wild depending on the build backend's metadata version.
_REQUIRES_KERNEL = re.compile(
    r"\Adotmac[-_]kernel\s*\(?\s*>=\s*(\d+\.\d+\.\d+a\d+)\s*\)?\Z"
)


class CanaryFailure(AssertionError):
    """A canary observed something the published artifact must never do."""


# ── the environment under test ──────────────────────────────────────────────


def _site_directories() -> list[Path]:
    """Every directory this interpreter installs distributions into."""
    found: list[Path] = []
    for key in ("purelib", "platlib"):
        path = sysconfig.get_paths().get(key)
        if path:
            found.append(Path(path).resolve())
    return found


def canary_installed_not_source() -> str:
    """The module under test is the INSTALLED one.

    Three independent statements, because each catches a different way this
    could be reading a checkout: the import resolved inside an install
    directory; there is no `src/` layout anywhere on the path that could have
    supplied it; and the distribution's metadata is discoverable, which a bare
    directory on `sys.path` would not be.
    """
    import importlib.metadata

    module = __import__(IMPORT_NAME)
    origin = Path(module.__file__ or "").resolve()
    sites = _site_directories()
    if not sites:
        raise CanaryFailure("this interpreter reports no install directory at all")
    if not any(origin.is_relative_to(site) for site in sites):
        raise CanaryFailure(
            f"{IMPORT_NAME} was imported from {origin}, which is not inside any "
            f"of this interpreter's install directories ({sites}). This canary "
            "is a statement about a built artifact; run it with the interpreter "
            "of an environment that has the wheel installed."
        )

    shadowing = [
        entry
        for entry in sys.path
        if entry
        and (Path(entry).resolve() / IMPORT_NAME / "__init__.py").is_file()
        and not any(Path(entry).resolve().is_relative_to(site) for site in sites)
    ]
    if shadowing:
        raise CanaryFailure(
            f"a source copy of {IMPORT_NAME} is importable from {shadowing}. Even "
            "though the install won this time, a path ordering change would "
            "silently move every canary below onto the checkout."
        )

    # Discoverable METADATA is the third statement: a directory dropped on
    # `sys.path` supplies a module and no distribution, so this fails on a
    # checkout even when the two path checks somehow pass.
    metadata_dir = importlib.metadata.distribution(DISTRIBUTION).locate_file("")
    return f"imported from {origin} (metadata under {metadata_dir})"


def canary_version_agreement(expect_version: str) -> str:
    """`__version__`, the wheel's METADATA and the declared version are ONE fact.

    a4 published `__version__ = "0.1.0a2"` from a tree declaring `0.1.0a4`. An
    authorization recording which version of Control decided something would
    have recorded the wrong one, and no check anywhere compared the two.
    """
    import importlib.metadata

    module = __import__(IMPORT_NAME)
    reported = getattr(module, "__version__", None)
    metadata_version = importlib.metadata.version(DISTRIBUTION)
    raw = importlib.metadata.metadata(DISTRIBUTION)["Version"]

    disagreements = []
    if reported != expect_version:
        disagreements.append(f"{IMPORT_NAME}.__version__ == {reported!r}")
    if metadata_version != expect_version:
        disagreements.append(f"importlib.metadata.version() == {metadata_version!r}")
    if raw != expect_version:
        disagreements.append(f"METADATA Version: == {raw!r}")
    if disagreements:
        raise CanaryFailure(
            f"the declared version is {expect_version!r} but "
            + "; ".join(disagreements)
            + ". Two literals for one fact is the a4 defect; there must be one."
        )
    if reported == "0.0.0+not-installed":
        raise CanaryFailure(
            "__version__ fell back to its not-installed sentinel, so the "
            "distribution's metadata was not found from inside its own package"
        )
    return f"__version__ == METADATA Version: == {expect_version}"


# ── the declared dependency floor, which a hash cannot see ──────────────────


def _alpha_key(version: str) -> tuple[int, int, int, int]:
    """An orderable key, refusing an unfamiliar shape rather than guessing.

    Ordering, not text: `0.1.0a97` sorts ABOVE `0.1.0a100` as a string, so a
    string comparison here would start answering wrongly at the kernel's
    hundredth alpha and would do it silently.
    """
    match = _ALPHA.fullmatch(version.strip())
    if match is None:
        raise CanaryFailure(
            f"{version!r} is not a version shape this canary can order. It "
            "accepts `<major>.<minor>.<patch>a<n>` only, and refuses anything "
            "else rather than reasoning about it."
        )
    major, minor, patch, alpha = match.groups()
    return (int(major), int(minor), int(patch), int(alpha))


def _declared_kernel_floor() -> str:
    """The kernel floor the INSTALLED artifact's own metadata declares.

    Read from `Requires-Dist`, never from `pyproject.toml`. This script runs
    where the repository is not importable, and the whole point of the floor
    lane is that the ARTIFACT's declaration is the thing under test — a source
    tree the artifact was built from is a different fact that nothing here can
    see.
    """
    import importlib.metadata

    requirements = importlib.metadata.metadata(DISTRIBUTION).get_all("Requires-Dist")
    matches = [
        match.group(1)
        for requirement in (requirements or [])
        for match in [_REQUIRES_KERNEL.fullmatch(str(requirement).strip())]
        if match
    ]
    if not matches:
        raise CanaryFailure(
            f"the installed {DISTRIBUTION} metadata declares no plain "
            f"`{KERNEL_DISTRIBUTION} >=<version>` requirement. Its "
            f"Requires-Dist is {list(requirements or [])}. This canary reads a "
            "bare lower bound and refuses anything else: an upper bound or an "
            "environment marker changes what 'the declared minimum' means, and "
            "the floor lane installs that minimum literally."
        )
    if len(matches) > 1:
        raise CanaryFailure(
            f"the metadata declares {KERNEL_DISTRIBUTION} more than once "
            f"({matches}), so 'the declared floor' is not one value"
        )
    return matches[0]


#: The kernel submodules whose availability BOUNDS this artifact from below,
#: each with one name it must export. Ordered highest-alpha LAST, so the module
#: that currently sets the floor is the last thing checked and the failure a
#: below-floor environment produces here names it.
#:
#: The actual imported module that currently sets the floor.
#:
#: Written here as literals ON PURPOSE. This script runs where the repository is
#: NOT importable, so it cannot ask `scripts/kernel_floor.py` — and it must not:
#: reading the source tree is the one thing these canaries exist to refuse.
#: `tests/architecture/test_kernel_floor.py` is what keeps the two tables from
#: drifting apart.
_FLOOR_MODULES = (("product_database_catalog", "ModuleDatabaseCatalogContributionV1"),)


def canary_declared_kernel_floor(expect_kernel: str | None = None) -> str:
    """THE DEFECT `0.1.0a6` WAS CUT FOR: the declared floor must be honest.

    a5's artifact identity was perfect and it could not be composed. It
    imported `dotmac_kernel.transactions`, first shipped in kernel `a98`, and
    declared `>=0.1.0a77`. Every proof the repository had was satisfied by an
    environment where a compatible kernel happened to be present.

    Three statements, because each closes a different half of that:

    1. the kernel installed here satisfies the floor the artifact declares —
       true in any lane, so the canary is never vacuous;
    2. every kernel submodule whose availability BOUNDS this artifact resolves
       out of `site-packages`, not out of a checkout, and exports the name it is
       imported for. `product_database_catalog` (kernel `a100`) sets the floor
       today;
    3. with `--expect-kernel`, the installed kernel is EXACTLY that version.
       That is the floor lane's tightening, and it is the one statement a
       resolver free to pick a newer kernel can never make.
    """
    import importlib.metadata

    floor = _declared_kernel_floor()
    installed = importlib.metadata.version(KERNEL_DISTRIBUTION)
    if _alpha_key(installed) < _alpha_key(floor):
        raise CanaryFailure(
            f"{KERNEL_DISTRIBUTION} {installed} is installed and the artifact "
            f"declares >={floor}. The environment does not satisfy the "
            "distribution's own metadata."
        )

    sites = _site_directories()
    for submodule, exported in _FLOOR_MODULES:
        dotted = f"{KERNEL_IMPORT_NAME}.{submodule}"
        module = __import__(dotted, fromlist=["x"])
        origin = Path(module.__file__ or "").resolve()
        if not any(origin.is_relative_to(site) for site in sites):
            raise CanaryFailure(
                f"{dotted} was imported from {origin}, which is not inside any "
                f"install directory ({sites}). The floor is a statement about a "
                "PUBLISHED kernel; satisfying it from a working tree would "
                "prove nothing about what a consumer resolves."
            )
        if not hasattr(module, exported):
            raise CanaryFailure(
                f"{dotted} exists but exports no `{exported}`, which is a name "
                "this floor is set by"
            )

    if expect_kernel is not None:
        if installed != expect_kernel:
            raise CanaryFailure(
                f"this lane pinned {KERNEL_DISTRIBUTION}=={expect_kernel} and "
                f"{installed} is installed. The floor lane's claim is that the "
                "DECLARED MINIMUM works, so it must run against that exact "
                "version — 'some compatible kernel' is what let 0.1.0a5 "
                "through."
            )
        if installed != floor:
            raise CanaryFailure(
                f"this lane pinned {installed}, the artifact declares "
                f">={floor}, and the two must be the same version. A floor "
                "lane testing anything other than the declared minimum has "
                "stopped testing the floor."
            )
        return (
            f"declared >={floor}; installed EXACTLY {installed} ({origin.name} present)"
        )
    return f"declared >={floor}; installed {installed} satisfies it"


# ── a database, inside the environment under test ───────────────────────────


def _session() -> Any:
    """The same in-memory SQLite shape `tests/unit` builds.

    Duplicated rather than imported: importing the test module would pull the
    repository's `tests/` package into the environment being proven, which is
    the one thing these canaries exist to avoid.
    """
    from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions
    from dotmac_kernel.models import Base
    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import sessionmaker

    from dotmac_deployment_control import module

    install_audit_actions(AuditActionRegistry.from_manifests([module]))
    engine = create_engine("sqlite://", future=True)

    @event.listens_for(engine, "connect")
    def _attach(dbapi_connection: Any, _record: Any) -> None:
        dbapi_connection.isolation_level = None
        dbapi_connection.execute("ATTACH DATABASE ':memory:' AS mod_deploy")

    @event.listens_for(engine, "begin")
    def _emit_begin(connection: Any) -> None:
        connection.exec_driver_sql("BEGIN")

    Base.metadata.create_all(
        engine,
        tables=[
            table
            for table in Base.metadata.tables.values()
            if table.schema == "mod_deploy"
            or table.name
            in {
                "platform_idempotency_records",
                "platform_audit_events",
                "platform_admins",
                "platform_outbox_events",
            }
        ],
    )
    return sessionmaker(bind=engine, autocommit=False, autoflush=False)()


_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
_POLICY = "deployment.production"
_POLICY_VERSION = 4
_RELEASE = "dotmac_sub@7.187.1"
#: A stand-in for the Deployment Foundation's `ExecutionPlanDigestV1`. Written
#: out and never computed, because Control cannot compute one — a canary that
#: derived it would be exercising a capability the artifact must not have.
_EXECUTION_PLAN = "sha256:" + "1a" * 32
#: A stand-in for the Foundation's canonical descriptor identity. Distinct
#: bytes from the execution plan on purpose: equality would make a swapped
#: field look correct.
_DESCRIPTOR = "sha256:" + "2b" * 32
_AUTHORIZATION_KEY = b"artifact-canary-key-not-production-material"
_DISPATCH_KEY = b"artifact-canary-dispatch-key-not-production-material"
_OBSERVATION_KEY = b"artifact-canary-observation-key-not-production-material"


def _public_key_b64(key: bytes) -> str:
    return base64.urlsafe_b64encode(key).decode("ascii").rstrip("=")


def _public_key_fingerprint(key: bytes) -> str:
    from dotmac_deployment_control import PublicKeyFingerprintV1

    return PublicKeyFingerprintV1.from_public_key_b64(_public_key_b64(key)).canonical


def _authorization_signer() -> Any:
    """A deterministic TEST provider for rollout canaries, never package policy."""
    import hashlib
    import hmac

    from dotmac_deployment_control import (
        AuthorizationSignature,
        AuthorizationSignerIdentity,
    )

    key = _AUTHORIZATION_KEY

    class CanarySigner:
        identity = AuthorizationSignerIdentity(
            key_id="artifact-canary",
            algorithm="hmac-sha256-test-only",
            public_key_fingerprint=_public_key_fingerprint(key),
        )

        def sign(self, canonical_bytes: bytes) -> AuthorizationSignature:
            return AuthorizationSignature(
                key_id=self.identity.key_id,
                algorithm=self.identity.algorithm,
                public_key_fingerprint=self.identity.public_key_fingerprint,
                signature=hmac.new(key, canonical_bytes, hashlib.sha256).hexdigest(),
            )

    return CanarySigner()


def _authorization_verifier() -> Any:
    """The public half of the canary authorization identity."""
    import hashlib
    import hmac

    from dotmac_deployment_control import AUTHORIZATION_PURPOSE

    key = _AUTHORIZATION_KEY

    class CanaryVerifier:
        def verify(
            self,
            *,
            key_id: str,
            algorithm: str,
            purpose: str,
            public_key_fingerprint: str,
            canonical_bytes: bytes,
            signature: str,
        ) -> bool:
            expected = hmac.new(key, canonical_bytes, hashlib.sha256).hexdigest()
            return (
                key_id == "artifact-canary"
                and algorithm == "hmac-sha256-test-only"
                and purpose == AUTHORIZATION_PURPOSE
                and public_key_fingerprint == _public_key_fingerprint(key)
                and hmac.compare_digest(signature, expected)
            )

    return CanaryVerifier()


def _dispatch_signer(*, key: bytes = _DISPATCH_KEY) -> Any:
    """A third physical test key for Control's distinct dispatch purpose."""
    import hashlib
    import hmac

    from dotmac_deployment_control import DispatchSignature, DispatchSignerIdentity

    class CanaryDispatchSigner:
        dispatch_identity = DispatchSignerIdentity(
            key_id="artifact-canary-dispatch",
            algorithm="hmac-sha256-test-only",
            public_key_fingerprint=_public_key_fingerprint(key),
        )

        def sign_dispatch(self, canonical_bytes: bytes) -> DispatchSignature:
            identity = self.dispatch_identity
            return DispatchSignature(
                key_id=identity.key_id,
                algorithm=identity.algorithm,
                purpose=identity.purpose,
                public_key_fingerprint=identity.public_key_fingerprint,
                signature=hmac.new(key, canonical_bytes, hashlib.sha256).hexdigest(),
            )

    return CanaryDispatchSigner()


def _dispatch_verifier() -> Any:
    import hashlib
    import hmac

    from dotmac_deployment_control import DISPATCH_PURPOSE

    key = _DISPATCH_KEY

    class CanaryDispatchVerifier:
        def verify_dispatch(
            self,
            *,
            key_id: str,
            algorithm: str,
            purpose: str,
            public_key_fingerprint: str,
            canonical_bytes: bytes,
            signature: str,
        ) -> bool:
            expected = hmac.new(key, canonical_bytes, hashlib.sha256).hexdigest()
            return (
                key_id == "artifact-canary-dispatch"
                and algorithm == "hmac-sha256-test-only"
                and purpose == DISPATCH_PURPOSE
                and public_key_fingerprint == _public_key_fingerprint(key)
                and hmac.compare_digest(signature, expected)
            )

    return CanaryDispatchVerifier()


def _execution_observation_signer(key_id: str, *, key: bytes = _OBSERVATION_KEY) -> Any:
    """A distinct target-side test purpose; never the authorization identity."""
    import hashlib
    import hmac

    from dotmac_deployment_control import (
        ExecutionObservationSignature,
        ExecutionObservationSignerIdentity,
    )

    class CanaryObservationSigner:
        execution_observation_identity = ExecutionObservationSignerIdentity(
            key_id=key_id,
            algorithm="hmac-sha256-test-only",
            public_key_fingerprint=_public_key_fingerprint(key),
        )

        def sign_execution_observation(
            self, canonical_bytes: bytes
        ) -> ExecutionObservationSignature:
            identity = self.execution_observation_identity
            return ExecutionObservationSignature(
                key_id=identity.key_id,
                algorithm=identity.algorithm,
                purpose=identity.purpose,
                public_key_fingerprint=identity.public_key_fingerprint,
                signature=hmac.new(key, canonical_bytes, hashlib.sha256).hexdigest(),
            )

    return CanaryObservationSigner()


def _execution_observation_verifier() -> Any:
    """The Control-side public verifier for the target purpose only."""
    import hashlib
    import hmac

    from dotmac_deployment_control import EXECUTION_OBSERVATION_PURPOSE

    class CanaryObservationVerifier:
        def verify_execution_observation(
            self,
            *,
            key_id: str,
            algorithm: str,
            purpose: str,
            public_key_b64: str,
            public_key_fingerprint: str,
            canonical_bytes: bytes,
            signature: str,
        ) -> bool:
            try:
                key = base64.urlsafe_b64decode(
                    public_key_b64 + "=" * (-len(public_key_b64) % 4)
                )
            except (ValueError, TypeError):
                return False
            expected = hmac.new(key, canonical_bytes, hashlib.sha256).hexdigest()
            return (
                algorithm == "hmac-sha256-test-only"
                and purpose == EXECUTION_OBSERVATION_PURPOSE
                and public_key_fingerprint == _public_key_fingerprint(key)
                and hmac.compare_digest(signature, expected)
            )

    return CanaryObservationVerifier()


def _command_id() -> str:
    return f"cmd-{uuid.uuid4().hex[:12]}"


def _proposed_plan(
    db: Any, *, replicas: int = 2, images: list[dict[str, str]] | None = None
) -> Any:
    """register -> set desired -> propose, returning the frozen plan."""
    from dotmac_deployment_control import (
        DesiredDeployment,
        ProposePlanCommand,
        RegisterTargetCommand,
        SetDesiredStateCommand,
        propose_plan,
        register_target,
        set_desired_state,
    )

    target = register_target(
        db,
        RegisterTargetCommand(
            command_id=_command_id(),
            target_ref=f"tgt-{uuid.uuid4().hex[:8]}",
            subject_ref="acme-operator",
            product_code="dotmac_sub",
            environment="production",
        ),
    )
    set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=_command_id(),
            target_id=target.id,
            desired=DesiredDeployment(
                release_ref="dotmac_sub@7.187.1",
                spec={"replicas": replicas},
                licence_ref="lic-1",
                brand_profile_ref="brand-acme",
                images=images,
            ),
        ),
    )
    plan = propose_plan(
        db,
        ProposePlanCommand(
            command_id=_command_id(),
            target_id=target.id,
            operation="deploy",
            descriptor_digest=_DESCRIPTOR,
            execution_plan_digest=_EXECUTION_PLAN,
            requires_approval=True,
            approval_policy_code=_POLICY,
            approval_policy_version=_POLICY_VERSION,
        ),
    )
    return target, plan


def _evidence(digest: str) -> Any:
    from dotmac_deployment_control import ApprovalEvidence

    return ApprovalEvidence(
        policy_code=_POLICY,
        policy_version=_POLICY_VERSION,
        decision_ref=f"apr-{uuid.uuid4().hex[:8]}",
        content_digest=digest,
        decided_at=_NOW,
        operation="deploy",
        execution_plan_digest=_EXECUTION_PLAN,
        decision_status="granted",
    )


def _approve(db: Any, plan_id: Any, digest: str) -> Any:
    from dotmac_deployment_control import ApprovePlanCommand, approve_plan

    return approve_plan(
        db,
        ApprovePlanCommand(
            command_id=_command_id(), plan_id=plan_id, evidence=_evidence(digest)
        ),
    )


def _enrolled_target(db: Any) -> tuple[Any, str, str]:
    """A target with an ACTIVE credential AND a bound rollout to report against.

    Enrolment and activation are two steps because the module refuses to admit
    a key it has only been told about: the caller proves possession through the
    kernel (ADR-0007) and activation is the record of that. Skipping it here
    would leave the credential PENDING, every observation would be recorded
    `not_eligible`, and the savepoint block would never be reached — a canary
    that passed while proving nothing.

    The plan and rollout are the same failure one layer up, added for
    `dc_0003`: an accepted observation must bind the same execution plan and
    operation across proposal, authorization and report, so a report with
    nothing to bind against is quarantined `unbound_report` and never reaches
    the canonical receipt either. Approval-exempt, because an external approval
    is not what this canary is about; the rollout still receives a signed
    portable authorization whose standing says `approval_exempt` explicitly.
    """
    from dotmac_deployment_control import (
        CredentialTransitionCommand,
        DesiredDeployment,
        EnrolCredentialCommand,
        ProposePlanCommand,
        RegisterTargetCommand,
        RequestRolloutCommand,
        SetDesiredStateCommand,
        activate_credential,
        dispatch_attempt,
        enrol_credential,
        propose_plan,
        register_target,
        request_rollout,
        set_desired_state,
    )

    target = register_target(
        db,
        RegisterTargetCommand(
            command_id=_command_id(),
            target_ref=f"tgt-{uuid.uuid4().hex[:8]}",
            subject_ref="acme-operator",
            product_code="dotmac_sub",
            environment="production",
        ),
    )
    set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=_command_id(),
            target_id=target.id,
            desired=DesiredDeployment(
                release_ref=_RELEASE, spec={"replicas": 2}, images=[]
            ),
        ),
    )
    key_id = f"key-{uuid.uuid4().hex[:8]}"
    credential_id = enrol_credential(
        db,
        EnrolCredentialCommand(
            command_id=_command_id(),
            target_id=target.id,
            key_id=key_id,
            algorithm="hmac-sha256-test-only",
            public_key_b64=_public_key_b64(_OBSERVATION_KEY),
            enrollment_authority="platform_admin_policy",
        ),
    )
    activate_credential(
        db,
        CredentialTransitionCommand(
            command_id=_command_id(),
            credential_id=credential_id,
        ),
    )
    plan = propose_plan(
        db,
        ProposePlanCommand(
            command_id=_command_id(),
            target_id=target.id,
            operation="deploy",
            descriptor_digest=_DESCRIPTOR,
            execution_plan_digest=_EXECUTION_PLAN,
            requires_approval=False,
        ),
    )
    rollout = request_rollout(
        db,
        RequestRolloutCommand(
            command_id=_command_id(),
            rollout_ref=f"rol-{uuid.uuid4().hex[:8]}",
            plan_id=plan.id,
            authorization_expires_at=datetime.now(UTC) + timedelta(days=1),
        ),
        signer=_authorization_signer(),
    )
    dispatch_attempt(
        db,
        command_id=_command_id(),
        rollout_id=rollout.id,
        verifier=_authorization_verifier(),
        dispatch_signer=_dispatch_signer(),
    )
    return target, key_id, rollout.rollout_ref


def _signed_execution_observation(
    db: Any,
    *,
    target: Any,
    key_id: str,
    rollout_ref: str,
    report_id: str,
    signing_key: bytes = _OBSERVATION_KEY,
    observed_revision: str = "desired:1",
) -> Any:
    """Build the signed target statement. The envelope's canonical bytes ARE
    the observation — there is no caller projection to build beside them."""
    from sqlalchemy import select

    from dotmac_deployment_control import (
        AuthorizationEnvelopeDigestV1,
        AuthorizationEnvelopeV2,
        RuntimeIdentityV1,
        issue_execution_observation_envelope,
        spec_digest,
    )
    from dotmac_deployment_control.models import (
        DeploymentPlan,
        Rollout,
        RolloutAttempt,
    )

    rollout = db.execute(
        select(Rollout).where(Rollout.rollout_ref == rollout_ref)
    ).scalar_one()
    plan = db.get(DeploymentPlan, rollout.plan_id)
    if plan is None:
        raise CanaryFailure("the rollout's plan disappeared before observation")
    snapshot = dict(plan.snapshot or {})
    authorization = AuthorizationEnvelopeV2.parse(rollout.authorization_envelope)
    attempt = db.execute(
        select(RolloutAttempt).where(RolloutAttempt.rollout_id == rollout.id)
    ).scalar_one()
    statement_fields = {
        "report_id": report_id,
        "authorization_id": str(rollout.id),
        "authorization_plan_id": authorization.statement.plan_id,
        "authorization_control_version": authorization.statement.control_version,
        "authorization_envelope_digest": (
            AuthorizationEnvelopeDigestV1.over_bytes(
                authorization.canonical_bytes
            ).canonical
        ),
        "execution_sequence": authorization.statement.execution_sequence,
        "attempt_no": attempt.attempt_no,
        "rollout_ref": rollout_ref,
        "target_id": str(target.id),
        "target_ref": target.target_ref,
        "product_code": target.product_code,
        "environment": target.environment,
        "operation": "deploy",
        "release_ref": _RELEASE,
        "observed_release_ref": _RELEASE,
        "authorized_images": snapshot.get("authorized_images") or [],
        "observed_images": snapshot.get("authorized_images") or [],
        "plan_digest": plan.plan_digest,
        "descriptor_digest": _DESCRIPTOR,
        "execution_plan_digest": _EXECUTION_PLAN,
        "observed_spec_digest": spec_digest({"replicas": 2}),
        "observed_revision": observed_revision,
        "runtime_identity": RuntimeIdentityV1(
            kind="canary_process", identifier="artifact-canary-runtime"
        ),
        "outcome": "succeeded",
        "observed_at": _NOW,
    }
    return issue_execution_observation_envelope(
        statement_fields,
        signer=_execution_observation_signer(key_id, key=signing_key),
    )


# ── the behavioural canaries ────────────────────────────────────────────────


def canary_propose_emits_canonical() -> str:
    """`propose_plan` freezes a CANONICAL `PlanDigestV1`, not bare hex."""
    from dotmac_deployment_control import PlanDigestV1, snapshot_digest

    db = _session()
    _, plan = _proposed_plan(db)
    frozen = plan.plan_digest or ""
    if not CANONICAL_DIGEST.fullmatch(frozen):
        raise CanaryFailure(
            f"propose_plan froze {frozen!r}, which is not `sha256:<64 lowercase "
            "hex>`. Through 0.1.0a4 it froze bare hex, which cannot say which "
            "algorithm produced it."
        )
    recomputed = PlanDigestV1.over_json(plan.snapshot)
    if PlanDigestV1.parse(frozen) != recomputed:
        raise CanaryFailure(
            f"the frozen digest {frozen} is not the digest of the snapshot it "
            f"was frozen from ({recomputed.canonical})"
        )
    if snapshot_digest(plan.snapshot) != frozen:
        raise CanaryFailure("snapshot_digest disagrees with the stored digest")
    return f"frozen {frozen}"


def canary_exact_digest_approves() -> str:
    """The digest Control emitted, handed straight back, AUTHORIZES."""
    from dotmac_deployment_control import PlanStatus

    db = _session()
    _, plan = _proposed_plan(db)
    approved = _approve(db, plan.id, plan.plan_digest or "")
    if approved.status != PlanStatus.APPROVED.value:
        raise CanaryFailure(
            f"supplying the exact frozen digest left the plan {approved.status!r}"
        )
    return f"plan {approved.id} approved on {plan.plan_digest}"


def canary_a4_bare_hex_still_binds() -> str:
    """THE SENSITIVITY PROOF, and the reason it is worth its length.

    The evidence carries a4's bare-hex encoding of the SAME digest. As STRINGS
    the two values differ, so the `0.1.0a4` implementation — `evidence
    .content_digest != row.plan_digest` — refuses this and says the plan
    changed. Approval succeeding here therefore cannot be satisfied by a
    string comparison, and the normalization has demonstrably happened INSIDE
    Control: the caller handed over exactly what a4 would have produced and did
    no work of its own.
    """
    from dotmac_deployment_control import PlanDigestV1, PlanStatus

    db = _session()
    _, plan = _proposed_plan(db)
    frozen_text = plan.plan_digest or ""
    a4_text = PlanDigestV1.parse(frozen_text).a4_bare_hex
    if a4_text == frozen_text:
        raise CanaryFailure(
            "the a4 encoding and the canonical encoding are the same string, so "
            "this canary would pass against a string comparison and prove "
            "nothing. Control is no longer emitting a canonical digest."
        )
    approved = _approve(db, plan.id, a4_text)
    if approved.status != PlanStatus.APPROVED.value:
        raise CanaryFailure(
            f"a4's bare-hex encoding of the plan's own digest left the plan "
            f"{approved.status!r}"
        )
    return (
        f"caller supplied {a4_text[:16]}… (a4 form, {len(a4_text)} chars); "
        f"Control bound it to {frozen_text[:23]}… ({len(frozen_text)} chars)"
    )


def canary_encoding_fault_is_not_a_mutation() -> str:
    """THE DEFECT ITSELF: an unreadable digest never says the plan changed."""
    from dotmac_deployment_control import ApprovalRefusedError, DigestEncodingError

    unreadable = [
        "",
        "not-a-digest",
        "SHA256:" + "a" * 64,
        "sha256:" + "A" * 64,
        "sha256:" + "a" * 63,
        "md5:" + "a" * 32,
        "sha512:" + "a" * 128,
    ]
    for value in unreadable:
        db = _session()
        _, plan = _proposed_plan(db)
        try:
            _approve(db, plan.id, value)
        except DigestEncodingError as exc:
            message = str(exc).lower()
            for forbidden in ("plan changed", "new approval is required"):
                if forbidden in message:
                    raise CanaryFailure(
                        f"an unreadable digest ({value!r}) was refused with "
                        f"{forbidden!r} in the message. That is a security "
                        "finding standing in for a formatting bug — the exact "
                        f"defect 0.1.0a5 was cut for. Message: {exc}"
                    ) from exc
            if isinstance(exc, ApprovalRefusedError):
                raise CanaryFailure(
                    "DigestEncodingError is a subclass of ApprovalRefusedError, "
                    "so a caller cannot tell an encoding fault from a changed "
                    "plan by type either"
                ) from exc
        except ApprovalRefusedError as exc:
            raise CanaryFailure(
                f"an unreadable digest ({value!r}) raised ApprovalRefusedError: "
                f"{exc}. Unreadable is not changed."
            ) from exc
        else:
            raise CanaryFailure(
                f"an unreadable digest ({value!r}) was ACCEPTED and the plan approved"
            )
    return f"{len(unreadable)} unreadable encodings refused, none as a mutation"


def canary_mutation_after_authorization_is_refused() -> str:
    """And the refusal a4 was REACHING for still happens, on a real change.

    Approval evidence bound to plan 1's digest must not authorize plan 2. That
    is ADR-0026 § 2's binding, and separating the encoding fault from it must
    not have loosened it — a fix that made everything approve would satisfy
    every canary above.
    """
    from dotmac_deployment_control import (
        ApprovalRefusedError,
        DesiredDeployment,
        DigestEncodingError,
        ProposePlanCommand,
        SetDesiredStateCommand,
        propose_plan,
        set_desired_state,
    )

    db = _session()
    target, first = _proposed_plan(db, replicas=2)
    set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=_command_id(),
            target_id=target.id,
            desired=DesiredDeployment(
                release_ref="dotmac_sub@7.187.1",
                spec={"replicas": 9},
                licence_ref="lic-1",
                brand_profile_ref="brand-acme",
            ),
        ),
    )
    second = propose_plan(
        db,
        ProposePlanCommand(
            command_id=_command_id(),
            target_id=target.id,
            operation="deploy",
            descriptor_digest=_DESCRIPTOR,
            execution_plan_digest=_EXECUTION_PLAN,
            requires_approval=True,
            approval_policy_code=_POLICY,
            approval_policy_version=_POLICY_VERSION,
        ),
    )
    if second.plan_digest == first.plan_digest:
        raise CanaryFailure(
            "the plan changed and its digest did not, so the binding cannot "
            "detect anything"
        )
    try:
        _approve(db, second.id, first.plan_digest or "")
    except DigestEncodingError as exc:
        raise CanaryFailure(
            f"a genuinely stale-but-well-formed digest was reported as an "
            f"encoding fault: {exc}"
        ) from exc
    except ApprovalRefusedError as exc:
        if "plan changed" not in str(exc).lower():
            raise CanaryFailure(
                f"the refusal does not say the plan changed: {exc}"
            ) from exc
        stale = (first.plan_digest or "")[:23]
        return f"stale digest {stale}… refused for plan {second.id}"
    raise CanaryFailure(
        "approval evidence bound to a superseded plan's digest AUTHORIZED a "
        "different plan"
    )


# ── the published database catalogue ────────────────────────────────────────
#
# `0.1.0a7`'s HEADLINE is a source-owned `ModuleDatabaseCatalogContributionV1`
# publishing `mod_deploy`'s exact seven platform tables and 95 columns; the
# literal below is the POST-`dc_0008` extent, eight tables and 133 columns, and
# it describes THIS TREE rather than the last release. It
# shipped with NO canary driving it: the nine canaries above are a6's exact set,
# and the extent was proven only by source tests on the release commit. That is
# the a4 shape one level up — a proof of one question (does the source declare
# the right structure?) read as a proof of another (does the ARTIFACT carry it?)
# — and a7's own record says so in the sentence
# `test_a7s_record_says_what_the_canaries_do_NOT_cover` pins.
#
# THE COUNTS ARE NOT THE CONTRACT. A canary asserting `len(tables) == 8 and
# len(columns) == 133` passes against a catalogue holding eight wrong tables, and
# this programme keeps finding and repairing exactly that check. So the whole
# canonical structure is written out below — every table name, every column
# name, its physical ordinal, its PostgreSQL type identity AND rendered
# spelling, its nullability and its server default — and the comparison is
# element-by-element with an attributed difference for each.
#
# Written as LITERALS, and for the same reason `_FLOOR_MODULES` is: this script
# runs in an environment that has the wheel installed and does NOT have this
# repository importable, so it cannot ask `src/` what the answer should be. A
# canary that derived its expectation from the artifact it is checking would be
# comparing the artifact against itself, which is the tautology a4 shipped
# inside. `tests/architecture/test_artifact_canaries.py` is what keeps this
# table and the source declaration from drifting apart, in both directions.

#: Type identity as `(pg_catalog name, rendered spelling)`. Both halves, because
#: they answer different questions: `varchar` is the type a consumer's
#: introspection reports and `character varying(128)` is the width `dc_0002`
#: exists to establish. A catalogue authored from the ROOT revision would agree
#: on the first and differ on the second.
_UUID = ("uuid", "uuid")
_INT = ("int4", "integer")
_BOOL = ("bool", "boolean")
_JSONB = ("jsonb", "jsonb")
_TEXT = ("text", "text")
_BYTEA = ("bytea", "bytea")
_TS = ("timestamptz", "timestamp with time zone")
_V20 = ("varchar", "character varying(20)")
_V24 = ("varchar", "character varying(24)")
_V40 = ("varchar", "character varying(40)")
_V60 = ("varchar", "character varying(60)")
_V120 = ("varchar", "character varying(120)")
_V128 = ("varchar", "character varying(128)")
_V200 = ("varchar", "character varying(200)")
_V500 = ("varchar", "character varying(500)")

#: The catalogue document's own identity, independent of any release.
CATALOGUE_DOCUMENT_SCHEMA = "dotmac.module-database-catalog/v1"
CATALOGUE_DOCUMENT_SCOPE = "tables_and_columns"
CATALOGUE_MODULE_CODE = "deployment_control"
CATALOGUE_DATABASE_SCHEMA = "mod_deploy"
CATALOGUE_LINEAGE_HEAD = "dc_0008_recovery_grants"
#: Every table is on the PLATFORM plane and owned by the module itself. Held as
#: single values rather than per-table, because "the module owns all eight and
#: none of them is tenant-scoped" is the actual claim (ADR-0023: the plane is
#: DECLARED, never inferred), and a per-table copy would let one row drift while
#: reading as if it had been checked.
CATALOGUE_PLANE = "platform"
CATALOGUE_OWNER = {"kind": "module", "code": CATALOGUE_MODULE_CODE}
CATALOGUE_RELATION_KIND = "table"

#: `(table, ((column, ordinal, type, nullable, server default), ...))`, in the
#: canonical table order the contract requires and the physical ordinal order
#: inside each table.
CATALOGUE_TABLES: tuple[
    tuple[str, tuple[tuple[str, int, tuple[str, str], bool, str], ...]], ...
] = (
    (
        "deployment_plans",
        (
            ("id", 1, _UUID, False, ""),
            ("target_id", 2, _UUID, False, ""),
            ("sequence", 3, _INT, False, ""),
            ("status", 4, _V24, False, ""),
            ("snapshot", 5, _JSONB, True, ""),
            ("desired_revision", 6, _INT, False, ""),
            ("plan_digest", 7, _V128, True, ""),
            ("requires_approval", 8, _BOOL, False, ""),
            ("approval_policy_code", 9, _V120, True, ""),
            ("approval_policy_version", 10, _INT, True, ""),
            ("approval_decision_ref", 11, _V200, True, ""),
            ("approved_at", 12, _TS, True, ""),
            ("superseded_by_id", 13, _UUID, True, ""),
            ("record_version", 14, _INT, False, ""),
            ("created_at", 15, _TS, False, "now()"),
            ("updated_at", 16, _TS, False, "now()"),
            # dc_0003, appended in ADD COLUMN order — see the declaration.
            ("operation", 17, _V20, True, ""),
            ("execution_plan_digest", 18, _V128, True, ""),
            ("authorized_operation", 19, _V20, True, ""),
            ("authorized_execution_plan_digest", 20, _V128, True, ""),
            # dc_0004, appended after dc_0003's for the same physical reason.
            # There is deliberately NO image column here — a plan's authorized
            # image set is inside `snapshot`, the document `plan_digest` covers.
            ("approval_decision_status", 21, _V24, True, ""),
            ("approval_revoked_at", 22, _TS, True, ""),
            ("approval_revocation_ref", 23, _V200, True, ""),
            ("approval_revocation_reason", 24, _V200, True, ""),
        ),
    ),
    (
        "deployment_targets",
        (
            ("id", 1, _UUID, False, ""),
            ("target_ref", 2, _V200, False, ""),
            ("subject_ref", 3, _V200, False, ""),
            ("product_code", 4, _V120, False, ""),
            ("environment", 5, _V60, False, ""),
            ("status", 6, _V24, False, ""),
            ("desired_release_ref", 7, _V200, True, ""),
            ("desired_spec", 8, _JSONB, True, ""),
            ("licence_ref", 9, _V200, True, ""),
            ("brand_profile_ref", 10, _V200, True, ""),
            ("desired_revision", 11, _INT, False, ""),
            ("observed_release_ref", 12, _V200, True, ""),
            ("observed_spec_digest", 13, _V128, True, ""),
            ("observed_revision", 14, _INT, True, ""),
            ("last_observed_at", 15, _TS, True, ""),
            ("record_version", 16, _INT, False, ""),
            ("created_at", 17, _TS, False, "now()"),
            ("updated_at", 18, _TS, False, "now()"),
            # dc_0004: the declared authorized image set, on the TARGET.
            ("desired_images", 19, _JSONB, True, ""),
            # dc_0006: trusted execution high-water coordinate.
            ("last_execution_sequence", 20, _INT, True, ""),
            ("last_execution_attempt_no", 21, _INT, True, ""),
            ("last_execution_state_digest", 22, _V128, True, ""),
        ),
    ),
    (
        "observation_attempts",
        (
            ("id", 1, _UUID, False, ""),
            ("received_at", 2, _TS, False, ""),
            ("raw_body", 3, _BYTEA, True, ""),
            ("raw_body_truncated", 4, _BOOL, False, ""),
            ("raw_body_digest", 5, _V128, True, ""),
            ("signature_status", 6, _V20, False, ""),
            ("eligibility_at_receipt", 7, _V20, False, ""),
            ("key_id", 8, _V200, True, ""),
            ("authenticated_target_ref", 9, _V200, True, ""),
            ("claimed_target_ref", 10, _V200, True, ""),
            ("report_id", 11, _V200, True, ""),
            ("disposition", 12, _V40, False, ""),
            ("receipt_id", 13, _UUID, True, ""),
            ("created_at", 14, _TS, False, "now()"),
            ("updated_at", 15, _TS, False, "now()"),
        ),
    ),
    (
        "observation_receipts",
        (
            ("id", 1, _UUID, False, ""),
            ("authenticated_target_ref", 2, _V200, False, ""),
            ("report_id", 3, _V200, False, ""),
            ("payload", 4, _BYTEA, True, ""),
            ("payload_digest", 5, _V128, True, ""),
            ("key_id", 6, _V200, False, ""),
            ("first_received_at", 7, _TS, False, ""),
            ("original_verdict", 8, _V40, False, ""),
            ("observed_release_ref", 9, _V200, True, ""),
            ("observed_spec_digest", 10, _V128, True, ""),
            ("created_at", 11, _TS, False, "now()"),
            ("updated_at", 12, _TS, False, "now()"),
            # dc_0006: signed execution coordinate and substantive state.
            ("execution_sequence", 13, _INT, True, ""),
            ("attempt_no", 14, _INT, True, ""),
            ("observed_state_digest", 15, _V128, True, ""),
        ),
    ),
    (
        "recovery_grants",
        (
            ("id", 1, _UUID, False, ""),
            ("grant_id", 2, _V200, False, ""),
            ("target_id", 3, _UUID, False, ""),
            ("product_code", 4, _V120, False, ""),
            ("environment", 5, _V60, False, ""),
            ("recovery_execution_plan_digest", 6, _V128, False, ""),
            ("recovery_bundle_digest", 7, _V128, False, ""),
            ("incumbent_prestate_digest", 8, _V128, False, ""),
            # The signed document; the five above are a lookup projection of
            # terms inside it and never the authority.
            ("grant_envelope", 9, _JSONB, False, ""),
            ("not_before", 10, _TS, False, ""),
            ("issued_at", 11, _TS, False, ""),
            ("expires_at", 12, _TS, False, ""),
            # Revocation is a state change; the row stays.
            ("revoked_at", 13, _TS, True, ""),
            ("revocation_ref", 14, _V200, True, ""),
            ("revocation_reason", 15, _V500, True, ""),
            ("record_version", 16, _INT, False, ""),
            ("created_at", 17, _TS, False, "now()"),
            ("updated_at", 18, _TS, False, "now()"),
        ),
    ),
    (
        "rollout_attempts",
        (
            ("id", 1, _UUID, False, ""),
            ("rollout_id", 2, _UUID, False, ""),
            ("attempt_no", 3, _INT, False, ""),
            ("outcome", 4, _V20, False, ""),
            ("integrator_ref", 5, _V200, True, ""),
            ("error_code", 6, _V60, True, ""),
            ("detail", 7, _TEXT, True, ""),
            ("dispatched_at", 8, _TS, True, ""),
            ("settled_at", 9, _TS, True, ""),
            ("created_at", 10, _TS, False, "now()"),
            ("updated_at", 11, _TS, False, "now()"),
            # dc_0007: exact signed attempt, nullable only for old rows.
            ("dispatch_envelope", 12, _JSONB, True, ""),
        ),
    ),
    (
        "rollouts",
        (
            ("id", 1, _UUID, False, ""),
            ("rollout_ref", 2, _V200, False, ""),
            ("target_id", 3, _UUID, False, ""),
            ("plan_id", 4, _UUID, False, ""),
            ("status", 5, _V24, False, ""),
            ("reason", 6, _TEXT, True, ""),
            ("completed_at", 7, _TS, True, ""),
            ("record_version", 8, _INT, False, ""),
            ("created_at", 9, _TS, False, "now()"),
            ("updated_at", 10, _TS, False, "now()"),
            # dc_0005: immutable issuance fact, nullable only for legacy rows.
            ("authorization_envelope", 11, _JSONB, True, ""),
            # dc_0006: per-target monotonic execution coordinate.
            ("execution_sequence", 12, _INT, True, ""),
        ),
    ),
    (
        "target_credentials",
        (
            ("id", 1, _UUID, False, ""),
            ("target_id", 2, _UUID, False, ""),
            ("key_id", 3, _V200, False, ""),
            ("public_key_b64", 4, _V200, False, ""),
            ("public_key_fingerprint", 5, _V128, False, ""),
            ("status", 6, _V20, False, ""),
            ("activated_at", 7, _TS, True, ""),
            ("retired_at", 8, _TS, True, ""),
            ("revoked_at", 9, _TS, True, ""),
            ("revocation_reason", 10, _V200, True, ""),
            ("enrollment_authority", 11, _V60, False, ""),
            ("created_at", 12, _TS, False, "now()"),
            ("updated_at", 13, _TS, False, "now()"),
            # dc_0006: exact verification interpretation, NULL on legacy rows.
            ("algorithm", 14, _V60, True, ""),
            ("purpose", 15, _V60, True, ""),
        ),
    ),
)


CATALOGUE_TABLE_COUNT = len(CATALOGUE_TABLES)
CATALOGUE_COLUMN_COUNT = sum(len(columns) for _, columns in CATALOGUE_TABLES)


def _expected_column(column: tuple[str, int, tuple[str, str], bool, str]) -> dict:
    """One column as the canonical document spells it."""
    name, ordinal, (type_name, formatted), nullable, default = column
    return {
        "name": name,
        "ordinal": ordinal,
        "postgres_type": {
            # BASE and `pg_catalog` for all 133: this module declares no domain,
            # enum, composite, range or array column, and stating that here is
            # what makes the absence a declaration rather than an oversight.
            "kind": "base",
            "schema": "pg_catalog",
            "name": type_name,
            "formatted": formatted,
        },
        "nullable": nullable,
        "generation": "default" if default else "none",
        "expression": default,
        # No column carries a non-default collation, and a catalogue that
        # started declaring one would be describing a different database.
        "collation": None,
    }


def _difference(where: str, field: str, expected: object, actual: object) -> str:
    return f"{where}: {field} is {actual!r}, the published contract says {expected!r}"


def catalogue_differences(document: object, expect_version: str) -> list[str]:
    """Every way one catalogue document differs from the declaration above.

    PURE — a parsed JSON document in, a list of attributed English differences
    out. No import, no environment, no filesystem. That is deliberate: it lets
    `tests/architecture/test_artifact_canaries.py` drive this exact function
    against the SOURCE tree's own declaration (which must produce no
    differences) and against mutated copies of it (each of which must produce a
    difference naming the thing that moved), so the comparator is proven
    sensitive without ever being run from a checkout in a lane that claims to be
    about an artifact.

    Every difference is collected rather than raised on the first, because a
    reader repairing a drifted catalogue needs the whole set; a first-failure
    abort turns one review into seven.
    """
    if not isinstance(document, dict):
        return [f"the catalogue document is {type(document).__name__}, not an object"]

    differences: list[str] = []

    def compare(where: str, field: str, expected: object, actual: object) -> None:
        if actual != expected:
            differences.append(_difference(where, field, expected, actual))

    header = {
        "schema": CATALOGUE_DOCUMENT_SCHEMA,
        "scope": CATALOGUE_DOCUMENT_SCOPE,
        "distribution_name": DISTRIBUTION,
        # From `--expect-version`, so the identity the catalogue claims is
        # compared against an EXTERNAL statement of what was built rather than
        # against the artifact's own report of itself.
        "distribution_version": expect_version,
        "module_code": CATALOGUE_MODULE_CODE,
        "module_release_version": expect_version,
        "database_schema": CATALOGUE_DATABASE_SCHEMA,
        "lineage_head": CATALOGUE_LINEAGE_HEAD,
    }
    for field, expected in header.items():
        compare("the catalogue", field, expected, document.get(field))

    # DELIBERATELY NOT PINNED TO A LITERAL. `manifest_contract_version` is the
    # kernel's manifest GENERATION, and Deployment Control declares none — the
    # kernel infers it from `KERNEL_MODULE_CONTRACT_VERSION` at manifest
    # construction. It is therefore a property of the kernel resolved into the
    # environment, not of this wheel, and a literal here would make the canary
    # red on a kernel bump that changed nothing about this artifact. What IS
    # checkable is that it is a real generation rather than a string or a
    # sentinel.
    generation = document.get("manifest_contract_version")
    if type(generation) is not int or generation < 1:
        differences.append(
            "the catalogue: manifest_contract_version is "
            f"{generation!r}, which is not a positive integer generation"
        )

    tables = document.get("tables")
    if not isinstance(tables, list):
        differences.append(
            f"the catalogue: tables is {type(tables).__name__}, not an array"
        )
        return differences

    observed_names = [
        table.get("name") if isinstance(table, dict) else table for table in tables
    ]
    expected_names = [name for name, _ in CATALOGUE_TABLES]
    if observed_names != expected_names:
        observed_set = {str(name) for name in observed_names}
        missing = sorted(set(expected_names) - observed_set)
        unknown = sorted(observed_set - set(expected_names))
        differences.append(
            f"the catalogue publishes {len(observed_names)} tables "
            f"{observed_names}, and the published contract is the "
            f"{len(expected_names)} tables {expected_names}"
            + (f"; missing={missing}" if missing else "")
            + (f"; unknown={unknown}" if unknown else "")
        )

    by_name = {
        table.get("name"): table
        for table in tables
        if isinstance(table, dict) and isinstance(table.get("name"), str)
    }
    for name, columns in CATALOGUE_TABLES:
        table = by_name.get(name)
        if table is None:
            continue  # already reported by the extent difference above
        where = f"{CATALOGUE_DATABASE_SCHEMA}.{name}"
        compare(where, "schema", CATALOGUE_DATABASE_SCHEMA, table.get("schema"))
        compare(where, "owner", CATALOGUE_OWNER, table.get("owner"))
        compare(where, "plane", CATALOGUE_PLANE, table.get("plane"))
        compare(
            where,
            "relation_kind",
            CATALOGUE_RELATION_KIND,
            table.get("relation_kind"),
        )
        observed_columns = table.get("columns")
        if not isinstance(observed_columns, list):
            differences.append(
                f"{where}: columns is {type(observed_columns).__name__}, not an array"
            )
            continue
        expected_columns = [_expected_column(column) for column in columns]
        if len(observed_columns) != len(expected_columns):
            observed_column_names = {
                column.get("name")
                for column in observed_columns
                if isinstance(column, dict)
            }
            expected_column_names = {column["name"] for column in expected_columns}
            unknown_columns = observed_column_names - expected_column_names
            differences.append(
                f"{where} publishes {len(observed_columns)} columns and the "
                f"published contract is {len(expected_columns)}; "
                f"missing={sorted(expected_column_names - observed_column_names)}, "
                f"unknown={sorted(str(name) for name in unknown_columns)}"
            )
        for expected_column in expected_columns:
            observed = next(
                (
                    column
                    for column in observed_columns
                    if isinstance(column, dict)
                    and column.get("name") == expected_column["name"]
                ),
                None,
            )
            if observed is None:
                differences.append(
                    f"{where}: column {expected_column['name']!r} is not published "
                    "at all"
                )
                continue
            for field, expected_value in expected_column.items():
                compare(
                    f"{where}.{expected_column['name']}",
                    field,
                    expected_value,
                    observed.get(field),
                )
    return differences


def _installed_origin(dotted: str) -> Path:
    """The file `dotted` resolved to, refusing anything outside an install.

    The SAME MECHANISM `installed_not_source` uses, factored out rather than
    reimplemented — a second way of asking "is this the artifact?" is a second
    answer waiting to disagree with the first. Two of its three statements are
    per-module and belong here (the origin is inside an install directory; no
    checkout copy shadows it on `sys.path`); the third, discoverable
    distribution METADATA, is a statement about the distribution rather than
    about one module and stays where it is.
    """
    module = __import__(dotted, fromlist=["x"])
    origin = Path(module.__file__ or "").resolve()
    sites = _site_directories()
    if not sites:
        raise CanaryFailure("this interpreter reports no install directory at all")
    if not any(origin.is_relative_to(site) for site in sites):
        raise CanaryFailure(
            f"{dotted} was imported from {origin}, which is not inside any of "
            f"this interpreter's install directories ({sites}). sys.path is "
            f"{sys.path}. This canary is a statement about a PUBLISHED "
            "catalogue; satisfying it from a working tree would prove nothing "
            "about what a consumer installs."
        )
    top_level = dotted.split(".")[0]
    shadowing = [
        entry
        for entry in sys.path
        if entry
        and (Path(entry).resolve() / top_level / "__init__.py").is_file()
        and not any(Path(entry).resolve().is_relative_to(site) for site in sites)
    ]
    if shadowing:
        raise CanaryFailure(
            f"a source copy of {top_level} is importable from {shadowing}, so a "
            f"path ordering change would move {dotted} onto the checkout"
        )
    return origin


def _published_catalogue(expect_version: str) -> Any:
    """The installed artifact's own release snapshot of its database catalogue.

    Built through the artifact's `build_database_catalog_snapshot`, which is the
    entry point a release lane actually calls, and handed the lineage head and
    owner from THIS FILE'S literals rather than from the artifact's own
    contribution. That direction matters: `from_manifest` refuses when the
    authored head disagrees with the supplied one, so passing the artifact its
    own value back would turn the check into `x == x`.
    """
    from dotmac_kernel.product_database_catalog import (
        ComposedDatabaseLineageHeadV1,
        DatabaseCatalogOwnerKind,
        DatabaseCatalogOwnerV1,
    )

    for dotted in (
        f"{IMPORT_NAME}.database_catalog",
        f"{IMPORT_NAME}.database_catalog_snapshot",
        f"{IMPORT_NAME}.manifest",
    ):
        _installed_origin(dotted)

    from dotmac_deployment_control import build_database_catalog_snapshot

    return build_database_catalog_snapshot(
        distribution_version=expect_version,
        composed_lineage_head=ComposedDatabaseLineageHeadV1(
            owner=DatabaseCatalogOwnerV1(
                kind=DatabaseCatalogOwnerKind.MODULE,
                code=CATALOGUE_MODULE_CODE,
            ),
            revision=CATALOGUE_LINEAGE_HEAD,
        ),
    )


def canary_database_catalogue_as_published(expect_version: str) -> str:
    """THE PROOF `0.1.0a7` SHIPPED WITHOUT: the ARTIFACT carries the catalogue.

    a7's headline was `mod_deploy`'s exact seven platform tables and 95
    columns — 114 after `dc_0006` — and not one of the nine canaries it published
    touched them. The extent was
    proven by source tests on the release commit — a real proof of a different
    question, and `docs/CONTROL_EXCEPTIONS.md` already records that a source
    check is not a control carried by any published artifact.

    Everything asserted here is asserted about the INSTALLED distribution:

    * the catalogue modules resolve out of `site-packages`, with no checkout
      copy shadowing them, and the evidence is in this canary's own output;
    * module identity — document schema and scope, distribution name and
      version, module code, release version, `mod_deploy`, and the `dc_0007`
      lineage head;
    * all eight table identities, in canonical order, with nothing missing and
      nothing extra;
    * all 133 columns by name, physical ordinal, PostgreSQL type identity AND
      rendered spelling, nullability, generation and server default;
    * plane and ownership metadata on every table — `platform`, owned by
      `module:deployment_control` (ADR-0023: a plane is DECLARED).

    The counts are the least of it. `len(tables) == 8 and len(columns) == 133`
    passes on seven wrong tables, and the whole structure is compared instead.
    """
    import json

    snapshot = _published_catalogue(expect_version)
    document = json.loads(snapshot.to_json_bytes())
    differences = catalogue_differences(document, expect_version)
    if differences:
        raise CanaryFailure(
            f"the installed artifact publishes a database catalogue that is not "
            f"the published contract ({len(differences)} difference(s)):\n        - "
            + "\n        - ".join(differences)
        )

    columns = sum(len(table["columns"]) for table in document["tables"])
    if (len(document["tables"]), columns) != (
        CATALOGUE_TABLE_COUNT,
        CATALOGUE_COLUMN_COUNT,
    ):  # pragma: no cover - unreachable once every table matched above
        raise CanaryFailure(
            f"{len(document['tables'])} tables / {columns} columns survived a "
            "comparison that found no differences"
        )
    origin = _installed_origin(f"{IMPORT_NAME}.database_catalog")
    return (
        f"{CATALOGUE_TABLE_COUNT} tables / {CATALOGUE_COLUMN_COUNT} columns, "
        f"every name, ordinal, type, nullability, default, plane and owner as "
        f"published; declared by {origin}"
    )


def canary_catalogue_digest_binds(expect_version: str) -> str:
    """The catalogue's canonical digest is over THAT structure, and it BINDS.

    A digest is how a consumer adopts a structural contract, so three separate
    things have to be true and each fails on its own:

    1. the digest is canonical in shape and is the sha256 of the document the
       artifact actually serialises — recomputed here with `hashlib`, not read
       back from the same property that produced it;
    2. the bytes round-trip: the kernel re-parses them, re-derives an equal
       snapshot, and re-serialises the identical bytes, which is what "canonical"
       means and is the only reason two parties can compare digests at all;
    3. THE SENSITIVITY, without which 1 and 2 are a self-consistent nothing: a
       one-byte change to the document is REFUSED against the same digest, and
       the true document is refused against a different digest. A digest that
       accepts either is not binding anything.

    NO LITERAL DIGEST IS PINNED HERE, and that is a deliberate limit worth
    stating. The document carries `distribution_version` and
    `module_release_version`, so its digest changes with every release; a
    literal would go stale at the next version and would then be silently
    weakened into whatever the next author replaced it with. The external
    statement this canary holds is the STRUCTURE, above, and the digest is
    proven to be over exactly that. The digest VALUE for a given release belongs
    in that release's record in `docs/published-versions.json`, where it is
    immutable, rather than in a canary that has to keep moving.
    """
    import hashlib
    import json

    from dotmac_kernel.product_database_catalog import (
        ModuleDatabaseCatalogSnapshot,
        ProductDatabaseCatalogError,
    )

    snapshot = _published_catalogue(expect_version)
    payload = snapshot.to_json_bytes()
    digest = snapshot.digest

    if not CANONICAL_DIGEST.fullmatch(digest):
        raise CanaryFailure(
            f"the catalogue digest is {digest!r}, which is not `sha256:<64 "
            "lowercase hex>`. An adopting consumer cannot say which algorithm "
            "produced it."
        )
    recomputed = f"sha256:{hashlib.sha256(payload).hexdigest()}"
    if digest != recomputed:
        raise CanaryFailure(
            f"the catalogue reports {digest} and its own canonical bytes hash "
            f"to {recomputed}"
        )

    # The digest covers the structure this file declares — stated here as well
    # as in the canary above, because a digest over the wrong document is a
    # perfectly valid digest.
    differences = catalogue_differences(json.loads(payload), expect_version)
    if differences:
        raise CanaryFailure(
            f"the digested document is not the published contract: {differences}"
        )

    restored = ModuleDatabaseCatalogSnapshot.from_json_bytes(
        payload, expected_digest=digest
    )
    if restored != snapshot or restored.to_json_bytes() != payload:
        raise CanaryFailure(
            "the catalogue document does not round-trip to identical bytes, so "
            "two parties comparing digests are comparing encodings"
        )

    # THE SENSITIVITY. `now()` appears as a server default on fourteen columns;
    # changing one of them is the smallest edit that is still a real structural
    # lie, and the digest must refuse it.
    mutated = payload.replace(b'"expression":"now()"', b'"expression":"NOW()"', 1)
    if mutated == payload:
        raise CanaryFailure(
            "the canonical document contains no server default to perturb, so "
            "this sensitivity check would pass without testing anything"
        )
    for description, bytes_, expected_digest in (
        ("a mutated document against the true digest", mutated, digest),
        ("the true document against a foreign digest", payload, "sha256:" + "0" * 64),
    ):
        try:
            ModuleDatabaseCatalogSnapshot.from_json_bytes(
                bytes_, expected_digest=expected_digest
            )
        except ProductDatabaseCatalogError:
            continue
        raise CanaryFailure(
            f"{description} was ACCEPTED. The digest does not bind the "
            "catalogue, so adopting by digest proves nothing."
        )

    return (
        f"{digest} over {len(payload)} canonical bytes "
        f"({CATALOGUE_TABLE_COUNT} tables / {CATALOGUE_COLUMN_COUNT} columns); "
        "round-trips, and a one-byte change is refused"
    )


def canary_portable_authorization_binds() -> str:
    """The installed artifact can issue and independently verify the envelope.

    The local HMAC is a canary provider, not package policy.  Its only job is
    to drive the provider-neutral protocols from the installed wheel and prove
    that a Foundation descriptor mutation invalidates the same signature.
    """
    import importlib.metadata
    import json

    from dotmac_deployment_control import (
        AUTHORIZATION_PURPOSE,
        AuthorizationEnvelopeRefusedError,
        issue_authorization_envelope,
        verify_authorization_envelope,
    )

    _installed_origin(f"{IMPORT_NAME}.authorization")
    issued = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)
    fields = {
        "authorization_id": "auth-artifact-canary",
        "rollout_ref": "rollout-artifact-canary",
        "plan_id": "plan-artifact-canary",
        "execution_sequence": 1,
        "target_id": "target-artifact-canary",
        "target_ref": "target/reference",
        "product_code": "artifact-canary",
        "environment": "test",
        "operation": "deploy",
        "release_ref": "artifact-canary@1",
        # Deliberately reverse lexical service order. Issuance must produce the
        # same bytes as the forward order because this is a set.
        "authorized_images": [
            {
                "service": "worker",
                "repository": "registry.invalid/worker",
                "digest": "sha256:" + "22" * 32,
            },
            {
                "service": "api",
                "repository": "registry.invalid/api",
                "digest": "sha256:" + "11" * 32,
            },
        ],
        "plan_digest": "sha256:" + "33" * 32,
        "descriptor_digest": "sha256:" + "44" * 32,
        "execution_plan_digest": "sha256:" + "55" * 32,
        "approval_policy_code": "deployment.test",
        "approval_policy_version": 1,
        "approval_decision_ref": "approval-artifact-canary",
        "approval_decision_status": "granted",
        "approved_at": issued,
        "issued_at": issued,
        "expires_at": issued.replace(year=2027),
    }
    signer = _authorization_signer()
    verifier = _authorization_verifier()
    envelope = issue_authorization_envelope(fields, signer=signer)
    verify_authorization_envelope(envelope, verifier=verifier, at=issued)
    installed = importlib.metadata.version(DISTRIBUTION)
    if envelope.statement.control_version != installed:
        raise CanaryFailure(
            "the signed authorization says Control "
            f"{envelope.statement.control_version}, while installed metadata says "
            f"{installed}"
        )
    if envelope.statement.purpose != AUTHORIZATION_PURPOSE:
        raise CanaryFailure("the signed authorization carries the wrong key purpose")

    reordered = dict(fields)
    reordered["authorized_images"] = list(reversed(fields["authorized_images"]))
    second = issue_authorization_envelope(reordered, signer=signer)
    if second.as_mapping() != envelope.as_mapping():
        raise CanaryFailure("image order changed portable authorization meaning")

    mutated = json.loads(json.dumps(envelope.as_mapping()))
    mutated["statement"]["descriptor_digest"] = "sha256:" + "66" * 32
    try:
        verify_authorization_envelope(mutated, verifier=verifier, at=issued)
    except AuthorizationEnvelopeRefusedError:
        pass
    else:
        raise CanaryFailure("a descriptor-only mutation kept a valid signature")

    fewer = dict(fields)
    fewer["authorized_images"] = fields["authorized_images"][1:]
    if (
        issue_authorization_envelope(fewer, signer=signer).signature
        == envelope.signature
    ):
        raise CanaryFailure("image membership did not change portable authorization")

    return (
        f"provider-neutral v2 envelope binds installed Control {installed}; image "
        "reorder was identical, descriptor mutation was refused, and image "
        "membership changed the signature"
    )


def canary_signed_dispatch_binds_attempt() -> str:
    """The installed artifact signs the concrete attempt before transport."""
    import json

    from dotmac_deployment_control import (
        DispatchEnvelopeRefusedError,
        RequestRolloutCommand,
        dispatch_attempt,
        request_rollout,
        verify_dispatch_envelope,
    )

    _installed_origin(f"{IMPORT_NAME}.dispatch_envelope")
    db = _session()
    # The empty list is a DECLARED empty image set. ``None`` means an old plan
    # that predates image authorization and is correctly refused by the
    # portable authorization path before this canary reaches dispatch.
    _target, plan = _proposed_plan(db, images=[])
    _approve(db, plan.id, plan.plan_digest)
    rollout = request_rollout(
        db,
        RequestRolloutCommand(
            command_id=_command_id(),
            rollout_ref=f"rol-{uuid.uuid4().hex[:8]}",
            plan_id=plan.id,
            authorization_expires_at=datetime.now(UTC) + timedelta(days=1),
        ),
        signer=_authorization_signer(),
    )
    command_id = _command_id()
    intent = dispatch_attempt(
        db,
        command_id=command_id,
        rollout_id=rollout.id,
        verifier=_authorization_verifier(),
        dispatch_signer=_dispatch_signer(),
    )
    verified = verify_dispatch_envelope(
        intent.dispatch_envelope,
        authorization_envelope=intent.authorization_envelope,
        authorization_verifier=_authorization_verifier(),
        dispatch_verifier=_dispatch_verifier(),
        at=intent.dispatch_envelope.statement.issued_at,
    )
    if verified.statement.attempt_no != 1 or intent.attempt_no != 1:
        raise CanaryFailure("the first dispatch did not bind attempt 1")
    if "attempt_no" in intent.__dataclass_fields__:
        raise CanaryFailure("DeliveryIntent still carries an unsigned attempt sibling")

    replay = dispatch_attempt(
        db,
        command_id=command_id,
        rollout_id=rollout.id,
        verifier=_authorization_verifier(),
        dispatch_signer=_dispatch_signer(),
    )
    if replay.dispatch_envelope.canonical_bytes != verified.canonical_bytes:
        raise CanaryFailure(
            "idempotent replay did not return the original signed bytes"
        )

    mutated = json.loads(json.dumps(verified.as_mapping()))
    mutated["statement"]["attempt_no"] = 2
    try:
        verify_dispatch_envelope(
            mutated,
            authorization_envelope=intent.authorization_envelope,
            authorization_verifier=_authorization_verifier(),
            dispatch_verifier=_dispatch_verifier(),
            at=verified.statement.issued_at,
        )
    except DispatchEnvelopeRefusedError:
        pass
    else:
        raise CanaryFailure("an attempt_no-only mutation kept a valid signature")

    try:
        from dotmac_deployment_control import issue_dispatch_envelope

        issue_dispatch_envelope(
            authorization_envelope=intent.authorization_envelope,
            dispatch_id="wrong-purpose",
            attempt_no=1,
            issued_at=verified.statement.issued_at,
            signer=_authorization_signer(),
        )
    except DispatchEnvelopeRefusedError:
        pass
    else:
        raise CanaryFailure("the authorization signer satisfied dispatch purpose")

    # A renamed adapter is still the same physical key. The distinct method and
    # purpose make accidental protocol crossing impossible; the fingerprint
    # comparison is what makes deliberate wrapping impossible too.
    try:
        issue_dispatch_envelope(
            authorization_envelope=intent.authorization_envelope,
            dispatch_id="reused-physical-key",
            attempt_no=1,
            issued_at=verified.statement.issued_at,
            signer=_dispatch_signer(key=_AUTHORIZATION_KEY),
        )
    except DispatchEnvelopeRefusedError as exc:
        if exc.code.value != "dispatch_signer_purpose_reused":
            raise CanaryFailure(
                "physical authorization-key reuse was refused for the wrong reason: "
                f"{exc.code.value}"
            ) from exc
    else:
        raise CanaryFailure(
            "the authorization physical key satisfied dispatch purpose through "
            "a renamed adapter"
        )

    return (
        "signed dispatch verified against its exact authorization; replay returned "
        "identical bytes; attempt mutation, protocol crossing and physical-key "
        "purpose reuse refused"
    )


def canary_signed_execution_observation_binds() -> str:
    """The installed artifact admits only a purpose-correct signed result."""
    import json

    from dotmac_deployment_control import (
        CredentialTransitionCommand,
        EnrolCredentialCommand,
        ExecutionObservationRefusedError,
        ExecutionObservationVerificationKey,
        ObservationDisposition,
        RecordObservationCommand,
        activate_credential,
        enrol_credential,
        issue_execution_observation_envelope,
        record_observation,
        verify_execution_observation_envelope,
    )

    _installed_origin(f"{IMPORT_NAME}.execution_observation")
    db = _session()
    target, key_id, rollout_ref = _enrolled_target(db)
    envelope = _signed_execution_observation(
        db,
        target=target,
        key_id=key_id,
        rollout_ref=rollout_ref,
        report_id=f"rep-{uuid.uuid4().hex[:8]}",
    )
    verification_key = ExecutionObservationVerificationKey(
        key_id=key_id,
        algorithm="hmac-sha256-test-only",
        public_key_b64=_public_key_b64(_OBSERVATION_KEY),
        public_key_fingerprint=_public_key_fingerprint(_OBSERVATION_KEY),
    )
    verify_execution_observation_envelope(
        envelope,
        verifier=_execution_observation_verifier(),
        verification_key=verification_key,
    )

    statement_fields = dict(envelope.statement.as_mapping())
    for derived in ("schema", "version", "purpose", "key_id", "algorithm"):
        statement_fields.pop(derived)
    try:
        issue_execution_observation_envelope(
            statement_fields,
            signer=_authorization_signer(),
        )
    except ExecutionObservationRefusedError:
        pass
    else:
        raise CanaryFailure(
            "the authorization signer satisfied the target-observation purpose"
        )

    mutated = json.loads(json.dumps(envelope.as_mapping()))
    mutated["statement"]["observed_revision"] = "git:mutated-after-signing"
    try:
        verify_execution_observation_envelope(
            mutated,
            verifier=_execution_observation_verifier(),
            verification_key=verification_key,
        )
    except ExecutionObservationRefusedError:
        pass
    else:
        raise CanaryFailure("an observed-runtime mutation kept a valid signature")

    verdict = record_observation(
        db,
        RecordObservationCommand(
            command_id=_command_id(),
            observation=envelope.canonical_bytes,
        ),
        observation_verifier=_execution_observation_verifier(),
        authorization_verifier=_authorization_verifier(),
    )
    if verdict.disposition != ObservationDisposition.ACCEPTED.value:
        raise CanaryFailure(
            f"the purpose-correct signed observation was {verdict.disposition!r}"
        )

    replay = record_observation(
        db,
        RecordObservationCommand(
            command_id=_command_id(),
            observation=envelope.canonical_bytes,
        ),
        observation_verifier=_execution_observation_verifier(),
        authorization_verifier=_authorization_verifier(),
    )
    if (
        replay.disposition != ObservationDisposition.IDEMPOTENT_REPLAY.value
        or replay.verdict != ObservationDisposition.ACCEPTED.value
        or replay.receipt_id != verdict.receipt_id
    ):
        raise CanaryFailure("exact signed bytes did not replay the first verdict")

    conflict_envelope = _signed_execution_observation(
        db,
        target=target,
        key_id=key_id,
        rollout_ref=rollout_ref,
        report_id=envelope.statement.report_id,
        observed_revision="desired:changed-under-same-report-id",
    )
    conflict = record_observation(
        db,
        RecordObservationCommand(
            command_id=_command_id(),
            observation=conflict_envelope.canonical_bytes,
        ),
        observation_verifier=_execution_observation_verifier(),
        authorization_verifier=_authorization_verifier(),
    )
    if conflict.disposition != ObservationDisposition.CONFLICT.value:
        raise CanaryFailure("changed signed bytes under one report id did not conflict")

    # Same key id, but an envelope signed by DIFFERENT physical material. A
    # verifier that resolves its own key by id instead of consuming Control's
    # enrolled bytes accepts this plant and fails the canary.
    other_key = b"artifact-canary-unenrolled-key-material"
    wrong_envelope = _signed_execution_observation(
        db,
        target=target,
        key_id=key_id,
        rollout_ref=rollout_ref,
        report_id=f"rep-wrong-key-{uuid.uuid4().hex[:8]}",
        signing_key=other_key,
    )
    wrong_verdict = record_observation(
        db,
        RecordObservationCommand(
            command_id=_command_id(),
            observation=wrong_envelope.canonical_bytes,
        ),
        observation_verifier=_execution_observation_verifier(),
        authorization_verifier=_authorization_verifier(),
    )
    if wrong_verdict.disposition != ObservationDisposition.BAD_SIGNATURE.value:
        raise CanaryFailure(
            "different physical material under the enrolled key id was not refused"
        )

    # A distinct key id does not create a distinct cryptographic purpose. Enrol
    # the authorization key itself as a target key, then prove Control refuses
    # its otherwise-valid target signature against the rollout authorization.
    reused_key_id = f"key-auth-reuse-{uuid.uuid4().hex[:8]}"
    reused_credential = enrol_credential(
        db,
        EnrolCredentialCommand(
            command_id=_command_id(),
            target_id=target.id,
            key_id=reused_key_id,
            algorithm="hmac-sha256-test-only",
            public_key_b64=_public_key_b64(_AUTHORIZATION_KEY),
            enrollment_authority="artifact_canary",
        ),
    )
    activate_credential(
        db,
        CredentialTransitionCommand(
            command_id=_command_id(), credential_id=reused_credential
        ),
    )
    reused_envelope = _signed_execution_observation(
        db,
        target=target,
        key_id=reused_key_id,
        rollout_ref=rollout_ref,
        report_id=f"rep-purpose-reuse-{uuid.uuid4().hex[:8]}",
        signing_key=_AUTHORIZATION_KEY,
    )
    reused_verdict = record_observation(
        db,
        RecordObservationCommand(
            command_id=_command_id(),
            observation=reused_envelope.canonical_bytes,
        ),
        observation_verifier=_execution_observation_verifier(),
        authorization_verifier=_authorization_verifier(),
    )
    if reused_verdict.disposition != ObservationDisposition.SIGNER_PURPOSE_REUSED.value:
        raise CanaryFailure(
            "one physical key under different purpose-specific ids was not refused"
        )
    return (
        "purpose-separated target envelope verified with its enrolled public key; "
        "exact replay was stable; changed report bytes, runtime mutation, same-id "
        "key substitution and physical-key purpose reuse were refused"
    )


def canary_web_surface_ships_its_templates() -> str:
    """The composed browser surface's templates are INSIDE the installed wheel.

    A different failure mode from every canary above, and the one a version
    number cannot see. `WebSurfaceContribution` declares a `TemplatePackage`,
    and the kernel's registry checks that package's root with `is_dir()` while
    building the surface graph — at application startup, in the consuming
    assembly. A wheel that shipped `web.py` and not `templates/` therefore
    imports perfectly, passes every behavioural canary, resolves cleanly, and
    dies at the consumer's container boot with a missing directory.

    That is the shape of the `0.1.0a5` defect wearing different clothes: a
    property nothing in this repository could observe, because the source tree
    always has the directory. So this canary asks the INSTALLED distribution.

    Three statements, because each catches a different way package data can go
    missing:

    * the declared root is a directory, which is the exact predicate the kernel
      will apply;
    * it sits inside the installed package rather than beside a checkout, so a
      source tree on the path cannot answer for it;
    * every template the surface renders is actually in it — a `MANIFEST`
      pattern that matched the directory and none of its files would satisfy
      the first two.
    """
    module = __import__(IMPORT_NAME)
    surface = module.DEPLOYMENT_CONTROL_SURFACE
    package_root = Path(module.__file__ or "").resolve().parent

    templates = surface.templates
    if templates is None:
        raise CanaryFailure(
            "the composed browser surface declares no template package at all, "
            "so its screens have nothing to render from"
        )
    root = Path(templates.root).resolve()
    if not root.is_dir():
        raise CanaryFailure(
            f"the surface declares templates at {root}, which is not a "
            "directory in the installed distribution. The wheel shipped the "
            "Python and not the package data; a consuming assembly would fail "
            "at startup when the kernel validates the surface graph."
        )
    if not root.is_relative_to(package_root):
        raise CanaryFailure(
            f"the template root {root} is outside the installed package "
            f"({package_root}). It is resolving against something other than "
            "the artifact under test."
        )

    required = {
        "targets.html",
        "target_detail.html",
        "arrivals.html",
        "_macros.html",
    }
    present = {path.name for path in root.glob("*.html")}
    missing = sorted(required - present)
    if missing:
        raise CanaryFailure(
            f"the template directory shipped without {missing}. A package-data "
            "pattern that matches the directory and not its files leaves every "
            "screen a TemplateNotFound at first request."
        )
    return f"{len(present)} templates under namespace {templates.namespace!r} at {root}"


def canary_web_surface_templates_render_their_states() -> str:
    """The SHIPPED templates render every state their views can hold.

    `web_surface_ships_its_templates` proves the files are inside the wheel. It
    cannot notice a wheel that shipped an OLD `_macros.html` — the filenames are
    the same, the surface composes, every behavioural canary passes, and the
    fleet page renders one answer where the module computed three. Package data
    is the part of this distribution with no `__version__` of its own, so it is
    the part that has to be executed rather than counted.

    ## Executed from somewhere else on purpose

    `_TEMPLATE_ROOT` resolves by PACKAGE PATH — `Path(__file__).parent /
    "templates"` — precisely because a wheel lives outside any assembly's
    working directory. A relative lookup would find the templates whenever the
    canary happened to run from a checkout and find nothing in production. So
    this runs from an empty temporary directory, and states first that the
    obvious relative path finds nothing there: without that, `is_dir()` on a
    package-resolved root proves the property in a place it could not fail.

    ## The property, stated as distinctness rather than as prose

    Each macro is rendered once per state its value can hold, and every state
    must produce a DIFFERENT rendering. That is exactly the tri-state contract
    — `None` is not `()`, `None` is not `False`, `UNAUTHORIZED` is not
    `DIVERGES` — and it does not hard-code the operator wording, which is
    presentation this canary has no business pinning.
    """
    from jinja2 import Environment, FileSystemLoader

    module = __import__(IMPORT_NAME)
    surface = module.DEPLOYMENT_CONTROL_SURFACE
    templates = surface.templates
    if templates is None:
        raise CanaryFailure("the composed surface declares no template package")
    root = Path(templates.root).resolve()

    origin = Path.cwd()
    with tempfile.TemporaryDirectory() as elsewhere:
        os.chdir(elsewhere)
        try:
            if Path("templates").exists():
                raise CanaryFailure(
                    "a `templates` directory exists in the scratch working "
                    "directory, so a relative resolution would succeed here and "
                    "this canary could not tell the two apart"
                )
            if not root.is_dir():
                raise CanaryFailure(
                    f"the declared template root {root} is not a directory when "
                    "the process runs from somewhere other than a checkout. "
                    "This is the production case: a consuming assembly's "
                    "working directory is its own, and the kernel validates "
                    "this exact path at startup."
                )
            env = Environment(loader=FileSystemLoader(str(root)), autoescape=True)
            macros = env.get_template("_macros.html").module
        finally:
            os.chdir(origin)

    rendered = prove_states_render_distinctly(macros, module)
    summary = ", ".join(f"{name}:{count}" for name, count in sorted(rendered.items()))
    return f"shipped macros render every state distinctly ({summary}) from {root}"


def prove_states_render_distinctly(macros: Any, module: Any) -> dict[str, int]:
    """THE RULE, separated from where the templates were found.

    Public so `tests/architecture/test_artifact_canaries.py` can drive it
    against a PLANTED `_macros.html` whose branches are collapsed. A canary
    nobody has seen refuse is a step name (ADR-0018), and this one cannot be
    proven sensitive by pointing it at the real package — where it passes.
    """
    image = module.AuthorizedImage(
        "api",
        "registry.dotmac.io/api",
        module.ImageDigestV1.parse("sha256:" + "aa" * 32),
    )
    standing = module.ExecutionBindingStanding
    cases: dict[str, tuple[Any, tuple[Any, ...]]] = {
        # `None` (never declared) / `()` (authorizes none) / the set.
        "image_set": (getattr(macros, "image_set", None), (None, (), (image,))),
        # `None` (no operation declared) / cannot / can.
        "executable": (getattr(macros, "executable", None), (None, False, True)),
        "binding": (
            getattr(macros, "binding", None),
            (
                standing.UNBOUND,
                standing.UNAUTHORIZED,
                standing.MATCHES,
                standing.DIVERGES,
            ),
        ),
        "approval_standing": (
            getattr(macros, "approval_standing", None),
            ("none", "unrecorded", "granted", "revoked"),
        ),
    }
    rendered: dict[str, int] = {}
    for name, (macro, states) in cases.items():
        if macro is None:
            raise CanaryFailure(
                f"the shipped `_macros.html` has no `{name}` macro. The wheel "
                "carries package data older than the code that renders through "
                "it, and every screen using it would flatten its states."
            )
        outputs = [str(macro(state)) for state in states]
        if len(set(outputs)) != len(states):
            raise CanaryFailure(
                f"`{name}` renders {len(states)} distinct states as "
                f"{len(set(outputs))} distinct outputs. A tri-state read "
                "through a two-state `{% if %}` is flattened in Jinja, where no "
                "type checker looks: the module computes the distinction and "
                "the operator never sees it."
            )
        rendered[name] = len(states)

    image_macro = cases["image_set"][0]
    if str(image_macro(None)) == str(image_macro(())):
        raise CanaryFailure(
            "an undeclared image set and a deliberately empty one render "
            "identically — `nobody said` shown as `nobody may`"
        )
    binding_macro = cases["binding"][0]
    if str(binding_macro(standing.UNAUTHORIZED)) == str(
        binding_macro(standing.DIVERGES)
    ):
        raise CanaryFailure(
            "an unapproved plan and a diverged binding render identically. "
            "That is the `proposed != authorized` comparison arriving on the "
            "screen: a plan waiting for a decision shown as an execution "
            "nobody authorized."
        )
    return rendered


# ── runner ──────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--expect-version",
        required=True,
        help=(
            "the version the artifact must report. Supplied by the caller so "
            "the canary compares the artifact against an EXTERNAL statement of "
            "what was built, rather than against itself."
        ),
    )
    parser.add_argument(
        "--expect-kernel",
        default=None,
        help=(
            "the EXACT dotmac-kernel version this environment was built with. "
            "Optional, and the option is the whole floor lane: without it the "
            "canaries run against whatever the resolver chose, which is "
            "precisely the environment in which 0.1.0a5's 21-alpha "
            "under-constraint was invisible. Supplied, it requires the "
            "installed kernel to be that version AND that version to be the "
            "floor the artifact declares."
        ),
    )
    args = parser.parse_args(argv)

    canaries: list[tuple[str, Callable[[], str]]] = [
        ("installed_not_source", canary_installed_not_source),
        ("version_agreement", lambda: canary_version_agreement(args.expect_version)),
        ("propose_emits_canonical", canary_propose_emits_canonical),
        ("exact_digest_approves", canary_exact_digest_approves),
        ("a4_bare_hex_still_binds", canary_a4_bare_hex_still_binds),
        (
            "encoding_fault_is_not_a_mutation",
            canary_encoding_fault_is_not_a_mutation,
        ),
        (
            "mutation_after_authorization_is_refused",
            canary_mutation_after_authorization_is_refused,
        ),
        (
            "declared_kernel_floor",
            lambda: canary_declared_kernel_floor(args.expect_kernel),
        ),
        (
            "database_catalogue_as_published",
            lambda: canary_database_catalogue_as_published(args.expect_version),
        ),
        (
            "catalogue_digest_binds",
            lambda: canary_catalogue_digest_binds(args.expect_version),
        ),
        ("portable_authorization_binds", canary_portable_authorization_binds),
        ("signed_dispatch_binds_attempt", canary_signed_dispatch_binds_attempt),
        (
            "signed_execution_observation_binds",
            canary_signed_execution_observation_binds,
        ),
        # The browser surface's package data, which only an installed
        # artifact can be asked about.
        ("web_surface_ships_its_templates", canary_web_surface_ships_its_templates),
        (
            "web_surface_templates_render_their_states",
            canary_web_surface_templates_render_their_states,
        ),
    ]

    print(f"artifact canaries — {DISTRIBUTION} {args.expect_version}")
    print(f"interpreter: {sys.executable}")
    # THE ENVIRONMENT, PRINTED RATHER THAN ASSUMED. Every canary below is a
    # claim about an installed artifact, and the claim is only as good as the
    # question "which files did this interpreter actually import?". The answer
    # is evidence, so it belongs in the run's own output where a reader of the
    # verify log can check it — not only inside a refusal that fires when it is
    # already too late.
    print("sys.path:")
    for entry in sys.path:
        print(f"  {entry or '(the current working directory)'}")
    print("install directories:")
    for site in _site_directories():
        print(f"  {site}")
    if args.expect_kernel:
        print(f"kernel pinned to the declared floor: {args.expect_kernel}")
    failures: list[str] = []
    for name, canary in canaries:
        try:
            detail = canary()
        except Exception as exc:  # every failure is reported, none escapes
            failures.append(name)
            print(f"  FAIL  {name}")
            for line in traceback.format_exception_only(type(exc), exc):
                print(f"        {line.rstrip()}")
            if not isinstance(exc, CanaryFailure):
                print(f"        (raised {type(exc).__name__}, not a canary refusal)")
        else:
            print(f"  ok    {name}: {detail}")

    if failures:
        print(f"\n{len(failures)} canary/canaries failed: {', '.join(failures)}")
        return 1
    print(f"\nall {len(canaries)} canaries passed against the installed artifact")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
