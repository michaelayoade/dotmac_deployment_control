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
                             `a100`); `transactions` remains a real bound and
                             both are checked. With `--expect-kernel` the
                             equality is exact, which is how `ci.yml`'s floor
                             lane pins the declared minimum literally rather
                             than accepting whatever the resolver chose.
* `conflict_savepoint_executes` — the symbol whose availability sets that floor
                             is not merely importable but WORKS: an accepted
                             observation runs the `with conflict_savepoint(...)`
                             block, and a genuine unique-constraint collision
                             driven through the same context manager leaves the
                             caller's transaction usable. `0.1.0a1` is the
                             version that got this wrong, so it is a property
                             with a history rather than a hypothesis.

## The two canaries `0.1.0a8` adds, and the gap they close

`0.1.0a7`'s headline is a source-owned `ModuleDatabaseCatalogContributionV1`
publishing `mod_deploy`'s exact seven platform tables and 95 columns — the
extent below is the POST-`dc_0003` one, seven tables and 99 columns, because
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
                             exact catalogue: module identity, all seven table
                             identities, all 99 columns by name, ordinal, type
                             identity and rendered spelling, nullability,
                             generation and default, and every table's plane and
                             owner. Compared element-by-element against literals
                             in this file, because `len(tables) == 7 and
                             len(columns) == 99` passes on seven wrong tables.
* `catalogue_digest_binds`  — the canonical digest is the sha256 of the document
                             the artifact serialises, the bytes round-trip, and
                             a one-byte change is REFUSED against that digest.
                             A digest a consumer adopts by has to bind.

Deliberately NOT exercised: `_replay_observation`. Its text comparison of
`payload_digest` is a recorded unmonitored region with its own enforceable
premise (`tests/architecture/test_digest_comparison_is_typed.py`), and it is
being addressed independently. A canary that drove it would make this file a
stakeholder in a redesign it has nothing to say about.
"""

from __future__ import annotations

import argparse
import re
import sys
import sysconfig
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
#: A tuple rather than the single module the floor is set by, because a floor
#: that moves does not retire the earlier bound: `dotmac_kernel.transactions`
#: (kernel `a98`) is still imported by `service.py`, and
#: `dotmac_kernel.product_database_catalog` (kernel `a100`) is what raised the
#: declaration. Dropping the older row would leave the artifact free to lose an
#: import nothing checks.
#:
#: Written here as literals ON PURPOSE. This script runs where the repository is
#: NOT importable, so it cannot ask `scripts/kernel_floor.py` — and it must not:
#: reading the source tree is the one thing these canaries exist to refuse.
#: `tests/architecture/test_kernel_floor.py` is what keeps the two tables from
#: drifting apart.
_FLOOR_MODULES = (
    ("transactions", "conflict_savepoint"),
    ("product_database_catalog", "ModuleDatabaseCatalogContributionV1"),
)


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
       imported for. `product_database_catalog` (kernel `a100`) is the one that
       sets the floor today; `transactions` (kernel `a98`) set it through
       `0.1.0a6` and is still a real bound;
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


def _command_id() -> str:
    return f"cmd-{uuid.uuid4().hex[:12]}"


def _proposed_plan(db: Any, *, replicas: int = 2) -> Any:
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
            ),
        ),
    )
    plan = propose_plan(
        db,
        ProposePlanCommand(
            command_id=_command_id(),
            target_id=target.id,
            operation="deploy",
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
    )


def _approve(db: Any, plan_id: Any, digest: str) -> Any:
    from dotmac_deployment_control import ApprovePlanCommand, approve_plan

    return approve_plan(
        db,
        ApprovePlanCommand(
            command_id=_command_id(), plan_id=plan_id, evidence=_evidence(digest)
        ),
    )


def _enrolled_target(db: Any) -> tuple[Any, str]:
    """A registered target with an ACTIVE credential, ready to be reported to.

    Enrolment and activation are two steps because the module refuses to admit
    a key it has only been told about: the caller proves possession through the
    kernel (ADR-0007) and activation is the record of that. Skipping it here
    would leave the credential PENDING, every observation would be recorded
    `not_eligible`, and the savepoint block would never be reached — a canary
    that passed while proving nothing.
    """
    from dotmac_deployment_control import (
        CredentialTransitionCommand,
        DesiredDeployment,
        EnrolCredentialCommand,
        RegisterTargetCommand,
        SetDesiredStateCommand,
        activate_credential,
        enrol_credential,
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
            desired=DesiredDeployment(release_ref=_RELEASE, spec={"replicas": 2}),
        ),
    )
    key_id = f"key-{uuid.uuid4().hex[:8]}"
    credential_id = enrol_credential(
        db,
        EnrolCredentialCommand(
            command_id=_command_id(),
            target_id=target.id,
            key_id=key_id,
            public_key_b64="AAAA",
            public_key_fingerprint=f"sha256:{uuid.uuid4().hex}",
            enrollment_authority="platform_admin_policy",
        ),
    )
    activate_credential(
        db,
        CredentialTransitionCommand(
            command_id=_command_id(),
            credential_id=credential_id,
            at=_NOW - timedelta(days=1),
        ),
    )
    return target, key_id


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


def canary_conflict_savepoint_executes() -> str:
    """THE SYMBOL THAT SETS THE FLOOR IS NOT MERELY IMPORTABLE — IT WORKS.

    `declared_kernel_floor` proves `dotmac_kernel.transactions` resolves. That
    is the check a5 would have failed and it is still only half the question:
    an import that succeeds and a mechanism that behaves are two facts, and
    this repository's whole argument is that two facts which can only fail
    together are one fact wearing two names.

    So this drives the real path, twice:

    * an ACCEPTED observation runs `record_observation`, whose canonical
      receipt is established inside `with conflict_savepoint(session)`. The
      happy path through the block.
    * a genuine unique-constraint collision is then driven through the SAME
      context manager, and the caller's transaction must still be usable
      afterwards. That is the property `0.1.0a1` shipped without — it did not
      recover the losing first arrival after the receipt constraint chose a
      winner — so it is a property with a history, not a hypothesis.

    `_replay_observation` is deliberately not reached. Its text comparison of
    `payload_digest` is a recorded unmonitored region being addressed
    independently, and a canary that drove it would tie this file to a
    redesign it has nothing to say about.
    """
    import importlib.metadata

    from dotmac_kernel.transactions import conflict_savepoint
    from sqlalchemy import select
    from sqlalchemy.exc import IntegrityError

    from dotmac_deployment_control import service

    # The service module resolved to the INSTALLED package, and the symbol it
    # calls is the kernel's rather than a local shim of the same name. Both are
    # cheap to state and neither is implied by the import succeeding.
    service_origin = Path(service.__file__ or "").resolve()
    if not any(service_origin.is_relative_to(site) for site in _site_directories()):
        raise CanaryFailure(
            f"{IMPORT_NAME}.service was imported from {service_origin}, which "
            "is not an install directory"
        )
    bound = getattr(service, "conflict_savepoint", None)
    if bound is not conflict_savepoint:
        raise CanaryFailure(
            f"{IMPORT_NAME}.service.conflict_savepoint is {bound!r}, not "
            f"{KERNEL_IMPORT_NAME}.transactions.conflict_savepoint. The floor "
            "is declared for the kernel's implementation; a local one of the "
            "same name would make the declaration describe nothing."
        )

    from dotmac_deployment_control import (
        ObservationDisposition,
        ObservationReceipt,
        ObservedState,
        RecordObservationCommand,
        SignatureStatus,
        spec_digest,
    )

    db = _session()
    target, key_id = _enrolled_target(db)
    report_id = f"rep-{uuid.uuid4().hex[:8]}"

    verdict = service.record_observation(
        db,
        RecordObservationCommand(
            command_id=_command_id(),
            observed=ObservedState(
                report_id=report_id,
                observed_release_ref=_RELEASE,
                observed_spec_digest=spec_digest({"replicas": 2}),
                reported_at=_NOW,
                authenticated_target_ref=target.target_ref,
                claimed_target_ref=target.target_ref,
                key_id=key_id,
                raw_body=b"{}",
                raw_body_digest="sha256:" + "b" * 64,
                signature_status=SignatureStatus.VALID.value,
            ),
            received_at=_NOW,
        ),
    )
    if verdict.disposition != ObservationDisposition.ACCEPTED.value:
        raise CanaryFailure(
            f"a valid, eligible, matching observation was {verdict.disposition!r} "
            "rather than accepted, so the savepoint block was never reached"
        )
    if verdict.receipt_id is None:
        raise CanaryFailure(
            "the observation was accepted and no canonical receipt was "
            "established, which is the row the savepoint exists to create"
        )

    # THE RECOVERY, which is the half an import cannot show. A second receipt
    # under the same (identity, report_id) violates
    # `uq_observation_receipts_identity_report`; the savepoint must absorb it
    # and leave the caller's transaction alive.
    #
    # The `try` sits OUTSIDE the `with`, exactly as `service.py` writes it, and
    # that placement is the contract rather than a style choice:
    # `conflict_savepoint` rolls the SAVEPOINT back and RE-RAISES unchanged, so
    # the caller's transaction survives and the caller still learns what
    # happened. A canary that caught the error inside the block would be
    # testing a shape no caller uses.
    collided = False
    try:
        with conflict_savepoint(db):
            db.add(
                ObservationReceipt(
                    authenticated_target_ref=target.target_ref,
                    report_id=report_id,
                    payload=b"{}",
                    payload_digest="sha256:" + "c" * 64,
                    key_id=key_id,
                    first_received_at=_NOW,
                    original_verdict=ObservationDisposition.ACCEPTED.value,
                )
            )
            db.flush()
    except IntegrityError:
        collided = True
    if not collided:
        raise CanaryFailure(
            "a duplicate canonical receipt was inserted without violating "
            "`uq_observation_receipts_identity_report`, so this canary proved "
            "nothing about recovering from a conflict — the constraint is "
            "missing from the artifact"
        )

    # The caller's transaction survived: it can still read, and there is still
    # exactly one canonical receipt.
    receipts = (
        db.execute(
            select(ObservationReceipt).where(
                ObservationReceipt.authenticated_target_ref == target.target_ref,
                ObservationReceipt.report_id == report_id,
            )
        )
        .scalars()
        .all()
    )
    if len(receipts) != 1:
        raise CanaryFailure(
            f"{len(receipts)} canonical receipts exist for one idempotency key; "
            "the savepoint either rolled back too much or too little"
        )
    if receipts[0].id != verdict.receipt_id:
        raise CanaryFailure(
            "the surviving receipt is not the one the accepted observation "
            "established, so the loser overwrote the winner"
        )

    kernel = importlib.metadata.version(KERNEL_DISTRIBUTION)
    return (
        f"accepted through conflict_savepoint, and a real collision left the "
        f"transaction usable (kernel {kernel})"
    )


# ── the published database catalogue ────────────────────────────────────────
#
# `0.1.0a7`'s HEADLINE is a source-owned `ModuleDatabaseCatalogContributionV1`
# publishing `mod_deploy`'s exact seven platform tables and 95 columns; the
# literal below is the POST-`dc_0003` extent, seven tables and 99 columns, and
# it describes THIS TREE rather than the last release. It
# shipped with NO canary driving it: the nine canaries above are a6's exact set,
# and the extent was proven only by source tests on the release commit. That is
# the a4 shape one level up — a proof of one question (does the source declare
# the right structure?) read as a proof of another (does the ARTIFACT carry it?)
# — and a7's own record says so in the sentence
# `test_a7s_record_says_what_the_canaries_do_NOT_cover` pins.
#
# THE COUNTS ARE NOT THE CONTRACT. A canary asserting `len(tables) == 7 and
# len(columns) == 99` passes against a catalogue holding seven wrong tables, and
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

#: The catalogue document's own identity, independent of any release.
CATALOGUE_DOCUMENT_SCHEMA = "dotmac.module-database-catalog/v1"
CATALOGUE_DOCUMENT_SCOPE = "tables_and_columns"
CATALOGUE_MODULE_CODE = "deployment_control"
CATALOGUE_DATABASE_SCHEMA = "mod_deploy"
CATALOGUE_LINEAGE_HEAD = "dc_0003_execution_plan_binding"
#: Every table is on the PLATFORM plane and owned by the module itself. Held as
#: single values rather than per-table, because "the module owns all seven and
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
            # BASE and `pg_catalog` for all 99: this module declares no domain,
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
    columns — 99 after `dc_0003` — and not one of the nine canaries it published
    touched them. The extent was
    proven by source tests on the release commit — a real proof of a different
    question, and `docs/CONTROL_EXCEPTIONS.md` already records that a source
    check is not a control carried by any published artifact.

    Everything asserted here is asserted about the INSTALLED distribution:

    * the catalogue modules resolve out of `site-packages`, with no checkout
      copy shadowing them, and the evidence is in this canary's own output;
    * module identity — document schema and scope, distribution name and
      version, module code, release version, `mod_deploy`, and the `dc_0003`
      lineage head;
    * all seven table identities, in canonical order, with nothing missing and
      nothing extra;
    * all 99 columns by name, physical ordinal, PostgreSQL type identity AND
      rendered spelling, nullability, generation and server default;
    * plane and ownership metadata on every table — `platform`, owned by
      `module:deployment_control` (ADR-0023: a plane is DECLARED).

    The counts are the least of it. `len(tables) == 7 and len(columns) == 99`
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
        ("conflict_savepoint_executes", canary_conflict_savepoint_executes),
        (
            "database_catalogue_as_published",
            lambda: canary_database_catalogue_as_published(args.expect_version),
        ),
        (
            "catalogue_digest_binds",
            lambda: canary_catalogue_digest_binds(args.expect_version),
        ),
        # The browser surface's package data, which only an installed
        # artifact can be asked about.
        ("web_surface_ships_its_templates", canary_web_surface_ships_its_templates),
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
