"""The authorized image set, and the one property that makes it an authorization.

## What was broken, measured rather than supposed

The Observability lane established this by reading Control's code, not by
guessing: Deployment Control's plan record carried **no image field**. The
images a deployment would run sat inside `desired_spec`, which this module
declares OPAQUE and never interprets.

The consequence reached all the way into another system's receipt. That
receipt requires `images` to equal the approved plan's image set; with no image
field to read, `authorized_images` was supplied by the promotion CALLER, and
the comparison proved the caller consistent with itself. A receipt could say
*what ran is what was approved* while nothing had checked what was approved.

## The property, and why it is a test rather than a comment

**The image set is INSIDE the plan digest, never beside it.**

If it were beside — a sibling `deployment_plans.authorized_images` column, the
tidier-looking design — an `UPDATE` could change an authorized image while
`plan_digest` sat still. The approval binds the digest, so the approval would
go on reading as valid for a set nobody approved, with the evidence, the
columns and every screen still agreeing. There is no observable symptom; that
is exactly why it needs a plant rather than a docstring.

So `test_planting_an_image_change_moves_the_plan_digest` plants one, and
`test_the_proof_above_is_not_vacuous` shows the same plant moving NO digest
once the image set is taken back out of the digested document — which is what
a "beside the digest" implementation would do, and it is the only way to know
the first test is testing anything.

In-memory SQLite; logic only.
"""

from __future__ import annotations

import uuid
from collections.abc import Generator
from datetime import UTC, datetime

import pytest
from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions
from dotmac_kernel.models import Base
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from dotmac_deployment_control import (
    AuthorizedImage,
    DesiredDeployment,
    ImageDigestV1,
    ImageSetRefusedError,
    ProposePlanCommand,
    RegisterTargetCommand,
    SetDesiredStateCommand,
    authorized_image_set,
    get_plan,
    module,
    plan_digest_of,
    plan_snapshot,
    propose_plan,
    register_target,
    set_desired_state,
)
from dotmac_deployment_control.models import DeploymentTarget

_NOW = datetime(2026, 9, 2, 9, 0, tzinfo=UTC)
_RELEASE = "dotmac_sub@7.187.1"
_EXECUTION_PLAN = "sha256:" + "1a" * 32

#: Three image digests, WRITTEN OUT rather than computed — the same discipline
#: the execution-plan fixtures follow, and for a stronger reason: Control does
#: not build images, does not talk to a registry, and holds none of the bytes an
#: image manifest is hashed over. A fixture that derived one would be
#: exercising a capability the module deliberately does not have.
_IMAGE_A = "sha256:" + "aa" * 32
_IMAGE_B = "sha256:" + "bb" * 32
_IMAGE_C = "sha256:" + "cc" * 32


def _image(service: str, digest: str, repository: str | None = None) -> dict[str, str]:
    return {
        "service": service,
        "repository": repository or f"registry.dotmac.io/{service}",
        "digest": digest,
    }


@pytest.fixture(autouse=True)
def _installed_module_audit_actions() -> None:
    install_audit_actions(AuditActionRegistry.from_manifests([module]))


@pytest.fixture
def db() -> Generator[Session, None, None]:
    engine = create_engine("sqlite://", future=True)

    @event.listens_for(engine, "connect")
    def _attach(dbapi_connection, _record):  # type: ignore[no-untyped-def]
        dbapi_connection.isolation_level = None
        dbapi_connection.execute("ATTACH DATABASE ':memory:' AS mod_deploy")

    @event.listens_for(engine, "begin")
    def _emit_begin(connection):  # type: ignore[no-untyped-def]
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
    session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _cmd() -> str:
    return f"cmd-{uuid.uuid4().hex[:12]}"


def _target(db: Session, *, images: object, target_ref: str = "tgt-1"):
    view = register_target(
        db,
        RegisterTargetCommand(
            command_id=_cmd(),
            target_ref=target_ref,
            subject_ref="acme-operator",
            product_code="dotmac_sub",
            environment="production",
        ),
    )
    set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=_cmd(),
            target_id=view.id,
            desired=DesiredDeployment(
                release_ref=_RELEASE,
                spec={"replicas": 2},
                images=images,  # type: ignore[arg-type]
            ),
        ),
    )
    return view


def _propose(db: Session, target_id):  # type: ignore[no-untyped-def]
    return propose_plan(
        db,
        ProposePlanCommand(
            command_id=_cmd(),
            target_id=target_id,
            operation="deploy",
            execution_plan_digest=_EXECUTION_PLAN,
            requires_approval=True,
            approval_policy_code="deployment.production",
            approval_policy_version=4,
        ),
    )


# ── THE PROPERTY ────────────────────────────────────────────────────────────


class TestTheImageSetIsInsideThePlanDigest:
    """Plant an image change; require the digest to move. Then show the plant
    moves nothing once the set is taken out of the digested document."""

    def test_planting_an_image_change_moves_the_plan_digest(self, db: Session) -> None:
        """One image's digest changes; the plan digest must not survive it.

        This is the whole authorization property. An approval binds
        `plan_digest`; if that digest is unchanged by a different image set,
        the approval covers a set nobody approved.
        """
        before = _target(db, images=[_image("api", _IMAGE_A)])
        first = _propose(db, before.id)

        # THE PLANT: same target, same release, same spec, same everything —
        # one image digest changed, which is the smallest edit an attacker or
        # an accident could make and the one a digest must not absorb.
        set_desired_state(
            db,
            SetDesiredStateCommand(
                command_id=_cmd(),
                target_id=before.id,
                desired=DesiredDeployment(
                    release_ref=_RELEASE,
                    spec={"replicas": 2},
                    images=[_image("api", _IMAGE_B)],
                ),
            ),
        )
        second = _propose(db, before.id)

        assert first.plan_digest != second.plan_digest, (
            "the plan digest did not move when an authorized image changed, so "
            "an approval bound to it authorizes a set nobody approved"
        )

    def test_the_proof_above_is_not_vacuous(self, db: Session) -> None:
        """The SENSITIVITY half: without the key, the same plant moves nothing.

        A test that plants a change and sees a digest move proves nothing
        unless something could have made it not move. Here that something is
        concrete and is the design actually rejected: an implementation storing
        the image set BESIDE the digest, in a column of its own.

        This reconstructs that implementation exactly — the same two snapshots
        with `authorized_images` removed, which is what the digested document
        looked like before this change — and shows the identical plant
        producing the identical digest. So the assertion above is carried by
        the key's presence in the document and by nothing else.
        """
        target = db.get(
            DeploymentTarget,
            _target(db, images=[_image("api", _IMAGE_A)]).id,
        )
        assert target is not None

        with_a = plan_snapshot(target)
        target.desired_images = [_image("api", _IMAGE_B)]
        db.flush()
        with_b = plan_snapshot(target)

        # As shipped: the key is in the document, so the digests differ.
        assert plan_digest_of(with_a) != plan_digest_of(with_b)

        # As the rejected design would have been: identical documents, one
        # digest, and an image change nothing can see.
        beside_a = {k: v for k, v in with_a.items() if k != "authorized_images"}
        beside_b = {k: v for k, v in with_b.items() if k != "authorized_images"}
        assert beside_a == beside_b
        assert plan_digest_of(beside_a) == plan_digest_of(beside_b), (
            "with the image set outside the digested document the plant is "
            "invisible — which is what this file exists to prevent, and what "
            "makes the test above non-vacuous"
        )

    def test_declaring_no_images_digests_differently_from_declaring_some(
        self, db: Session
    ) -> None:
        """Absent, empty and populated are THREE authorizations, so three digests.

        Taken over ONE target's snapshot with only `desired_images` moving.
        Three separate targets would also produce three digests — because
        `target_ref` is in the document — and the assertion would pass with the
        image set outside the digest entirely. This is the same vacuity the
        test above exists to rule out, so it is ruled out here too.
        """
        target = db.get(DeploymentTarget, _target(db, images=None).id)
        assert target is not None

        absent = plan_snapshot(target)
        target.desired_images = []
        db.flush()
        empty = plan_snapshot(target)
        target.desired_images = [_image("api", _IMAGE_A)]
        db.flush()
        populated = plan_snapshot(target)

        assert absent["authorized_images"] is None
        assert empty["authorized_images"] == []
        assert (
            len(
                {
                    plan_digest_of(absent),
                    plan_digest_of(empty),
                    plan_digest_of(populated),
                }
            )
            == 3
        ), "an empty declaration and an absent one must not share a digest"

    def test_a_plan_view_keeps_absent_and_empty_apart(self, db: Session) -> None:
        """The same distinction, as a frozen plan reports it.

        `None` means the plan froze no image set and a consumer must not read
        it as "no images"; `()` means it authorizes none. `find_approved_plan`
        refuses the first and answers the second.
        """
        empty = _propose(db, _target(db, images=[], target_ref="tgt-empty").id)
        absent = _propose(db, _target(db, images=None, target_ref="tgt-absent").id)

        assert empty.authorized_images == ()
        assert absent.authorized_images is None

    def test_the_same_set_declared_in_a_different_order_is_the_same_digest(
        self, db: Session
    ) -> None:
        """A SET has no order, so two orderings must not be two authorizations.

        Control canonicalizes the order because this is Control's own document
        — the same act as `sort_keys=True` in `canonical_json`. Without it, one
        approved image set would have two identities, which is the `0.1.0a4`
        defect wearing different clothes.
        """
        forward = _propose(
            db,
            _target(
                db,
                images=[_image("api", _IMAGE_A), _image("worker", _IMAGE_B)],
                target_ref="tgt-forward",
            ).id,
        )
        reverse = _propose(
            db,
            _target(
                db,
                images=[_image("worker", _IMAGE_B), _image("api", _IMAGE_A)],
                target_ref="tgt-reverse",
            ).id,
        )

        # Same digest requires the rest of the snapshot to match too, and
        # `target_ref` is in it — so compare the image halves and the digest of
        # a rebuilt document rather than the two plan digests directly.
        assert forward.authorized_images == reverse.authorized_images
        forward_doc = dict(forward.snapshot)
        reverse_doc = dict(reverse.snapshot)
        reverse_doc["target_ref"] = forward_doc["target_ref"]
        assert plan_digest_of(forward_doc) == plan_digest_of(reverse_doc)

    def test_the_frozen_set_survives_a_later_desired_state_edit(
        self, db: Session
    ) -> None:
        """A plan is frozen: editing the target after proposal must not move it.

        The same rule the module already holds for the release and the spec,
        stated for images because this is the field an operator is most likely
        to edit between an approval and a rollout.
        """
        view = _target(db, images=[_image("api", _IMAGE_A)])
        plan = _propose(db, view.id)
        frozen_digest = plan.plan_digest

        set_desired_state(
            db,
            SetDesiredStateCommand(
                command_id=_cmd(),
                target_id=view.id,
                desired=DesiredDeployment(
                    release_ref=_RELEASE,
                    spec={"replicas": 2},
                    images=[_image("api", _IMAGE_C)],
                ),
            ),
        )

        reread = get_plan(db, plan.id)
        assert reread is not None
        assert reread.plan_digest == frozen_digest
        assert reread.authorized_images is not None
        assert reread.authorized_images[0].digest == ImageDigestV1.parse(_IMAGE_A)


# ── The value type ──────────────────────────────────────────────────────────


class TestAnAuthorizedImageIsPinnedAndUnambiguous:
    def test_a_tag_is_refused_and_the_refusal_says_why(self) -> None:
        """The refusal names the tag, not the hex length.

        "not 64 lowercase hex characters" would send a caller looking for a
        typo. The actual fault is a pinning strategy: a tag is a mutable
        pointer, so a tag-pinned set authorizes whatever the tag names later,
        under an approval nobody re-ran.
        """
        with pytest.raises(ImageSetRefusedError) as caught:
            authorized_image_set(
                [{"service": "api", "repository": "r", "digest": "v7.1.2"}],
                where="test",
            )
        assert "tag" in str(caught.value).lower()
        assert "mutable" in str(caught.value)

    def test_two_digests_for_one_service_are_refused_not_deduplicated(self) -> None:
        """Choosing between them would be inferring an authorization."""
        with pytest.raises(ImageSetRefusedError) as caught:
            authorized_image_set(
                [_image("api", _IMAGE_A), _image("api", _IMAGE_B)], where="test"
            )
        assert "two answers" in str(caught.value)

    def test_an_exact_duplicate_is_refused_too(self) -> None:
        """A set with a repeated member is not a set, and tidying it silently
        would be this module cleaning up a declaration nobody has checked."""
        with pytest.raises(ImageSetRefusedError):
            authorized_image_set(
                [_image("api", _IMAGE_A), _image("api", _IMAGE_A)], where="test"
            )

    def test_an_unknown_key_is_refused_rather_than_ignored(self) -> None:
        """Dropping it would freeze a set that says less than the caller wrote,
        and the approval would cover the shorter one."""
        with pytest.raises(ImageSetRefusedError) as caught:
            authorized_image_set(
                [{"service": "api", "repository": "r", "digest": _IMAGE_A, "tag": "x"}],
                where="test",
            )
        assert "unknown key" in str(caught.value)

    def test_a_missing_term_is_refused_with_no_default(self) -> None:
        with pytest.raises(ImageSetRefusedError) as caught:
            authorized_image_set([{"service": "api", "digest": _IMAGE_A}], where="test")
        assert "repository" in str(caught.value)

    def test_absent_is_not_empty(self) -> None:
        """The round trip that must not collapse: `None` stays `None`."""
        assert authorized_image_set(None, where="test") is None
        assert authorized_image_set([], where="test") == ()

    def test_control_cannot_compute_an_image_digest(self) -> None:
        """Same structural absence as `ExecutionPlanDigestV1`, for the plainest
        possible reason: Control does not build images and holds none of the
        bytes an image manifest is hashed over.

        `parse` is the only constructor, so there is no route from a payload to
        an `ImageDigestV1` and no plausible-looking number can be invented.
        """
        assert not hasattr(ImageDigestV1, "over_json")
        with pytest.raises(AttributeError):
            ImageDigestV1.over_json({"anything": True})  # type: ignore[attr-defined]

    def test_an_image_digest_can_never_satisfy_a_plan_digest_binding(self) -> None:
        """Distinct dataclasses compare unequal even on identical bytes — the
        protection `0.1.0a4`'s string comparisons did not have."""
        from dotmac_deployment_control import ExecutionPlanDigestV1, PlanDigestV1

        image = ImageDigestV1.parse(_IMAGE_A)
        plan = PlanDigestV1.parse(_IMAGE_A)
        execution = ExecutionPlanDigestV1.parse(_IMAGE_A)

        assert image.digest == plan.digest == execution.digest
        assert image != plan
        assert image != execution
        assert plan != execution

    def test_a_parsed_image_renders_the_canonical_text_it_was_read_from(
        self,
    ) -> None:
        """What is written into the snapshot is what can be read back, so a
        round trip through the frozen document cannot move a plan digest."""
        parsed = AuthorizedImage.parse(_image("api", _IMAGE_A), where="test")
        assert parsed.as_mapping() == _image("api", _IMAGE_A)
        assert parsed.reference == f"registry.dotmac.io/api@{_IMAGE_A}"
