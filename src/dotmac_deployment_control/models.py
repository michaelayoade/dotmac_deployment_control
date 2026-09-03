"""The deployment-control tables, bound to `mod_deploy` (ADR-0006 D1).

Platform catalog tables: no `tenant_id`, no RLS, `app_user` REVOKEd. Deciding
what a fleet of deployments should run is a control-plane act; the deployments
themselves are separate applications that learn what to do through the
Integrator, never by reading this schema (ADR-0024).

## Seven tables, and the two pairings that matter

Most of these are the obvious decomposition — target, credential, plan, rollout,
attempt. Two are not:

**`observation_attempts` and `observation_receipts` are a pair, not a
duplication.** A single append-only table keyed uniquely on
`(identity, report_id)` cannot work: the SECOND arrival under a key is exactly
the row worth keeping — the replay, or the conflicting bytes — and the unique
constraint forbids inserting it. Updating the first row instead breaks
append-only semantics AND discards the conflicting bytes, destroying the evidence
the table exists to preserve. It also leaves nowhere to record an arrival that
never resolved to an identity: an unknown key, a malformed envelope, a bad
signature. Those are the tripwires.

So: an append-only log of ATTEMPTS (every arrival, whatever happens to it) and
one canonical RECEIPT per idempotency key.

**`rollouts` and `rollout_attempts` are a pair for the same reason in a
different domain.** A rollout is the DECISION to converge a target on a plan; an
attempt is one execution of it. Retrying does not change the decision, and
collapsing them would make "how many times did we try?" and "what did we decide?"
one column that answers neither.

## A claim and a proof never share a column

`observation_attempts.authenticated_target_ref` is the identity resolved from the
SIGNED key (ADR-0007 § 4). `claimed_target_ref` is what the report said about
itself. Two columns, with a CHECK making it structural: a row may carry an
authenticated ref only when something actually authenticated it.

One column holding both would make deployment binding decorative — anyone
reaching the endpoint could activate any target's deployment by naming it — and
would make "did we actually verify this?" unanswerable after the fact.

## There is no private key and no provider credential anywhere

`TargetCredential` holds a deployment's own PUBLIC verification key: the target's
identity, not a way to reach a provider. Provider credentials, endpoints,
transports and connector state are the Integrator's (ADR-0024, hard rule 28), and
the absence here is structural rather than conventional.

## No foreign key leaves this schema

`release_ref`, `licence_ref` and `brand_profile_ref` are bare strings. A
deployment record must outlive a superseded release and a replaced licence, and
ADR-0006 D1 forbids the cross-lineage foreign key that would splice four module
lineages into one release unit.

## Status is text with no CHECK

ADR-0008's reason: adding a lifecycle member should cost a module release, not an
`ALTER TYPE` on every deployment. The CHECKs that ARE here constrain things true
independent of any vocabulary — versions and attempt numbers start at 1, and a
claim/proof pairing cannot contradict itself.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from dotmac_kernel.models import Base, TimestampMixin, uuid_pk
from dotmac_kernel.namespaces import module_schema, schema_table_args
from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

#: JSONB in production, portable `JSON` everywhere else — the module's logic
#: tests run on in-memory SQLite, and a bare `JSONB` column makes the whole model
#: layer unimportable there. The MIGRATION names `JSONB` unconditionally.
_JSON_DOC = JSON().with_variant(JSONB(), "postgresql")

#: Derived from the allocated short code — never a literal here.
SCHEMA: str = module_schema("deploy")

_TARGETS = "deployment_targets"
_CREDENTIALS = "target_credentials"
_PLANS = "deployment_plans"
_ROLLOUTS = "rollouts"
_ATTEMPTS = "rollout_attempts"
_OBS_ATTEMPTS = "observation_attempts"
_OBS_RECEIPTS = "observation_receipts"


class TargetStatus(StrEnum):
    """A deployment target's own standing, distinct from any rollout's.

    `REGISTERED` — known, with no desired state yet. `ACTIVE` — has a desired
    state and is being converged. `SUSPENDED` — deliberately excluded from
    rollouts without being forgotten. `DECOMMISSIONED` — terminal.

    Deliberately NOT a health status. Whether a deployment is UP belongs to
    Dotmac Observability; ruling A4 keeps health separate from fleet so that
    "no mutating consumer of health" stays a checkable dependency direction.
    """

    REGISTERED = "registered"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DECOMMISSIONED = "decommissioned"


class CredentialStatus(StrEnum):
    """A target credential's eligibility, projected from its timestamps.

    `PENDING` — enrolled, possession not yet proven. `ACTIVE` — admits reports.
    `RETIRED` — rotated out; verifies nothing new. `REVOKED` — compromise.

    `RETIRED` and `REVOKED` are separate for the reason the licence keyring keeps
    them separate: a rotation is planned and a compromise is not, and an operator
    triaging a suspicious report needs to know which happened.
    """

    PENDING = "pending"
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class PlanStatus(StrEnum):
    """`DRAFT` — being assembled. `PROPOSED` — frozen, digest computed, awaiting
    approval. `APPROVED` — approval evidence bound to the digest.
    `SUPERSEDED` — a newer plan for the same target took over. `CANCELLED`.

    A plan is never edited after `PROPOSED`; a change is a new plan. That is what
    makes an approval bind to something.
    """

    DRAFT = "draft"
    PROPOSED = "proposed"
    APPROVED = "approved"
    SUPERSEDED = "superseded"
    CANCELLED = "cancelled"


class RolloutStatus(StrEnum):
    """The full outcome vocabulary, including the three states an implementation
    usually discovers it needs the hard way.

    `REQUESTED` — decided, not yet dispatched. `DISPATCHED` — an intent is with
    the Integrator. `SUCCEEDED` — the target acknowledged the planned state.
    `FAILED` — an attempt reported a terminal error. `TIMED_OUT` — no
    acknowledgement inside the window. `CANCELLED` — withdrawn before completion.
    `MANUAL_REPAIR` — automated convergence has stopped and a human owns it.

    `TIMED_OUT` is not `FAILED`: a failure means something reported an error, a
    timeout means nothing reported at all, and the second is far more likely to
    be a transport problem than a deployment one. `MANUAL_REPAIR` is not
    `CANCELLED`: a cancelled rollout is not wanted, a repairing one is wanted and
    stuck, and an operator's queue must distinguish them.
    """

    REQUESTED = "requested"
    DISPATCHED = "dispatched"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    MANUAL_REPAIR = "manual_repair"


#: Statuses from which no further transition is legal.
TERMINAL_ROLLOUT_STATUSES: frozenset[str] = frozenset(
    {
        RolloutStatus.SUCCEEDED.value,
        RolloutStatus.CANCELLED.value,
    }
)


class AttemptOutcome(StrEnum):
    """One execution's result. `PENDING` until something reports."""

    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class SignatureStatus(StrEnum):
    """*Did this key sign these bytes?* — independent of lifecycle.

    Resolved for any KNOWN key regardless of credential state, INCLUDING revoked.
    A revoked key's signature is still a fact, and refusing to evaluate it would
    discard the evidence that a compromised key is still in use — an operator's
    cue to go looking for the theft.
    """

    UNRESOLVED = "unresolved"
    INVALID = "invalid"
    VALID = "valid"


class EligibilityAtReceipt(StrEnum):
    """*Was that credential admitted at `received_at`?* — the timeline predicate.

    `NOT_APPLICABLE` when the signature is not valid, because the eligibility of
    an unproven claim is not a meaningful question. ONLY `ELIGIBLE` gates
    consequences: a valid-but-not-eligible arrival is recorded, attributable, and
    activates nothing.
    """

    NOT_APPLICABLE = "n/a"
    ELIGIBLE = "eligible"
    NOT_ELIGIBLE = "not_eligible"


class ObservationDisposition(StrEnum):
    """What was done with an arrival. Every path writes one."""

    ACCEPTED = "accepted"
    IDEMPOTENT_REPLAY = "idempotent_replay"
    CONFLICT = "conflict"
    UNKNOWN_KEY = "unknown_key"
    MALFORMED = "malformed"
    BAD_SIGNATURE = "bad_signature"
    NOT_ELIGIBLE = "not_eligible"
    TARGET_MISMATCH = "target_mismatch"
    UNKNOWN_TARGET = "unknown_target"
    #: The three-term binding (proposal, authorization, report) did not hold.
    #:
    #: THREE members and not one, because they are three different findings
    #: with three different readers. A digest mismatch says the executor ran a
    #: plan nobody authorized. An operation mismatch says it ran the RIGHT plan
    #: as the WRONG kind of act — a rollback executed under a deploy's approval
    #: is the case this vocabulary exists for, and it is invisible to a
    #: digest-only check. An unbound report says the arrival named no
    #: authorization at all, which is an absence rather than a contradiction and
    #: is triaged by looking at the sender, not at the plan.
    #:
    #: Collapsing any two of them would make the audit trail say "the report did
    #: not bind" and leave the operator to work out which of three unrelated
    #: systems to open.
    EXECUTION_PLAN_MISMATCH = "execution_plan_mismatch"
    OPERATION_MISMATCH = "operation_mismatch"
    UNBOUND_REPORT = "unbound_report"
    AUTHORIZATION_INVALID = "authorization_invalid"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    AUTHORIZATION_REVOKED = "authorization_revoked"
    AUTHORIZATION_MISMATCH = "authorization_mismatch"
    SIGNER_PURPOSE_REUSED = "signer_purpose_reused"
    EXECUTION_FAILED = "execution_failed"
    STALE_OBSERVATION = "stale_observation"
    EXECUTION_COORDINATE_CONFLICT = "execution_coordinate_conflict"


class DeploymentTarget(Base, TimestampMixin):
    """One deployment this control plane is responsible for converging."""

    __tablename__ = _TARGETS
    __table_args__ = (
        UniqueConstraint("target_ref", name="uq_deployment_targets_ref"),
        CheckConstraint("desired_revision >= 0", name="ck_targets_desired_revision"),
        CheckConstraint("record_version >= 1", name="ck_targets_record_version"),
        CheckConstraint(
            "((last_execution_sequence IS NULL) = "
            "(last_execution_attempt_no IS NULL)) AND "
            "((last_execution_attempt_no IS NULL) = "
            "(last_execution_state_digest IS NULL))",
            name="ck_targets_execution_coordinate_complete",
        ),
        CheckConstraint(
            "last_execution_sequence IS NULL OR "
            "(last_execution_sequence >= 1 AND last_execution_attempt_no >= 1)",
            name="ck_targets_execution_coordinate_positive",
        ),
        schema_table_args(SCHEMA),
    )

    id: Mapped[UUID] = uuid_pk()
    #: The stable identity a deployment proves and an operator quotes. Supplied
    #: by the caller — `dotmac-numbering` owns allocation of numbered series, and
    #: generating one here would make this module a second numbering authority.
    target_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    #: Opaque. The counterparty as the assembly identifies it (ADR-0019 § 1).
    subject_ref: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    product_code: Mapped[str] = mapped_column(String(120), nullable=False)

    #: An open registered string, not an enum (ADR-0008): a product names its own
    #: environments — production, staging, pilot, air-gapped — without a kernel
    #: change. Deliberately NOT a deployment-profile name: ADR-0003 forbids
    #: feature code branching on a profile string, and a column that held one
    #: would invite exactly that.
    environment: Mapped[str] = mapped_column(String(60), nullable=False)

    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=TargetStatus.REGISTERED.value, index=True
    )

    # ── Desired ─────────────────────────────────────────────────────────────
    #: Opaque references. `dotmac-release-catalog` owns releases,
    #: `dotmac-licensing` owns licences, brand profiles own brands. No FK.
    desired_release_ref: Mapped[str | None] = mapped_column(String(200))
    desired_spec: Mapped[dict[str, Any] | None] = mapped_column(_JSON_DOC)
    licence_ref: Mapped[str | None] = mapped_column(String(200))
    brand_profile_ref: Mapped[str | None] = mapped_column(String(200))
    #: THE DECLARED AUTHORIZED IMAGE SET — a list of
    #: `{"service", "repository", "digest"}` objects, canonically ordered by
    #: `images.authorized_image_set` before it is written.
    #:
    #: Separate from `desired_spec` on purpose, and the separation IS the
    #: repair. `desired_spec` is opaque and this module interprets nothing in
    #: it, so images living there could never be an authorization — a consumer
    #: needing to know which images an approval covered had to be told by
    #: whoever was asking. This column is a declared, validated, Control-owned
    #: term, and `plan_snapshot` freezes it INSIDE the document the plan digest
    #: is taken over.
    #:
    #: NULL is not an empty set. NULL means no image set has been declared for
    #: this target; `[]` means it authorizes none. `find_approved_plan` refuses
    #: the first rather than answering it, so a consumer cannot promote a plan
    #: whose image set nobody wrote down.
    desired_images: Mapped[list[dict[str, Any]] | None] = mapped_column(_JSON_DOC)
    #: Bumped every time the desired state changes. A plan freezes ONE revision,
    #: and an observation is compared against the revision that was rolled out
    #: rather than the newest — otherwise every desired-state edit would make
    #: every deployed target look instantly drifted.
    desired_revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # ── Observed ────────────────────────────────────────────────────────────
    observed_release_ref: Mapped[str | None] = mapped_column(String(200))
    observed_spec_digest: Mapped[str | None] = mapped_column(String(128))
    observed_revision: Mapped[int | None] = mapped_column(Integer)
    last_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Trusted high-water coordinate for target execution reports. It is
    #: independent of the observed deployment projection: a failed newer
    #: attempt still prevents an older success from regressing state.
    last_execution_sequence: Mapped[int | None] = mapped_column(Integer)
    last_execution_attempt_no: Mapped[int | None] = mapped_column(Integer)
    last_execution_state_digest: Mapped[str | None] = mapped_column(String(128))

    record_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    credentials: Mapped[list[TargetCredential]] = relationship(
        lambda: TargetCredential, back_populates="target"
    )


class TargetCredential(Base, TimestampMixin):
    """A deployment's own PUBLIC verification key and its eligibility window.

    Not a provider credential and not a secret: this is how a target proves it is
    itself when it reports (ADR-0007). There is deliberately no private-key
    column, so a database dump cannot leak anything that could impersonate a
    deployment — structurally, not by convention.
    """

    __tablename__ = _CREDENTIALS
    __table_args__ = (
        UniqueConstraint("key_id", name="uq_target_credentials_key_id"),
        UniqueConstraint(
            "public_key_fingerprint", name="uq_target_credentials_fingerprint"
        ),
        schema_table_args(SCHEMA),
    )

    id: Mapped[UUID] = uuid_pk()
    target_id: Mapped[UUID] = mapped_column(
        ForeignKey(f"{SCHEMA}.{_TARGETS}.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    key_id: Mapped[str] = mapped_column(String(200), nullable=False)
    #: Unpadded base64url, exactly as the kernel's verifier expects it.
    public_key_b64: Mapped[str] = mapped_column(String(200), nullable=False)
    #: `sha256:<hex>` over the DECODED raw key bytes — never over the base64
    #: text, which is not canonical: padding, alphabet and whitespace variants
    #: would each hash differently and defeat the uniqueness constraint above.
    public_key_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    #: Purpose and algorithm are enrolled facts, never selected by an inbound
    #: statement. NULL is reserved for pre-a10 rows, which cannot verify a10
    #: observations and must rotate to a newly purpose-bound key.
    algorithm: Mapped[str | None] = mapped_column(String(60))
    purpose: Mapped[str | None] = mapped_column(String(60))

    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=CredentialStatus.PENDING.value
    )
    #: The eligibility window: admits reports received from `activated_at`, up to
    #: but NOT including `retired_at` / `revoked_at`.
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(String(200))
    #: Under which authority the enrollment was asserted. Recorded because an
    #: interim authority is policy rather than proof, and historic registrations
    #: must keep reading as "authorised under that policy" rather than being
    #: silently reinterpreted when a stricter one lands.
    enrollment_authority: Mapped[str] = mapped_column(String(60), nullable=False)

    target: Mapped[DeploymentTarget] = relationship(
        lambda: DeploymentTarget, back_populates="credentials"
    )


class DeploymentPlan(Base, TimestampMixin):
    """An immutable snapshot of what a target should converge on, plus approval.

    Frozen at `PROPOSED`; a change is a NEW plan. That is what makes an approval
    bind to something, and it is why `plan_digest` and the evidence's digest are
    compared rather than trusted.
    """

    __tablename__ = _PLANS
    __table_args__ = (
        UniqueConstraint("target_id", "sequence", name="uq_plans_target_sequence"),
        UniqueConstraint("plan_digest", name="uq_plans_digest"),
        CheckConstraint("sequence >= 1", name="ck_plans_sequence"),
        CheckConstraint("record_version >= 1", name="ck_plans_record_version"),
        schema_table_args(SCHEMA),
    )

    id: Mapped[UUID] = uuid_pk()
    target_id: Mapped[UUID] = mapped_column(
        ForeignKey(f"{SCHEMA}.{_TARGETS}.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=PlanStatus.DRAFT.value, index=True
    )

    #: The frozen snapshot, and the revision of the target's desired state it was
    #: taken from. Both, because the snapshot is what gets rolled out and the
    #: revision is what makes drift computable afterwards.
    snapshot: Mapped[dict[str, Any] | None] = mapped_column(_JSON_DOC)
    desired_revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: `sha256:<64 lowercase hex>` — the CANONICAL serialization of
    #: `PlanDigestV1`, 71 characters. `String(64)` through `0.1.0a4` was exactly
    #: the width of bare hex, which is a fair summary of why a4 stored bare hex:
    #: the column could not hold a value that said which algorithm produced it.
    #: Widened to 128 by `dc_0002_canonical_plan_digest`, matching the other
    #: digest columns on this plane so the next algorithm does not need a third
    #: width.
    plan_digest: Mapped[str | None] = mapped_column(String(128))

    # ── The execution binding: proposal, then authorization ─────────────────
    #
    # FOUR columns and not two, and the pairing is the whole design. Steps 3
    # and 4 of the flow freeze what Platform CP submitted; step 8 accepts a
    # report only when proposal, authorization AND report bind the same values.
    # Two stored terms plus the report is a TWO-term gate wearing a three-term
    # name, and a gate can always be weakened by quietly passing fewer terms
    # than it names. So the approval records what it authorized in its own
    # columns, written once at `approve_plan`, and the report is compared
    # against both.
    #
    # `operation` is text with no CHECK, like every other vocabulary column
    # here (ADR-0008) — but unlike them the vocabulary is CLOSED, and the
    # closure lives in `operations.require_operation` where a refusal can
    # explain itself. A database CHECK would put the same closed set in two
    # places and make a coordinated change with the executor an `ALTER TABLE`
    # on every deployment.
    #
    # NULLABLE, and no server default. Nullable because `0.1.0a7` rows exist
    # and predate the contract; no default because a default IS an inference,
    # and an operation is never inferred. A plan holding NULL here is refused a
    # rollout rather than being treated as a deploy.

    #: WHAT was proposed — frozen at `propose_plan`, from what Platform CP
    #: submitted after the Foundation rendered and digested its execution plan.
    operation: Mapped[str | None] = mapped_column(String(20))
    #: `sha256:<64 lowercase hex>` — `ExecutionPlanDigestV1`, the FOUNDATION's
    #: digest over its own canonical execution-plan bytes.
    #:
    #: Control never computes this and cannot: the type it is read back as does
    #: not inherit a constructor that takes a payload, and the bytes it is over
    #: are a `FoundationExecutionPlanV1` this module has no renderer for and no
    #: column to hold. Stored verbatim as received — the parser refuses a
    #: non-canonical spelling rather than rewriting it, so nothing here is a
    #: second canonicalization of somebody else's value.
    execution_plan_digest: Mapped[str | None] = mapped_column(String(128))

    #: WHAT was authorized — written once at `approve_plan` from the approval
    #: evidence, and refused unless it equals what was proposed. Redundant only
    #: while nothing has gone wrong, which is the same thing that is true of
    #: every independent term in every binding check.
    authorized_operation: Mapped[str | None] = mapped_column(String(20))
    authorized_execution_plan_digest: Mapped[str | None] = mapped_column(String(128))

    #: Whether this plan is a SENSITIVE operation requiring approval. Declared
    #: per plan rather than inferred, because sensitivity is a product policy
    #: (a production release is sensitive; a pilot's is not) and inferring it
    #: from `environment` would bake one product's policy into the module.
    requires_approval: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    approval_policy_code: Mapped[str | None] = mapped_column(String(120))
    approval_policy_version: Mapped[int | None] = mapped_column(Integer)
    approval_decision_ref: Mapped[str | None] = mapped_column(String(200))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # ── Does the approval still STAND? ──────────────────────────────────────
    #
    # `approval_decision_ref` says WHICH decision approved this plan and
    # `approved_at` says when. Neither says whether that decision has since
    # been withdrawn, and before these columns nothing did: a consumer asking
    # "is this plan approved?" read `status`, which stays `approved` forever,
    # and got a yes for a revoked authorization.
    #
    # The plan's own `status` deliberately does NOT move on revocation. It was
    # approved; that is history and rewriting it would delete the record. This
    # column owns the standing, `request_rollout` refuses a plan whose approval
    # no longer stands, and `find_approved_plan` refuses it with its own typed
    # code. A `PlanStatus.REVOKED` member would be a second writer for one
    # fact.
    #
    # Text with no CHECK, like every other vocabulary column here (ADR-0008),
    # and the closure lives in `dotmac_deployment_control.approvals` where a
    # refusal can explain itself. NULL for a plan that was never approved and
    # for the `0.1.0a7`-era rows that predate the column.

    #: `granted` | `revoked` — `approvals.ApprovalDecisionStatus`.
    approval_decision_status: Mapped[str | None] = mapped_column(String(24))
    approval_revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    #: The REVOKING decision's opaque reference, resolvable in the approvals
    #: authority. Required by `revoke_plan_approval`: a revocation nobody can
    #: attribute is an authorization disappearing with no decision behind it,
    #: which reads to an operator exactly like a bug.
    approval_revocation_ref: Mapped[str | None] = mapped_column(String(200))
    approval_revocation_reason: Mapped[str | None] = mapped_column(String(200))

    superseded_by_id: Mapped[UUID | None] = mapped_column(
        ForeignKey(f"{SCHEMA}.{_PLANS}.id", ondelete="RESTRICT")
    )
    record_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class Rollout(Base, TimestampMixin):
    """The DECISION to converge a target on a plan.

    Separate from its attempts: retrying does not change the decision, and one
    column for both would answer neither "how many times did we try?" nor "what
    did we decide?".
    """

    __tablename__ = _ROLLOUTS
    __table_args__ = (
        UniqueConstraint("rollout_ref", name="uq_rollouts_ref"),
        UniqueConstraint(
            "target_id", "execution_sequence", name="uq_rollouts_target_execution"
        ),
        CheckConstraint("record_version >= 1", name="ck_rollouts_record_version"),
        CheckConstraint(
            "execution_sequence IS NULL OR execution_sequence >= 1",
            name="ck_rollouts_execution_sequence",
        ),
        schema_table_args(SCHEMA),
    )

    id: Mapped[UUID] = uuid_pk()
    rollout_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    target_id: Mapped[UUID] = mapped_column(
        ForeignKey(f"{SCHEMA}.{_TARGETS}.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    plan_id: Mapped[UUID] = mapped_column(
        ForeignKey(f"{SCHEMA}.{_PLANS}.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=RolloutStatus.REQUESTED.value, index=True
    )
    reason: Mapped[str | None] = mapped_column(Text)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    record_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    #: Immutable issuance fact. NULL is reserved for rollouts created before
    #: the portable authorization contract; they are refused, never inferred.
    authorization_envelope: Mapped[dict[str, Any] | None] = mapped_column(_JSON_DOC)
    #: Per-target monotonic coordinate, NULL only on pre-a10 history.
    execution_sequence: Mapped[int | None] = mapped_column(Integer)

    attempts: Mapped[list[RolloutAttempt]] = relationship(
        lambda: RolloutAttempt,
        back_populates="rollout",
        order_by=lambda: RolloutAttempt.attempt_no,
    )


class RolloutAttempt(Base, TimestampMixin):
    """One execution of a rollout. Append-only.

    Append-only because it is the operational history an incident review reads.
    An attempt log that can be tidied is a log that will be, and the tidying
    always removes the attempt that explains the outage.
    """

    __tablename__ = _ATTEMPTS
    __table_args__ = (
        UniqueConstraint("rollout_id", "attempt_no", name="uq_attempts_no"),
        CheckConstraint("attempt_no >= 1", name="ck_attempts_no"),
        schema_table_args(SCHEMA),
    )

    id: Mapped[UUID] = uuid_pk()
    rollout_id: Mapped[UUID] = mapped_column(
        ForeignKey(f"{SCHEMA}.{_ROLLOUTS}.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    attempt_no: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(
        String(20), nullable=False, default=AttemptOutcome.PENDING.value
    )
    #: An opaque handle into the Integrator's own delivery evidence. This module
    #: never dereferences it; it stores it so an operator can correlate.
    integrator_ref: Mapped[str | None] = mapped_column(String(200))
    #: A stable code, never a provider's raw error text — that would carry
    #: provider vocabulary (and sometimes credentials) into this schema.
    error_code: Mapped[str | None] = mapped_column(String(60))
    detail: Mapped[str | None] = mapped_column(Text)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    rollout: Mapped[Rollout] = relationship(lambda: Rollout, back_populates="attempts")


class ObservationReceipt(Base, TimestampMixin):
    """One canonical row per idempotency key — the FIRST eligible verified arrival.

    "First **eligible verified**", not "first accepted": an observation can be
    validly signed, eligible, and still be quarantined (an unknown target, a
    contradiction between claim and proof). Those establish the canonical row
    too, and their verdict must be as stable as an acceptance's — otherwise a
    quarantined `report_id` could be re-sent with different bytes and re-decided,
    which is exactly the re-litigation the idempotency key exists to prevent.
    """

    __tablename__ = _OBS_RECEIPTS
    __table_args__ = (
        #: Scoped to the PROVEN identity, so one target's `report_id` can never
        #: collide with another's.
        UniqueConstraint(
            "authenticated_target_ref",
            "report_id",
            name="uq_observation_receipts_identity_report",
        ),
        CheckConstraint(
            "((execution_sequence IS NULL) = (attempt_no IS NULL)) AND "
            "((attempt_no IS NULL) = (observed_state_digest IS NULL))",
            name="ck_observation_receipts_execution_coordinate_complete",
        ),
        CheckConstraint(
            "execution_sequence IS NULL OR "
            "(execution_sequence >= 1 AND attempt_no >= 1)",
            name="ck_observation_receipts_execution_coordinate_positive",
        ),
        schema_table_args(SCHEMA),
    )

    id: Mapped[UUID] = uuid_pk()
    authenticated_target_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    report_id: Mapped[str] = mapped_column(String(200), nullable=False)
    #: The exact signed bytes — not a parsed projection of them. This is what
    #: keeps the report portable evidence a third party can verify.
    payload: Mapped[bytes | None] = mapped_column(LargeBinary)
    payload_digest: Mapped[str | None] = mapped_column(String(128))
    key_id: Mapped[str] = mapped_column(String(200), nullable=False)
    #: The receipt time that DECIDED eligibility, retained so the decision stays
    #: reproducible rather than being re-derived from a moving clock.
    first_received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    #: Returned verbatim to every subsequent identical replay. Recomputing could
    #: yield a different answer against changed target state for bytes the
    #: deployment sent once, which would make an at-least-once transport look
    #: like a state change.
    original_verdict: Mapped[str] = mapped_column(String(40), nullable=False)
    observed_release_ref: Mapped[str | None] = mapped_column(String(200))
    observed_spec_digest: Mapped[str | None] = mapped_column(String(128))
    execution_sequence: Mapped[int | None] = mapped_column(Integer)
    attempt_no: Mapped[int | None] = mapped_column(Integer)
    observed_state_digest: Mapped[str | None] = mapped_column(String(128))


class ObservationAttempt(Base, TimestampMixin):
    """Append-only: one row per ARRIVAL, whatever happens to it.

    Written on EVERY path, including the ones that fail before an identity
    exists, because an unknown key or a bad signature against a known one is
    precisely the evidence an operator needs — and the thing a fail-closed system
    would otherwise discard silently.
    """

    __tablename__ = _OBS_ATTEMPTS
    __table_args__ = (
        #: Claim/proof separation, made structural: a row may carry an
        #: "authenticated" ref only when something actually authenticated it.
        CheckConstraint(
            "(signature_status = 'valid') OR (authenticated_target_ref IS NULL)",
            name="ck_observation_identity_needs_valid_signature",
        ),
        CheckConstraint(
            "(signature_status = 'valid') OR (eligibility_at_receipt = 'n/a')",
            name="ck_observation_eligibility_needs_valid_signature",
        ),
        schema_table_args(SCHEMA),
    )

    id: Mapped[UUID] = uuid_pk()
    #: The trusted receipt instant, stamped by Control after the complete
    #: bounded body has arrived and BEFORE parsing.
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    #: The exact inbound bytes. Bounded by the caller, because they are
    #: attacker-controlled and unauthenticated at the moment they are stored.
    raw_body: Mapped[bytes | None] = mapped_column(LargeBinary)
    raw_body_truncated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    #: `sha256:` over the full body as received, computed BEFORE truncation so
    #: two truncated attempts remain distinguishable. NULL when there was no
    #: complete body to hash — claiming a digest for bytes never held would be a
    #: lie about evidence.
    raw_body_digest: Mapped[str | None] = mapped_column(String(128))

    #: The two questions, kept separate on purpose — see the enums above.
    signature_status: Mapped[str] = mapped_column(String(20), nullable=False)
    eligibility_at_receipt: Mapped[str] = mapped_column(String(20), nullable=False)

    #: As presented; meaningless until resolved, kept for triage.
    key_id: Mapped[str | None] = mapped_column(String(200))
    #: The PROVEN identity. NULL unless `signature_status = 'valid'`.
    authenticated_target_ref: Mapped[str | None] = mapped_column(String(200))
    #: Parsed from the payload. EVIDENCE ONLY — never authority.
    claimed_target_ref: Mapped[str | None] = mapped_column(String(200))
    report_id: Mapped[str | None] = mapped_column(String(200))

    disposition: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    #: The canonical row this arrival resolved to, when one was established. A
    #: LOSING concurrent arrival points at the winner.
    receipt_id: Mapped[UUID | None] = mapped_column(
        ForeignKey(f"{SCHEMA}.{_OBS_RECEIPTS}.id", ondelete="RESTRICT")
    )


__all__ = [
    "SCHEMA",
    "TERMINAL_ROLLOUT_STATUSES",
    "AttemptOutcome",
    "CredentialStatus",
    "DeploymentPlan",
    "DeploymentTarget",
    "EligibilityAtReceipt",
    "ObservationAttempt",
    "ObservationDisposition",
    "ObservationReceipt",
    "PlanStatus",
    "Rollout",
    "RolloutAttempt",
    "RolloutStatus",
    "SignatureStatus",
    "TargetCredential",
    "TargetStatus",
]
