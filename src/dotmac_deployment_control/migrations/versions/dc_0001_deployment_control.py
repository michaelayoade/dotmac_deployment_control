"""Deployment-control tables — the `deployment_control` lineage root.

Lineage ROOT: `down_revision = None`, `branch_labels` names the owner, and the
only `depends_on` edge is the LOGICAL one the assembly binds (ADR-0006 D1
amendment). No edge to a release, licence, brand or agreement table, and no
foreign key to one either — `release_ref`, `licence_ref` and `brand_profile_ref`
are bare strings with no constraint. A deployment record must outlive a
superseded release and a replaced licence.

## There is no private key and no provider credential

`target_credentials` holds a deployment's own PUBLIC verification key: the
target's identity, not a way to reach a provider. Provider credentials,
endpoints, transports, connector schedules and checkpoints are the Integrator's
(ADR-0024, hard rule 28), and their absence here is structural rather than
conventional.

## Platform catalog grants, not RLS

There is no `tenant_id` to scope by, so RLS would have no predicate. Grants
instead (hard rule 27):

- `platform_api` — the ONLINE role. SELECT and INSERT everywhere, plus UPDATE on
  the four mutable tables: targets, credentials, plans and rollouts. Attempts and
  the two observation tables get no UPDATE, which is what makes them immutable to
  the online role.
- `app_admin` — the OFFLINE migration role. Full DML on the four mutable tables,
  so a mis-entered target is correctable under review. SELECT and INSERT only on
  the three append-only tables.
- `app_user` — the tenant data-plane role. REVOKEd everywhere. On this plane the
  revoke IS the isolation.

## Three append-only tables, enforced by trigger against every role

`rollout_attempts`, `observation_attempts` and `observation_receipts` refuse
UPDATE and DELETE from EVERY role, including `app_admin`.

Each is evidence whose value is precisely that it cannot be adjusted:

- an attempt log that can be tidied is a log that will be, and the tidying always
  removes the attempt that explains the outage.
- an observation attempt is the record of what a remote party sent and what was
  done about it, including the arrivals that failed before an identity existed.
  Those are the tripwires; a rewritable tripwire is decoration.
- a receipt's `original_verdict` is returned verbatim to every replay. If it can
  be edited, an at-least-once transport can be made to look like a state change.

`ondelete="RESTRICT"` on every parent link closes the same holes from the other
side: "delete the parent" must not launder a rewrite through a path the trigger
never sees.

## Two CHECKs that make the claim/proof split structural

`ck_observation_identity_needs_valid_signature` and
`ck_observation_eligibility_needs_valid_signature`. A row may carry an
"authenticated" ref, or a non-`n/a` eligibility, only when something actually
authenticated it. Without them the columns are two strings a careless writer can
fill identically, and deployment binding becomes decorative.

They are declared HERE and on the model, deliberately. The unit lane builds its
schema with `create_all` from the model metadata, so a constraint living only in
the migration would mean the fast tests run against a schema production does not
have. Migrations stay self-contained — a frozen snapshot must not import app code
— so the predicates are duplicated on purpose and the Postgres canary proves they
agree.

## No CHECK on `status`, `environment` or `disposition`

ADR-0008's reason: adding a member should cost a module release, not an
`ALTER TYPE` on every deployment. The CHECKs that ARE here constrain things true
independent of any vocabulary — revisions and attempt numbers start at 1 — plus
the two structural predicates above.

Revision ID: dc_0001_deployment_control
Revises: (lineage root)
Create Date: 2026-08-19
"""

from __future__ import annotations

import sqlalchemy as sa
from dotmac_kernel.migrations.verify import require_prerequisites
from dotmac_kernel.prerequisites import resolve_depends_on
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "dc_0001_deployment_control"
down_revision = None
branch_labels = ("deployment_control",)

# COMMON, and the three lists are written out in full so the reader sees the
# decision rather than an omission. This module owns exactly one plane, so the
# platform plane installs atomically and no selection exists under which either
# effect stops being needed.
COMMON_REQUIRES = ("idempotency_ledger.v1", "platform_audit_log.v1")
TENANT_REQUIRES: tuple[str, ...] = ()
PLATFORM_REQUIRES: tuple[str, ...] = ()
REQUIRES = COMMON_REQUIRES + TENANT_REQUIRES + PLATFORM_REQUIRES

# The assembly binds each effect to the revision that SUPPLIES it.
depends_on = resolve_depends_on(COMMON_REQUIRES)

# A literal, not `module_schema("deploy")`. A migration is a frozen historical
# artifact, and the static gate reads this file without importing it.
_SCHEMA = "mod_deploy"


def _grant(privileges: str, table: str, role: str) -> None:
    """One GRANT, spelled out at the call site.

    A helper only because the statement text is otherwise identical many times
    over; the CALL SITES stay one line each and fully literal, so the module's
    whole access-control surface remains greppable and statically checkable —
    which a loop over a table tuple would not be.
    """
    op.execute(f"GRANT {privileges} ON mod_deploy.{table} TO {role};")


def _revoke(table: str) -> None:
    """Revoke everything from the tenant app role. On this plane the revoke IS
    the isolation (hard rule 27)."""
    op.execute(f"REVOKE ALL ON mod_deploy.{table} FROM app_user;")


def upgrade() -> None:
    # Prove the two request-time effects BEFORE any DDL of this module's own
    # runs. Deploy is the last moment at which a missing ledger is a failed
    # migration rather than a failed rollout in production.
    require_prerequisites(op.get_bind(), REQUIRES)

    op.execute("CREATE SCHEMA IF NOT EXISTS mod_deploy;")
    op.execute("GRANT USAGE ON SCHEMA mod_deploy TO platform_api, app_admin;")

    op.create_table(
        "deployment_targets",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("target_ref", sa.String(length=200), nullable=False),
        sa.Column("subject_ref", sa.String(length=200), nullable=False),
        sa.Column("product_code", sa.String(length=120), nullable=False),
        sa.Column("environment", sa.String(length=60), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("desired_release_ref", sa.String(length=200), nullable=True),
        sa.Column("desired_spec", postgresql.JSONB(), nullable=True),
        sa.Column("licence_ref", sa.String(length=200), nullable=True),
        sa.Column("brand_profile_ref", sa.String(length=200), nullable=True),
        sa.Column("desired_revision", sa.Integer(), nullable=False),
        sa.Column("observed_release_ref", sa.String(length=200), nullable=True),
        sa.Column("observed_spec_digest", sa.String(length=128), nullable=True),
        sa.Column("observed_revision", sa.Integer(), nullable=True),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("target_ref", name="uq_deployment_targets_ref"),
        sa.CheckConstraint("desired_revision >= 0", name="ck_targets_desired_revision"),
        sa.CheckConstraint("record_version >= 1", name="ck_targets_record_version"),
        schema="mod_deploy",
    )
    op.create_index(
        "ix_targets_subject_ref",
        "deployment_targets",
        ["subject_ref"],
        schema="mod_deploy",
    )
    op.create_index(
        "ix_targets_status", "deployment_targets", ["status"], schema="mod_deploy"
    )

    op.create_table(
        "target_credentials",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("key_id", sa.String(length=200), nullable=False),
        # PUBLIC material only. There is deliberately no sibling column for a
        # private half and none for a provider credential.
        sa.Column("public_key_b64", sa.String(length=200), nullable=False),
        sa.Column("public_key_fingerprint", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(length=200), nullable=True),
        sa.Column("enrollment_authority", sa.String(length=60), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["mod_deploy.deployment_targets.id"],
            name="fk_target_credentials_target_id",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("key_id", name="uq_target_credentials_key_id"),
        # Over the DECODED key bytes, never the base64 text — which is not
        # canonical, so two spellings of one key would each enrol separately.
        sa.UniqueConstraint(
            "public_key_fingerprint", name="uq_target_credentials_fingerprint"
        ),
        schema="mod_deploy",
    )
    op.create_index(
        "ix_credentials_target_id",
        "target_credentials",
        ["target_id"],
        schema="mod_deploy",
    )

    op.create_table(
        "deployment_plans",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("snapshot", postgresql.JSONB(), nullable=True),
        sa.Column("desired_revision", sa.Integer(), nullable=False),
        sa.Column("plan_digest", sa.String(length=64), nullable=True),
        sa.Column("requires_approval", sa.Boolean(), nullable=False),
        sa.Column("approval_policy_code", sa.String(length=120), nullable=True),
        sa.Column("approval_policy_version", sa.Integer(), nullable=True),
        sa.Column("approval_decision_ref", sa.String(length=200), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("superseded_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["mod_deploy.deployment_targets.id"],
            name="fk_deployment_plans_target_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["superseded_by_id"],
            ["mod_deploy.deployment_plans.id"],
            name="fk_deployment_plans_superseded_by_id",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("target_id", "sequence", name="uq_plans_target_sequence"),
        # Two plans with one digest means two approvals could bind to one
        # snapshot, which is exactly the ambiguity the digest exists to remove.
        sa.UniqueConstraint("plan_digest", name="uq_plans_digest"),
        sa.CheckConstraint("sequence >= 1", name="ck_plans_sequence"),
        sa.CheckConstraint("record_version >= 1", name="ck_plans_record_version"),
        schema="mod_deploy",
    )
    op.create_index(
        "ix_plans_target_id", "deployment_plans", ["target_id"], schema="mod_deploy"
    )
    op.create_index(
        "ix_plans_status", "deployment_plans", ["status"], schema="mod_deploy"
    )

    op.create_table(
        "rollouts",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("rollout_ref", sa.String(length=200), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["mod_deploy.deployment_targets.id"],
            name="fk_rollouts_target_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["plan_id"],
            ["mod_deploy.deployment_plans.id"],
            name="fk_rollouts_plan_id",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("rollout_ref", name="uq_rollouts_ref"),
        sa.CheckConstraint("record_version >= 1", name="ck_rollouts_record_version"),
        schema="mod_deploy",
    )
    op.create_index(
        "ix_rollouts_target_id", "rollouts", ["target_id"], schema="mod_deploy"
    )
    op.create_index("ix_rollouts_status", "rollouts", ["status"], schema="mod_deploy")

    op.create_table(
        "rollout_attempts",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("rollout_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("attempt_no", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(length=20), nullable=False),
        sa.Column("integrator_ref", sa.String(length=200), nullable=True),
        # A stable code, never a provider's raw error text — that would carry
        # provider vocabulary, and sometimes credentials, into this schema.
        sa.Column("error_code", sa.String(length=60), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("settled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["rollout_id"],
            ["mod_deploy.rollouts.id"],
            name="fk_rollout_attempts_rollout_id",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("rollout_id", "attempt_no", name="uq_attempts_no"),
        sa.CheckConstraint("attempt_no >= 1", name="ck_attempts_no"),
        schema="mod_deploy",
    )
    op.create_index(
        "ix_attempts_rollout_id",
        "rollout_attempts",
        ["rollout_id"],
        schema="mod_deploy",
    )

    op.create_table(
        "observation_receipts",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("authenticated_target_ref", sa.String(length=200), nullable=False),
        sa.Column("report_id", sa.String(length=200), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=True),
        sa.Column("payload_digest", sa.String(length=128), nullable=True),
        sa.Column("key_id", sa.String(length=200), nullable=False),
        sa.Column("first_received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("original_verdict", sa.String(length=40), nullable=False),
        sa.Column("observed_release_ref", sa.String(length=200), nullable=True),
        sa.Column("observed_spec_digest", sa.String(length=128), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        # Scoped to the PROVEN identity, so one target's report_id can never
        # collide with another's.
        sa.UniqueConstraint(
            "authenticated_target_ref",
            "report_id",
            name="uq_observation_receipts_identity_report",
        ),
        schema="mod_deploy",
    )

    op.create_table(
        "observation_attempts",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw_body", sa.LargeBinary(), nullable=True),
        sa.Column("raw_body_truncated", sa.Boolean(), nullable=False),
        sa.Column("raw_body_digest", sa.String(length=128), nullable=True),
        sa.Column("signature_status", sa.String(length=20), nullable=False),
        sa.Column("eligibility_at_receipt", sa.String(length=20), nullable=False),
        sa.Column("key_id", sa.String(length=200), nullable=True),
        # The PROVEN identity.
        sa.Column("authenticated_target_ref", sa.String(length=200), nullable=True),
        # What the report said about itself. EVIDENCE ONLY — never authority.
        sa.Column("claimed_target_ref", sa.String(length=200), nullable=True),
        sa.Column("report_id", sa.String(length=200), nullable=True),
        sa.Column("disposition", sa.String(length=40), nullable=False),
        sa.Column("receipt_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["receipt_id"],
            ["mod_deploy.observation_receipts.id"],
            name="fk_observation_attempts_receipt_id",
            ondelete="RESTRICT",
        ),
        # Claim/proof separation, made structural. Declared here AND on the
        # model — see the module docstring for why the duplication is deliberate.
        sa.CheckConstraint(
            "(signature_status = 'valid') OR (authenticated_target_ref IS NULL)",
            name="ck_observation_identity_needs_valid_signature",
        ),
        sa.CheckConstraint(
            "(signature_status = 'valid') OR (eligibility_at_receipt = 'n/a')",
            name="ck_observation_eligibility_needs_valid_signature",
        ),
        schema="mod_deploy",
    )
    op.create_index(
        "ix_observation_attempts_disposition",
        "observation_attempts",
        ["disposition"],
        schema="mod_deploy",
    )

    # ── Append-only evidence, enforced against every role ───────────────────
    op.execute(
        """
        CREATE FUNCTION mod_deploy.refuse_evidence_rewrite() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION
                '%.% is append-only evidence; correct it by appending, never '
                'by rewriting', TG_TABLE_SCHEMA, TG_TABLE_NAME
                USING ERRCODE = '23514';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    # Written out per table rather than looped: a loop is invisible to a static
    # reader, to `grep`, and to the architecture guard that checks every
    # append-only table is covered.
    op.execute(
        """
        CREATE TRIGGER refuse_evidence_rewrite
        BEFORE UPDATE OR DELETE ON mod_deploy.rollout_attempts
        FOR EACH ROW EXECUTE FUNCTION mod_deploy.refuse_evidence_rewrite();
        """
    )
    op.execute(
        """
        CREATE TRIGGER refuse_evidence_rewrite
        BEFORE UPDATE OR DELETE ON mod_deploy.observation_attempts
        FOR EACH ROW EXECUTE FUNCTION mod_deploy.refuse_evidence_rewrite();
        """
    )
    op.execute(
        """
        CREATE TRIGGER refuse_evidence_rewrite
        BEFORE UPDATE OR DELETE ON mod_deploy.observation_receipts
        FOR EACH ROW EXECUTE FUNCTION mod_deploy.refuse_evidence_rewrite();
        """
    )

    _grant("SELECT, INSERT", "deployment_targets", "platform_api")
    _grant("UPDATE", "deployment_targets", "platform_api")
    _grant("SELECT, INSERT", "target_credentials", "platform_api")
    _grant("UPDATE", "target_credentials", "platform_api")
    _grant("SELECT, INSERT", "deployment_plans", "platform_api")
    _grant("UPDATE", "deployment_plans", "platform_api")
    _grant("SELECT, INSERT", "rollouts", "platform_api")
    _grant("UPDATE", "rollouts", "platform_api")
    _grant("SELECT, INSERT", "rollout_attempts", "platform_api")
    _grant("SELECT, INSERT", "observation_receipts", "platform_api")
    _grant("SELECT, INSERT", "observation_attempts", "platform_api")

    _grant("SELECT, INSERT, UPDATE, DELETE", "deployment_targets", "app_admin")
    _grant("SELECT, INSERT, UPDATE, DELETE", "target_credentials", "app_admin")
    _grant("SELECT, INSERT, UPDATE, DELETE", "deployment_plans", "app_admin")
    _grant("SELECT, INSERT, UPDATE, DELETE", "rollouts", "app_admin")
    # SELECT and INSERT only, even for the offline role — see the module
    # docstring for why each of these three must be unadjustable.
    _grant("SELECT, INSERT", "rollout_attempts", "app_admin")
    _grant("SELECT, INSERT", "observation_receipts", "app_admin")
    _grant("SELECT, INSERT", "observation_attempts", "app_admin")

    _revoke("deployment_targets")
    _revoke("target_credentials")
    _revoke("deployment_plans")
    _revoke("rollouts")
    _revoke("rollout_attempts")
    _revoke("observation_receipts")
    _revoke("observation_attempts")


def downgrade() -> None:
    for table in (
        "rollout_attempts",
        "observation_attempts",
        "observation_receipts",
    ):
        op.execute(
            f"DROP TRIGGER IF EXISTS refuse_evidence_rewrite ON mod_deploy.{table};"
        )
    op.execute("DROP FUNCTION IF EXISTS mod_deploy.refuse_evidence_rewrite();")
    op.drop_index(
        "ix_observation_attempts_disposition",
        "observation_attempts",
        schema="mod_deploy",
    )
    op.drop_table("observation_attempts", schema="mod_deploy")
    op.drop_table("observation_receipts", schema="mod_deploy")
    op.drop_index("ix_attempts_rollout_id", "rollout_attempts", schema="mod_deploy")
    op.drop_table("rollout_attempts", schema="mod_deploy")
    op.drop_index("ix_rollouts_status", "rollouts", schema="mod_deploy")
    op.drop_index("ix_rollouts_target_id", "rollouts", schema="mod_deploy")
    op.drop_table("rollouts", schema="mod_deploy")
    op.drop_index("ix_plans_status", "deployment_plans", schema="mod_deploy")
    op.drop_index("ix_plans_target_id", "deployment_plans", schema="mod_deploy")
    op.drop_table("deployment_plans", schema="mod_deploy")
    op.drop_index("ix_credentials_target_id", "target_credentials", schema="mod_deploy")
    op.drop_table("target_credentials", schema="mod_deploy")
    op.drop_index("ix_targets_status", "deployment_targets", schema="mod_deploy")
    op.drop_index("ix_targets_subject_ref", "deployment_targets", schema="mod_deploy")
    op.drop_table("deployment_targets", schema="mod_deploy")
    op.execute("DROP SCHEMA IF EXISTS mod_deploy RESTRICT;")
