# Control health enrollment source preparation

This is unpublished source on baseline
`ad95f4e1ef2bc454450ffc1f59a8d6f090b32431`. It does not qualify a production
source adapter, apply a migration, publish a package or close an operational
gate. Runtime tests are authored for the repository's hosted lanes and have not
been run locally.

## Bounded owner inventory

The inventory preceded implementation. Existing owners are retained:

- `service.py` and `models.py`: target, frozen plan, signed authorization,
  rollout, immutable attempt and separate immutable successful settlement.
  Existing target → plan → rollout lock ordering is reused; attempt and
  settlement evidence is read without explicit locking.
- `foundation_consumption.py`: public
  `lookup_foundation_execution_consumption` authenticates the permanent
  verified EXECUTED ledger and exact signed-pair digests. Its projection has no
  consumption timestamp. Enrollment does not invent one, verify an old token
  at issuance time or now, invoke a finalizer, or read a staged private marker.
- `images.py` and `digests.py`: existing typed signed image/digest values and
  the Control-owned frozen snapshot digest are reused. Foundation continues
  to own descriptor parsing and qualification; no opaque desired spec is read.
- `host_admission_service.py`: enrollment delegates current-host resolution to
  `require_current_target_host_locked` after the target lock. The existing owner
  enforces one open association, pointer/history agreement and Fleet host grammar.
  `models.py` retains the host association and closure evidence.
- The pinned Starter receiver's `dotmac_platform_health.admission` owns
  `EnrollmentProjection`, `HealthEligibilityAssessment` and PH grant admission.
  This independent package emits structurally identical values without adding
  a dependency on Starter or a PH persistence owner.

No existing source supplies authenticated postdeployment runtime measurements,
startup credential assignment or the installation/source/account/transport/
configuration and immutable credential-generation join. Those remain required
startup owner ports. `QualifiedDescriptor` is an adapter result from the exact
Foundation-parsed V5 descriptor, not an authenticated runtime DTO. There is no
accepting production implementation for descriptor/runtime/custody/installation
qualification in this change. Production composition must supply and qualify
those existing-owner adapters independently.

## Public surface and invariants

The public operations are `install_sources`, `enroll_deployment`,
`assess_health_eligibility`, `close_enrollment`, `historical_get`, and
`current_eligibility_get`. The three mutation commands require `command_id` as their first field and accept
optional `actor_ref` last. Commands carry exact references, never caller roles,
producer proof DTOs, verified flags, verifiers, clocks or selected sources.
`PublicCommittedConsumptionReader` only delegates to the existing public
Control reader inside a required assembly-owned separate committed read scope;
it constructs no engine, Session or transaction and commits nothing.

Enrollment requires the exact attempt's successful settlement, retained signed
pair, frozen descriptor and execution plan, historical committed consumption,
complete qualified active roster, independent authenticated runtime and startup
custody, and the existing installation owner join. It stores an immutable
projection, original evidence references, original credential reference and
version separately, and the owner's immutable generation reference verbatim.
Codes are `dc1:<attempt-hex32>:<sha256(dc-health-role:v1\\0 + role)>` (101 bytes).
The identity hash excludes only eligible-from, eligible-until and standing,
matching PH; baseline runtime/custody evidence references remain in identity.

Four append-only ledgers and one current-target pointer are introduced by
unpublished `dc_0017_deployment_enrollment`, with no historical backfill. Attempt,
installation, role and code uniqueness persist after closure. Pointer and
closure-successor foreign keys qualify the target. Target locking serializes
successor/closure/replay. Prior enrollment history prevents an older epoch from
becoming current even after a pointer was removed by closure.

Explicit assessments authenticate fresh owner evidence and append a validity
intersection with no TTL default. A per-enrollment sequence preserves append
order when the trusted clock returns equal instants. Current reads lock the
same target order and confirm current pointer, closure, host, unchanged runtime
incarnation/consumers, installation/generation and live source authority. They
check the latest assessment's original bounded interval and never renew on
read. Trusted time is sampled again after all external owner lookups, before
eligibility flushes and before return, against those same fixed bounds. Clock
regression refuses; current eligibility requires `valid_from <= assessed_at <=
now < valid_until`, and appended assessments cannot precede the latest durable
assessment time (equal instants retain explicit sequence order). Expired deployment tokens or later execution-approval withdrawal do not
couple to unchanged health eligibility and confer no further execution right.

Each mutation delegates canonical request fingerprinting and at-most-once
execution to the public Kernel `fingerprint_of` and `execute_once_platform`.
Accepted commands write the declared sixth subject audit action
`deployment.health_enrollment.changed` through the public platform audit writer
in that same operation, with existing platform-admin/opaque actor attribution.
No outbox event is added. The Kernel receipt stores the original result; an exact
command replay does not consult sources, renew eligibility, reopen an epoch or
append another audit. A changed request or actor under the same command ID
conflicts. A new command ID that reuses an existing natural domain reference
receives its own receipt and audit with `reused_domain` disposition, retaining
the original domain bytes and validity. Domain uniqueness is unchanged.

All mutations flush only; transaction completion belongs to the caller. New
enrollment and assessment mutations, pointer changes, successor closures and
all their flushes/final time checks execute inside the existing Kernel
`conflict_savepoint`. An outer savepoint includes audit and Kernel receipt
flushing followed by a check against the original owner interval (no renewed
bounds); late refusal removes domain changes, audit and receipt together. Every add and payload change begins inside that context,
so its mandatory preflush cannot flush new eligibility outside the savepoint.
A late expiry/refusal rolls back only this operation while retaining unrelated
caller work; catching a refusal and committing cannot persist refused epochs
or assessments.
PostgreSQL evidence triggers reject UPDATE/DELETE/TRUNCATE, including id=id;
narrow UPDATE(id) supports parent RI row locking for both service roles.
Downgrade locks the whole new graph and refuses to discard any retained row.

## Validation boundary

Local validation is limited to Python stdlib AST/source/TOML inspection,
Git whitespace checks and pinned Ruff 0.6.9. No local project import, runtime
test, dependency installation, build, Docker, host, credential, release, commit
or push action was performed by this worker. The adjacent JSON manifest freezes
source hashes and this validation boundary for review.

Hosted tests cover partial/fabricated/mismatched provenance, each signed and
consumption coordinate, runtime/custody startup identity, expired execution
tokens with fresh health, explicit renewal with immutable identity, changed
credential generations, revocation/staleness/outages/closure, permanent unique
constraints, real role FK admission plus no-op rewrite negatives, separate
public-reader precommit invisibility, observed PostgreSQL target-lock waits,
and downgrade retention. Review canaries additionally advance the clock from
inside an owner callback to immediately before, exactly at and after expiry for
enrollment, assessment and current reads; test rollback behind durable assessment
time; exercise ambiguous and malformed coherent host histories; and create the
whole initial/successor/closure graph through each real service role. The late
flush canary advances time only after the new mutation flush, catches the
ordinary refusal, commits an unrelated caller sentinel, then uses a fresh
Session to prove no refused enrollment, assessment, component, closure or
pointer change persisted. Initial/successor/assessment cases cover before-end
admission and exact/after-end refusal. Test doubles are explicitly test-only and do not
qualify production source adapters.


## Command boundary repair at `1ee79229`

The authored unit and migrated PostgreSQL canaries additionally cover audit
attribution and command receipts for enrollment, assessment and closure; exact
replay during source outage/after expiry; new-command natural-reference reuse
without renewal; payload/actor conflicts; concurrent identical/new/conflicting
command IDs waiting on the existing target lock; caller rollback; and expiry
triggered specifically by Kernel receipt flushing while unrelated caller work
survives a caught refusal and commit. These new canaries remain runtime-unrun.
The original five audit subjects retain their source callers. The audit
architecture census now includes the separate enrollment command owner.
No model, migration, catalogue, DTO identity or production adapter was changed
by this repair.
