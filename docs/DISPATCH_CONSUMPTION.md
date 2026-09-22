# Dispatch-consumption boundary

This document is the source of truth for Control's single-use dispatch
authority. It does not define an executor transport or launch adapter.

## Rehearsal-grant staging

`_stage_rehearsal_consumption` follows the same caller-owned transaction rule:
it locks and flushes the durable grant-state row for the replay coordinate,
but is private and NOT a launch grant. A future trusted assembly adapter must
verify the signed rehearsal grant, own the transaction, call the stage, observe
a successful commit, and
only then launch. No such adapter exists in this distribution. An unknown
commit outcome gives no launch or automatic replay authority; the adapter must
resolve durable standing before any further action. A committed spend remains
final; no unspend path is implied here.

`_stage_dispatch_consumption` is an internal service seam. It accepts only a
Control attempt identifier and an independently resolved expected target
coordinate after trusted composition has authenticated a presenter. The
coordinate's `target_id` must come from the Control-stored credential selected
by that authentication, and its `target_ref` from the corresponding target row;
neither may come from the presented envelope. The coordinate is compared to the
locked target; it is not itself authentication. Its sole production caller is
ADR-0073's `admit_and_consume_host_admission`, after that function has
re-authenticated and re-locked the complete coordinate fresh. It does not
accept an envelope, verifier or standing assertion from an untrusted caller.

Within one caller-owned transaction, Control locks target, plan and the mutable
rollout in the same order as approval revocation, then reads immutable attempt
evidence without explicit `FOR UPDATE`; parses and compares the exact
stored authorization/dispatch coordinate; checks target liveness, rollout and
attempt state, authorization lifetime, and current approval standing; then calls
Kernel `execute_once_platform`. Its key is the stored signed dispatch id, its
scope is `deployment.consume_dispatch_challenge.v1`, its fingerprint is the
bare 64-hex SHA-256 over the canonical dispatch/candidate/installed evidence
coordinate, and `expires_at` is always `NULL`.

The service flushes but never commits. Its private staged result is not a launch
grant. A CP adapter may launch only after the transaction owner observes commit;
that transport adapter is not part of this distribution. The marker and the
launch must never be reset or expired. If approval revocation commits first,
consumption refuses even though dispatch history stays immutable. If consumption
commits first, that is the final authorization cut-off; recovery requires a new
signed dispatch attempt. This is distinct from at-most-once external delivery,
which stays with Integrator/outbox.

## Authenticated host-admission extension (redesigned 2026-09-22)

ADR-0073 requires a three-phase Control boundary for a signed host-admission
presentation, redesigned from an earlier single-transaction shape specifically
to eliminate a lock held across an out-of-process Foundation verification
call (see "Why this redesigned the original shape" below). It retains the
signed dispatch envelope's `dispatch_id` as the Kernel key. Its fingerprint is
the SHA-256 of the canonical admission-coordinate mapping containing the
dispatch, candidate-attestation and installed-attestation envelope digests.
Therefore a replay of the exact coordinate is consumed, while the same
dispatch with changed attestation evidence is an integrity conflict; no second
replay ledger exists.

**Phase 1 — `resolve_host_admission_context` (no lock, no transaction
affinity).** Authenticates the presentation and resolves every current fact
Foundation verification needs — target, credential, current host association
and admission policy, both attestation root contexts, the stored dispatch
coordinate — with plain, non-locking reads. Returns
`HostAdmissionVerificationContextV1`: a freely-copyable, non-authorizing plain
value. Nothing about possessing it grants anything; it carries no Session or
transaction reference. Its `context_digest` field is Control's own canonical
digest over the ENTIRE resolved context (the signed presentation including its
signature, the dispatch coordinate, full credential/target/host identity, the
immutable association and admission-policy row UUIDs, both audiences, the
expected package, and every field of both root contexts) — an
optimistic-concurrency fingerprint, recomputed and compared in phase 3, never
trusted from this returned copy alone. The caller is responsible for closing
(committing) the short read transaction this ran in before proceeding to phase
2 — this function itself never commits or rolls back.

**Phase 2 — Foundation verification, no open database transaction.** The
trusted CP adapter calls Foundation's `verify_attestation_pair` with the real
candidate/installed envelopes, passing `context.context_digest` as its opaque
`verification_context_digest` parameter. Foundation does not interpret or
reproduce this value — it verifies the presented evidence exactly as before,
and, on success only, returns a typed
`AttestationPairVerificationResultV1` echoing that same digest back unchanged,
alongside the two envelope digests it independently computed from the real
parsed envelope objects. No Control lock is held anywhere during this phase,
however long it takes — this is the entire point of the redesign.

**Phase 3 — `admit_and_consume_host_admission` (fresh clock, full re-lock,
full re-derivation, then consume).** Trusted composition first installs the
purpose-specific presentation verifier and trusted clock exactly once at
startup; a second install is refused, same as before. This function
re-authenticates the presentation with a FRESH clock read (not any timestamp
carried over from phase 1 — real time passes during phase 2, and a
presentation that expired during that gap must refuse cleanly here, via the
dedicated `CONTEXT_EXPIRED` code, checked before re-authentication even runs).
It then re-locks target, credential, current host association and admission
policy, and both attestation-subject rows, in the SAME canonical order the
prior single-transaction design used, re-derives every fact from those locked
rows, and refuses (`PREPARED_STATE_CHANGED`, or the resolver's own natural
refusal such as `HOST_ABSENT`/`POLICY_ABSENT`/`ROOT_REFUSED` where one of the
re-derivation calls itself raises) on any drift against the resolved
`context`. It recomputes the context digest from that freshly re-derived state
and requires it to equal `context.context_digest`; it separately requires the
caller-supplied `HostAdmissionForeignVerificationEvidenceV1.verification_context_digest`
to ALSO equal `context.context_digest` (`FOREIGN_EVIDENCE_CONTEXT_MISMATCH` if
not) — binding Foundation's success to the exact context Control resolved,
without either package reproducing the other's digest algorithm — and that its
two envelope digests match the presentation's own signed claims
(`EVIDENCE_CHANGED` if not). Only then does it call this private staging seam
and return its result. Neither Control service commits or rolls back.

**Why this redesigned the original shape.** The prior single-transaction
design held row locks — including the `("host_attester", host_id)` subject
lock, which is GLOBAL to that host attester, not scoped to one target — for
the entire duration of phase 2's out-of-process Foundation call. A stalled or
slow presenter/adapter could hold those locks indefinitely, which could delay
an operator's emergency root revocation or any other mutation of the locked
target. Splitting resolve from admit-and-consume, with zero locks held during
Foundation verification, eliminates that exposure structurally rather than
bounding it with a timeout. Finite `statement_timeout`/`lock_timeout`/
`idle_in_transaction_session_timeout` GUCs on the now-short phase-3 transaction
remain worthwhile defense-in-depth against a genuinely pathological hang
inside that transaction itself, but they are no longer the primary correctness
mechanism the way they would have had to be under the old design.

**The CP adapter must construct `HostAdmissionForeignVerificationEvidenceV1`
from Foundation's ACTUAL returned result, never fabricate it from `context`.**
Every test in this distribution necessarily constructs matching (or
deliberately mismatched) evidence directly from `context`'s own fields,
because no real Foundation call is available in-process — that is a known,
explicit test-suite limitation, not a pattern to copy. A real adapter's
`candidate_attestation_envelope_digest`/`installed_attestation_envelope_digest`
must come from Foundation's typed result (computed by Foundation from the
actual parsed envelope bytes it verified), and
`verification_context_digest` must be the value Foundation itself returned
(the blind echo of what the adapter gave it), never a value the adapter reads
back out of its own copy of `context`. Control's checks above cannot
distinguish "Foundation genuinely verified this" from "the adapter fabricated
matching public fields without ever calling Foundation" — that is a property
of the adapter's own wiring, not something a digest comparison can prove from
Control's side of the boundary. A required test for any real CP adapter,
before it composes against a released Control/Foundation pair: swap in a
stub/broken `verify_attestation_pair` binding and prove the adapter's own
production code path cannot reach `admit_and_consume_host_admission` with a
result that produces a consumption — using fixed, signed test fixtures, no
published candidate required.

## The cut-off class also covers cancel and settle

The permanent-cut-off rule above was proven, on real PostgreSQL, for approval
revocation. It applies identically to `cancel_rollout` (and
`require_manual_repair`, its sibling transition) and to `settle_attempt`:

- `settle_attempt` locks the mutable rollout decision before reading immutable
  issuance evidence and INSERTing one append-only settlement row. It never
  explicitly `FOR UPDATE` locks or updates either evidence table (FK key-share
  locks may still occur). `UNIQUE (attempt_id)` is the final race arbiter for
  competing terminal reports.
- `_rollout_transition` (used by `cancel_rollout` and `require_manual_repair`)
  locks the rollout `FOR UPDATE` first, and, when it is cancelling in-flight
  attempts, reads each still-pending issuance attempt after that rollout lock
  before appending its cancellation settlement.

If cancel or settle reaches the rollout lock first, a concurrent consumption
blocks, then re-reads the now-committed rollout/attempt state and refuses
(`ROLLOUT_NOT_OPEN` or `ATTEMPT_NOT_PENDING`) — the dispatch was never
consumed. If consumption reaches the lock first and commits, a concurrent
cancel or settle blocks behind it, then proceeds once released: it still
records ITS OWN outcome (e.g. the attempt becomes `cancelled`, or its settled
outcome), because a decision to stop retrying or an executor's own report are
both real events worth recording even for an attempt whose dispatch authority
was already, separately, spent. Neither reopens or reclaims the consumed
marker — only a newly signed dispatch attempt does that. A rollout or attempt
row therefore does not by itself prove a dispatch was never launched; the
`PlatformIdempotencyRecord` scoped `deployment.consume_dispatch_challenge.v1`
is the sole evidence for that.

## Isolation level

Scoped to this boundary — `_stage_dispatch_consumption`, `revoke_plan_approval`,
`settle_attempt`, and `_rollout_transition` (`cancel_rollout`/
`require_manual_repair`) — not a module-wide claim. Every application-directed
serialization lock THESE take is an explicit `SELECT ... FOR UPDATE` (FK
referential-integrity locks may still occur), and every check that follows a wait
re-reads the row (`populate_existing=True`) rather than trusting a value read
before the wait. That makes this boundary correct at PostgreSQL's default
READ COMMITTED — its floor — and it remains correct, unchanged, at
SERIALIZABLE. Nothing here depends on snapshot isolation or on a stronger
level than the database's default.

Not every mutation in this module holds to the same discipline yet — e.g.
`cancel_plan` decides from an unlocked `_load_plan` plus an unlocked
rollout-existence check, and only takes the plan lock at flush, which is a
separate, pre-existing gap outside this boundary.
