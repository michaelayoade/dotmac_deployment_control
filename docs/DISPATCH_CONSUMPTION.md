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
ADR-0073's `finalize_host_admission`, after `prepare_host_admission` has
authenticated and locked the complete coordinate. It does not accept an
envelope, verifier or standing assertion from an untrusted caller.

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

## Authenticated host-admission extension

ADR-0073 requires a private Control preparation/finalization path for a signed
host-admission presentation. It retains this scope and the signed dispatch
envelope's `dispatch_id` as the Kernel key.  Its fingerprint is instead the
SHA-256 of the canonical admission-coordinate mapping containing the dispatch,
candidate-attestation and installed-attestation envelope digests.  Therefore a
replay of the exact coordinate is consumed, while the same dispatch with changed
attestation evidence is an integrity conflict; no second replay ledger exists.

The implemented preparation and finalization use one caller-owned transaction.
Trusted composition first installs the purpose-specific presentation verifier
and trusted clock exactly once; preparation has no request-time verifier or
clock parameter and fails closed before authentication if startup wiring is
absent. A second install is refused.
Preparation exposes immutable verification facts but registers the separately
opaque, non-public finalization capability in that Session and root transaction.
Copied facts or a forged object cannot reach consumption. Finalization calls
this private staging seam, consumes that capability, and returns its private
staged result. Neither Control service commits or rolls back.

**Lock-duration bound is a stated CP obligation, not a Control mechanism.**
Between `prepare_host_admission` returning and `finalize_host_admission` being
called, the caller-owned transaction holds row locks on the target, the
selected credential, the current host-association and admission-policy
projections, and both candidate/installed attestation-subject rows. Foundation
verification and any network round-trip the trusted adapter performs happen
inside that window by design — finalize re-checks everything against the
locked state rather than a fresh read, which is only safe because nothing
under those locks can change. This is correct for correctness but has no
Control-side time bound: a stalled or slow presenter/adapter keeps those locks
— including the `("host_attester", host_id)` subject lock, which is global to
that host attester, not scoped to one target — held for as long as the
transaction stays open, which can delay an operator's emergency root
revocation or any other mutation of the locked target. Control cannot bound
this itself without taking over session configuration; the composing CP
adapter MUST set a `statement_timeout`/`lock_timeout` (and should consider
`idle_in_transaction_session_timeout`) on the connection used for the
prepare/finalize transaction, sized to the real Foundation-verification and
network latency it expects, so an admission attempt fails closed rather than
holding fleet-wide locks indefinitely. This is not yet enforced by any test in
this distribution.

**The CP adapter must pass Foundation's computed digests to finalize, never
the digests `prepare_host_admission` already returned.** Finalization's
`EVIDENCE_CHANGED` check (comparing the caller-supplied digests against the
prepared coordinate) is the ONLY thing binding what Foundation actually
verified to what the presenter signed. Feeding `prepare`'s own returned facts
straight back into `finalize` — the shape every test in this distribution
uses, because no real Foundation call is available in-process — makes that
check compare a value to itself and defeats it silently; Control cannot detect
an adapter that does this, because both call sites are, by construction, given
exactly the same interface. A real adapter must call Foundation's
`attestation_envelope_digest` on the envelopes it verified and pass THAT
result, never the value it read out of `prepare`'s facts. This deserves a
fixed cross-repository vector test on the adapter itself, since Control
structurally cannot enforce it from its own side of the boundary.

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
