# Dispatch-consumption boundary

This document is the source of truth for Control's single-use dispatch
authority. It does not define an executor transport or launch adapter.

`_stage_dispatch_consumption` is an internal service seam. It accepts only a
Control attempt identifier and an independently resolved expected target
coordinate after trusted composition has authenticated a presenter. The
coordinate's `target_id` must come from the Control-stored credential selected
by that authentication, and its `target_ref` from the corresponding target row;
neither may come from the presented envelope. The coordinate is compared to the
locked target; it is not itself authentication. No production caller exists. It
does not accept an envelope, verifier or standing assertion from an untrusted
caller.

Within one caller-owned transaction, Control locks target, plan, rollout and
attempt in the same order as approval revocation; parses and compares the exact
stored authorization/dispatch coordinate; checks target liveness, rollout and
attempt state, authorization lifetime, and current approval standing; then calls
Kernel `execute_once_platform`. Its key is the stored signed dispatch id, its
scope is `deployment.consume_dispatch_challenge.v1`, its fingerprint is the
bare 64-hex form of the typed dispatch-envelope digest, and `expires_at` is
always `NULL`.

The service flushes but never commits. Its private staged result is not a launch
grant. An adapter may launch only after the transaction owner observes commit;
no such adapter is present in this distribution today. The marker and the
launch must never be reset or expired. If approval revocation commits first,
consumption refuses even though dispatch history stays immutable. If consumption
commits first, that is the final authorization cut-off; recovery requires a new
signed dispatch attempt. This is distinct from at-most-once external delivery,
which stays with Integrator/outbox.

## The cut-off class also covers cancel and settle

The permanent-cut-off rule above was proven, on real PostgreSQL, for approval
revocation. It applies identically to `cancel_rollout` (and
`require_manual_repair`, its sibling transition) and to `settle_attempt`:

- `settle_attempt` locks the rollout, then the exact attempt row it is
  settling, `FOR UPDATE` — the same rollout-then-attempt relative order
  consumption locks in — before deciding.
- `_rollout_transition` (used by `cancel_rollout` and `require_manual_repair`)
  locks the rollout `FOR UPDATE` first, and, when it is cancelling in-flight
  attempts, locks each still-PENDING attempt `FOR UPDATE` before touching it.

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
`require_manual_repair`) — not a module-wide claim. Every lock THESE take is
an explicit `SELECT ... FOR UPDATE`, and every check that follows a wait
re-reads the row (`populate_existing=True`) rather than trusting a value read
before the wait. That makes this boundary correct at PostgreSQL's default
READ COMMITTED — its floor — and it remains correct, unchanged, at
SERIALIZABLE. Nothing here depends on snapshot isolation or on a stronger
level than the database's default.

Not every mutation in this module holds to the same discipline yet — e.g.
`cancel_plan` decides from an unlocked `_load_plan` plus an unlocked
rollout-existence check, and only takes the plan lock at flush, which is a
separate, pre-existing gap outside this boundary.
