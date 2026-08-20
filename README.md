# dotmac-deployment-control

The owner of **desired deployment intent, rollout planning, acknowledgement and
reconciliation** for licensed Dotmac application deployments.

Built under [ADR-0033](../../docs/adr/0033-the-vendor-control-plane-composes-existing-owners.md) § 3.
Source inventory: [`vendor-cp-gap-sources.md`](../../docs/inventories/vendor-cp-gap-sources.md) § 3.
Ownership record: [`EXTRACTION.toml`](EXTRACTION.toml).

## Provenance is split, and recorded that way

`source_mode = "historical-mixed"`, not `product-first`:

- **The receipt half** ports the Vendor V6 admission design — the attempt/receipt
  pair, the claim/proof separation, the stable-verdict rule. Those branches were
  **never merged and never deployed**, and their migration slots were later reused
  by different work on Vendor `main`. A *tested reference*, not production code.
- **The plan/rollout half is greenfield**, with the absence of any source proven
  across every branch, stash, dangling object and reflog of the Vendor repository
  plus seven other repositories.

## Three rules

**1. What is dispatched is a PLAN, and a plan is frozen.** Nothing reads the
target's *current* desired state at dispatch time — otherwise editing it
mid-rollout would silently change what is deployed, and the approval would be for
something else.

**2. A claim is never a proof.** The authoritative identity comes from the
**signed** key (ADR-0007 § 4). What the report says about itself lives in a
different column, under a CHECK that makes the separation structural.

**3. Every arrival is recorded, including the ones that fail.** Unknown key, bad
signature, ineligible credential, contradicted claim, replay, conflict — all
written. A fail-closed system that discards the failures is closed *and* blind.

## Flow

```
register_target ─► set_desired_state ─► propose_plan ─► approve_plan
                        (rev++)          (frozen +        (digest-bound
                                          digest)          evidence)
                                                              │
                                                       request_rollout
                                                              │
                                                     dispatch_attempt ──► DeliveryIntent
                                                              │            (to Integrator)
                                                       settle_attempt
                                                              │
   record_observation ◄── (target reports, kernel-verified) ──┘
            │
          drift()   ── computed on demand, against the plan that was ROLLED OUT
```

## Two tables where one looks sufficient

**`observation_attempts` + `observation_receipts`.** A single append-only table
keyed uniquely on `(identity, report_id)` cannot work: the *second* arrival under
a key is exactly the row worth keeping — the replay, or the conflicting bytes —
and the unique constraint forbids inserting it. Updating the first row breaks
append-only semantics *and* discards the conflicting bytes. It also leaves nowhere
for an arrival that never resolved to an identity at all.

**`rollouts` + `rollout_attempts`.** A rollout is the *decision*; an attempt is one
*execution*. Retrying does not change the decision, and one column for both
answers neither "how many times did we try?" nor "what did we decide?".

## Distinctions the vocabulary keeps

- `TIMED_OUT` ≠ `FAILED` — a failure means something reported an error; a timeout
  means nothing reported at all, and the second is far more likely a transport
  problem than a deployment one.
- `MANUAL_REPAIR` ≠ `CANCELLED` — a cancelled rollout is not wanted; a repairing
  one is wanted and stuck. An operator's queue must tell them apart.
- `never_observed` ≠ `drifted` — a target that has never reported is *unknown*,
  not *wrong*. Collapsing them shows every freshly registered target as an
  incident.
- A settled *attempt* does not fail the *rollout*. One transport error is not a
  deployment decision.

## Composition

- **Platform plane only** — a module that decides what a *fleet* should run cannot
  live inside one of those deployments (ADR-0023, ADR-0033 § 7).
- **No provider anything.** No SSH/Kubernetes/cloud/panel client, no HTTP library,
  no endpoint, credential reference, transport name or retry policy. It emits a
  provider-neutral `DeliveryIntent`; the Integrator owns everything after that
  (ADR-0024, hard rule 28).
- **It verifies nothing itself.** `dotmac_kernel.licensing.verify_applied_state`
  and `verify_possession` own that (ADR-0007); the caller runs them and passes the
  result in.
- **No health status at all.** Whether a deployment is UP belongs to Dotmac
  Observability. Ruling A4 keeps them apart so "no mutating consumer of health"
  stays a checkable dependency direction.
- **Imports no sibling module** (ADR-0024).

## Published facts

Nineteen types, all `.v1` — read `PUBLISHED_EVENT_TYPES` rather than keeping a
hand-written list.

## Status

**Built and validated, not adopted.** Unlike its two siblings there is nothing to
cut over *from*: the V6 slices were never merged. `EXTRACTION.toml` records the
two proofs the composition still owes — the claim/proof CHECKs against raw SQL,
and a concurrency rehearsal for the stable-verdict rule that a single-process test
cannot establish — and the obligation to **delete** the two abandoned V6 branches,
whose migration slots `main` has since reused.
