# dotmac-deployment-control

The owner of **desired deployment intent, rollout planning, acknowledgement and
reconciliation** for licensed Dotmac application deployments.

Built under [ADR-0057](../../docs/adr/0057-the-vendor-control-plane-composes-existing-owners.md) § 3.
Source inventory: [`vendor-cp-gap-sources.md`](../../docs/inventories/vendor-cp-gap-sources.md) § 3.
Ownership record: [`EXTRACTION.toml`](EXTRACTION.toml).

## Provenance is split, and recorded that way

`source_mode = "greenfield-after-inventory"`, not `product-first`. The
historical evidence is mixed, but neither half qualifies as product-first code:

- **The receipt half** ports the Vendor V6 admission design — the attempt/receipt
  pair, the claim/proof separation, the stable-verdict rule. Those branches were
  **never merged and never deployed**, and their migration slots were later reused
  by different work on Vendor `main`. A *tested reference*, not production-used
  code, so rule 24 classifies the port as greenfield.
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
  live inside one of those deployments (ADR-0023, ADR-0057 § 7).
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

## A digest is a value, not a string

A plan's identity is `PlanDigestV1` — an algorithm and its bytes — serialized
canonically as `sha256:<64 lowercase hex>`. Equality is over the bytes, so no
encoding can change it, and nothing on the authorization path compares digest
text.

This is the defect `0.1.0a5` was cut for. Through `0.1.0a4` `propose_plan`
stored bare hex while `spec_digest` produced the prefixed form, and
`approve_plan` compared the two as strings — so a caller supplying the plan's
own digest in the other encoding was refused with *"the plan changed after
approval"*. A security refusal standing in for a formatting bug is the worst
failure shape available, because it looks exactly like the system working.

So the two outcomes are two exceptions and neither is a subclass of the other:
`DigestEncodingError` means the value could not be READ and nothing was
compared; `ApprovalRefusedError` means it was read and the plan really did move.

**Consumers do not normalize.** a4's bare-hex form is accepted through
`parse_a4_bare_hex` / `parse_accepting_a4_bare_hex`, inside Control, and nowhere
else. A consumer that normalizes has forked this parser; the two will disagree,
and the disagreement surfaces as a false "the plan changed".

## Published facts

Nineteen types, all `.v1` — read `PUBLISHED_EVENT_TYPES` rather than keeping a
hand-written list.

## Status

**Built and validated, not adopted.** Pin `0.1.0a5` or later. `0.1.0a4` is
immutable and identity-verified and must never be pinned: it refuses a
correctly-supplied approval digest and reports the wrong version of itself
(`docs/CONTROL_EXCEPTIONS.md`, "0.1.0a4 is identity-verified AND unadoptable").
`0.1.0a3` is published and permanently unprovable.

Unlike its two siblings there is nothing to cut over *from*: the V6 slices were never merged. `EXTRACTION.toml` records the
two proofs the composition still owes — the claim/proof CHECKs against raw SQL,
and a concurrency rehearsal for the stable-verdict rule that a single-process test
cannot establish — and the obligation to **delete** the two abandoned V6 branches,
whose migration slots `main` has since reused.
