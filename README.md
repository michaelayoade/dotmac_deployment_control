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

## The browser surface

A contract-v2 `WebSurfaceContribution` (`DEPLOYMENT_CONTROL_SURFACE`) targeting
the kernel's existing `platform_admin` facet. The facet owns the `/platform`
prefix, the shell, the session policy and the authentication; this module
supplies four facet-relative routes, two navigation entries and its own
packaged templates, and authors none of those other things.

- **The screens.** The fleet list; one target's detail — desired against
  observed, reconciliation state, the server-derived canonical plan and its
  digest, plans with their approval standing and immutable decision reference,
  rollouts with their full attempt history, observation receipts; the plan
  proposal; and a fleet-wide arrival log for the reports that proved nothing and
  therefore belong to no target's page.
- **It declares no authentication.** The facet already authenticated the
  request. A second owner on the same route is not defence in depth — and the
  obvious candidate, `require_platform_admin`, is the BEARER guard, which inside
  a browser facet makes a valid cookie session fail the handler for want of an
  `Authorization` header. The actor is read from
  `dotmac_kernel.facet_principal`, the request-scoped projection of whoever the
  facet authenticated, declaring the PLATFORM plane so a tenant identity can
  never be attributed a fleet decision.
- **It builds no query.** Every read is a typed contract in `service.py`. A
  consuming assembly that wrote `select(DeploymentTarget)` would have taken a
  second read authority over tables it does not own.
- **The browser may never submit its own PlanDigest**, and that is a refusal
  rather than a convention. `refuse_client_supplied_digest` is declared on the
  router — so it covers every route in the surface, including the reads — and
  refuses both a field NAMED for a digest and a digest-SHAPED value in any
  field, in either encoding this module has ever issued. What the propose form
  does submit is `expected_desired_revision`: an immutable evidence coordinate
  this module issued, naming which desired state the operator was looking at.
- **Nothing is decided in a template.** Eligibility comes from
  `PlanProposalPreview.can_propose` and its `blocking_reasons`, both computed by
  the same `_plan_blockers` that `propose_plan` refuses with; drift, "never
  observed" and "identity proven" are all fields on frozen views. No ORM row
  reaches Jinja.
- **Design system.** Authored against `dotmac-ui`'s published `var(--dmui-*)`
  role tokens only. This distribution does not import `dotmac_ui` — the sibling
  guard forbids it — so the token vocabulary is declared in
  `tests/architecture/test_browser_surface_contract.py` as a closed set that
  ratchets in both directions, and no `.dmui-*` class is authored anywhere.

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

**Built and validated, not adopted.** Pin `0.1.0a7`, with `dotmac-kernel
>=0.1.0a100`. That is the newest PUBLISHED version — release run `33507951778`,
independently VERIFIED by run `33508897684` on 2026-09-01 — and it requires
`dotmac-kernel >=0.1.0a100` because `database_catalog.py` imports
`dotmac_kernel.product_database_catalog`, absent from the published `0.1.0a99`
wheel and present in `0.1.0a100`. `0.1.0a6` remains published, verified and
pinnable, against `dotmac-kernel >=0.1.0a98`.

Adopting a7 is not a dependency bump for a consumer still on kernel `a98`:
`a100` makes `ProductAssemblySpec.api_documentation` mandatory, so the move is
the ADR-0016 cutover. `docs/published-versions.json` carries that obligation on
a7's row.

The published artifact carries `mod_deploy`'s exact structure — seven platform
tables, 95 columns — through a source-owned
`ModuleDatabaseCatalogContributionV1`. That extent is proven by source tests,
NOT by the nine artifact canaries, which are unchanged from a6 and drive none of
it. It is not production-adoption evidence.

The tree has since moved past that: `dc_0003_execution_plan_binding` appends four
columns to `deployment_plans`, so the CURRENT declaration is seven tables and 99
columns. The 95 above is a fact about the published a7 wheel and stays as one.

Three published versions must never be pinned, and they failed three different
questions — the distinction is the record, so the reason is named rather than
collapsed into "bad":

- `0.1.0a3` is published and permanently **unprovable**: its evidence chain was
  never closed.
- `0.1.0a4` is immutable and **identity-verified and unadoptable**: it refuses a
  correctly-supplied approval digest and reports the wrong version of itself.
- `0.1.0a5` is immutable, verified on all seven properties, and
  **under-constrained**: it imports `dotmac_kernel.transactions`, first shipped
  in kernel `a98`, while declaring `>=0.1.0a77`. Its bytes and its behaviour are
  sound; its declaration is not, and a consumer that resolves a kernel inside
  the declared range gets a clean lock, matching hashes and a
  `ModuleNotFoundError` at container boot.

`docs/CONTROL_EXCEPTIONS.md` carries each disposition in full. A hash comparison
proves you got the published bytes; it cannot prove they import, which is why
the declared floor is now proven in both directions by CI's floor and mutation
lanes — and why the module that floor is declared for is DERIVED from the
package's own imports (`scripts/kernel_floor.py symbol`) rather than written
into the workflow, so that raising the floor moves the proof with it.

Unlike its two siblings there is nothing to cut over *from*: the V6 slices were never merged. `EXTRACTION.toml` records the
two proofs the composition still owes — the claim/proof CHECKs against raw SQL,
and a concurrency rehearsal for the stable-verdict rule that a single-process test
cannot establish — and the obligation to **delete** the two abandoned V6 branches,
whose migration slots `main` has since reused.
