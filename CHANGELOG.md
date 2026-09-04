# Changelog — dotmac-deployment-control

All notable changes to the `dotmac-deployment-control` distribution. This package
follows [Semantic Versioning](https://semver.org). Pre-1.0 (`0.x`, incl. this
alpha) the surface is still settling — a `0.MINOR` bump may carry breaking
changes, each called out here.

## Unreleased — the prestate discriminator

### Added

- `FailedSystemObservationDigestV1`, a READ-ONLY digest type for the value
  Foundation produces and Control signs. Named after the document it digests
  rather than after Control's `incumbent_prestate_digest` field, per
  Foundation's ruling: a digest named for a consumer's field would need
  renaming the moment a second consumer stored it elsewhere, with the bytes
  unchanged. It cannot construct, which enforces "Control implements no second
  canonicalizer" structurally rather than by discipline.
- `incumbent_prestate_discriminator` on `RecoveryGrantStatementV1` and
  `RecoveryGrantSubject`, inside the canonical bytes and therefore SIGNED. A
  digest alone is 64 hex characters and cannot say which encoding produced it;
  `incumbent_prestate_digest NOT NULL` proves only that a string exists.
- `PRESTATE_UNDISCRIMINATED` and `PRESTATE_UNKNOWN_DISCRIMINATOR`, distinct
  from `PRESTATE_MISMATCH`. Three refusals with three destinations: a
  historical row nobody can execute, a version this deployment does not have,
  and a host holding a different incumbent.
- `dc_0009_prestate_discriminator`, adding the column NULLABLE. `NOT NULL` with
  a default would make absence unrepresentable and recreate, one column over
  and in the same commit, the exact defect this repairs.

### Changed

- `verify_recovery_grant` checks the discriminator BEFORE the digest. Comparing
  the digest first would report "not the authorized prestate" for a value whose
  provenance was never establishable.
- The discriminator is deliberately NOT required at parse. A grant predating
  the term stays readable so it can be refused precisely as historical, rather
  than failing as a malformed document. Optionality is STATED
  (`_OPTIONAL_STATEMENT_KEYS`) rather than left implicit: the statement's key
  check compares the key set in both directions, so a term named in neither the
  required set nor an optional one is not tolerated but FORBIDDEN, and every
  grant carrying the new term would be refused as unexpected.
- The database catalogue advances to `dc_0009_prestate_discriminator`, nine
  revisions, eight tables and 134 columns — `recovery_grants` gains its
  nineteenth column, nullable, appended by `ALTER TABLE ADD COLUMN` rather than
  placed beside the digest it describes.

### Rename history — recorded here because Foundation's changelog does not carry it

Foundation's discriminator was renamed before anything pinned it. An earlier
spelling used `...incumbent_prestate...`, naming Control's FIELD; the published
identity names the DOCUMENT it digests. **The old spelling is obsolete and is
REFUSED, deliberately not aliased** — an alias would give one contract two valid
spellings, which is the defect the rename removed. A reader meeting the old
string in an archived transcript should conclude it is dead, not that both are
valid. `tests/unit/test_recovery_grant_prestate.py` proves the refusal is active.

### Note on Control's mirror

Control does not depend on `dotmac-deployment-foundation` — every
cross-repository coupling is cut at a value, which is what makes this module
independently releasable — so the identity is mirrored, not imported.
Foundation's frozen release canary asserts its identity strings, so the identity
cannot CHANGE silently. That protection is asymmetric: nothing in Control's CI
can detect a mirror that was WRONG WHEN WRITTEN, because Foundation is not
installed here. The planted cases are what catch a transcription error, and
nothing else does.

## 0.1.0a12 (published 2026-09-04) — recovery grants, and reads that reach a screen

Published by run `33854964978` from protected main `8e8342bcbefc`; independent
verify run `33855190724` fetched both artifacts by name, matched their recorded
digests, installed the wheel with its dependency graph, drove all fifteen
behavioural canaries, and only then wrote the annotated tag. Exact coordinates
and the adoption disposition are recorded in `docs/published-versions.json`.

### Added

- `RecoveryGrantV1`, a separately-signed document authorizing ONE recovery under
  the purpose `deployment_recovery`. It binds the bundle being restored from,
  the incumbent the target was on when that bundle was taken, and the window the
  restoration may run in — none of which a deployment authorization has a place
  for. There is no `operation` field: `schema` identifies the document and
  refuses any other before a field is compared, and `purpose` binds the signer,
  so a deployment authorization presented here is refused as a schema mismatch
  rather than as whichever field happens to be missing.
- `RecoveryStanding`, five answers that are not collapsed into "unavailable":
  `ABSENT`, `NOT_YET_VALID`, `EXPIRED`, `REVOKED` and `UNRESOLVED` (a grant
  exists and does not authorize THIS recovery). Each binding term — product,
  target, environment, recovery-plan digest, bundle digest, incumbent digest —
  is compared rather than merely required to be present, and carries its own
  refusal code, so an operator is not sent round the loop once per field during
  an incident. No path consults a deployment authorization: a dead deployment
  authorization is not weak recovery authority, it is none.
- `dc_0008_recovery_grants`, which stores the exact signed envelope as the
  authority. The product, environment and three digests beside it are a lookup
  projection and are never consulted to decide whether a grant authorizes
  anything, so a drifted lookup column can make a grant hard to FIND and cannot
  make a bad one VERIFY. Revocation is a state change — `revoked_at` withdraws a
  grant and the row stays, because a trail that erases its withdrawn entries
  cannot answer who revoked this and when.
- Four owner-computed read projections over the fleet — approval standing, the
  execution binding, operation executability, and the authorized image set —
  each answering by total function rather than by a write-path gate that raises
  on a historical vocabulary word.
- `ExecutionBindingStanding`, four members. `UNAUTHORIZED` and `DIVERGES` are
  separate because `proposed != authorized` reports an unapproved plan as one
  the executor was authorized differently for, and those send an operator to
  different systems. `UNBOUND` is the third a boolean loses: a `0.1.0a7` plan
  names no execution at all, and reporting a schema-era absence as a mismatch is
  the same false incident one shape up.
- A browser surface rendering every state each projection can answer, with
  explicit branches rather than truthiness — `{% if value %}` reads `False`,
  `None` and `()` as one thing, and `{% for x in value or () %}` merges "nobody
  declared a set" with "this authorizes no image".
- An anti-rot ratchet over `dataclasses.fields` for both read views: each field
  is rendered through its bound name or exempt with a reason on the line, and
  the exemption count is two-directional.
- Two canaries in the environments that can see them. The installed-wheel canary
  RENDERS the shipped macros and requires each state to render distinctly —
  package data is the only part of this distribution with no `__version__`, so a
  wheel carrying an older `_macros.html` passes every check that counts files.
  It runs from a working directory that is not a checkout and states first that
  the naive relative path finds nothing there. The PostgreSQL canary proves the
  correlated standing subquery resolves on the real dialect, returns all four
  states, and reads the plans table exactly once for a page of any size.

### Changed

- Authorizing an operation the executor cannot honour is refused at the
  authorization, not discovered at dispatch.
- A recovery may not be `approval_exempt`, which deployment authorizations
  accept. An exempt recovery is a destructive act with no approval evidence, and
  approval evidence is one of the things this grant exists to bind — a
  deliberate tightening.
- The database catalogue advances to `dc_0008_recovery_grants`, eight revisions,
  with `recovery_grants` declared in `manifest.platform_tables` and joining both
  `TABLES` and `MUTABLE_TABLES` in the isolation canary across all seven
  privileges.
- Fifteen behavioural canaries run against the installed wheel, up from
  fourteen.

## 0.1.0a11 (published 2026-09-03) — signed dispatch attempt

Published by run `33802000337` from protected main `98b2a257f418`;
independent verify run `33802164085` fetched both artifacts by name, matched
their recorded digests, installed the wheel with its dependency graph, drove
all fourteen behavioural canaries, and only then wrote the annotated tag.
Exact coordinates and the adoption disposition are recorded in
`docs/published-versions.json`.

### Added

- `DispatchEnvelopeV1`, a provider-neutral Control-to-executor signed document
  whose canonical statement binds the exact verified authorization envelope,
  its signer identity and Control version, execution sequence, concrete attempt,
  rollout, target, operation, release, authorized images and all three digests.
- A typed refusal when the dispatch signer reuses the authorization signer's
  physical public key, even through a correctly-shaped dispatch adapter.
- Purpose-specific `DispatchSigner` and `DispatchVerifier` protocols. Their
  identity and method names are structurally distinct from both authorization
  and target-observation keys; Control selects no provider or algorithm.
- `dc_0007_signed_dispatch_envelope`, which stores the exact envelope on its
  append-only attempt. Pre-a11 attempts remain readable with a null value; new
  dispatches refuse to return executable intent without signed evidence.
- An installed-wheel canary that verifies the signed dispatch against its exact
  authorization, proves idempotent replay returns identical stored bytes, and
  refuses an `attempt_no`-only mutation, protocol crossing and physical-key
  purpose reuse.

### Changed

- `dispatch_attempt` requires a dispatch signer and signs the attempt inside the
  same idempotent transaction that creates it. `DeliveryIntent` carries the
  signed envelope and no stored unsigned `attempt_no`; the compatibility
  property derives that number only from the signed statement.
- Replaying a pre-a11 dispatch idempotency record now returns a typed refusal
  naming the unsigned historical attempt; malformed, mixed and unknown result
  shapes are refused instead of surfacing an untyped lookup error.
- The database catalogue advances to `dc_0007_signed_dispatch_envelope`, seven
  tables and 115 columns.

### Compatibility

- Published a10 authorization and execution-observation bytes are unchanged.
  This is an additive successor contract, not a rewrite of either published
  schema. Callers adopting a11 must inject a third, dispatch-purpose signer and
  verify the dispatch envelope before executing it.

## 0.1.0a10 (published 2026-09-03) — signed execution result

Published by run `33767109015` from protected main `4a56f5836cab`; independent
verify run `33767371612` fetched both artifacts by name, matched their recorded
digests, installed the wheel with its dependency graph, drove its behavioural
canaries, and only then wrote the annotated tag. Exact coordinates and the
adoption disposition are recorded in `docs/published-versions.json`.

### Added

- **`record_observation` takes ONE bounded raw byte input.** The earlier a10
  shape took a parsed envelope beside an `ObservedState` carrying
  `raw_body`/`raw_body_digest` — two inputs that had to agree, held apart so
  nothing forced them to. Control could verify envelope A while storing
  caller-supplied bytes B, with only a field-by-field comparison bolted between
  the parameters standing in the way. The repair is single-input BY
  CONSTRUCTION: `RecordObservationCommand.observation` is the exact wire
  bytes, Control derives the digest itself (over the FULL body, before any
  truncation), parses those bytes with `parse_bytes` (duplicate JSON keys and
  non-JSON numbers refused, because two readers must never read two reports out
  of one signature), verifies those bytes, and stores those bytes — verbatim,
  even when they are not the rendering Control's own encoder would produce.
  `ObservedState` is REMOVED with the split: there is no projection type left
  for a caller to contradict the body through, no field for a signature
  outcome, an identity, or a digest, and `signed_report_mismatch` is gone from
  the disposition vocabulary because the disagreement it recorded is now
  unrepresentable. Covered by mutation on every path Michael named: malformed,
  unknown key, bad signature, exact replay, changed-byte conflict — plus the
  two the single input newly makes provable, non-canonical wire bytes stored
  exactly as received and an oversize body truncated-stored with its digest
  taken first over everything.
- **The typed `recover` operation.** The closed vocabulary grows its
  coordinated third member — `deploy`, `rollback`, `recover` — for
  post-migration restoration. A RECOVER is neither a deploy (it converges on
  state already authorized once) nor a rollback (it does not return to a
  previous release; it re-establishes the current one), and an operator
  triaging an authorization trail needs those to be three different words
  because they are three different consent conversations. Added as exactly the
  coordinated change `operations.py` says a new member must be, with the
  Foundation's a5 built against the same three-member vocabulary.

- `AuthorizationEnvelopeV2`, adding the `deployment_authorization` key purpose
  and the installed Control distribution version to the signed statement. The
  version is derived inside Control and cannot be caller-supplied.
- `ExecutionObservationEnvelopeV1`, a provider-neutral signed target result
  binding the exact authorization bytes, authorization and rollout identities,
  the per-target execution sequence and attempt, target, operation, release and
  exact image set, all three plan digests, observed spec/revision/runtime,
  outcome and timestamp.
- Purpose-specific target observation signer/verifier protocols whose methods
  and identity type cannot be satisfied by the authorization signer by accident.
- `dc_0006_observation_key_identity`: typed target verification algorithm and
  purpose, immutable rollout execution sequences, and target/receipt execution
  high-water coordinates. The catalogue advances to seven tables and 114
  columns.

### Changed

- `record_observation` verifies against the exact enrolled public key, derives
  the proven target from that credential, and compares every caller projection
  and authorization term. Eligibility and authorization expiry use Control's
  receipt clock; a target cannot backdate itself into standing.
- The first eligible, verified, attributable envelope establishes the canonical
  receipt even when its verdict is a quarantine. Exact bytes replay the original
  verdict; the same report id with different bytes conflicts.
- Target, credential and plan rows serialize in one lock order. The signed
  `(execution_sequence, attempt_no)` coordinate advances a target monotonically:
  delayed reports are retained without regressing newer state, and a reused
  coordinate with different substantive state is refused.
- An observed desired revision is taken only from the exact authorized plan and
  only when the observed spec digest matches its frozen spec. Equal content in a
  later plan cannot borrow an earlier execution, and a mismatched observed spec
  remains visible as drift rather than being attributed to the authorized
  revision.
- Authorization issuance bytes and rollout execution sequence are immutable at
  the database boundary. Transport settlement and signed target execution
  evidence remain separate facts.
- The installed-wheel observation canary replaces the a6 conflict-savepoint
  canary: the service no longer imports that kernel helper now that target-row
  locking makes the old absent-receipt race unreachable. The replacement drives
  acceptance, exact replay, changed-byte conflict, enrolled-key substitution and
  physical-key purpose reuse against the installed artifact.

### Compatibility

- V1 authorizations remain parseable as historical documents but are not
  silently promoted to V2. New service lookups and dispatch require V2 so a
  missing purpose or Control-version binding cannot be invented by a reader.

## 0.1.0a9 (published 2026-09-02) — portable authorization

Published by run `33686171205` from protected main `b8427af26101`; independent
verify run `33686335734` fetched both artifacts by name from the registry,
installed the wheel with its dependency graph, ran the behavioral canaries and
only then wrote the annotated tag. Exact package digests and the human adoption
disposition are recorded in `docs/published-versions.json`. `0.1.0a8` remains
published, verified and pinnable; it simply lacks this release's contracts.

### Added

- `DescriptorDigestV1`, a received-only Foundation descriptor identity. A
  proposal must carry it, and Control freezes it inside the canonical plan
  snapshot. A descriptor-only mutation therefore moves `plan_digest`; Control
  neither imports nor reconstructs the Foundation's canonical document.
- `AuthorizationEnvelopeV1`, a provider-neutral portable authorization whose
  canonical signed statement binds authorization and approval identity, target,
  operation, release, canonical image set, Control plan digest, Foundation
  descriptor digest, Foundation execution-plan digest, approval standing,
  issue/expiry instants, schema version and signer identity/algorithm.
- Injected `AuthorizationSigner` and `AuthorizationVerifier` protocols. The
  signer declares immutable key identity and algorithm before signing, so both
  are inside the signed bytes; a returned identity mismatch is refused. Control
  stores no private key, chooses no cryptographic provider and does not reuse
  the target-to-Control observation signer.
- Typed approved-plan lookup refusals for an absent descriptor, a descriptor
  mismatch, an absent/invalid/unresolved envelope, and an absent verifier.
- `dc_0005_portable_authorization`, appending the immutable envelope to the
  rollout record. Revocation blocks lookup and dispatch but never rewrites the
  historical issuance bytes.

### Changed

- `ProposePlanCommand.descriptor_digest` is required and received-only.
  `ApprovedPlanAuthorization` and `DeliveryIntent` return the identical frozen
  value, separately from `plan_digest` and `execution_plan_digest`.
- `request_rollout` requires an injected signer and an explicit expiry;
  `dispatch_attempt` requires an injected verifier. A live Control database row
  is no longer representable as portable signed authorization.
- The database catalogue advances to `dc_0005_portable_authorization`, seven
  tables and 105 columns.

### Security

- Every signed field has a mutation test; changing any one invalidates the
  signature. Image ordering is canonical (order does not change meaning) while
  membership or digest mutation does. Missing signatures, unsupported versions,
  expiry, not-yet-valid issuance, non-standing approval and signer-identity
  substitution are distinct refusals.
- Transport settlement remains separate from signed authorization: settling an
  attempt changes delivery evidence and cannot replace or rewrite the envelope.

## 0.1.0a8 (published 2026-09-02) — the record stops being remembered

Published from protected main, independently verified and tagged. The release
recorder opened PR #28 and the completed coordinates are in
`docs/published-versions.json`.

### Added

- **The release recorder**, ported from `dotmac_starter_mt` without redesign:
  `.github/actions/release-recorder-token` (byte-identical to the Starter's) and
  `scripts/open_release_record_pr.sh`, plus `scripts/write_release_record.py`
  for this repository's two record files.

  `verify-release.yml` already computed every mechanical field into
  `observations.json`, already wrote the tag on a VERIFIED verdict — and ended
  by printing `::notice::OWED`, **a notice nothing reads**. The follow-up was
  missed twice: `0.1.0a4`'s ledger row said `never-published` and outlived its
  own publication by six hours, and `0.1.0a7`'s absence turned protected `main`
  red for every open pull request. a4 failed silently; a7 failed loudly at
  innocent people. The verify run now opens the record itself, straight after
  tagging, with `if: always()` so a later failure cannot leave a tag with no
  record.

- **COORDINATES ONLY, and it is checked.** The writer opens exactly
  `docs/publication-ledger.json` and `docs/published-versions.json`; the opener
  compares the real `git diff --name-only` against the same two BEFORE staging
  and refuses anything else. Machine-owned and written: version, tag, tag
  object, peeled commit, release and verify run ids, source repository, index,
  status, per-filename sha256, supersedes, declared kernel floor. Human-owned
  and never written: `pinnable`, `superseded_by`, `unpinnable_reason`, the
  release notes — and the release floor's own literals, because a bot writing
  the guard's positive control is a bot editing the constraint that binds it.

- `tests/architecture/test_every_release_tags_a_record.py`, ported and trimmed:
  a tag writer is DISCOVERED rather than listed, must open a record after the
  tag with `if: always()`, and the App token must declare exactly
  `permission-contents: write` and `permission-pull-requests: write`.

### Changed

- The record is written from the REGISTRY's bytes rather than the build's — the
  same values, since verification already proved exact equality in both
  directions, but the stronger of two identical statements: it is what a
  consumer will fetch. The writer refuses if they disagree.
- `observations.json` is copied to `${RUNNER_TEMP}` before the recorder runs.
  The recorder rebinds git with a second `actions/checkout`, whose default
  clean removes untracked files — the evidence the record is written from must
  outlive that checkout.

### The recorder identity's three proofs are observed, not inferred

`.github/workflows/recorder-identity-proofs.yml` (dispatch-only, publishes and
records nothing) observes what the configuration merely implies:

1. the installation resolves **this** repository — access, not mere
   installation, since an App can be installed on an account and still not
   reach a given repository;
2. it can create a branch and open a pull request, demonstrated end to end;
3. it **cannot** put a commit on protected `main`, and holds no administration
   authority over it.

The third is the one worth having. `enforce_admins: true`, no push-restriction
allowlist and `can_approve_pull_request_reviews: false` together imply it — and
configuration implying a property is not the same as observing it. An identity
that *can* bypass protection is a different risk from the one that was granted,
and the only way to know which one you have is to try.

Both negatives are safe by construction. The push attempt is a fast-forward of
an **empty** commit, so an unexpected success leaves `main` carrying no content
change — loud, trivially revertable, and itself the finding. The administration
probe is a **read** of branch protection rather than a write: a malformed write
returns 422 and proves nothing about authority, while a well-formed one that
succeeded would have disabled protection on `main`. Reading protection requires
administration rights, so a refused read is the strictly stronger evidence and
cannot damage anything whichever way it answers.

The workflow's own token is granted `permissions: {}`. Every observation is made
with the App's installation token, or it is not a statement about the App.

### One deliberate divergence from the Starter

The Starter's script ends `gh pr merge --auto --squash`; this one does not, and
the reason is specific to this repository. A coordinates-only record is a
correct record of what was published and an **incomplete** record of what it
means: recording a version raises the derived release floor, and the floor's own
literals — its positive control, its refusal strings, two parametrize lists —
plus the disposition are human-owned and land on the same branch afterwards.

Auto-merge would then do the wrong thing at the worst moment. It stays dormant
while the branch is red for the missing literals and fires the instant somebody
pushes them, merging the disposition in the same breath as the coordinates with
nobody having read either. `required_approving_review_count` on this repository
is 0, so nothing else would have stopped it.

The recorder opens the record and never merges it, and
`test_the_recorder_opens_the_record_and_never_merges_it` asserts the absence so
the divergence stays deliberate rather than becoming drift.

### Not automated, and recorded rather than implied

Two entries in `docs/CONTROL_EXCEPTIONS.md`: the recorder App is not yet
installed on this repository (so the loud `GITHUB_TOKEN` fallback is in force),
and a coordinates-only pull request is RED until a human adds the floor
literals and the disposition. The recorder removes the bookkeeping that was
forgotten twice; it does not remove the judgement.


## Unreleased — a verifiable approved plan: the image set, and a read API

No version is allocated and nothing is published here. `0.1.0a7` remains the
published, tagged and VERIFIED release; the browser surface (#18), the execution
plan binding (#22) and this change all wait on the shared release-recorder hold.

**Why this exists.** Two gaps, both established by the Observability lane
reading this package's code rather than by supposition, and both of which made
a promotion receipt unverifiable:

1. **This module's plan record carried no image field.** The images a deployment
   runs sat inside `desired_spec`, which this module declares OPAQUE and never
   interprets. So a consumer checking that what ran was what was approved had to
   be TOLD the authorized set by whoever was asking it — its `authorized_images`
   was caller-supplied, and the comparison proved a caller consistent with
   itself.
2. **There was no read API for an approved plan.** No fetch-by-digest, no
   verify-approved: only the write path, which compares an expected digest while
   an approval is being recorded. A promotion was HANDED an authorization and
   could not confirm one.

**The property that carries the repair: the authorized image set is INSIDE the
plan digest, never beside it.** An approval binds `plan_digest`; a set stored in
a sibling column is a set an `UPDATE` can change while the digest — and the
approval, and every screen — sit still. So there is deliberately no
`deployment_plans.authorized_images` column, and
`tests/unit/test_authorized_image_set.py` plants an image change, requires the
digest to move, and then reconstructs the rejected "beside the digest" shape to
show the same plant moving nothing — which is the only way to know the first
assertion is testing anything.

### Added

- **`AuthorizedImage` and the canonical image set**
  (`dotmac_deployment_control.images`): three typed terms — `service`,
  `repository`, `digest` — matching what a consumer's receipt actually compares.
  Pinned by DIGEST and never by tag, because a tag is a mutable pointer and a
  tag-pinned set authorizes whatever the tag names later under an approval
  nobody re-ran. Canonically ordered (a set has no order, and two orderings must
  not be two authorizations) and duplicate-refusing (two digests for one service
  is a question with two answers, and choosing either would be inferring an
  authorization).
- **`ImageDigestV1`** — a fourth digest type, added deliberately and NOT a
  fourth plan digest: its subject is an OCI image manifest, so it takes part in
  no plan/spec/execution comparison and being a distinct dataclass is what makes
  that structural. It inherits the READ-ONLY base for the plainest reason
  available — Control does not build images and holds none of the bytes — so
  `ImageDigestV1.over_json(...)` is an `AttributeError`.
- **`find_approved_plan` / `require_approved_plan`** — the read-only lookup. It
  writes nothing, derives nothing, and returns what was frozen; in particular it
  hands back the Foundation's `execution_plan_digest` without re-deriving it,
  which remains structurally impossible.
  - `find_approved_plan` is TOTAL: every path returns an `ApprovedPlanLookup`
    carrying exactly one of an authorization or a typed refusal. It is FALSY for
    every refusal, so `if find_approved_plan(...)` cannot pass on a no — a plain
    dataclass would have been truthy for all of them.
  - `require_approved_plan` raises `ApprovedPlanRefusedError` carrying the same
    typed refusal, for a caller that must not proceed without an authorization.
    One decision, one function, no second copy of the rules.
- **Eight typed refusal codes** (`ApprovedPlanRefusalCode`), each a different
  finding with a different reader, each observed on its own in
  `tests/unit/test_approved_plan_lookup.py`: `digest_unreadable` (an encoding
  fault in the caller, naming no plan — the `0.1.0a4` lesson applied to the read
  path), `digest_unresolved` (a statement about this database),
  `not_approved`, `approval_revoked`, `approval_standing_unrecorded`,
  `execution_binding_absent`, `image_set_undeclared` and
  `execution_plan_mismatch`.
- **`revoke_plan_approval`** and `deployment.plan.approval_revoked.v1`.
  Revocation is answered by the LOOKUP a consumer already calls, not by a
  separate query it has to remember: a consumer told "yes" for a revoked plan is
  worse off than one with no API, because the one with no API asks a person.
- **`ApprovalDecisionStatus`** (`dotmac_deployment_control.approvals`) — a closed
  `granted` / `revoked` vocabulary. Deliberately not a second copy of the
  approvals lifecycle: Control holds the standing of a decision it was handed,
  and every other state belongs to the system that owns it.
- **Five columns** (`dc_0004_authorized_image_set`): `deployment_targets
  .desired_images`, and `deployment_plans.approval_decision_status` /
  `approval_revoked_at` / `approval_revocation_ref` /
  `approval_revocation_reason`. All nullable with NO server default — `'[]'`
  would make every existing target claim to authorize no images (a declaration,
  not an absence) and `'granted'` would make every previously approved plan
  assert a standing decision nobody recorded.

### Changed

- `DesiredDeployment` carries `images`; `ApprovalEvidence` carries
  `decision_status`, which `approve_plan` now REQUIRES. Reaching `approve_plan`
  is not evidence that a decision granted anything — that is the same inference
  a defaulted `operation` makes — and a revoked decision replayed there is
  refused rather than recorded as an approval.
- `request_rollout` refuses a plan whose approval was revoked. A second gate and
  not a redundant one: the plan's `status` still reads `approved` after a
  revocation, deliberately, because it WAS approved and that is history.
  `PlanStatus` gains no member, so the standing has exactly one writer.
- `plan_snapshot` carries `authorized_images`, unconditionally — present as
  `null` when nothing was declared, so "predates the field" and "declared
  nothing" are one state rather than two encodings of one absence.
- `PlanView` surfaces the approval's standing and its withdrawal, and projects
  the frozen image set out of the snapshot. A surface showing only `status`
  would render a revoked authorization as an approved plan.
- The published catalogue is now **seven tables and 104 columns** with lineage
  head `dc_0004_authorized_image_set`. The canary literal in
  `scripts/artifact_canaries.py` moved with it; the two are held in sync in both
  directions by `test_the_canary_literal_and_the_declaration_do_not_drift`.

### Not changed, and stated because it is the property most easily lost

`ExecutionPlanDigestV1` still inherits `_ReceivedSha256Digest`, so
`over_json` is still an `AttributeError`. The new lookup RETURNS that value,
which is exactly the point at which somebody would be tempted to re-derive it;
`test_the_lookup_returns_the_frozen_digest_and_still_cannot_compute_one` asserts
both halves together.

Revocation deliberately does not reach an already-dispatched rollout, and does
not quarantine a report that arrives after it. Rule 3 stands: every arrival is
recorded, and what actually ran is evidence regardless of what happened to the
authorization afterwards.


## Unreleased — the execution plan binding, and the first receipt it makes possible

No version is allocated and nothing is published here. `0.1.0a7` remains the
published, tagged and VERIFIED release; the browser surface (#18) and this
change both wait on the shared release-recorder hold.

**Why this exists.** Platform CP authorizes a deployment and the Deployment
Foundation executes it, and until now the two could not exchange a receipt at
all. Three independent reasons, all measured:

1. Platform CP's receipt carried 17 fields; the Foundation's parser required
   exactly 9 and was strict about both unknown and missing keys.
2. **The digests disagreed about what is hashed.** Control's `plan_digest`
   hashes the desired-state snapshot WRAPPED IN SIX SIBLING KEYS; the Foundation
   hashes its rendered execution plan ALONE. Both use canonical JSON with sorted
   keys and sha256, so they agree completely about SERIALIZATION and disagree
   about PAYLOAD — they can never be equal, and both implementations read as
   correct in review.
3. The Foundation refuses any receipt whose `operation` is not `deploy` or
   `rollback`. At `0.1.0a7`, `operation` appeared in this package only as an
   English word inside docstrings: no column, absent from the seven-table
   catalogue, from all eight `StrEnum`s, from `DeliveryIntent` and from all 19
   fact types.

The middle term is `ExecutionPlanDigestV1 = sha256(canonical
FoundationExecutionPlanV1 bytes)` — NOT the descriptor digest, NOT the
authorization-envelope digest, and NOT Control's own `PlanDigestV1`. The
Foundation owns that type and its canonicalization. Control owns the closed
operation vocabulary and holds both values on its plan model, receiving,
freezing and signing them.

### Added

- **A closed operation vocabulary** (`dotmac_deployment_control.operations`):
  `deploy` and `rollback`. `require_operation` refuses anything else —
  `None`, a non-string, the empty string, an unknown word, and a case variant of
  a known one. Never defaulted, never coerced, never inferred from a diff or a
  command name. Deliberately the one closed vocabulary in a module whose other
  vocabularies are open by ADR-0008: this one is a word Control says to an
  executor that has already published which words it accepts, so an open set
  would let Control sign an authorization that can never produce a receipt.
- **`ExecutionPlanDigestV1`** — a RECEIVED-ONLY digest type. It does not inherit
  `over_json`, so `ExecutionPlanDigestV1.over_json(...)` is an `AttributeError`
  rather than a second canonicalization discovered in production. Its only
  constructor is a STRICT `parse`: a non-canonical spelling is REFUSED rather
  than rewritten, so the text Control stores is byte-identical to the text it
  was handed. Refusing is not normalizing. There is no `parse_a4_bare_hex`,
  because this value never existed in `0.1.0a4` and tolerance would mean
  reshaping somebody else's digest.
- **Four columns on `deployment_plans`** (`dc_0003_execution_plan_binding`), in
  two pairs: `operation` / `execution_plan_digest` are the PROPOSAL, frozen at
  `propose_plan`; `authorized_operation` /
  `authorized_execution_plan_digest` are the AUTHORIZATION, written once at
  `approve_plan`. Two pairs because the acceptance rule is a THREE-term one, and
  one stored pair plus the report is a two-term gate wearing a three-term name.
  All four nullable with NO server default: nullable because `0.1.0a7` rows
  predate the contract, no default because a default is an inference.
- **Three new observation dispositions**, because a failed binding is three
  findings with three readers: `execution_plan_mismatch` (the executor ran a
  plan nobody authorized), `operation_mismatch` (the right plan as the wrong
  kind of act — invisible to a digest-only check, which is why DEPLOY and
  ROLLBACK are separately authorized), and `unbound_report` (the arrival named
  no authorization at all — an absence, not a contradiction).
- `ExecutionPlanBindingError` and `OperationRefusedError`, neither a subclass of
  the other and neither an `ApprovalRefusedError`. Same discipline `0.1.0a5`
  established for `DigestEncodingError`: "I cannot read what you sent", "you
  authorized a different execution" and "the plan moved under your approval"
  are three findings for three people.
- `tests/architecture/test_control_cannot_recompute_the_execution_plan.py` —
  the structural property, held as a fact about the class graph and the source
  rather than as a convention, each non-existence claim paired with the positive
  control that stops it passing over an empty set.

### Changed

- `ProposePlanCommand` requires `operation` and `execution_plan_digest`.
  `ApprovalEvidence` and `ObservedState` carry the values they bind;
  `DeliveryIntent` carries the authorized operation and execution plan so the
  executor can recompute before running and report the same values back.
  `PlanView` surfaces both pairs.
- `request_rollout` REFUSES a plan carrying no execution plan binding. An
  unbound plan cannot produce a receipt, and dispatching one would put an
  execution into a running system that this control plane could never
  acknowledge — the rollout would time out and read as a transport fault. This
  is where `0.1.0a7` plans stop.
- The published catalogue is now **seven tables and 99 columns** with lineage
  head `dc_0003_execution_plan_binding`. The canary literal in
  `scripts/artifact_canaries.py` moved with it; the two are held in sync in both
  directions by `test_the_canary_literal_and_the_declaration_do_not_drift`.
- The read-contract property narrowed rather than lapsed. It said
  `ProposePlanCommand` carries no digest field at all; it now says exactly ONE
  digest field exists on the whole input surface and it is exactly the one whose
  type cannot be computed here. Both halves are asserted, because either alone
  is satisfiable by the wrong shape.

### Removed, in effect

- **The admin surface can no longer propose a plan.** `POST
  /deployments/{id}/plans` now returns 400 in the module's own words.
  `refuse_client_supplied_digest` rejects a digest by SHAPE whatever the field
  is called — correctly, because a browser is not the Deployment Foundation and
  has rendered no execution plan — so this surface cannot construct a bound
  proposal. That is the architecture rather than a regression: a proposal that
  can produce a receipt is made by Platform CP's composition adapter, and an
  operator's part of the flow is upstream in the desired state. The operator MAY
  still declare the `operation`; it is a word, not a digest.
- The old POSITIVE CONTROL for the digest refusal — "the same submission without
  a digest succeeds" — is replaced by a stronger one: a clean submission is
  refused with DIFFERENT words, having reached the handler. Distinguishing two
  refusals proves the digest guard fires specifically, where distinguishing a
  refusal from a success only proved the surface accepts something.

## Unreleased — the catalogue canary a7 shipped without

**CLOSED for `0.1.0a7` by supplemental verify run `33517740717`** (2026-09-01),
dispatched from main `61611da8` against the SAME published bytes. VERIFIED on
all seven properties with ELEVEN canaries; `database_catalogue_as_published` and
`catalogue_digest_binds` passed against the wheel the registry served, reporting
`7 tables / 95 columns` and
`sha256:92be901f92ec2a2861d2b44e3693bb7645e84d9d60c14d7caeb6c12051abb01e over
21399 canonical bytes`. Nothing was published; the tag reached `tag_once`'s
ALREADY notice and was not written. a7's original record is appended to, never
rewritten — run `33508897684` still drove nine canaries and none of them the
catalogue, and that stays true of that run.

**One constraint a consumer must read before adopting by digest:** the digest
moves with the resolved kernel, not with this wheel. See a7's
`supplemental_verify_runs[0].adoption_constraint`.

No published artifact changes here, and no version is allocated. `0.1.0a7` is
published, tagged and VERIFIED, and stays exactly where it is.

**The gap.** a7's headline is a source-owned
`ModuleDatabaseCatalogContributionV1` publishing `mod_deploy`'s exact seven
platform tables and 95 columns. It was verified on seven release properties and
nine behavioural canaries — a6's exact set. **No canary drove the catalogue.**
The extent was proven only by source tests on the release commit, so the
artifact proved nothing about the contract the artifact exists to ship: a proof
of one question read as a proof of another, which is the a4 shape one level up.

### Added

- `database_catalogue_as_published` — a verifier-only canary that drives the
  INSTALLED distribution's catalogue: module identity (document schema and
  scope, distribution name and version, module code and release version,
  `mod_deploy`, the `dc_0002` lineage head), all seven table identities in
  canonical order, all 95 columns by name, physical ordinal, PostgreSQL type
  identity AND rendered spelling, nullability, generation and server default,
  and every table's plane and owner. Compared element-by-element against
  literals, because `len(tables) == 7 and len(columns) == 95` passes against a
  catalogue holding seven wrong tables.
- `catalogue_digest_binds` — the canonical digest is the sha256 of the document
  the artifact serialises (recomputed with `hashlib`, not read back from the
  property that produced it), the bytes round-trip through the kernel's strict
  parser, and a one-byte change to a server default is REFUSED against that
  digest. A digest a consumer adopts by has to bind. No literal digest is
  pinned: the document carries the release version, so a literal would go stale
  every release; the release's digest belongs in its record.
- `scripts/plant_catalogue_mutation.py` and `scripts/assert_catalogue_refusal.sh`
  — two planted mutations, in two environments, each with its own refusal. A
  table nobody declared (`rollout_attempts` → `rollout_events`, edited in BOTH
  the contribution and the manifest so the artifact stays internally coherent
  rather than failing at import) and a column right by name and wrong by type
  (`deployment_plans.plan_digest` back to the `dc_0001` width `character
  varying(64)`). The assertion is not satisfied by any red run: it requires the
  refusal to name what moved, requires `database_catalogue_as_published` to be
  the canary that refused, and requires `installed_not_source` and
  `conflict_savepoint_executes` to still PASS — which is how "the catalogue
  canary refused a lie" is told apart from "the mutated package no longer
  imports".
- The canary runner now prints `sys.path` and this interpreter's install
  directories. The absence of a checkout import is evidence, so it belongs in
  the run's own output rather than only inside a refusal that fires too late.

### Added — the operator's browser surface

**NOT in `0.1.0a7`.** These entries were authored while a7 was the pending
version and a clean textual rebase filed them under a heading that had since
become `RELEASED`. a7 was published, verified twice and tagged without the
browser surface; a changelog claiming otherwise is a published release
describing a feature it does not contain, which no amount of correct merging
makes true. They belong to whatever version ships them, and no version is
allocated yet.

- **The operator's browser surface**, as a contract-v2 `WebSurfaceContribution`
  targeting the kernel's existing `platform_admin` facet. Four facet-relative
  routes and two navigation entries: the fleet list, one target's detail (desired
  and observed state, reconciliation, the server-derived canonical plan and its
  digest, plans with their approval standing and immutable decision reference,
  rollouts with their full attempt history, and observation receipts), the plan
  proposal itself, and a fleet-wide arrival log for the reports that proved
  nothing and therefore belong to no target.
- **A refusal that makes "the browser may never submit its own PlanDigest" a
  property rather than a convention.** `ProposePlanCommand` still has no digest
  field and `PlanProposalPreview` still takes no input, but both of those are
  absences — nothing fails when somebody adds a field, and nothing has ever
  watched them hold. `refuse_client_supplied_digest` is declared on the ROUTER,
  so it covers every route in the surface, and it refuses in two directions: by
  field NAME (`plan_digest`, `content_digest`, …) and by VALUE SHAPE (`sha256:`
  canonical or `0.1.0a4` bare hex, in any field, including one the surface
  legitimately reads). Planted requests in
  `tests/unit/test_deployment_control_browser_surface.py` observe it firing on
  all three routes a digest could arrive by, and a positive control shows the
  same submission without a digest producing a plan whose digest the server
  derived.
- `ProposePlanCommand.expected_desired_revision` — the immutable evidence
  coordinate plan creation now runs from. It is an integer THIS MODULE issued,
  naming which desired state the operator was shown; if the desired state moved
  between the render and the click, `propose_plan` refuses rather than freezing
  a plan nobody read. It is the opposite kind of value from a digest: a
  coordinate identifies WHICH state, a digest would name the thing the approval
  is checked against.
- Typed read contracts for everything the surface renders, all in the module's
  own service layer so no consuming assembly builds a query over these tables:
  `plans_for_target`, `rollouts_for_target`, `observation_log`,
  `observation_receipts`, and the `ObservationAttemptView` /
  `ObservationReceiptView` projections behind the last two. The projections
  exist because a presentation surface must never be handed a live ORM row, and
  they deliberately carry a body DIGEST and never the stored bytes.
- `PlanProposalPreview` gained `canonical_plan_json` (the exact serialization the
  digest is taken over, so the screen and the hash are one artefact),
  `blocking_reasons` and `can_propose`. The last two come from `_plan_blockers`,
  which is now the single owner of the target-state half of `propose_plan`'s
  refusals: the write path raises the first and the preview shows all of them,
  so a screen never works eligibility out for itself.
- `python-multipart` as a DEV dependency only. Starlette's `Request.form()`
  asserts the library is importable BEFORE it looks at the content type, so even
  an `application/x-www-form-urlencoded` body needs it — and the kernel's own
  platform surface reads forms the same way while deliberately not depending on
  it, because form parsing is an assembly concern (the vendor control plane pins
  it itself). It is in the dev group so this repository can drive its own surface
  with real requests, and it must never become a runtime dependency of a
  distribution whose defining property is that it performs no I/O.
- A ninth artifact canary, `web_surface_ships_its_templates`. The templates ship
  as package data and the kernel validates that directory with `is_dir()` while
  building the surface graph — at the CONSUMER's startup. A wheel carrying
  `web.py` and not `templates/` imports perfectly, passes every other canary,
  and composes nowhere; that is the `0.1.0a5` failure shape in different
  clothes, so it is proven against the built artifact rather than this tree.

### Changed — the operator's browser surface

- The surface renders timestamps as explicit UTC through its own `moment(...)`
  context helper rather than the kernel's `local_datetime` / `local_date`
  filters. Those resolve TENANT display settings and fall back to
  `default_display()`, which reads the `display` setting specs — and this is the
  platform plane, where there is no tenant and where an assembly that never
  registered those specs (the vendor control plane has not) would get a
  `KeyError` out of the fallback and a 500 out of every dated screen. A fleet
  operator is also the reader least served by a localized stamp.

### Not covered

The pre-merge lane runs against a wheel built on the runner. Until a
`verify-release` run of the PUBLISHED `0.1.0a7` reports these canaries passing,
a7 carries no artifact-level catalogue proof — see
`docs/CONTROL_EXCEPTIONS.md`.

## 0.1.0a7 — RELEASED 2026-09-01, verified on seven properties with nine canaries

Published by run `33507951778` from protected main `6b1ce371`; independently
verified by run `33508897684`, which wrote the tag on a VERIFIED verdict.
Wheel `b9534111a197ce818c3d0bac166f3a5a2857dc3ceb937cc9e53452e3d7ffcfb0`, sdist
`d5ca7ae82469f57ae0b9443f579be5316dc3c31004a791a38c0bf5200f9e9b51`.

**Both halves of the floor mutation are now derived, not written down.** On the
release commit the lane derived `0.1.0a99` from the index as the newest kernel
the floor excludes and `dotmac_kernel.product_database_catalog` as the module
that exclusion must fail on, saw pip refuse the pairing (`ERROR: Cannot install
dotmac-deployment-control==0.1.0a7 and dotmac-kernel==0.1.0a99 because these
package versions have conflicting dependencies`), then forced a99 in with
`--no-deps --force-reinstall` and saw all nine canaries fail with
`ModuleNotFoundError: No module named 'dotmac_kernel.product_database_catalog'`.
a6's literal would have demanded a failure naming `dotmac_kernel.transactions`,
which a99 contains.

**The nine canaries are the same nine a6 shipped.** None of them drives the
database catalogue. Its seven-table, 95-column extent is proven by source tests
on the release commit, not by the published artifact, and is not
production-adoption evidence.

### Added

- A source-owned `ModuleDatabaseCatalogContributionV1` binding the exact
  post-`dc_0002_canonical_plan_digest` structure: seven `mod_deploy` platform
  tables and 95 columns. It records PostgreSQL type identity and modifiers,
  physical ordinals, nullability, server defaults and relation kinds. It is
  authored from the frozen migration lineage, never from Platform CP production.
- A typed release-build emission seam accepts composed lineage-head evidence and
  produces the canonical `ModuleDatabaseCatalogSnapshot`. It records the
  distribution coordinate, module release version and integer manifest-contract
  generation as three explicit facts and makes no PostgreSQL-major or
  all-product-completeness claim.
- A clean-room PostgreSQL comparison checks the declaration in both directions
  after applying the module lineage. A `VARCHAR(64)` declaration for
  `deployment_plans.plan_digest` therefore fails against the `VARCHAR(128)`
  result even though the table and column counts are unchanged.

### Corrected

- `ModuleManifest.version` stays DERIVED from installed metadata, as the
  unreleased `ce9e44d0` made it. Publishing the module's database structure is orthogonal
  to how the manifest reports its version, so this change reintroduces no
  literal there and the catalogue tests read `module.version` rather than
  restating `pyproject.toml`. Manifest compatibility remains the independent
  integer `ModuleManifest.contract_version`, unchanged at `2`: the declared
  surface a composing assembly is checked against did not move, only this
  distribution's release coordinate did.

### Changed

- **The declared `dotmac-kernel` floor is `>=0.1.0a100`, not `>=0.1.0a98`.**
  `database_catalog.py` reads `from dotmac_kernel.product_database_catalog
  import ...`, and `dotmac_kernel/product_database_catalog.py` is **absent**
  from the published `dotmac_kernel-0.1.0a99` wheel and **present** in
  `dotmac_kernel-0.1.0a100` — the same kind of observation that set the a98
  floor, made against the wheels on either side of the boundary rather than
  against a changelog entry about them. `dotmac_kernel.transactions` is still
  imported and still a real lower bound; it is simply no longer the highest one.
- The kernel contract is imported through its SUBMODULE rather than the
  top-level re-export, matching how every other module in this package names a
  kernel dependency. It is also what keeps the mutation lane honest: `from
  dotmac_kernel.product_database_catalog import X` against a kernel that lacks
  it raises `ModuleNotFoundError: No module named
  'dotmac_kernel.product_database_catalog'`, which names the boundary, where
  `from dotmac_kernel import X` raises an `ImportError` naming no module at all.
- The module the mutation lane greps for is now DERIVED. `FIRST_SHIPPED_IN` and
  the import collector moved from `tests/architecture/test_kernel_floor.py` into
  `scripts/kernel_floor.py`, which grew a `symbol` subcommand, and `ci.yml`
  calls it instead of holding `dotmac_kernel.transactions` as a literal. That
  literal would have gone stale at exactly this change: the lane would have
  demanded a failure naming a module that a99 contains perfectly well, and gone
  red for a reason that says nothing about the floor. `floor_symbol()` refuses
  three ways — no recorded module introduced the floor, more than one did, or
  the package no longer imports the one that did.

### Release blocker — CLEARED

The contract types were absent from published kernel `0.1.0a98` and `0.1.0a99`.
`dotmac-kernel 0.1.0a100` is published from `dotmac_starter_mt` protected main
`917181b38dcc5954bac932b630909afdfb19012b`, tag `dotmac-kernel-v0.1.0a100`
peeling to that same commit, wheel
`sha256:60a9ba68e4f659ada1d38583e2e5a8d6c803f387a692496cb49e60019772b88c` and
sdist `sha256:d7d6bd6e4ae9bddf90e1b473fdefd02277a20645561f57929d461ce4da0840ae`,
and it carries `product_database_catalog`, `database_catalog_comparator` and
`ModuleManifest.database_catalog`. The floor is moved to that version and
proved in both directions by the floor and mutation lanes, and the release guard
has allocated `0.1.0a7`. **Publication is still owed:** this version is declared,
recorded in `docs/publication-ledger.json`, and not on the index. Nothing may pin
it until a release run and an independent verify run record its coordinates.

## 0.1.0a6 — RELEASED 2026-08-30, verified on seven properties with nine canaries

Published by run `33322980430` from protected main `518711c3`; independently
verified by run `33323067886`, which wrote the tag on a VERIFIED verdict.
Wheel `9b02cf33f954b6562858af320b518c10f9e93aa92fbc3873e4a83fdf117b8fc0`, sdist
`68871c24360ece99d8cd8301daa6c0d246e646c2c57ed19a7b9ea3d42b1adad0`.

**The floor was observed failing before it was observed passing.** On the
release commit the mutation lane derived `0.1.0a97` from the index as the newest
kernel the floor excludes, saw pip refuse the pairing (`ERROR: Cannot install
dotmac-deployment-control==0.1.0a6 and dotmac-kernel==0.1.0a97 because these
package versions have conflicting dependencies`), then forced a97 in with
`--no-deps --force-reinstall` and saw all nine canaries fail with
`ModuleNotFoundError: No module named 'dotmac_kernel.transactions'`. The floor
lane then installed `dotmac-kernel==0.1.0a98` exactly — the declared minimum,
not the resolver's choice — and all nine passed.

Supersedes `0.1.0a5` for its DECLARED DEPENDENCY FLOOR. **a5's artifact identity
and its behaviour are sound and are not withdrawn**; what failed is the
declaration. Platform CP pins a6 with kernel a98, never a5.

**No behaviour changes in this release.** The public surface, models and
migrations were untouched. The published a6 artifact also left
`ModuleManifest.version` at `0.1.0a2`; that was based on the incorrect premise
that this string named manifest compatibility rather than the module release.
The held source correction is recorded above and cannot rewrite a6's bytes.

### Fixed

- **The declared `dotmac-kernel` floor is `>=0.1.0a98`, not `>=0.1.0a77`.**
  `service.py:73` imports `dotmac_kernel.transactions`, and that module first
  shipped in kernel `a98` — it is absent from the published `a97` wheel.
  Under-constrained by 21 alphas.

  a5 is the strongest artifact this repository has published and it could not be
  composed. Its bytes are the published bytes, seven canaries passed against the
  wheel the registry served, and the Platform CP lane raised
  `ModuleNotFoundError` at container boot after resolution succeeded, the lock
  wrote cleanly, and both sha256 digests matched byte-for-byte.

  **A hash comparison proves you got the published bytes; it cannot prove they
  import.** a5's verification did exercise importability — in an environment
  where a compatible kernel happened to be installed. That proves the wheel
  imports; it says nothing about whether the declared floor is honest, because
  nothing in that run ever installed the declared floor.

### Added

- **A floor lane, in the required `behavioural canaries (installed wheel)`
  context.** It installs the built wheel with `dotmac-kernel==${FLOOR}` — the
  floor read from the declaration by `scripts/kernel_floor.py`, never a literal
  — and runs the canaries with `--expect-kernel`, so an environment holding
  anything else is refused. "Some compatible kernel" is what let a5 through.

- **A mutation lane, without which the floor lane passes for the wrong reason.**
  It asks the index for the newest kernel the floor EXCLUDES — the closest
  possible near-miss — and requires two independent things: that pip refuses to
  place that kernel beside this wheel, and that forcing it in (`--no-deps
  --force-reinstall`) makes the canaries fail **naming
  `dotmac_kernel.transactions`**. Any other failure is unrelated breakage
  standing in for the proof.

  Together the two lanes make the floor falsifiable in BOTH directions: too low
  and the floor lane goes red, too high and the mutation lane does. An
  over-constrained floor is a smaller harm than a5's and it is still a harm — it
  forces a consumer into an upgrade nothing requires.

- **Two canaries, running in every lane.** `declared_kernel_floor` reads the
  floor out of the artifact's own `Requires-Dist` (never `pyproject.toml`, which
  is the source tree these canaries exist to exclude) and checks that
  `dotmac_kernel.transactions` resolves from `site-packages`.
  `conflict_savepoint_executes` drives the symbol that floor is set by: an
  accepted observation runs the `with conflict_savepoint(...)` block, and a real
  unique-constraint collision through the same context manager must leave the
  caller's transaction usable — the property `0.1.0a1` shipped without.

- **`scripts/kernel_floor.py`**, which both lanes ask for their versions so the
  workflow carries no second literal. It refuses a constraint shape it was not
  written for, and refuses loudly when the index lists nothing below the floor —
  an empty answer there would turn the mutation into a lane that proves nothing.

### Consequence for consumers, recorded and not discharged here

Adopting a6 obliges a **21-alpha kernel jump, a77 → a98**. That upgrade gets its
own migration and compatibility run; it must not be chosen silently by a
resolver.

### Historical version declaration — corrected in the held source above

- a6 deliberately left `ModuleManifest.version` at `0.1.0a2`, but the premise
  was wrong: the kernel contract defines that field as the module release
  version. Manifest compatibility is the independent integer
  `ModuleManifest.contract_version`. Published a6 is immutable; the next release
  must carry the corrected semantics and its own properly allocated version.
- **The replay path is untouched and stays out of scope.**
  `_replay_observation` compares `payload_digest` as text. It is a recorded
  unmonitored region with an enforceable premise
  (`test_digest_comparison_is_typed.py`), it is being addressed independently,
  and `test_the_conflict_savepoint_canary_does_not_touch_the_replay_path` keeps
  the new canary out of it.

## 0.1.0a5 — RELEASED 2026-08-30, independently verified on seven properties

Supersedes `0.1.0a4` for FUNCTIONAL reasons. a4's identity proofs stand and are
not withdrawn: it is immutable, independently verified, and **unadoptable**
(Michael's ruling, 2026-08-30). Platform CP pins a5, never a4.

### Fixed

- **`approve_plan` no longer reports an encoding difference as a plan
  mutation.** This is the defect a5 exists for. `snapshot_digest` returned bare
  hex, `spec_digest` returned the `sha256:`-prefixed form, `propose_plan` stored
  the bare one, and `approve_plan` compared the two as STRINGS — so a caller
  supplying the plan's own digest in the other encoding was refused with *"the
  plan changed after approval, so a new approval is required"*.

  A security refusal standing in for a formatting bug is the worst available
  failure shape: it looks exactly like the system working, and the operator
  re-runs an approval that was never stale.

- **`__version__` is derived from the installed distribution's metadata.** The
  published a4 wheel carries `__version__ = "0.1.0a2"` while declaring
  `0.1.0a4`, so an authorization would have recorded the wrong version of the
  deciding module. Two literals for one fact is the root cause; one is deleted
  rather than a third check added. A source tree with no install reports
  `0.0.0+not-installed`, a shape `release_guard` refuses, rather than guessing.

### Added

- **`dotmac_deployment_control.digests` — Control-owned `PlanDigestV1`.** An
  ALGORITHM and its digest BYTES, not a string. Canonical serialization
  `sha256:<64 lowercase hex>`. Equality is over the bytes, so no encoding can
  change it, and nothing on the authorization path compares digest text —
  `tests/architecture/test_digest_comparison_is_typed.py` parses the package and
  fails the build if it comes back.

  `SpecDigestV1` is a separate type for the observation path. Same algorithm and
  encoding, different subject, and the values compare unequal across types — so
  a spec digest can never satisfy a plan-digest binding by arriving in the right
  shape.

  Malformed, uppercase, wrong-length and unknown-algorithm values are refused,
  each naming what is wrong: those have genuinely different repairs.

- **`DigestEncodingError`, and it is deliberately NOT an
  `ApprovalRefusedError`.** "I cannot read the value you sent" and "the plan you
  approved is not the plan you are approving" are different findings, for
  different readers, with different repairs. Both remain catchable as
  `DeploymentControlError`.

- **a4's bare-hex form is accepted, in ONE named place, inside Control.**
  `PlanDigestV1.parse_a4_bare_hex` / `parse_accepting_a4_bare_hex` — named for
  the version they exist for, so the compatibility carries an expiry
  conversation rather than becoming the format. **Consumers must not normalize
  a Control digest.** A second implementation of this parser will disagree
  eventually, and the disagreement arrives as a false "the plan changed".

- **`scripts/artifact_canaries.py` — seven behavioural canaries that execute the
  INSTALLED wheel**, never a source checkout. Its first canary refuses to
  continue unless the module it imported came out of the environment's
  `site-packages`; without that the rest would be a slower copy of the unit
  tests wearing a stronger claim, which is precisely how a4 shipped a stale
  `__version__`. Run pre-merge in `ci.yml` against a wheel built from the pull
  request, and post-publication in `verify-release.yml` against the wheel the
  registry served.

- **Property 7 of the release verdict: "the installed distribution behaves as
  published".** a4 passed all six identity properties and was unadoptable; the
  seventh is what stops that combination reaching a tag. A failing canary is
  UNPROVABLE and therefore untagged.

### Changed

- `mod_deploy.deployment_plans.plan_digest` widened `VARCHAR(64)` ->
  `VARCHAR(128)` by `dc_0002_canonical_plan_digest`. 64 was exactly the width of
  bare hex, which is a fair summary of why a4 stored bare hex: the column could
  not hold a value that said which algorithm produced it. Metadata-only in
  PostgreSQL; existing rows are deliberately NOT rewritten, because rewriting
  them would be a migration silently restating other people's frozen approval
  bindings.
- `snapshot_digest` now returns the canonical `sha256:`-prefixed form. Its
  bare-hex return is the a4 behaviour and is gone. `spec_digest` is unchanged.
  `plan_digest_of` and `spec_digest_of` are the new typed accessors.
- `0.1.0a4` is recorded `pinnable: false` and refused BY NAME by
  `scripts/release_guard.py`, distinctly from the floor. Its original PASS
  record is untouched and the superseding disposition is APPENDED beside it —
  both facts are true and the pair is the useful evidence.

### Released

- Published by release run `33318227812` from peeled commit
  `b182a99892067f26c0c1d03d958c5fcdc97c5869`, the exact tip of protected main.
  That run neither verified itself nor tagged.

- **Independently** verified by run `33318433336`, which returned VERIFIED on
  all seven properties: both artifacts fetched from the index by name and
  sha256-equal to the release build (wheel
  `c02804b1b9f6dab7becc21696efccdf3820de06dba50903568e2db4c966e0aec`, sdist
  `5883f8ead3caab1a5d93977e6f086ad0f9f2b9df3e5828b5380ea0c41d841ef8`),
  provenance closed on that commit, publisher read-back, a read-only consumer
  install with the real dependency graph, import, exactly one wheel and one
  sdist on the index, and **all seven behavioural canaries passing against the
  wheel the registry served**.

  The first release cut through the corrected two-workflow path, and the first
  verified on seven properties rather than six. Only the verification run wrote
  the tag, on a VERIFIED verdict, through `tag_once.py`.

## 0.1.0a4 — RELEASED 2026-08-30, independently verified

Supersedes `0.1.0a3`. No source change from a3: the module's code is identical,
and the bump exists because a3 can never be pinned.

### Changed

- Nothing in the package. `0.1.0a3` was published by a release run cancelled
  during its own verification, so the upload succeeded while the read-back,
  consumer proof and tag never ran. Both a3 artifacts were later confirmed
  byte-correct out of band — the BYTES are sound and the EVIDENCE CHAIN is not.
  An index cannot un-publish, so a3 remains on it permanently, recorded
  UNPROVABLE and never pinnable, and a4 carries the same code with a complete
  chain behind it.

### Released

- Published by release run `33297423568` from peeled commit
  `2c61540f74018b7e19d7c5add893e0653cfcdb17`, and **independently** verified by
  run `33310594187`: both artifacts fetched from the index by name and
  sha256-equal to the release build (wheel
  `ad1aaaa2d20b9a565d0656f64762564f4dfd90eb4c367187aa63fdd54a33c37e`, sdist
  `a5dae85d76e17ab34b1868741def46aab514ffba119110ec750794f5dc1c6e2c`),
  provenance closed on that commit, publisher read-back, read-only consumer
  install, and exactly one wheel and one sdist on the index.

  The tag was written earlier, by a job in the release run that called itself a
  verification and compared the wheel only. That defect is recorded in
  `docs/CONTROL_EXCEPTIONS.md` and structurally removed: a publishing run can no
  longer tag, and only `verify-release.yml` may.

## 0.1.0a3 — PUBLISHED, UNPROVABLE, NEVER PIN

**Published and unusable.** It was declared a3 rather than a2 because the package
source changed after a2 was published, and a version that names two different
contents is the hazard, not the bump. a2's artifact in the index is untouched
and stays the authoritative a2 forever.

### Fixed

- `record_observation` imported `conflict_savepoint` from `dotmac_kernel.db` —
  the reference assembly's CONFIGURED instance, which builds a
  `DatabaseRuntime` at module import time. Every operation in this package
  takes a caller-owned `Session` and opens nothing, so importing the module
  that makes a connection was a boundary violation whether or not the runtime
  was ever used. It now imports the engine-free `dotmac_kernel.transactions`,
  which re-exports the same function and constructs nothing.

  The import was also LAZY, inside the handler, which is how the violation
  stayed invisible: absent from the file's imports, absent when the package was
  imported, and surfacing only as `ArgumentError: Could not parse SQLAlchemy
  URL` deep inside SQLAlchemy when an observation was finally admitted. It is
  now a module-level import, so the boundary is a fact static analysis can
  read.

  A consumer sees one behavioural difference: admitting an observation no
  longer causes the assembly's database runtime to be constructed as a side
  effect.

## 0.1.0a2 — 2026-08-21

Published, installed back from the private index, conformance-checked and
tagged from exact protected-main revision `5c87272a` by release run
`32471956734`. Publication is supply-chain evidence only; it composes no product
and moves no authority.

### Fixed

- A genuinely concurrent first observation now establishes exactly one
  canonical receipt. The receipt insert runs inside a savepoint; the losing
  transaction retains its append-only attempt, points it at the winner, and
  returns the winner's original verdict as a replay or conflict instead of
  leaking the unique-constraint error.
- The PostgreSQL rehearsal now gates both workers after their first production
  receipt lookup has returned empty. This makes the race deterministic and
  covers identical and divergent arrivals rather than relying on thread-start
  timing.
- The README now uses the dossier's authoritative
  `greenfield-after-inventory` source mode. The receipt half has a historical
  tested reference, but it was never production-used and therefore does not
  qualify as product-first extraction under rule 24.

## 0.1.0a1 — 2026-08-19

First release, under ADR-0057 § 3. **Split historical evidence**, recorded as
`source_mode = "greenfield-after-inventory"`: the receipt half ports the
never-merged and never-deployed Vendor V6 admission design as a tested
reference, while the plan/rollout half is greenfield with the absence evidenced.

### Added

- `mod_deploy` — `deployment_targets`, `target_credentials`, `deployment_plans`,
  `rollouts`, `rollout_attempts`, `observation_receipts`, `observation_attempts`
  on the platform plane. Lineage root `dc_0001_deployment_control`, which verifies
  `idempotency_ledger.v1` and `platform_audit_log.v1` before any DDL of its own.
- Versioned desired state, immutable digest-bearing plan snapshots, and
  approval evidence bound to the plan digest (ADR-0026 § 2's binding, applied
  where the blast radius is other people's running systems).
- Rollouts with one in-flight attempt at a time, a provider-neutral
  `DeliveryIntent` return, and the full outcome vocabulary including `TIMED_OUT`
  and `MANUAL_REPAIR` as states distinct from `FAILED` and `CANCELLED`.
- Observation admission: every arrival written as an append-only attempt, only
  valid-and-eligible-and-matching arrivals admitted, replays returning the
  original verdict verbatim, and the proven identity kept in a different column
  from the reported claim under two CHECK constraints.
- Drift computed on demand against the plan that was actually **rolled out** —
  never against the current desired state, which would make every desired-state
  edit look like fleet-wide drift.

### Ported from the V6 reference

- The attempt/receipt pair, and the reasoning for it: a single table keyed on
  `(identity, report_id)` cannot store the second arrival, which is the row worth
  keeping.
- The claim/proof separation, and the two CHECK constraints that make it
  structural rather than conventional.
- The stable-verdict rule: a replay returns the original decision rather than
  recomputing, so an at-least-once transport cannot look like a state change.
- Credential eligibility as a half-open window evaluated against the stored
  timestamps, so a report that arrived while a credential was live stays
  evaluable after it is rotated out.
- Enrollment to `PENDING`, never straight to `ACTIVE`.
- The fingerprint over DECODED key bytes, never the base64 text.

### Deliberately NOT included

- **Any provider client, HTTP library or transport.** The Integrator's
  (ADR-0024, hard rule 28).
- **Any signature verification.** `dotmac_kernel.licensing` owns it (ADR-0007);
  a second verifier could disagree with the first.
- **Any health status.** Ruling A4 keeps health separate from fleet.
- **Any private key or provider credential.** `target_credentials` holds a
  deployment's own PUBLIC verification key and nothing else.
