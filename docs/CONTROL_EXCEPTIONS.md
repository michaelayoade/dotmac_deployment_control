# Control exceptions

Controls this repository claims, where the claim is narrower than it sounds.
Each entry states what is enforced, what is NOT, and by whom — so that a reader
does not infer coverage that does not exist.

## Database-catalogue publication was blocked on an unpublished kernel contract

**Status:** CLOSED by `0.1.0a7`, published 2026-09-01 by release run
`33507951778` and independently VERIFIED by run `33508897684`. Every condition
this entry set for closure was met in one release slice: the first published
kernel carrying `ModuleDatabaseCatalogContributionV1` is `0.1.0a100`; the floor
was raised to `>=0.1.0a100`; the floor and excluded-near-miss lanes ran in both
directions on the release commit (CI run `33488407034`); the next distribution
version was allocated through `release_guard`; and every required check was
green before publication. The published `ModuleManifest.version` is now derived
rather than declared, so the `0.1.0a2` self-report a6 carried is gone.

**What did NOT change at closure, and is the reason this entry stays:** the
declaration's exact table and column sensitivity checks, the clean-room
PostgreSQL comparison included, are SOURCE checks. None of the nine artifact
canaries drives the catalogue, and the set did not grow with the capability. No
published artifact carries an artifact-level proof of the seven-table,
95-column extent, and the checked-in source must still not be cited as
production adoption evidence. Platform CP binding it into a release catalogue
is a separate, undischarged step.

**The artifact-level half, added after a7 and NOT part of what a7 published.**
Two canaries now drive the catalogue against an INSTALLED distribution —
`database_catalogue_as_published` and `catalogue_digest_binds`. They compare the
whole canonical structure against literals in `scripts/artifact_canaries.py`:
module identity, all seven table identities, all 95 columns by name, physical
ordinal, PostgreSQL type identity and rendered spelling, nullability, generation
and server default, and every table's plane and owner. Counts are deliberately
not the check — `len(tables) == 7 and len(columns) == 95` passes on seven wrong
tables. Two planted mutations in `ci.yml` require the refusal to be observable:
a table nobody declared (`rollout_attempts` → `rollout_events`, in both the
contribution and the manifest, so the artifact stays internally coherent) and a
column right by name and wrong by type (`deployment_plans.plan_digest` back to
the `dc_0001` width), each in its own environment so each refusal is attributed.

**DISCHARGED for a7 by supplemental verify run `33517740717`** (2026-09-01,
dispatched from main `61611da8`). It fetched the SAME published bytes from
registry.dotmac.io by name and returned VERIFIED on all seven properties with
ELEVEN canaries. `database_catalogue_as_published` and `catalogue_digest_binds`
both passed against the wheel the REGISTRY served, so a7 now carries an
artifact-level proof of the seven-table, 95-column extent and the paragraph
above is no longer the only thing standing behind it. The tag was not touched:
the run reached `tag_once`'s ALREADY notice on
`6b1ce371b07220914696243647aeb0d3947b87cc`. Nothing was published or rebuilt —
`verify-release.yml` uploads nothing by construction.

`0.1.0a7`'s ORIGINAL verification, run `33508897684`, still ran nine canaries
and none of them the catalogue; that record is appended to, never rewritten, and
the two runs must not be read as one.

**What is still owed, and is NOT discharged by the run above:** the observed
catalogue digest
`sha256:92be901f92ec2a2861d2b44e3693bb7645e84d9d60c14d7caeb6c12051abb01e` is a
coordinate of (artifact, kernel) rather than of the wheel alone — the canonical
document carries `manifest_contract_version`, which this module declares none of
and the kernel infers from `KERNEL_MODULE_CONTRACT_VERSION` — so a consumer
adopting the STRUCTURE is safe across kernels and a consumer adopting the DIGEST
must pin the kernel too. Recorded on a7's row as
`supplemental_verify_runs[0].adoption_constraint`. And Platform CP binding the
catalogue into a release catalogue remains a separate, undischarged step.

The record below is the original entry, kept unchanged.

---

This branch authors Deployment Control's exact post-`dc_0002` database
contribution and binds it to the module manifest. The fully typed contract
classes it consumes exist only in the Starter's candidate kernel source; the
currently published and declared floor, `dotmac-kernel >=0.1.0a98`, does not
contain them.

The same held slice corrects a separate source declaration: published a6 carries
`ModuleManifest.version = "0.1.0a2"`, although the kernel defines that field as
the module release version and uses the integer `contract_version` for manifest
compatibility. Published a6 is immutable. The candidate source uses the current
source coordinate `0.1.0a6`; the release guard must replace it with the next
properly allocated distribution version before any later artifact is published.

The dependency is deliberately not assigned a guessed future version. This
means the branch is stacked and expected to be non-releasable until the kernel
owner publishes the contract. Closure requires all of the following in one
release slice: name the first published kernel version containing
`ModuleDatabaseCatalogContributionV1`; raise this distribution's floor to that
version; run the existing floor and excluded-near-miss canaries; allocate the
next Deployment Control distribution version through `release_guard`; and
publish only after every required check is green.

**What is source-checked on the stacked candidate:** the declaration has exact
table and column sensitivity checks, including a clean-room PostgreSQL
comparison, when this source is evaluated against the candidate kernel contract.
That source check is not a control carried by any published artifact.

**What is not enforced:** no published Deployment Control artifact carries the
declaration, and Platform CP cannot yet bind it into a release catalogue. The
checked-in source must not be cited as production adoption evidence.

## 0.1.0a3 is published, immutable, and must never be pinned

**Status:** permanent. Not a gap to close — a fact to keep visible.

`0.1.0a3` was published by release run `33295149495`, which was **cancelled
during its own verify job**. The upload succeeded; the authenticated read-back,
the consumer proof and the tag never ran. Verify run `33296262948` returned
**UNPROVABLE**.

Both artifacts were subsequently confirmed byte-correct out of band — wheel
45,911 bytes and sdist 42,256 bytes, each sha256-matching what the release run
built. **The bytes are sound. The evidence chain is not**, and it cannot be
repaired after the fact: the proofs that were skipped were meant to run against
that publication, in that order, before the tag asserted them.

Michael ruled on 2026-08-30: do not tag, adopt, overwrite or delete it. An index
cannot un-publish, so a3 exists permanently and the only available control is to
make it unpinnable. `docs/published-versions.json` records it with
`pinnable: false`, `scripts/release_guard.py` refuses it by name with a distinct
message, and the release floor moves through it — a floor that skipped a3 would
let a later release collide with bytes that are permanently there.

**What is NOT enforced:** nothing stops a consumer outside this repository
pinning `==0.1.0a3` from the index. The refusal is a publish-side control, and
no server-side mechanism exists to withdraw a version. The compensating control
is the record itself.

## 0.1.0a4 was tagged by a check that could not perform the check

**Status:** closed for a4, structurally closed for every version after it.

`0.1.0a4` was published by release run `33297423568` from the exact tip of
protected main, and tagged **by a job inside that same run**. That job was named
"An ordinary consumer can install it, and the bytes match" and did neither
reliably:

- it compared hashes over whatever `pip download` returned. pip takes the wheel
  and has no reason to pull the sdist beside it, so the run's own log shows
  exactly one `identical:` line and the sdist was never compared — **the same
  gap that made a3 unprovable, repeated on the version published to replace
  a3**;
- it ended with `pip install … || true`, so the installation could fail without
  the step noticing;
- and it ran inside the publishing run, holding the publishing credential, with
  the bytes already on disk. That party cannot be an independent witness to what
  the registry serves.

**The bytes are sound and now independently proven.** Verify run `33310594187`
— a separate workflow, separate run, uploading nothing — fetched both artifacts
from `registry.dotmac.io` **by name** and found them sha256-equal to release run
`33297423568`'s build:

| artifact | bytes | sha256 |
| --- | --- | --- |
| `dotmac_deployment_control-0.1.0a4-py3-none-any.whl` | 45,911 | `ad1aaaa2d20b9a565d0656f64762564f4dfd90eb4c367187aa63fdd54a33c37e` |
| `dotmac_deployment_control-0.1.0a4.tar.gz` | 42,262 | `a5dae85d76e17ab34b1868741def46aab514ffba119110ec750794f5dc1c6e2c` |

Provenance closes on peeled commit
`2c61540f74018b7e19d7c5add893e0653cfcdb17`, which is on protected main and
declares `dotmac-deployment-control 0.1.0a4`. The publisher read the version
back, a read-only `ci-reader` consumer installed it, and the index lists exactly
one wheel and one sdist for the version. The verdict was **VERIFIED**.

Michael ruled 2026-08-30: **published and independently provable, so a4 is
retained and never republished.** The tag stays exactly where that run wrote it.

**What was NOT proven at the time of that verdict:** the installed distribution
did not import. `ModuleNotFoundError: No module named 'dotmac_kernel'` was
raised in the run and swallowed by a `|| true`, because the install passed
`--no-deps`. That is a defect in the VERIFIER, not in the artifact — the wheel's
`Requires-Dist` is correct and the dependency is on the same index. The verifier
now installs the real dependency graph and asserts the import as **property 6**,
and a4 has not yet been re-verified against it.

**What is structurally closed.** The publishing run can no longer tag, can no
longer claim to verify itself, and no longer holds `contents: write`.
`test_the_publishing_run_writes_no_tag`,
`test_the_publishing_run_cannot_write_to_the_repository` and
`test_the_publishing_run_does_not_claim_to_verify_itself` fail the build if any
of that is undone. Ordering the read-back before the tag — the previous rule —
was satisfied by a4 and did not help: ordering is not the property when one run
controls both ends of it.

## 0.1.0a4 is identity-verified AND unadoptable

**Status:** permanent. Both halves are true, and the PAIR is the record.

Michael ruled on 2026-08-30: **a4 remains immutable and identity-verified, but
it is unadoptable. Cut a5. Platform CP must pin a5, never a4.**

Four terms, and they are separate findings:

| | |
|---|---|
| Artifact identity | **passed** |
| Functional authorization | **failed** |
| Version self-reporting | **failed** |
| Adoption eligibility | **refused** |

**Artifact identity passed, and that proof stands.** All five: the tag peels to
`2c61540f74018b7e19d7c5add893e0653cfcdb17`; the wheel is
`ad1aaaa2d20b9a565d0656f64762564f4dfd90eb4c367187aa63fdd54a33c37e` and the sdist
`a5dae85d76e17ab34b1868741def46aab514ffba119110ec750794f5dc1c6e2c`, both fetched
from the index by name by INDEPENDENT verify run `33310594187` and equal to
release run `33297423568`'s build; a clean read-only consumer installed it with
its dependencies; it imported. Nothing about that is withdrawn, and the entry
above about how a4's TAG was written is a different finding again.

**Functional authorization failed.** `approve_plan` refused a correctly-supplied
approval digest. `snapshot_digest` (`service.py:305`) returned bare hex,
`spec_digest` (`:311`) returned the `sha256:`-prefixed form, `propose_plan`
stored the bare one (`:889`), and `approve_plan` compared
`evidence.content_digest != row.plan_digest` (`:974`) — two encodings of one
kind of value, ten lines apart in one file, with a string comparison between
them at the point an approval is authorized. A caller using the other encoding
of the same digest was told *"the plan changed after approval, so a new approval
is required"*.

That message is why this is a ruling and not a bug report. A security refusal
standing in for a formatting bug is the worst available failure shape, because
it looks exactly like the system working: the operator reads "the plan changed",
does the diligent thing, and re-runs an approval that was never stale.

**Version self-reporting failed.** The published wheel carries
`__version__ = "0.1.0a2"` while `pyproject.toml` declares `0.1.0a4`. An
authorization recording which version of Control decided something would record
the wrong one. Two literals for one fact; `0.1.0a5` derives `__version__` from
the installed distribution's metadata and deletes the second.

**Adoption eligibility is refused.** `docs/published-versions.json` records a4
`pinnable: false` with an `unpinnable_reason` naming a5, and
`scripts/release_guard.py` refuses it by name — a distinct refusal from the
floor's, because "publish something higher" would say the same thing about a4 as
about a3 and they failed different questions.

**The disposition is APPENDED, never a rewrite.** a4's original PASS record —
the tag, the tag object, the peeled commit, both digests, the release run, the
verify run and the note recording them — is unchanged in
`docs/published-versions.json`, and
`test_the_disposition_is_APPENDED_and_never_overwrites_the_pass_record` fails if
any of it is lost. Rewriting it to say "failed" would destroy the only worked
example the fleet has of the distinction between an artifact's identity and its
behaviour, and would also be false.

**The tag and both artifacts are never deleted, moved, overwritten or
recreated.** An index cannot un-publish, and a tag that moved would make one
version name two commits.

**What is NOT enforced:** nothing stops a consumer outside this repository
pinning `==0.1.0a4`. The refusal is a publish-side control. The compensating
control is this record plus the `pinnable: false` row a consumer's own gate can
read.

## Six identity properties could not see a functional defect

**Status:** closed by property 7 as of `0.1.0a5`.

`verify-release.yml` proved six things about a4 and every one of them was true.
None of them could see either defect above, because all six are questions about
WHICH BYTES are on the index and by whom — not about what those bytes do.

The gap was not a weak check. It was a missing KIND of check, and its shape is
worth naming: every proof the repository had ran against the SOURCE TREE, where
`__version__ = "0.1.0a2"` and `pyproject.toml` disagreed in two files that no
test compared. A proof about an artifact has to execute the artifact.

`scripts/artifact_canaries.py` is that proof. It runs with the interpreter of an
environment that has the wheel installed, and its first canary refuses to
continue unless the module it imported came out of that environment's
`site-packages` — without which the rest would be a slower copy of the unit
tests wearing a stronger claim. It runs twice, on two different claims:

- **`ci.yml`, pre-merge**, against a wheel built from the pull request. Catches a
  functional defect before an immutable upload exists.
- **`verify-release.yml`, post-publication**, against the wheel the REGISTRY
  served, as property 7 of the verdict. A failure is UNPROVABLE, and an
  UNPROVABLE version is never tagged.

**What is NOT enforced:** the canaries prove the behaviours they name and no
others. They are a floor under "does this artifact work", not a claim that it is
correct. A defect in a path no canary drives ships exactly as a4's did, and the
answer is to add a canary in the change that finds one — never to describe the
existing set as coverage. `0.1.0a5` is the worked example: seven canaries passed
against the wheel the registry served, and the entry below is what they could
not see.

## The module the floor is declared for was a second literal

**Status:** closed for `0.1.0a7`; derived from the package's own imports.

The floor lanes a6 introduced work, and one half of the mutation was written as
a literal: `ci.yml` required the forced failure to mention
`dotmac_kernel.transactions`, which is what stops "the canaries failed" standing
in for "the canaries failed at the boundary the floor describes".

That literal is correct exactly as long as the floor does not move. `0.1.0a7`
moves it. `database_catalog.py` imports
`dotmac_kernel.product_database_catalog`, absent from the published
`dotmac_kernel-0.1.0a99` wheel and present in `dotmac_kernel-0.1.0a100`, so the
floor rises to `>=0.1.0a100` and the excluded kernel becomes a99 — **which
contains `dotmac_kernel.transactions` perfectly well**. The lane would have gone
red demanding a failure that cannot happen, and the message would have pointed
at a module with nothing wrong with it.

The failure mode worth naming is not that: it is the near miss. Had the moved
floor happened to keep the old module in the traceback for some unrelated
reason, the lane would have gone GREEN while proving nothing about the new
boundary. Two literals for one fact is the `0.1.0a4` defect, and it does not
become safe for being in a workflow rather than in a source file.

So `FIRST_SHIPPED_IN` and the import collector moved out of
`tests/architecture/test_kernel_floor.py` and into `scripts/kernel_floor.py` —
a test module is not importable from a workflow step, which is the whole reason
the second copy existed — and `scripts/kernel_floor.py symbol` derives the one
module whose recorded introduction equals the declared floor. `ci.yml` greps for
that. It refuses rather than guessing when no recorded module introduced the
floor, when more than one did, or when the package no longer imports the one
that did; the last is the sensitivity half, because a row whose import was
deleted leaves the lane requiring an impossible failure.

**What is NOT claimed:** that the table is complete. It records the kernel
submodules whose introduction has ever bounded this distribution, and a new
import whose introducing alpha nobody records is invisible to it — the floor
would then be under-constrained again, in the a5 shape, and the mutation lane
would report the floor too high rather than naming the gap. The repair is a row
in the same change that adds the import.

## Seven canaries could not see a dishonest dependency floor

**Status:** closed for a6 by the floor and mutation lanes; **a5 is permanently
under-constrained and unsuitable for new adoption.**

`0.1.0a5` is the strongest artifact this repository has published and it could
not be composed.

Its identity is beyond doubt and nothing about that is withdrawn. The tag peels
to `b182a99892067f26c0c1d03d958c5fcdc97c5869`; the wheel is
`c02804b1b9f6dab7becc21696efccdf3820de06dba50903568e2db4c966e0aec` and the
sdist `5883f8ead3caab1a5d93977e6f086ad0f9f2b9df3e5828b5380ea0c41d841ef8`, both
fetched from `registry.dotmac.io` by INDEPENDENT verify run `33318433336` and
equal to release run `33318227812`'s build. A read-only consumer installed it
with its real dependency graph and imported it. Seven behavioural canaries
passed against the wheel the registry served. The encoding defect a5 was cut for
is genuinely fixed.

**What failed is the declaration.** `service.py:73` reads

    from dotmac_kernel.transactions import conflict_savepoint

`dotmac_kernel/transactions.py` — the public, engine-free re-export a module
holding a caller-owned `Session` is meant to use instead of importing
`dotmac_kernel.db` — is **absent** from the published
`dotmac_kernel-0.1.0a97-py3-none-any.whl` and **present** in
`dotmac_kernel-0.1.0a98-py3-none-any.whl`. a5's metadata declares
`Requires-Dist: dotmac-kernel (>=0.1.0a77)`. **Under-constrained by 21 alphas.**

The Platform CP lane found it at container boot: resolution succeeded, the lock
wrote cleanly, and both artifacts matched their published hashes byte-for-byte.

### The lesson, stated narrowly enough to act on

**A hash comparison proves you got the published bytes; it cannot prove they
import.**

And the half that is easier to miss: a5's verification DID exercise
importability. It ran in an environment where a compatible kernel happened to be
installed. That proves the wheel imports. It says nothing about whether the
declared FLOOR is honest, because nothing in that run ever installed the
declared floor. Property 6 asks "does it import?"; nobody was asking "does it
import against the minimum it claims to need?".

### What now makes the floor falsifiable

Two lanes inside `behavioural canaries (installed wheel)`, which is a REQUIRED
context on `main`, so neither can be skipped past:

| the floor is… | which lane goes red | because |
| --- | --- | --- |
| too LOW (a5's defect) | the floor lane | the declared minimum cannot import |
| too HIGH | the mutation lane | the version below it runs everything fine |

- **The floor lane** installs the built wheel with `dotmac-kernel==${FLOOR}`,
  where `FLOOR` comes from `scripts/kernel_floor.py declared` rather than from a
  literal, and runs the canaries with `--expect-kernel`. Two new canaries run
  there and in every other lane: `declared_kernel_floor` reads the floor out of
  the ARTIFACT'S OWN `Requires-Dist` and refuses an environment that does not
  match, and `conflict_savepoint_executes` drives the symbol the floor is set by
  — an accepted observation through the `with conflict_savepoint(...)` block,
  then a real unique-constraint collision through the same context manager,
  proving the caller's transaction survives.
- **The mutation lane** asks the index for the newest kernel the floor EXCLUDES
  — the closest possible near-miss, so an over-constrained floor is caught too —
  and requires two independent things: that pip refuses to place that kernel
  beside this wheel at all, and that FORCING it in (`--no-deps
  --force-reinstall`) makes the canaries fail **naming
  `dotmac_kernel.transactions`**. Any other failure is some unrelated breakage
  standing in for the proof, and the lane says so.

Without the mutation the floor lane passes for the wrong reason and nobody
learns whether it can fail (ADR-0018). Without the floor lane the mutation is
comparing an artifact against itself.

**Both lanes were observed doing their job on the release commit itself**
(`518711c3`), which is why this entry says "closed" rather than "guarded":

| observation | result |
| --- | --- |
| floor lane, `dotmac-kernel==0.1.0a98` pinned exactly | all 9 canaries passed |
| mutation, resolver | `ERROR: Cannot install dotmac-deployment-control==0.1.0a6 and dotmac-kernel==0.1.0a97 because these package versions have conflicting dependencies` |
| mutation, a97 forced in | all 9 canaries failed, `ModuleNotFoundError: No module named 'dotmac_kernel.transactions'` |

`0.1.0a6` was published by release run `33322980430` and verified by
independent run `33323067886` — VERIFIED on all seven properties, nine canaries
against the wheel the registry served, tag written by that run alone.

### a5's disposition, and what is NOT withdrawn

Michael ruled 2026-08-30: **a5 remains immutable and verified, and is
under-constrained and unsuitable for new adoption. Cut a6. Platform CP must pin
a6 with kernel a98, never a5.**

| | |
|---|---|
| Artifact identity | **passed** |
| Functional authorization | **passed** |
| Declared dependency floor | **failed** |
| Adoption eligibility | **refused** |

**The disposition is APPENDED, never a rewrite** — the same treatment a4
received, for a different failure, and the two rows are worth reading together:
a4 separated artifact identity from functional behaviour, and a5 separates both
of those from the declared dependency floor. a5's original PASS record in
`docs/published-versions.json` is unchanged, and
`test_a5s_disposition_is_APPENDED_and_never_overwrites_the_pass_record` fails if
any of it is lost.

**The tag and both artifacts are never deleted, moved, overwritten or
recreated.** An index cannot un-publish, and a tag that moved would make one
version name two commits.

**What is NOT enforced:** nothing stops a consumer outside this repository
pinning `==0.1.0a5`, and the refusal remains a publish-side control. The
compensating control is this record plus the `pinnable: false` row a consumer's
own gate can read. And the two lanes prove the floor of THIS distribution
against THIS kernel; they say nothing about any other dependency's floor, and
`scripts/kernel_floor.py` refuses a constraint shape it has not been taught
rather than reasoning about one.

**The consequence a consumer inherits, recorded because it is not this
repository's to discharge:** raising the floor obliges anyone adopting a6 to
move from kernel a77 to a98 — a 21-alpha jump. Michael's constraint is that
the upgrade receives its own migration and compatibility run and is not chosen
silently by a resolver.

## The publication gate was blind to tags in CI

**Status:** closed.

`test_ported_gate_declared_publication.py` decides whether a declared version is
published by asking `git tag --list`, and its two-directional ratchet is
supposed to catch a ledger row that outlives its own publication. It never
caught one, because `actions/checkout` fetches no tags by default: in CI the
gate could only ever answer "no tags exist", so the stale-absolution half could
not fire at all.

It did not fire. `0.1.0a4` was tagged at 06:41 on 2026-08-30 and
`docs/publication-ledger.json` went on recording it `never-published` through
green CI. A guard that cannot observe the thing it rules on is not lenient, it
is absent — `AGENTS.md` rule 23 in the Starter, and the reason the repair is
`fetch-tags: true` on the CI checkout plus
`test_a_tag_this_repository_published_is_visible_to_the_gate`, which fails when
a recorded tag is not locally visible rather than passing over an empty set.

## Credentials appear in curl process arguments, not in URLs

**Status:** REMEDIATED 2026-08-30 by PR #10. Recorded rather than deleted: the
entry is the record of an acceptance that was made deliberately, held for four
releases, and then withdrawn — and of an undercount that the acceptance itself
contained.

### What was accepted, and why

Two steps authenticated with `curl -u "ci-reader:${TOKEN}"` — the CI credential
probe and the release guard's index-conflict check. `-u` places the credential
in the process arguments, where a process listing can read it. **No credential
was in a URL** anywhere in either workflow, and
`test_no_credential_ever_appears_in_a_url` enforced that across both workflows
and both credentials; the argv exposure was a strictly smaller and different
thing.

It was recorded rather than fixed because the only argv-free curl form then
considered (`--config -` on stdin) would have been an untested change to a path
CI does not exercise: the release guard runs on `workflow_dispatch` only, so a
mistake in it would surface at the next release rather than in a pull request.
The exposure was bounded by the runner being ephemeral and single-tenant, and by
the credential being read-only.

**The premise, stated so it could be falsified:** acceptable only while these
runners are ephemeral and not shared with untrusted workloads.

### The premise was not what changed. Michael withdrew the acceptance.

The runners are still ephemeral. The ruling on 2026-08-30 was that a credential
in argv is not worth holding open for a reason that amounts to "the fix is
untested" — the fix being untested is an argument for testing it.

### The entry also had the exposure backwards, and the tests found it

The record said `-u` "places the credential in the process arguments, where a
process listing can read it". That is only half right, and the first version of
the process-table sensitivity proof **failed** because of it: reconstructing
`curl -u` and scanning `/proc` found nothing.

curl built with writable argv **blanks its own `-u` argument in place** once it
has parsed it. A `ps` taken during the request shows
`curl -sS -u<spaces> http://…` while `Authorization: Basic …` still goes on the
wire. curl does this for `--user` and `--proxy-user`; it does **not** do it for
`-H`.

So the two sites the record named were the LESS exposed pair, and the five it
did not name were the ones readable in the process table for the entire
request — including a thirty-attempt read-back loop. `-u` is still not safe:
`execve` records argv before curl can scrub it, so auditd and any exec tracer
keep the credential, and `bash -x` prints the expanded command untouched.
`test_curl_scrubs_its_own_dash_u_value_but_not_the_wire_or_the_trace` holds
that finding as an assertion rather than as prose.

**The lesson, which outlives this entry:** the sensitivity proof was not
ceremony. It was the only thing in the change that could discover that the
recorded description of the defect was wrong about its own mechanism, and it
discovered it by failing.

### The entry undercounted the defect: it was five more steps, not two

The acceptance named the two `-u` sites. `-H "Authorization: token ${TOKEN}"`
places the credential in argv in exactly the same way, and there were **five**
of those: the publisher identity probe, the package-namespace read, the
repository-refusal loop, the publish read-back (a thirty-attempt loop, so up to
five minutes of a credential-bearing command line), and the verify workflow's
publisher read-back. A remediation that fixed only what the record named would
have left the property false while claiming it true, so all seven were changed.

### What replaced it

`scripts/curl_with_credential.sh`. A curl configuration file supplies `user =`
or `header =`; only its PATH reaches argv. The file is created under
`umask 077` — 0600 from the instant it exists, never world-readable and then
tightened — under `RUNNER_TEMP` rather than the workspace, so no
`upload-artifact` glob can reach it, and it is removed by a `trap` on `EXIT`,
`HUP`, `INT` and `TERM`. A trailing `rm` was not sufficient: it runs only when
every preceding line succeeded, and this repository lost `0.1.0a3` to a
cancelled run. The same trap repair was applied to the consumer step's `.netrc`
in `verify-release.yml`, which had exactly the trailing-`rm` shape.

The wire form is unchanged. Both modes send the header the previous flags sent,
so this is a transport change and not an authentication change.

### What proves it, and what each proof does NOT prove

`tests/architecture/test_curl_credential_transport.py`, in three unequal
layers, described there in full. In short:

- **A process-table observation** is the only layer that measures the property.
  Real curl, a real request held open against a loopback socket, and every
  readable `/proc/<pid>/cmdline` scanned for the credential — while also
  asserting the credential reached the server, so a clean argv cannot be the
  argv of a request that never authenticated.
- **A `curl` shim on `PATH`** records argv, and the config file's path, mode
  and contents at the moment curl opened it. It carries the cleanup proofs on
  the FAILING paths — a non-zero curl, an unexecutable curl, and a `SIGTERM`
  cancellation — and the `bash -x` log proof.
- **A static ratchet** over the workflows and `scripts/*.sh`. This proves the
  checked-in SOURCE contains no argv-placing form. **It proves nothing about a
  running process**, and must never be cited as though it did.

Every one of those detectors is paired with a reconstruction of the offending
shape — a planted `curl -u`, a planted trailing `rm`, a planted 0644 config, a
planted un-suppressed `set -x`, a planted workspace-local config, and planted
workflow mutations — and the pair asserts the detector fires. The repository is
clean, so without those pairs each check would pass over an empty set.

**What is still NOT enforced.** The credential remains in the step's
ENVIRONMENT, which is where a workflow secret has to live and is readable by
anything running as the same user in the same step. Moving it out of argv
narrows the exposure to that; it does not remove it. And the static ratchet
scans `.github/workflows/*.yml` and `scripts/*.sh` only — a credential-bearing
curl inside a composite action, a reusable workflow, or a Python script would
be an unmonitored region rather than a covered one.

**The boundary this did not cross.** "The publish path may not rely on a
credential file" (recorded above, after twine dropped `.netrc` support between
two runs) is about twine, and the upload step still authenticates by
`TWINE_USERNAME`/`TWINE_PASSWORD` and reads no file.
`test_the_upload_still_authenticates_only_through_the_environment` asserts that
rather than leaving it to be assumed, because the curl config file and the
uploader now sit in the same workflow.

## The publisher's identity IS asserted — resolved 2026-08-30

**Status:** closed. Recorded rather than deleted, because the reasoning that
looked like a dead end is the reasoning a future reader will repeat.

The earlier entry said this was unimplementable as specified: a
`write:package`-only token returned 403 from `/api/v1/user`, so the preflight
could not compare an identity, and the honest outcome was to record that rather
than soften the check into "a token exists and can reach the registry".

**What was actually wrong was the diagnosis, not the requirement.** Scopes and
package reach turned out to be two different mechanisms:

- `read:package` was **normalised away** by Forgejo, implied by `write:package`,
  and the token still 401'd on the index. The scope string was a red herring.
- Package access is granted by **org team membership**. A team carrying only
  unit type 9 (packages) at write made the index read succeed immediately, while
  every repository endpoint stayed 403.
- The account is **not** `restricted`. That flag was set initially, broke index
  reads, and removing it changed no refusal — so it never provided containment
  and must not be cited as though it did.

So the preflight asserts **behaviour, never a scope string**: `/api/v1/user`
returns exactly `dotmac-deployment-control-publisher`, and a package-namespace
read returns 200. It additionally re-proves that the credential cannot reach
repositories, because a publish token that can read source has a different blast
radius than the one recorded here.

**The general lesson, which outlives this entry:** a permission system can have
two independent mechanisms where the documented one is the more visible. Asserting
on configuration would have passed with the token that did not work and would
pass again with a token whose team membership was later removed.

## Publisher scope cannot be restricted to one package NAME

**Status:** open, structural, and now the only remaining gap.

Forgejo packages belong to the **owner**. Registry permission is
owner/package-namespace scoped, so a credential that may publish
`dotmac-deployment-control` under `dotmac` may publish **any** package under
that owner. Repository linkage does not narrow it, and the packages-only team
above stops repository access without touching package-name reach.

**The protected workflow is the boundary, and nothing on the Forgejo side is.**
`.github/workflows/release.yml` refuses a foreign distribution before any build
or upload, refuses a version at or below the inherited floor, requires the exact
protected-main SHA, refuses a conflicting re-upload, reads the published version
back as the publisher before tagging, and carries an unconditional identity
preflight. `tests/architecture/test_release_workflow_structure.py` is the sixth
layer: it exists because the first five are each removable by one line, and each
removal leaves a workflow that still runs and still goes green.

Compensating controls: a dedicated principal with no repository permissions;
`write:package` only; a packages-only team; and the credential held in the
protected `registry-release` environment with
`deployment_branch_policy.protected_branches = true`, so a job using it must
declare that environment and can only run from a protected branch.

**Preferred replacement.** Authorized Integrations would issue short-lived
OIDC/JWT bound to this repository, workflow and protected ref. The capability
endpoint is scope-blocked from the tokens available, so an administrator must
confirm availability on Forgejo `11.0.16`.

## The copied evidence vocabulary is pinned, not shared

**Status:** controlled.

`tests/architecture/adoption_evidence.py` belongs to `dotmac_starter_mt` and is
copied here because the dossier gate cannot run without it. Rule 24 permits a
one-time extraction and forbids a permanent fork. The control is a git blob-id
pin against a named source commit
(`tests/architecture/test_vocabulary_is_not_a_fork.py`), which fails if the copy
drifts and names the two legitimate repairs. What is NOT controlled: the Starter
changing its own copy. Nothing here watches that; the pin detects divergence
only when someone re-extracts.
