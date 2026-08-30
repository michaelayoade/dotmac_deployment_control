# Control exceptions

Controls this repository claims, where the claim is narrower than it sounds.
Each entry states what is enforced, what is NOT, and by whom — so that a reader
does not infer coverage that does not exist.

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

**Status:** REMEDIATED 2026-08-30. Recorded rather than deleted: the entry is
the record of an acceptance that was made deliberately, held for four releases,
and then withdrawn — and of an undercount that the acceptance itself contained.

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
