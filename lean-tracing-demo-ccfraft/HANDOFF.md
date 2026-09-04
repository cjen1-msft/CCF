# CCFRaft trace validation and TLA port handoff

## Purpose

Continue the CCFRaft Lean model and trace-validation work on another machine.
The target is:

1. Represent every behavior emitted by the 50 files in `tests/raft_scenarios/`.
2. Prove the Lean model's safety and action lowering without `sorry`, new
   axioms, or trusted evaluation shortcuts.
3. Replace the executable projected SMT encoding with a complete encoding that
   is proved equivalent to the typed Lean formula.
4. Keep `reduction.py` as the only reducer.

This document describes the working tree at handoff time. Read the repository
artifacts for design detail instead of treating this file as a specification.

## Repository state

- Repository: `cjen1-msft/CCF`
- Worktree: `/home/cjen1-msft/CCF/.worktrees/veil-consistency`
- Branch: `lean-ccfraft-slices`
- Semantic handoff checkpoint:
  `2740abd99e867bbe8b777e0102794cc300b4aa1c`
  (`Checkpoint full Raft trace coverage port`)
- Checkpoint parent:
  `be96121c6a9d0caa9b78cafa7c9984a0d1163e67`
- Remote branch contains the semantic checkpoint:
  `origin/lean-ccfraft-slices` at `2740abd99`
- Unrelated untracked directory: `arena-bounded-containers/`
  - Do not add, delete, or modify it.

The current semantic work is committed and pushed. Check out the remote branch
or the semantic checkpoint above. Do not reset or rebase it before inspecting:

```bash
git status --short
git diff --stat
```

## Important decisions

### One reducer

`lean-tracing-demo-ccfraft/reduction.py` is the only reducer.

`lean-tracing-demo-ccfraft/Reduction.lean` is deleted. Do not restore it.

The reducer emits one ordered JSON `steps` array. Each step is either an
action or an observation. Array order defines the state boundary.

### Claim

The Lean theorem in `TraceProperties.lean` defines
`MidtraceSatisfiable`. It starts from an arbitrary `ValidEntryState`.

The executable Python SMT backend in `Shared/smt.py` is still a projection.
It is not proved equivalent to the typed Lean formula.

Do not describe Python SAT or UNSAT as full Lean-model validation.

### Entry-state retirement facts

`ValidEntryState` now includes `RetirementInvariantFacts`. This prevents an
arbitrary mid-trace witness from inventing `retirementCompleted` and gaining
election eligibility.

### Trace callbacks

CCF can emit `send_append_entries` inside `add_configuration` before the outer
`replicate` updates `last_idx`.

The reducer emits `changeConfiguration` before these sends, because the model
action is atomic. It omits only the stale `logLength` observation on these
nested sends. The preprocessing artifact records
`configuration-callback-mixed-snapshot`.

### Terminal role abstraction

C++ uses leadership state `None` after terminal retirement. The Lean model
uses `follower`. The Python reducer normalizes a `retiredCommitted` node with
raw role `None` to model role `follower`.

## Committed foundation

Key commits:

- `be96121c6` - scenario coverage and proof gates
- `6e67722c1` - colleague report
- `9edfd91ec` - timing and report tooling
- `d78ea540b` - semantic reducer rule names
- `4c66094c1` - flat reduced traces
- `2e80086b0` - budgeted UNSAT core reduction

The current uncommitted work adds:

- pre-vote
- check-quorum same-term step-down
- retirement and membership phases
- successor nomination and proposal messages
- expanded runtime parsers and witnesses
- Python support for all emitted trace functions

## Current executable coverage

Regenerate the corpus artifact:

```bash
cd lean-tracing-demo-ccfraft
python3 audit_trace_coverage.py
```

Solve every scenario:

```bash
PATH="/nix/store/74v9g1l0b43xbr9pd0acg0qcdgf9srgw-cvc5-1.3.4/bin:$PATH" \
  python3 audit_trace_coverage.py \
    --refresh-demo-certificates \
    --solve \
    --solver-timeout-seconds 300 \
    --require-all
```

Last confirmed result before the final Lean audit:

```text
scenarios=50 accepted=50 sat=50
```

Artifact:

- `lean-tracing-demo-ccfraft/Measurements/corpus-coverage.json`

The 50 scenarios emit 12,541 trace records.

## Current Lean proof state

Before successor nomination was added, these passed:

```text
RuntimeAudit: 659 theorems, 0 explicit axioms
Demo: 1950 theorems, 0 explicit axioms
```

`MachineGenerated.ReconfigurationPreservation` now builds after adding the
missing retirement invariant case for `receive`.

`MachineGenerated.Proof` builds after restoring a combined
`SystemInductiveInvariant` API.

Current validation status:

```bash
cd lean-tracing-demo-ccfraft
lake build MachineGenerated.Runtime.NaiveFullStateWitness
lake build MachineGenerated.Runtime.TraceValidation
lake build MachineGenerated.ReconfigurationPreservation
lake build MachineGenerated.Proof
```

The first two runtime targets passed. `MachineGenerated.Proof` passed before
the cancelled proposal-vote changes landed.

The current `MachineGenerated.ReconfigurationPreservation` has not been
validated after the last edit. Its last completed build failed at
`retirementInvariantFacts_networkFrame`: the helper needed to prove that each
AppendEntries request in a replacement network came from the old network. The
helper now takes an `appendRequestBack` argument. Two argument-wiring errors
were corrected. The last verification build was interrupted for handoff
preparation, so run the target before trusting the proof state.

Run this first, sequentially:

```bash
cd lean-tracing-demo-ccfraft
nice -n 10 lake build MachineGenerated.ReconfigurationPreservation
nice -n 10 lake build MachineGenerated.Proof
nice -n 10 lake build Demo
nice -n 10 lake build RuntimeAudit
```

Do not run `lake build Demo RuntimeAudit` as one command on a memory-constrained
machine. Lake compiled `ReconfigurationPreservation` and `Simulation` in
parallel and used about 14 GiB. Sequential targets keep one Lean compiler
active.

The axiom audit uses an explicit allowlist:

- `propext`
- `Classical.choice`
- `Quot.sound`

It rejects explicit `CCFRaft` axioms and all other theorem dependencies.

## Current model coverage

`Model.lean` now includes:

- `PreVoteCandidate`
- per-node `PreVoteStatus`
- pre-vote requests and responses
- `becomePreVoteCandidate`
- `becomeCandidate`
- `requestPreVote`
- `checkQuorum`
- membership phases:
  - active
  - retirement ordered
  - retirement signed
  - retirement completed
  - retired committed
- retirement indices
- `retiredCommitted` log entries
- `appendRetiredCommitted`
- `retirementCompleted` observer sets
- proposal vote request messages
- `proposeVote`
- `advanceCommitIndexAndProposeVote`

Use `git diff -- Model.lean` to inspect the exact current action and state
schemas.

## Reviews already performed

The latest retirement review found and drove fixes for:

1. Terminal retirement had left a node as leader.
2. Retirement-completed nodes could not campaign.
3. Runtime trace parsing did not classify configuration and retired appends.
4. Full-state witnesses omitted retirement and pre-vote fields.
5. Retirement facts were absent from the formal invariant.
6. `ValidEntryState` allowed forged retirement eligibility.
7. Retired-committed entries lacked formal provenance.

The current worktree contains attempted fixes for all of these. Re-review them.

Files:

- `MachineGenerated/Invariant.lean`
- `MachineGenerated/ReconfigurationPreservation.lean`
- `MachineGenerated/Runtime/TraceValidation.lean`
- `MachineGenerated/Runtime/NaiveFullStateWitness.lean`
- `TraceProperties.lean`

Do not assume that a successful build proves correspondence with C++ or TLA.

## Current Python semantics

The sole reducer supports all 18 emitted trace function names.

It now handles:

- regular vote and pre-vote packets by `packet.msg`
- same-term AppendEntries fallback
- check-quorum `become_follower`
- retirement membership and index observations
- `cleanup_nodes` as `appendRetiredCommitted`
- proposal vote sends and receives
- dropped proposal destination correlation
- terminal `None` to Lean `follower` normalization

The projected SMT includes state fields for:

- allocated
- joined
- role
- pre-vote status
- term
- log length
- commit index
- membership state
- retirement indices

It still does not encode the complete model state.

## Remaining proof work

### 1. Finish successor nomination

Verify all of these are present and proved:

- `ProposeVoteRequest`
- `.proposeVote source destination`
- `.advanceCommitIndexAndProposeVote source destination`
- proposal receive becomes candidate and increments term
- lowering
- preservation
- public wrappers
- simulator materialization completeness
- runtime parsing
- full-state witness support
- focused examples

The cancelled proposal agent left files in the worktree. Inspect before adding
anything.

### 2. Retired-committed provenance

The formal invariant must prove the TLA `RetiredCommittedInv` property:

> Every node named by a retired-committed entry has a prior committed
> configuration that removes it.

The old cached-index equality was insufficient.

Search:

```bash
rg -n "retiredCommitted|provenance|RetirementInvariantFacts" \
  MachineGenerated/Invariant.lean \
  MachineGenerated/ReconfigurationPreservation.lean
```

### 3. Complete SMT equivalence

This is the largest remaining milestone.

The Python SMT backend still over-approximates:

- exact logs and entry contents
- submitted transaction IDs
- sent and match indices
- vote state
- exact configurations and quorums
- queues and message contents
- first-message-from-source
- exact receive handlers
- exact commit calculation
- retirement observer sets

Required theorem chain:

```text
Python certificate
  -> typed Lean trace
  -> typed Lean formula
  -> emitted SMT-LIB
```

Prove:

```text
SMT satisfiable emitted text
  iff FormulaSatisfiable
  iff MidtraceSatisfiable
```

For SAT, reconstruct and replay a complete Lean witness.

For UNSAT, decide whether cvc5 self-checking remains trusted or add an
independent checker.

### 4. Final 50-scenario gate

After the Lean model and SMT equivalence are complete:

```bash
python3 audit_trace_coverage.py \
  --refresh-demo-certificates \
  --solve \
  --solver-timeout-seconds 300 \
  --require-all
```

Then run:

```bash
./check_demo.sh
```

## Generated and temporary files

Do not commit these logs:

- `lean-tracing-demo-ccfraft/.review-retirement.log`
- `lean-tracing-demo-ccfraft/.review-runtime.log`
- `lean-tracing-demo-ccfraft/.provenance-errors.log`

The report servers on ports 8773 and 8774 are detached background processes.
They are not needed on the new machine.

## Toolchain and setup

Run commands from `lean-tracing-demo-ccfraft/` so Elan reads
`lean-toolchain`.

Measured versions:

```text
Lean 4.28.0
Lake 5.0.0-src+7e01a1b
Python 3.12.9
cvc5 1.3.4
Nix 2.34.7
```

The machine-specific `/nix/store/.../cvc5` path in examples is not portable.
On another Nix machine:

```bash
cvc5_store="$(nix build --no-link --print-out-paths nixpkgs#cvc5)"
export PATH="$cvc5_store/bin:$PATH"
cvc5 --version
```

Restore the pinned Mathlib cache if needed:

```bash
cd lean-tracing-demo-ccfraft
lake exe cache get
```

## Exact focused Lean targets

Build these sequentially:

```bash
lake build MachineGenerated.PreVoteExamples
lake build MachineGenerated.CheckQuorumExamples
lake build MachineGenerated.RetirementExamples
lake build MachineGenerated.SuccessorNominationExamples
lake build MachineGenerated.Runtime.RetirementConsistencyExamples
lake build MachineGenerated.Runtime.SuccessorNominationExamples
```

Then build:

```bash
lake build Demo
lake build RuntimeAudit
```

The allowlist audit lives in:

- `lean-tracing-demo-ccfraft/Demo.lean`
- `lean-tracing-demo-ccfraft/RuntimeAudit.lean`

## Current successor-nomination files

The cancelled proposal agent left these uncommitted files and edits:

- `MachineGenerated/SuccessorNominationExamples.lean`
- `MachineGenerated/Runtime/SuccessorNominationExamples.lean`
- proposal message/action changes in `Model.lean`
- lowering changes in `MachineGenerated/Lowering.lean`
- preservation changes in
  `MachineGenerated/ReconfigurationPreservation.lean`
- simulator/runtime/witness changes under `MachineGenerated/Runtime/`

Search:

```bash
rg -n "ProposeVote|proposeVote|advanceCommitIndexAndProposeVote" \
  Model.lean MachineGenerated
```

## Complete SMT implementation paths

- Typed action/formula definitions:
  `MachineGenerated/Lowering.lean`
- Typed equivalence proof:
  `MachineGenerated/LoweringProofs.lean`
- Public trace contract:
  `TraceProperties.lean`
- Sole reducer and certificate schema:
  `reduction.py`
- Python SMT encoder and serializer:
  `Shared/smt.py`
- Solver runner and diagnostics:
  `validate.py`
- Old bounded SAT witness reconstruction:
  `MachineGenerated/Runtime/NaiveFullStateWitness.lean`
- Corpus gate:
  `audit_trace_coverage.py`

There is no current theorem connecting Python certificate decoding or emitted
SMT-LIB to `MachineGenerated.Formula`.

## Solver trust decision

For this MVP, the user explicitly chose to trust cvc5 for SAT and UNSAT.
Do not start a verified external proof checker unless that decision changes.

Still prove the encoding and serializer correspond to the typed Lean formula.
SAT should eventually reconstruct and replay a complete Lean witness. The
cvc5 decision itself remains trusted.

## Trace capture and emitted vocabulary

`audit_trace_coverage.py` invokes `build/raft_driver` directly for every file
under `tests/raft_scenarios/`.

To capture one scenario while debugging:

```bash
python3 audit_trace_coverage.py \
  --scenario reconfig_0_1 \
  --capture-dir Artifacts/corpus-traces \
  --output Artifacts/reconfig_0_1-coverage.json
```

The implementation emit sites are in:

- `src/consensus/aft/raft.h`
- `src/consensus/aft/test/driver.h`

The complete current event and packet counts are in
`Measurements/corpus-coverage.json`.

## Audited reducer abstractions

Two current transformations require focused regression coverage:

1. `configuration-callback-mixed-snapshot`
   - `add_configuration` mutates configuration/retirement state during the
     outer `replicate`.
   - Nested send callbacks see new membership state but stale `last_idx`.
   - The reducer emits `changeConfiguration` before the sends and omits only
     the nested send's stale `logLength`.
2. Terminal role normalization
   - C++ reports leadership state `None` for `RetiredCommitted`.
   - Lean abstracts this as `follower`.
   - `reduction.py` normalizes that one combination.

The retired-committed append is identified from the explicit
`cleanup_nodes,...` scenario command, not the writer's membership phase.

## Unrelated report edits

The worktree also contains dirty edits to:

- `Report/colleague-overview.html`
- `generate_colleague_report.py`

These came from a separate report-copy-edit thread. Preserve them, but do not
mix them into semantic reasoning. The next agent can commit them separately.

## Suggested skills

Invoke these skills before working:

- `principle-sequence-verifiable-units`
- `principle-fix-root-causes`
- `principle-build-the-lever`
- `machine-friendly-builds`
- `technical-writing` when updating the handoff or report
- `unslop` for any user-facing text

Use `how` when explaining the architecture. Use `why` when reconstructing
design rationale from history.

## Recommended next steps

1. Run the sequential build commands listed under "Current Lean proof state".
2. Inspect the dirty proposal-vote files before editing.
3. Run the focused successor nomination and retirement examples.
4. Run the final independent semantic review.
5. Commit the semantic model and proof slice separately from report edits.
6. Start complete SMT equivalence only after the Lean model checkpoint is
   clean and reviewed.

## Handoff snapshot

This document is committed separately from the semantic snapshot.

- Semantic commit:
  `2740abd99e867bbe8b777e0102794cc300b4aa1c`
- Parent:
  `be96121c6a9d0caa9b78cafa7c9984a0d1163e67`
- Remote: `origin/lean-ccfraft-slices`
- Semantic commit pushed: yes
- Expected worktree after the handoff-document commit:
  only unrelated `arena-bounded-containers/` remains untracked
