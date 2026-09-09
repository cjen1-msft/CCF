# Resume the checked CCFRaft trace encoder

This is a migration checkpoint, not a completed implementation. It supersedes
the handoff in commit `dfd8669f5`. The user requested a portable handoff and a
commit of all repository changes while the next encoder slice was in progress.

## Start here

Repository: `cjen1-msft/CCF`. Branch: `lean-ccfraft-slices`.
All paths below are relative to `lean-tracing-demo-ccfraft/`, unless stated
otherwise. Do not assume the old machine's absolute paths exist.

The last completed semantic preparation is `032f02820`. The checkpoint after
that commit includes incomplete guarded trace encoding. In particular, accepted
JSON syntax is ahead of the last confirmed executable encoder.

The session's commits have not been pushed by this assistant. Transfer this
branch, not just the older remote branch. For an offline transfer, run this
from the repository root and copy the resulting bundle to the other machine:

```bash
git bundle create ../ccf-checked-trace-handoff.bundle lean-ccfraft-slices
```

In an existing clone on the destination machine:

```bash
git fetch /path/to/ccf-checked-trace-handoff.bundle \
	lean-ccfraft-slices:lean-ccfraft-slices
git switch lean-ccfraft-slices
cd lean-tracing-demo-ccfraft
git status --short
```

The sibling directory `../arena-bounded-containers/candidate-1/` contains
pre-existing design documents and an HTML prototype. The migration request
includes these files in the repository checkpoint. They were not implementation
work from this session, and their proposals are not an adopted specification.

## Restore the environment

Use the versions in `lean-toolchain` and `lake-manifest.json`. This work used
Lean 4.28.0 and cvc5 1.3.4. Python tests use the standard library. Black is the
existing Python formatter.

Install the pinned Lean toolchain through elan. Restore Lake dependencies and
their cached artifacts using the project's normal Lake workflow. Do not update
the pinned mathlib revision merely to fix a build.

The old host was Azure Linux 3 with Nix. A portable solver selection is:

```bash
nix shell nixpkgs#cvc5
export CVC5="$(command -v cvc5)"
```

The user has explicitly authorized cvc5 execution. Do not ask again.

Build a known independent target first:

```bash
nice -n 10 lake build ControlActionAudit
```

The eventual complete encoder gate and native executable are:

```bash
nice -n 10 lake build EncoderAudit
nice -n 10 lake build encode_trace
```

These last two commands may fail at this checkpoint because guarded trace
encoding is unfinished. Do not bypass the proof gate to get a solver verdict.
Do not run the entire default `Demo` target as the first diagnostic.

`validate_checked.py` builds `encode_trace` from the audited `EncodeTrace`
module and runs `.lake/build/bin/encode_trace`. It no longer runs
`lake env lean --run` per certificate. The first native build compiled thousands
of mathlib C objects and took many minutes. That is distinct from solver time.
On the old host, a representative encoding fell from about 17 seconds to
0.2 seconds after native compilation. The Lake build check still has overhead.

Use low-priority builds. Do not add arbitrary memory limits or timeouts.
Batch related test selectors, and avoid repeated full suites.

## Required correctness boundary

The user rejected the old Python SMT projection because its transitions had
no proved link to `Model.lean`.

Python should emit observations and proposed actions, including unknowns.
Lean must generate constraints with a generic, machine-checked correspondence
to the actual model. No proof is generated per trace.

The reviewed contract is `BoundedTrace.VerifiedEncoder`. For every entry
template, trace, bounds, and the **same assignment**, it requires:

```lean
(encode bounds entry trace).Holds assignment <->
  (forall index, assignment index < bounds.transactionCount) /\
    Follows bounds assignment
      (TransactionMapping.mapState (TraceSmt.NatTerm.eval assignment) entry)
      trace
```

`Follows` uses real `Model.Enabled` and `Model.next`, with full bounds before
each instruction and at the end. `encode_holds_correct` is the pointwise
theorem. `encode_correct` is its existential satisfiability corollary.

Review boundaries:

| Category | Files and responsibility |
| --- | --- |
| Reviewed model-specific contracts | `Model.lean`, `TraceInstructions.lean`, `BoundedTrace.lean`, `BoundedState.lean`, `TransactionMapping.lean`, JSON decoders, `EncodeTrace.lean`, audit entry points |
| Machine-checked implementation | `MachineGenerated/` encoder, representation, equality, mapping and guarded-step proofs |
| Reviewed reusable infrastructure | `Shared/Smt.lean`, `SmtOrder.lean`, `Equality.lean`, `Guarded.lean`, SMT serialization, solver execution, core reduction |

The allowed proof axioms are `propext`, `Classical.choice`, and `Quot.sound`.
No `sorry`, new axioms, `native_decide`, unsafe extraction, or runtime bypasses.
The executable encoder must be computable.

The theorem covers the formula AST's meaning. JSON decoding, serialization,
the compiler, cvc5, and diagnostic provenance remain trusted. Labels and core
membership are not a second formal correspondence theorem.

## Completed commits

| Commit | Completed unit |
| --- | --- |
| `c04ceca25` | Full explicit entry templates, four leader writes, pointwise checked encoder, Python orchestration, causal core diagnostics, removal of retired code |
| `359931271` | Native audited encoder executable and build-cache invalidation |
| `bd9e59adc` | Generic list equality and exact symbolic entry and packet equality under transaction aliasing |
| `cf9b2ff2c` | Exact AppendEntries request mapping and conditional deduplication correction |
| `83f4ea642` | Executable guarded choices with generic evaluation, composition and queue-operation proofs |
| `50ed2728e` | Executable guarded AppendEntries step, aliasing regressions, shared tests in the audit |
| `032f02820` | Mapping and enabledness proofs for eleven control actions, with `ControlActionAudit` |

The last confirmed end-to-end CLI supports `clientRequest`,
`signCommittableMessages`, `changeConfiguration`, and
`appendRetiredCommitted`. Sixteen focused integration cases passed before
native compilation. Twenty-two cases, including toolchain failure paths,
passed through the native executable.

The general leader-write example returned SAT:

```bash
python3 validate_checked.py \
	Traces/LeaderWrites/bootstrap-writes.json \
	Artifacts/checked-traces/leader-writes --cvc5 "$CVC5"
```

The guarded AppendEntries **step** is complete and proved, but this does not
mean arbitrary traces containing it have passed the full encoder.

## Current partial slice

The checkpoint adds these reviewed interface changes:

- `Instruction.appendEntries source destination batchEnd`.
- `Observation.queueLength node value`.
- A direct AppendEntries clause in `BoundedTrace.Follows`.
- General-schema JSON fields `node`, `destination`, and `batchEnd`.
- Queue-length observations through the observation decoder.
- Updated supported-action metadata and Python coverage text.
- `tests/test_replication_encoding.py` and `Traces/Replication/send.json`.

`MachineGenerated.TraceCertificateTests` passed, including required send
arguments and legacy-schema rejection. The persistent replication fixture
matches its Python builder. The new replication solver tests have not passed
as a group yet. README coverage still describes the last completed CLI slice.

Active implementation files at migration:

- `MachineGenerated/TraceEncoding.lean`
- `MachineGenerated/TraceEncodingProofs.lean`
- `Shared/Guarded.lean`
- `Shared/GuardedTests.lean`

These contain partial guarded-frame encoding, branch-specific binding
namespaces, queue-length tracking, and associated proofs. Preserve this work.
Do not revert it to make the old four-action build green.

The paused agent's final notes, if available, are recorded in the checkpoint
status section at the end of this document.

## Complete guarded trace encoding next

Keep one group for each instruction: group 0 is unknown domains, groups 1
through N are instructions, and the final group is final-state bounds.
Fine inspection must retain individually labelled field constraints.

Use `GuardedAppendEntries.step` and `step_correct`, not a copied transition.
Propagate guarded state alternatives through the whole trace. Bounds,
enabledness and observations must constrain the selected branch under the
same assignment.

Preserve these diagnostic properties:

- Existing log-length, transaction, retirement, allocation, join and sent-index
  bindings remain causal.
- An actual enqueue defines a named queue length from previous length plus
  one. A duplicate retains the previous length.
- Queue observations and capacity checks use the symbolic tracked length,
  not an additional constant physical-length constraint.
- Distinct branch histories get distinct slots for newly defined values.
  Ancestor bindings retain their original names and owners.
- Branches known to be true or false are simplified rather than multiplied.

`Formula.prepare` rejects conflicting definitions of the same group and slot.
Its definitions are unconditional total equations. Distinct branch-local
names are therefore essential. Inlining every name is not an acceptable fix
because it loses causal action attribution.

After the proof and native executable build, run the focused integration set:

```bash
nice -n 10 python3 -m unittest -v \
	tests.test_replication_encoding \
	tests.test_leader_writes \
	tests.test_client_request_encoding.SatisfiableCertificateTests \
	tests.test_client_request_encoding.ToolchainFailureTests \
	tests.test_template_client_requests.TemplateClientRequestTests.test_distinct_names_do_not_imply_distinct_transaction_values \
	tests.test_template_client_requests.TemplateClientRequestTests.test_log_capacity_core_keeps_the_causal_action \
	tests.test_template_client_requests.TemplateClientRequestTests.test_retirement_refresh_bound_keeps_the_causal_action
```

Then run the persistent send example:

```bash
python3 validate_checked.py \
	Traces/Replication/send.json \
	Artifacts/checked-traces/replication --cvc5 "$CVC5"
```

Critical regressions cover semantic packet aliases, forced distinctness,
queue capacity, repeated heartbeats, causal send cores, fine inspection, and
later writes after a symbolic queue branch. Update README only after these
paths work. Independently review the evidence-backed result, then commit this
slice before starting the next integration.

## Remaining semantic work

`ControlActionMappingProofs.lean` exports `mapState_<action>` and
`enabled_mapState_<action>_iff` for:

`advanceCommitIndex`, `timeout`, `becomePreVoteCandidate`, `becomeCandidate`,
`requestVote`, `requestPreVote`, `checkQuorum`, `updateTerm`, `becomeLeader`,
`proposeVote`, and `advanceCommitIndexAndProposeVote`.

These are arbitrary-state, non-injective mapping proofs. They are not yet
accepted trace instructions. Integrate them into the guarded encoder in small
families. Their local-state changes also need causal tracking for observed
roles, terms, indices and truncated logs.

### Receive

`receive` is the remaining semantic obstruction, not an ordinary unconditional
mapping lemma. `noConflictExtension` compares full entry prefixes. Two
syntactically different transaction terms can become equal after evaluation,
changing both enabledness and successor state.

A receive implementation was requested in new `ReceiveMappingProofs.lean`,
`GuardedReceive.lean`, and `GuardedReceiveTests.lean`. Any files present at
checkpoint are partial unless the final notes explicitly say otherwise.

The proposed approach is to prove ordinary handler mapping under an exact
prefix-equality agreement, then use a guarded normalization of decode-equal
prefix representatives before calling real `Model.Enabled` and `Model.next`.
Normalizing either the incoming prefix or the local prefix must preserve the
decoded pre-state, queue order, and absent node slots. This is a design
proposal, not a completed proof.

The minimal regression has a follower with one transaction entry and a
two-entry request whose first transaction uses another unknown. Equal terms
do not imply equal transaction IDs. Aliasing can enable the extension while
a distinct assignment leaves it disabled. Same-term candidate step-down
must leave the request queued, as the actual model does.

### Symbolic entry controls and shapes

Only transaction IDs are unknown in the completed encoder. Roles, terms,
allocation, log shape and queue shape are explicit at entry. Guarded queue
alternatives after a send do not solve arbitrary symbolic entry states.

The intended next design uses verified guarded operations over bounded
containers. Whole-state enumeration is not a practical substitute for
15-node states. Do not fabricate concrete values for unobserved fields or
silently strengthen the entry-state assumptions.

### Raw trace integration and explorer

`reduction.py` remains the only reducer. `validate.py` still uses the unproved
projection in `ccfraft_projection.py`. Do not restore the old `Reduction.lean`.

The raw reducer's partial observations do not supply a complete explicit entry
state. Connect it to the checked backend only after the missing symbolic entry
semantics exist. Unsupported syntax must fail explicitly, never fall back.
Remove the projection only after its live callers migrate.

The requested HTML explorer remains unimplemented. It has three horizontal
panes: raw NDJSON, ordered reduced actions and observations with core
highlighting, and the reduced core. Selecting an action opens its detailed
constraints. Reduction first removes instruction groups, then refines one
selected action while keeping the other reduced context fixed. Use "reduced",
not "minimum". Existing `--inspect-group` does not yet implement this full
two-stage workflow.

## Data and diagnostic constraints

- Bounds on transactions, terms and indices are exclusive. Log and queue
  capacities are inclusive.
- Full bounds include all seven packet variants, queued payloads, every peer
  index, optional retirement indices and submitted transaction IDs.
- An absent node is not an allocated fresh node. Node tables have 15 slots.
- Entry templates need not be reachable or satisfy extra protocol invariants.
- Different unknown names may alias. Freshness uses evaluated submitted IDs.
- Non-injective mapping may merge submitted IDs and packet identities.
- `appendEntries` cannot use unconditional transaction-map commutation.
  Its guarded step preserves real sender updates but suppresses an enqueue
  when the evaluated packet is already queued.
- A reduced SMT core is not a replayable subsequence of model actions.
  Concrete state during encoding may depend on the full prefix.
- Structural guards are currently coarse clauses. Not every failed
  precondition has its own fine-grained label.

Schemas remain `ccfraft-trace/v1`, `ccfraft-client-request/v1`, and
`ccfraft-client-request/v2`. Legacy schemas restrict actions to client
requests. The v1 bootstrap adapter derives term count 2, index count 1 and
queue capacity 0. General and v2 certificates declare all five bounds.

## Existing failures and cleanup

Full safety proofs in the default `Demo` target had failures reproduced
against the untouched starting commit. Do not attribute those failures to the
new encoder or repair them as an unrelated part of this migration.
`EncoderAudit`, `ControlActionAudit`, and targeted runtime tests are the
relevant checks for these slices. `RuntimeAudit` had also passed earlier.

Completed cleanup removed the old bootstrap-only encoder, 36 archived
prototype files, `bootstrap_from_checkpoint.py`, and the unused long-trace
probe. It moved 36 theorem blocks out of `Model.lean` into
`MachineGenerated/ModelProofs.lean` without changing model definitions.
Keep live legacy projection and runtime consumers until their replacements
are connected.

Ignored `.lake/` build products and `Artifacts/` solver outputs are not portable
source dependencies. Regenerate them. The old Copilot session directory was
`/home/cjen1-msft/.copilot/session-state/ad3933b2-6bbf-4ed0-bd2e-bfdd2b54f302/`.
Its logs and SQLite task state are not required to resume from this document.

## Checkpoint status

Stop requests were sent to both implementation agents before preparing this
checkpoint. Do not resume their old IDs on the new machine. Resume from the
committed files and the status recorded here.

The agent handles were no longer available when migration resumed. No final
stop acknowledgements or compiler-error handoffs could be retrieved.
No receive implementation files were present in the checkpoint inventory.
The guarded encoder sources contain the intended theorem declarations,
including `encode_holds_correct` and `checkedEncoder`, but their presence is
not evidence that the current versions compile. No explicit `sorry` or
`admit` was found in the changed encoder and guarded helper sources.

The latest fully completed independent command was
`nice -n 10 lake build ControlActionAudit`. The whole guarded trace encoder
has not been declared complete. This checkpoint intentionally preserves
unfinished implementation rather than discarding it.
