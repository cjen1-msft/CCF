# Resume the checked CCFRaft trace encoder

The guarded AppendEntries and control trace slices are complete. This document supersedes
the unfinished migration checkpoint in `f1c84033b`. Receive trace integration,
symbolic entry controls, and raw-trace integration
remain unfinished.

## Start here

Repository: `cjen1-msft/CCF`. Branch: `lean-ccfraft-slices`.
All paths below are relative to `lean-tracing-demo-ccfraft/`, unless stated
otherwise. Do not assume the old machine's absolute paths exist.

The control-action mapping proofs in `032f02820` are integrated into
trace instructions. The executable supports the four leader writes, guarded
`appendEntries`, and all eleven control actions.

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

Use the versions in `lean-toolchain` and `lake-manifest.json`. The completed
slice used Lean 4.28.0 and cvc5 1.3.4. Python tests use the standard library.
Black is the existing Python formatter.

Install the pinned Lean toolchain through elan. Restore Lake dependencies and
their cached artifacts using the project's normal Lake workflow. Do not update
the pinned mathlib revision merely to fix a build.

Ensure `tar` and `gzip` are available before fetching Lake release archives
and running `lake exe cache get`. A Nix environment for restoration and the
solver is:

```bash
nix shell nixpkgs#gnutar nixpkgs#gzip nixpkgs#cvc5
export CVC5="$(command -v cvc5)"
```

The user has explicitly authorized cvc5 execution. Do not ask again.

Build a known independent target first:

```bash
nice -n 10 lake build ControlActionAudit
```

The completed encoder audit and native executable are:

```bash
nice -n 10 lake build EncoderAudit
nice -n 10 lake build encode_trace
```

These commands pass at this checkpoint.
Do not bypass the proof gate to get a solver verdict.
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
| `c60b54f81` | Guarded AppendEntries trace encoding and same-assignment correspondence |
| `2ca80ab43` | Truncated SMT natural subtraction for causal decreases |
| `f5907da7e` | Guarded receive enabledness and successor correspondence, all packet variants |
| `3c0bd951c` | Fixed-context core refinement and standalone source-linked explorer |
| `88f246b25` | Raw identifier normalization and exact partial-message observation contract |
| `9f7ddc1d7` | Stored retirement and pre-vote observation contract and decoder |
| `f8836d49c` | Compositional symbolic state, exact bounds, finite containers and SMT serialization |
| `9478d8430` | Generic symbolic trace composition and symbolic partial-message observations |
| `8f3dd1b1d` | Symbolic stored retirement and pre-vote observations |
| `c7fbf01ab` | Full-model symbolic trace contract and complete observation dispatch |
| `e28cc28aa` | Strict symbolic certificate decoder with six saved raw-trace regressions |
| `94850592f` | Typed intermediate names, owner-group equations, and strict serialization |
| `c83a33f11` | Whole-state causal naming with proved indexed trace composition |
| `efbafbaaa` | Symbolic assurance metadata and matching explorer contract links |
| `dd1bea352` | Coarse and fine symbolic output with matching constraint metadata |
| `e4f626a4b` | Exact named-definition comparison without repeated shared-tree traversal |
| `432ba9feb` | Proved conditional natural values with causal predicate retention |
| `a6274e2e8` | Shared solver reuse and restored PATH discovery in the raw runner |
| `b7fa4f6d0` | All eleven control actions, complete causal tracking, and send scaling regressions |
| `214a222af` | Exact memoized equality for independently allocated symbolic expression DAGs |
| `ff7faf2be` | Proved symbolic evaluation with an assignment-local cache |

The end-to-end CLI supports `clientRequest`,
`signCommittableMessages`, `changeConfiguration`,
`appendRetiredCommitted`, `appendEntries`, and all eleven control actions.
The expanded `check_checked.sh` gate passes 184 tests without skips,
including symbolic infrastructure and controls. Independent review closed the
causal-tracking and repeated-send scaling findings.

The general leader-write example returned SAT:

```bash
python3 validate_checked.py \
	Traces/LeaderWrites/bootstrap-writes.json \
	Artifacts/checked-traces/leader-writes --cvc5 "$CVC5"
```

The guarded AppendEntries step and full trace composition are now proved.
The general same-assignment `encode_holds_correct` theorem remains unchanged.

## Completed guarded trace slice

The general schema and reviewed interfaces include:

- `Instruction.appendEntries source destination batchEnd`.
- `Observation.queueLength node value`.
- A direct AppendEntries clause in `BoundedTrace.Follows`.
- General-schema JSON fields `node`, `destination`, and `batchEnd`.
- Queue-length observations through the observation decoder.
- Updated supported-action metadata and Python coverage text.
- `tests/test_replication_encoding.py` and `Traces/Replication/send.json`.

`MachineGenerated.TraceCertificateTests` passes, including required send
arguments and legacy-schema rejection. The persistent replication fixture
matches its Python builder and returns SAT. README coverage includes this slice.

Implementation files:

- `MachineGenerated/TraceEncoding.lean`
- `MachineGenerated/TraceEncodingProofs.lean`
- `Shared/Guarded.lean`
- `Shared/GuardedTests.lean`

These implement guarded-frame encoding, branch-specific binding namespaces,
queue-length tracking, and their proofs. Local AppendEntries tracking lemmas
require an allocated sender because `next` can allocate a sender even when
the action is disabled. The trace proof derives allocation from `Enabled`
and rejects disabled actions. The public theorem still covers arbitrary
entry templates.

## Preserve the guarded trace invariants

Keep one group for each instruction: group 0 is unknown domains, groups 1
through N are instructions, and the final group is final-state bounds.
Fine inspection must retain individually labelled field constraints.

Use `GuardedAppendEntries.step` and `step_correct`, not a copied transition.
Guarded state alternatives propagate through the whole trace. Bounds,
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

Run the repeatable proof, native-build, integration, and persistent-fixture gate:

```bash
CVC5="$CVC5" ./check_checked.sh
```

To run the persistent send example separately:

```bash
python3 validate_checked.py \
	Traces/Replication/send.json \
	Artifacts/checked-traces/replication --cvc5 "$CVC5"
```

Passing regressions cover semantic packet aliases, forced distinctness,
same-assignment queue observations, queue capacity, repeated heartbeats,
causal send cores, fine inspection, absent senders, and later writes after
a symbolic queue branch. Shared guard and trace correspondence changes
received separate independent reviews with no material findings.

## Remaining semantic work

`ControlActionMappingProofs.lean` exports `mapState_<action>` and
`enabled_mapState_<action>_iff` for:

`advanceCommitIndex`, `timeout`, `becomePreVoteCandidate`, `becomeCandidate`,
`requestVote`, `requestPreVote`, `checkQuorum`, `updateTerm`, `becomeLeader`,
`proposeVote`, and `advanceCommitIndexAndProposeVote`.

These arbitrary-state, non-injective mapping proofs are integrated into the
guarded encoder. Repairs cover copied fields, conditional commit
frontiers, retirement-completed sets, truncated term lookups, and downstream
guards and bounds. Queue deduplication also avoids spurious retransmission
writers. Both queue-update helpers retain the old length once and condition
only the increment. Duplicate control sends also reuse unchanged network and
tracking functions. The scaling regression checks binding traversal growth
before 24- and 48-send native cases, without wall-clock limits.
The complete 184-test gate passes, and independent review found no remaining
issues. Concrete receive integration is next.

### Receive

`receive` requires guarded semantics, not an unconditional mapping lemma.
`noConflictExtension` compares full entry prefixes. Two
syntactically different transaction terms can become equal after evaluation,
changing both enabledness and successor state.

`ReceiveMappingProofs.lean`, `GuardedReceive.lean`, and
`GuardedReceiveTests.lean` implement and prove exact guarded receive semantics.
The implementation uses direct symbolic prefix equality, not normalization.
`GuardedReceive.step state source destination` returns guarded enabledness
and successor fields. `step_enabledExpr_correct` and `step_correct` relate
them to real `Enabled` and `next` under the same arbitrary assignment.
The step has 100 executable regressions and a transitive allowed-axiom audit.

Trace integration remains pending. Constrain selected `enabledExpr` values
under their branch guards. Track consumption with `.sub oldQueueLength 1`;
deduplicate responses against the post-removal queue. For self-receives,
compose removal and response insertion on the same tracked queue.

The minimal regression has a follower with one transaction entry and a
two-entry request whose first transaction uses another unknown. Equal terms
do not imply equal transaction IDs. Aliasing can enable the extension while
a distinct assignment leaves it disabled. Same-term candidate step-down
must leave the request queued, as the actual model does.

### Symbolic entry controls and shapes

Only transaction IDs are unknown in the completed encoder. Roles, terms,
allocation, log shape and queue shape are explicit at entry. Guarded queue
alternatives after a send do not solve arbitrary symbolic entry states.

The compositional foundation is committed in `Shared/Symbolic*.lean`,
`Shared/BoundedContainer.lean`, and `MachineGenerated/Symbolic*.lean`.
It represents all 15 node slots, roles, scalar fields, finite sets, optional
fields, logs, and packet queues without whole-state alternatives.
`stateWithin_correct` proves exact agreement with full model bounds.
Inactive fields do not inherit scalar-domain restrictions, so an all-absent
empty state remains possible when scalar bounds are zero.

`freshEntry_complete` currently requires the recursive `Fits` capacity
predicate. The bridge from arbitrary bounded model states to that predicate,
and actual symbolic model transition encoding, remain unfinished.
`Shared.SymbolicTrace.encode_correct` composes adapters under the same
assignment. Each adapter must prove real model enabledness, successor, and
observation correspondence on bounded states. This generic theorem does not
replace the unfinished model adapters.

`BoundedSymbolicTrace.VerifiedEncoder` now states the actual-model symbolic
contract for arbitrary entry expressions. Structural holes have their own
types and capacity constraints. Explicit transaction names occupy indices
`entryWidth bounds + nameIndex` and alone receive transaction-domain constraints.
`MachineGenerated.SymbolicTraceEncoding.Adapter` requires exact rejection of
disabled actions and unbounded actual successors. Its successor theorem
requires representation only when the actual successor is bounded.
Every `Follows` suffix already requires these bounds, so this condition does
not weaken the public trace correspondence.

`Expr.named` evaluates its underlying expression under the same assignment.
Normalization retains the name. Grouped serialization gives each name a typed
constant and a total defining equality in its producer group.
The symbolic trace encoder names the initial state in group 0 and each
successor in its action group. Observations advance instruction numbering
without introducing state writes. `tests.test_symbolic_causality` checks that
an inconsistent counter trace retains its entry, writer, and observation
groups, and that removing any of them makes the constraints satisfiable.
This test covers shared composition, not the unfinished model transitions.

`Shared/SymbolicNamedScalingTests.lean` exercises repeated product updates
whose fields share the previous named state. Structural comparison of every
duplicate definition previously traversed those shared trees repeatedly.
The serializer now uses Lean's safe `withPtrEq` API with structural equality
as its fallback. `sameDefinition_correct` proves that the result is unchanged.
The 64-update fixture serializes to 24,544 bytes and cvc5 accepts it.

`Shared/SymbolicSharing.lean` adds opt-in typed equality for independently
allocated expression DAGs. Address hints select cache buckets, but every hit
still checks both typed expressions. The safe Lean API requires the result to
be independent of those hints. Equality proofs and the transitive axiom audit
cover that boundary. Separate doubled and overlapping DAGs at depth 64 compare
in about 2 ms in the fixture.

`Shared/SymbolicEvalMemo.lean` provides `Expr.evalMemo` and `Expr.evalMemoM`.
Cached values carry proofs for the assignment indexed by `EvaluationState`.
The same-assignment theorem preserves `Expr.eval`; names evaluate their
underlying definitions. Regressions cover all constructors, short-circuiting,
hash collisions, and independently allocated DAGs.

Run these committed units separately:

```bash
nice -n 10 lake build Shared.SymbolicSharingMain Shared.SymbolicEvalMemoMain
nice -n 10 lake env lean --run Shared/SymbolicSharingMain.lean
nice -n 10 lake env lean --run Shared/SymbolicEvalMemoMain.lean
```

These libraries do not complete symbolic Receive integration. Normalization
and serialization must also preserve sharing without losing useful selector
and sequence simplification. Native Receive execution remains a separate
gate; small DAG regressions do not establish its performance.

First-source queue selection uses a skipped-prefix accumulator. The earlier
implementation traversed its recursive result three times per level.
`Shared/SymbolicContainerScalingTests.lean` exercises complete selected-packet
results at capacities 16 and 32, with a 200 KB serialized-size ceiling.
`tests.test_symbolic_encoding` runs 13 cvc5 cases for operations, aliases,
15-node entries, partial packets, finite selectors, and zero bounds.

### Raw trace integration and explorer

`reduction.py` remains the only reducer. `validate.py` still uses the unproved
projection in `ccfraft_projection.py`. Do not restore the old `Reduction.lean`.

The raw reducer's partial observations do not supply a complete explicit entry
state. Connect it to the checked backend only after the missing symbolic entry
semantics exist. Unsupported syntax must fail explicitly, never fall back.
Remove the projection only after its live callers migrate.

`raw_normalization.py` preserves instruction order and provenance, converts
transaction names to shared unknowns, and retains correlation evidence
separately by instruction index. Node IDs must remain canonical slots 0 through
14 because renumbering would change the model's implicit bootstrap configuration.
AppendEntries summaries constrain payload length as `batchEnd - previousIndex`,
not the absolute batch end. Missing payloads and previous terms remain unobserved.
`TraceMessageSummary` and `SymbolicMessageSummary` prove the exact partial
observation against the first matching-source packet, not a later match.

The strict `ccfraft-symbolic-trace/v1` decoder accepts `entry: "symbolic"`,
all 17 model actions, and the complete symbolic observation type.
`NormalizedTrace.certificate(bounds)` supplies its input without fabricating
entry fields. Run `python3 -m unittest tests.test_symbolic_trace_decoding`
to parse all six saved normalized traces through Lean. This is a decode-only
check, not an execution or solver verdict.

The HTML explorer is implemented by `explore_checked.py`. It has three horizontal
panes: raw NDJSON, ordered reduced actions and observations with core
highlighting, and the reduced core. Selecting an action opens its detailed
constraints. `refine_checked.py` implements the second reduction stage inside
an existing group-level core, keeping all other reduced groups fixed even if
the solver's next core omits them. The static explorer precomputes these
refinements for core actions and switches views without a browser solver.
It displays raw files supplied with `--raw-trace`, using instruction provenance.
The raw-to-checked semantic integration is still pending; displaying raw text
does not establish that missing correspondence.

See README's "Explore a reduced core" section. The generator rejects malformed
metadata and stale or non-checked verdicts. Saved run artifacts themselves are
trusted inputs. Browser interaction regressions are in `tests.test_explorer`;
run them with Chromium on PATH. Missing browser support does not affect the
Lean proof gate.

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

Live schemas remain `ccfraft-trace/v1`, `ccfraft-client-request/v1`, and
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
source dependencies. Regenerate them. Session logs and task state are not
required to resume from this document.

## Checkpoint status

The last complete checked-encoder gate passed 184 tests with no skips and
returned SAT for the persistent send example. It includes the control
causality and repeated-send corrections. The two newer shared-DAG libraries
have separate proof, runtime, and independent-review results; the full gate
must run again after Receive and the symbolic model adapters are integrated.
`EncoderAudit` enforces the allowed proof axioms transitively.
The receive step is complete but not yet exposed as a trace instruction.
Resume from committed files, not old agent handles. Symbolic entry-state
lowering remains the prerequisite for migrating raw traces.
