# CCFRaft trace validation demo

This directory contains the bounded trace validator and work on a sparse exact
encoder for the CCFRaft Lean model.

## Sparse proof foundation

`Sparse/` contains the reviewed semantic proofs for sparse logs, source-local
queues, integer and packet representations, and finite log summaries.
The entry point `Sparse.lean` imports their transitive axiom audits.

```bash
python3 export_sparse_proofs.py --check
nice -n 10 lake build Sparse
```

These commands use repository files and the pinned Lake dependencies. They do
not need the original session artifacts. `Sparse/provenance.json` records the
source hashes and proof-body hashes. The exporter changes namespaces and removes
diagnostic printing and the historical session command log.

New bridge modules add aligned multi-version interval completion, finite
membership traces, projection-backed readback hints, and typed scalar SMT terms.
They are ordinary repository source, separate from the exported snapshots.
`QueueReadback` connects finite equations to a whole queue execution under an
explicit plan and demand-closure invariant.
`QueuePlan.generated_exists_iff` constructs that plan and its closed demands.
For unconditional queue events, its finite constraints hold iff one concrete
queue of the supplied length executes the entire trace.
The theorem requires tracked-key coverage and a fresh filler value.

The opt-in solver fixtures exercise Lean-rendered scalar terms:

```bash
CCF_SPARSE_SMT_TESTS=1 CVC5=/path/to/cvc5 python3 -m unittest tests.test_sparse_smt
```

These fixtures cover term printing, not full trace correctness.

This is a proof library, not a complete sparse trace validator. Full Model
composition, SMT emission correspondence, and end-to-end performance remain
unfinished. The design and remaining work are in [HANDOFF.md](HANDOFF.md).

## Checked trace encoding

The checked encoder is a separate entry point:

```bash
python3 validate_checked.py \
  Traces/LeaderWrites/bootstrap-writes.json \
  Artifacts/checked-traces/leader-writes
```

Add `--cvc5 /path/to/cvc5` if cvc5 is not on `PATH`.

The runner builds `encode_trace` from the audited `EncodeTrace` module, then
runs that executable. Repeated encodings do not re-elaborate the Lean proofs.

The `ccfraft-trace/v1` schema accepts the four leader writes,
`appendEntries`, and all eleven control actions:
`advanceCommitIndex`, `timeout`, `becomePreVoteCandidate`, `becomeCandidate`,
`requestVote`, `requestPreVote`, `checkQuorum`, `updateTerm`, `becomeLeader`,
`proposeVote`, and `advanceCommitIndexAndProposeVote`.
Observations cover `role`, `currentTerm`, `logLength`, `queueLength`,
`commitIndex`, `allocated`, `joined`, and `submitted`.
The leader writes are `clientRequest`, `signCommittableMessages`,
`changeConfiguration`, and `appendRetiredCommitted`.
Single-node actions use `node`. Two-node actions use `node` for the source
and `destination` for the receiver. In particular, `updateTerm` updates the
destination from a newer queued message from the source; it does not take
an arbitrary term value. `clientRequest` supplies `transaction`,
`changeConfiguration` supplies a `configuration` array, and `appendEntries`
also supplies `batchEnd`. Entry can be the canonical bootstrap or an explicit
full-state template:

```bash
python3 validate_checked.py \
  Traces/ClientRequests/template.json \
  Artifacts/checked-client-requests/template
```

The v2 example has node 1 leading in term 7, a pre-existing log entry, and
symbolic old and new transaction IDs. Every other state field is explicit.
Unknown roles, terms, allocation, and queue shapes are not supported yet.
Other actions and raw NDJSON input remain unsupported. Unsupported syntax
is an error; the runner never falls back to the projected backend.

AppendEntries deduplication compares evaluated packets. Different transaction
unknowns can alias, so a send may retain the existing queue or append a packet.
The encoder carries these guarded alternatives through later actions and
observations under the same assignment. Constant guards collapse without
duplicating later frames. Queue-length observations use `node` to identify
the receiving queue.

Run the persistent send example:

```bash
python3 validate_checked.py \
	Traces/Replication/send.json \
	Artifacts/checked-traces/replication
```

The general schema declares exclusive `transaction_count`, `term_count`, and `index_count`
limits, plus inclusive `log_capacity` and `queue_capacity` limits. Bounds
apply before every instruction and at the end, including transaction payloads
inside queued AppendEntries messages. A bound violation produces UNSAT, not a
parse error. The older `ccfraft-client-request/v1` bootstrap and
`ccfraft-client-request/v2` template schemas remain accepted by the same encoder,
but retain their client-request-only action restrictions.

Transaction values are
natural numbers or references such as `{"unknown": "first"}` to names in the
`unknowns` array. Every occurrence of a name denotes the same value. All named
unknowns range from zero through `transaction_count - 1`. Different names may
denote the same value; client-request freshness is checked after evaluation.
JSON `null` is not a transaction unknown. It denotes an absent node slot or an
absent optional field where the schema permits one.

Every node-indexed table has exactly 15 entries in node-ID order. Template
field names match `Model.lean`, including votes, peer indices, all seven
message variants, and retirement metadata. The entry need not be reachable
from bootstrap: this is a bounded execution claim from the supplied template,
not a reachability claim. See `TraceStateJson.lean` for the exact JSON mapping.

`BoundedTrace.lean` is the reviewed execution contract.
`VerifiedEncoder` requires a single theorem, quantified over all supported
entries, traces, bounds, and assignments, connecting the actual formula to
that contract. Updates call `Model.next` on transaction-symbolic templates;
`TransactionMapping.lean` defines their evaluation into concrete model states.
The executable uses a value of this type and rejects unapproved proof axioms.
The proof is not regenerated for each input trace.

The assurance boundary is:

- Review the model, contracts, bounds, transaction mapping, JSON decoders,
  and `EncodeTrace.lean`, listed below.
- Lean checks representation roundtrips, transaction mapping, and encoding
  equivalence in `MachineGenerated/`.
- Review `Shared/Smt.lean`, `Shared/SmtOrder.lean`, solver execution, and core reduction
  as infrastructure. SMT serialization and cvc5 remain trusted.

The output includes `formula.smt2` and `constraint-map.json`. Each instruction
has a group ID and labelled component constraints. `--inspect-group N` changes
one action's assertion granularity without changing its meaning. Group indices
are recorded in the map; index 0 is the unknown-domain group, not an action.
In this mode, reduction removes only clauses of the selected action. Other
assertions in that run's solver core stay fixed. This does not yet reuse a
previously reduced high-level core. Use `refine_checked.py` for that second stage.
`instruction_index` is one-based, matching the existing reduction diagnostics.
Intermediate log lengths, terms, commit frontiers, accepted transaction IDs,
refreshed retirement indices and completion sets, allocation and join markers,
assigned sent indices, and queue lengths
have defining equalities in their action groups. Later constraints refer to these values
so the core can retain the actions that produced them.
A new enqueue defines the prior queue length plus one; a duplicate retains
the prior binding. Branch-local definitions have distinct names while references
to earlier actions keep their original names.
The equivalence theorem covers formula meaning. Diagnostic labels and their
source mapping are infrastructure metadata, not an additional proved claim.
Structural action guards are single clauses, so a failed guard does not yet
identify which model precondition failed.
A reduced SMT core is not a replayable subsequence of model actions: other
instructions can contribute concrete state used during encoding.

The runner writes the verdict to `result.json`. Reusing an output directory
replaces that run's artifacts, even if the new certificate is rejected.
Failures write `error.json` instead when the directory is writable.

SAT and UNSAT apply only to the supplied entry template and declared bounds.
They do not quantify over unspecified structural fields or establish an
unbounded result. The existing `validate.py` entry point still uses the
separate, unverified projection described below.

To run the focused checked-encoder gate:

```bash
./check_checked.sh
```

Set `CVC5` to an executable path if the solver is not on `PATH`.
The gate builds `ControlActionAudit`, `EncoderAudit`, and `encode_trace`,
runs the checked action, diagnostic, and explorer regressions, and requires SAT for the
persistent send example. Missing tools fail the gate rather than skip tests.
It does not build the unrelated safety proofs in `Demo`.

## Explore a reduced core

First produce a group-level checked run. Then generate its explorer:

```bash
python3 validate_checked.py \
	Traces/ClientRequests/wrong-log-length.json Artifacts/checked-traces/conflict
python3 explore_checked.py \
	Artifacts/checked-traces/conflict Artifacts/explorer/conflict.html
```

The standalone HTML has three panes: raw NDJSON, ordered actions and
observations, and the reduced core. Selecting an instruction shows its labelled
constraints and highlights its source lines. Pass `--raw-trace PATH` when the
certificate's instruction provenance refers to that file. Without a raw file,
the first pane says that the run starts from a certificate.

For each action remaining in an UNSAT core, the generator precomputes a
clause reduction with every other reduced group fixed. **Show reduced clauses**
displays that result; **Group view** returns to the high-level core. No discarded
group is restored. The report does not run a solver in the browser.
`--no-refine` omits clause reductions but retains full constraint inspection.
SAT and unknown runs show their status without a conflicting core.

To refine just one action without generating a report:

```bash
python3 refine_checked.py Artifacts/checked-traces/conflict \
	Artifacts/checked-traces/conflict-action-2 --inspect-group 2
```

The source directory remains unchanged. The refinement has its own formula,
constraint map, diagnosis, solver outputs, and result. The operation rejects
an action outside the reduced core or a formula that disagrees with its map.
Saved run artifacts remain trusted local inputs.

Both tools accept `--cvc5 PATH`. The explorer's `--workspace-uri` sets its
remote VS Code workspace link. The report embeds its data and needs no network
access except when you follow a source link.

## Review these files

The manual review boundary contains these files:

- `Model.lean` contains the model's types, state, and executable definitions,
  including `CCFRaft.Action`, `CCFRaft.Enabled`, and `CCFRaft.next`.
  Only inline proofs required to construct typed values remain here.
- `Properties.lean` defines the three consensus-safety claims.
- `reduction.py` defines the preprocessing and reduction rules.
- `TraceProperties.lean` defines `ValidEntryState`,
  `MidtraceSatisfiable`, `FormulaSatisfiable`, and `lowerTrace_correct`.
- `TraceInstructions.lean` defines typed instructions and observations.
- `BoundedTrace.lean` defines full-entry execution and the
  correctness requirement for its encoder.
- `BoundedState.lean` defines lossless finite state data and full-state bounds.
- `TransactionMapping.lean` defines transaction evaluation throughout a state.
- `TraceJson.lean`, `TraceStateJson.lean`, `LegacyClientRequestCertificate.lean`, and
  `TraceCertificate.lean` define the JSON mapping and v1 adapter.
- `EncodeTrace.lean` enforces the checked-encoder type and proof-axiom
  policy before emitting the formula and its constraint map.

The reducers separate three jobs:

1. Shared code parses and consumes the captured trace without changing its
   meaning.
2. Audited preprocessing groups or removes implementation events.
3. Audited reduction rules emit model actions and observations.

The reduction certificate has one ordered `steps` array. Each item is either:

```json
{"kind": "observation", "node": "2", "variable": "currentTerm", "value": 3}
```

or:

```json
{"kind": "action", "node": "2", "action": "receive", "source": "1"}
```

Array order defines the semantics. An observation reads the current state. An
action checks `Enabled` and advances the state with `next`.

Before every receive, the reducer emits a `firstMessageFrom` observation with
the packet fields available in the implementation trace. The Lean definition
means the first queued message from the chosen source equals that message.

## Do not manually review generated proofs

`MachineGenerated/` contains lowering code, proof bodies, and the inductive
model proof. An agent may replace these files. Lean must compile them without
`sorry` before the demo passes.

`MachineGenerated/ModelProofs.lean` contains the model's bootstrap, state-update,
retirement, and reachability lemmas. Proof consumers import this module for
the lemmas and their simplification rules. `Model.lean` does not import it.

`Shared/` contains model-independent trace and solver code. Review this code
once as infrastructure, not once per model.

## Claim made by the validator

`TraceProperties.lean` defines the intended claim. For one reduced trace,
`MidtraceSatisfiable` means that an entry state satisfying `ValidEntryState`
and a sequence of enabled `CCFRaft.next` transitions can explain every reduced
action and observation.

The result does not prove that the entry state is reachable from bootstrap.
It does not prove whole-implementation equivalence. Running many overlapping
segments provides operational evidence, not a stronger theorem.

The legacy `validate.py` backend checks only a projection of that claim.
`ccfraft_projection.py` models terms, roles, log lengths, commit indices, allocation,
and join state. It does not encode complete logs, messages, votes, or
configurations. Its `sat` and `unsat` results therefore do not yet establish
`MidtraceSatisfiable` for the complete model.

The projected backend checks the shape and ordering of `firstMessageFrom`, but
does not yet encode queues or message contents. The generated SMT file marks
that observation as an unencoded projection constraint.

`MachineGenerated/Lowering.lean` and
`MachineGenerated/LoweringProofs.lean` prove that the typed action
lowerings preserve the canonical Lean transition relation. The remaining
blocker is to connect the emitted SMT formula to that typed formula.

The projected backend trusts cvc5 for `sat` and `unsat`. For `unsat`, it saves
the cvc5 proof and unsat core and asks cvc5 to check both. It reduces the core
within a fixed wall-clock budget by removing deterministic chunks and then
individual assertions. It accepts a removal only when cvc5 still returns
`unsat`. It reconstructs a formula from the reduced core and generates the
proof from that formula. `diagnosis.json` maps each remaining constraint back
to its action or observation, reducer rule, and raw trace line.
The report records wall-clock time for the initial check, core generation,
budgeted reduction, and proof invocation.

For repeated timing measurements, run:

```bash
python3 benchmark_pipeline.py --cvc5 /path/to/cvc5
```

The benchmark removes only this package's `.lake/build` directory for the
clean project build. It retains the pinned toolchain and dependency cache. It
then runs five interleaved capture and validation samples per trace and writes
raw samples plus median and p90 values to `Measurements/pipeline.json`.

Generate the colleague overview from those measurements with:

```bash
python3 generate_colleague_report.py
```

The output is `Report/colleague-overview.html`.

## Run the demo

Run:

```bash
./check_demo.sh
```

The command:

1. Builds `Demo.lean` and checks every `CCFRaft` theorem for forbidden axioms.
2. Runs the Python reducer tests.
3. Checks that both captured traces are `sat`.
4. Checks that all four hand-edited traces are `unsat`.
5. Uses `jq -S` and `diff` to compare regenerated Python certificates with
   the checked-in certificates.
6. Writes `Report/index.html`.

The Python reducer is the sole reducer implementation. Its deterministic JSON
certificate is the input to SMT lowering.

To reproduce the captured implementation traces, run:

```bash
./Shared/capture_traces.py --check
```

This command invokes `build/raft_driver` directly. It does not call the old
semantic preprocessor in `tests/raft_scenarios_runner.py`.

## Source checkpoint

The original CCFRaft model and proof came from commit `73292060d`.
Development continues in this directory. Git history retains the retired
prototype encoders, reports, and one-time checkpoint migration script.
