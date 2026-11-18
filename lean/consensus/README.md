# CCF consensus protocol model

An executable Lean model of the CCF consensus protocol ([`src/consensus/aft/cft.h`](../../src/consensus/aft/cft.h)) and the safety properties it is intended to satisfy.
It assumes familiarity with the [CCF consensus protocol documentation](../../doc/architecture/consensus/index.rst).

## Source map

| Area                                   | Source                                                                                                                         |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Node state, log entries, log queries   | [`Model/NodeState.lean`](Consensus/Model/NodeState.lean)                                                                       |
| Configurations, quorums, retirement    | [`Model/ClusterConfig.lean`](Consensus/Model/ClusterConfig.lean) (`activeConfigurations`, `hasQuorum`, `NodeState.retirement`) |
| Messages                               | [`Model/Messages.lean`](Consensus/Model/Messages.lean)                                                                         |
| Protocol policy (one node's step)      | [`Model/Node.lean`](Consensus/Model/Node.lean) (`Node.step`, `receive`, `act`, `highestCommittableIndex`, `eligiblePeers`)     |
| Initial states and network composition | [`Model.lean`](Consensus/Model.lean) (`initialNodeState`, `transitionSystem`)                                                  |
| Safety theorems and witness lemmas     | [`Properties.lean`](Consensus/Properties.lean)                                                                                 |
| Valid initial memberships              | [`Properties/Config.lean`](Consensus/Properties/Config.lean)                                                                   |
| Supporting proofs and executions       | [`Proofs/`](Consensus/Proofs)                                                                                                  |
| Action-trace tests                     | [`Tests/CanonicalTraces.lean`](Consensus/Tests/CanonicalTraces.lean)                                                           |

Transition systems, traces, effects and network composition come from the local [`ccf_common` package](../common/README.md).
Each node reads membership, quorums and retirement from its own ledger; there is no model-wide configuration after initialization.
Initialization takes a nonempty initial voting membership, whose smallest member starts as primary with the genesis configuration transaction.
Actions are local inputs (including timeouts) or delivery of a queued message; no clock is modeled.

## Scope

Like CCF's `init_as_backup`, a fresh node may initialize once as a follower: with an empty ledger in term zero, or from another node's committed ledger prefix ending at a signature, in that signature's term.
Crashes are not modeled, so a committed prefix keeps its history, and a valid snapshot, fetched from another node or read from a local file, is such a prefix ([`Model.networkStep`](Consensus/Model.lean)).
The join protocol is not modeled: any configuration may add a node, and a fresh node may instead follow from its first AppendEntries.
There are no liveness properties or fairness assumptions.

## Validation

Install Lean via [elan](https://lean-lang.org/install/), then run from this directory:

```sh
lake build --wfail --fail-fast
lake exe check-imports
lake lint
lake exe replay-checks
../../scripts/lean-format-checks.sh consensus
```

Run `lake check` only in CI, not locally.
The [kernel check](replay/README.md#kernel-checks) builds with compiler warnings, including `sorry`, treated as errors, before replaying the compiled proofs in Lean's kernel and rejecting nonstandard axioms.
Kernel tracing reports the declarations checked during compilation; cached modules do not emit fresh compilation traces.
CI runs this before import coverage, formatting, and linting so the initial build and its traces occur in this step.
The build also runs explicit action traces from an initialized network: committing a client request, and adding two nodes, one joining from a snapshot, then electing a new primary and committing another request.
The reconfiguration trace checks each node's ledger before delivery, after setup, after replication and commitment, after election, and after the new primary's client request.
Append regressions check configuration heartbeats followed by flushing, pre-commit packet headers, per-entry flushing, term-bounded packets, and atomic rejection of invalid flush choices.
These are regression examples, not exhaustive checking.
`lake check` checks both default targets, `Consensus` and `consensus-replay`, in one invocation.
It runs without sandboxing here, so build-time code must be trusted.
`Consensus.lean` reexports `Properties.lean` and the replay API transitively, while importing tests privately.
The shared `check-imports` command rejects modules missing from that import closure.

## Proofs

[`Properties.lean`](Consensus/Properties.lean) contains the full theorem and witness-lemma statements, with one-line proof links into `Proofs/`.
Import `Consensus.Properties` and use `Consensus.Properties.<name>` for these declarations.
Proof modules follow the shared [dependency import contract](../common/README.md#dependency-imports); import additional facilities explicitly rather than relying on incidental reexports.
`Proofs/Direct.lean` establishes node-local commit invariants; `Proofs/SafetyInvariant.lean` establishes the cross-node history invariant, in the `Consensus.Proofs.Safety` namespace, used for election safety and committed-log comparability.
[`Proofs/Witnesses.lean`](Consensus/Proofs/Witnesses.lean) supplies the checked witness implementations, using shared execution-construction helpers in [`Proofs/GenericWitnesses.lean`](Consensus/Proofs/GenericWitnesses.lean).
The safety-invariant proof remains independent of the witness construction, allowing Lake to check them in parallel.

To list the safety-invariant declarations used by the exported theorems, run `lake env lean scripts/invariant-dependencies.lean`.

## Trace replay

The [trace replayer](replay/README.md) checks finite driver observations against direct model transitions, independently of proofs.
It checks each native send against the model, delivers any matching queued packet, treats undelivered packets as lost, and never repairs model state.
The current native Fluentd capture path and replay's assurance limits are documented there.

## Proof-derived snapshot coverage

The [coverage reader](../consensus-coverage/scripts/pair-coverage.lean) scores consecutive
snapshots against two questions from the [consensus safety proof](Consensus/Proofs/SafetyInvariant.lean).
For each step it prints three bits: is any node at commit index zero **before**, is any
node **newly primary** for its term, and is any node at zero **after**? The middle bit
includes a candidate becoming primary in its current term, but not a primary continuing
in the same term.

The reachable rows are exactly `101`, `111`, `100`, `000`, and `010`. No step can reintroduce
a zero index after every node has committed, and the election-winning step cannot advance
the winner's commit index. One 13-step execution first commits on both nodes, then elects
a primary (`010`). Repeating the schedule with an idle third node witnesses an election
while that node remains at zero (`111`). Together the two executions visit all five rows.

Run from the repository root:

```sh
WS=$(python3 lean/relevance/scripts/workspace.py consensus-coverage)
lake -d "$WS/consensus-coverage" build ConsensusCoverage.Snapshot ConsensusCoverage.PairWitnesses
reader="$PWD/lean/consensus-coverage/scripts/pair-coverage.lean"
lake -d "$WS/consensus-coverage" env lean --run "$reader" check
lake -d "$WS/consensus-coverage" env lean --run "$reader" trace run1.json run2.json
```

Each JSON file is one run: a chronological array of full-cluster snapshots. Each snapshot
is an array of records like `{"id":0,"primary":true,"currentTerm":2,"commitIndex":0}`.
Include the same IDs (including idle nodes) exactly once in each snapshot; order is immaterial.
Provide consecutive model-action boundaries, not arbitrary sampling intervals or raw per-node
Fluentd events. Files are scored separately, then coverage is combined.

[The reduction](../consensus-coverage/ConsensusCoverage/PairQuestions.lean) proves agreement with
`state_committed_logs_comparable_left_backed_inl` and `step_leader_led_leader_inr` on every
valid step. [The projection theorem](../consensus-coverage/ConsensusCoverage/Snapshot.lean)
proves that the four recorded fields suffice; [exactness](../consensus-coverage/ConsensusCoverage/PairWitnesses.lean)
is over reachable steps of the original model, across configurations. A missing row is a
coverage gap; an unexpected row cannot occur on a model step. Hitting every row does not
validate a trace or cover the rest of the history proof.

The [historical vote monitor](../consensus-coverage/ConsensusCoverage/GrantMonitor.lean)
is separate from that table. For one fixed voter, candidate, term and vote request,
it computes the election proof's `Granted` predicate exactly. It needs only two bits
between snapshot pairs: whether the candidate has been seen in that term and whether
the grant has been established. A grant implies the candidate was seen, so there are
at most three memory states per query. This does not bound how many different queries
the full proof might need.
