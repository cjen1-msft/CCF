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
`Proofs/Direct.lean` establishes node-local commit invariants; `Proofs/SafetyInvariant.lean` establishes the cross-node invariant used for election safety and committed-log comparability.
[`Proofs/Witnesses.lean`](Consensus/Proofs/Witnesses.lean) supplies the checked witness implementations, using shared execution-construction helpers in [`Proofs/GenericWitnesses.lean`](Consensus/Proofs/GenericWitnesses.lean).
The safety-invariant proof remains independent of the witness construction, allowing Lake to check them in parallel.

To list the safety-invariant declarations used by the exported theorems, run `lake env lean scripts/invariant-dependencies.lean`.

The two properties follow from `Inv f`, where `f : Frame` holds the current protocol
state and two ghost fields. `inv_initial` establishes it at `Frame.start`; `Ctx.inv_step`
preserves it at `f.advance after` given only `Inv f` and one protocol transition.
`inv_of_reachable` lifts this result to any reachable state. The public properties
still speak about positions in a trace; preservation does not take a trace as input.

[`VoteFacts.Inv`](Consensus/Proofs/VoteFacts.lean) tracks observed
`(voter, term, votedFor)` facts and cannot introduce a second candidate for one voter and term.
[`LogFacts.advance`](Consensus/Proofs/LogFacts.lean) updates the evidence for seen logs,
grants, elections, leader logs and commits using the two endpoints and the previous ghost.
An independent [historical specification](../consensus-coverage/ConsensusCoverage/Historical.lean)
proves that folding this update agrees with looking through the history. The safety proof
does not import that specification.
When comparing same-term elections, the proof carries the first election's quorum and
commit backing rather than recovering them from the snapshot where it won.

The commit/election intersection lemma (`core`) now takes only quorum and log facts.
At a grant, the request must outrank each signed prefix the voter retained, or a
leader log must witness that the voter lost the prefix. A later observation cannot
introduce a lower-term prefix for that voter. Elections retain this evidence, so
`new_in_elected` can induct on the election term without revisiting the vote or the
election. This also handles a commit recorded after a higher-term election.

For the other direction, a new election must carry every older committed prefix.
`CommitChain` records the signed quorum evidence for a commit and, if its base is
nonzero, the committed prefix backing that base. `commitChains_step` preserves
these certificates; `carried_of_chain` inducts over their links, not over execution
steps. Idle steps do not lengthen a certificate.

For a candidate that cannot win, `Blocked` records an ungranted request and a
blocking signed log for a voter in every possible election quorum. A single
step cannot turn that request into a grant: the signature outranks the request,
and no leader in the allowed term range can explain losing it. This replaces
the comparison of when the blocking commit and individual grants occurred.

Each queued AppendEntries request carries backing for the commit index it advertises.
Delivery and snapshot installation can copy a leader log using its retained
prefix evidence, without looking up the state that supplied the log.

This proof is stepwise, not finite-state: the ghost ranges over unbounded terms and
logs. The finite counts below are for proof answers, not protocol states.

## Trace replay

The [trace replayer](replay/README.md) checks finite driver observations against direct model transitions, independently of proofs.
It checks each native send against the model, delivers any matching queued packet, treats undelivered packets as lost, and never repairs model state.
The current native Fluentd capture path and replay's assurance limits are documented there.

## Proof-derived coverage

**State denominator: three profiles for nonempty clusters.** All twelve generated
state questions reduce to two facts: is any node's commit index zero, and does
some node's committed prefix fit inside a commit certificate held by the proof?
In that order the reachable keys are `10` (no backing yet), `11` (some node still
at zero, backing exists), and `01` (no node at zero). The model also permits
initializing an empty node list under a nonempty voting configuration: this gives
`00`, a fourth reachable state with no possible action. It is not a target for
nonempty implementation runs.

This is not a sample of the state questions. [The reduction](../consensus-coverage/ConsensusCoverage/StateBasis.lean)
covers every constructor of the generated state dispatcher. [`same_answers` and
`exact`](../consensus-coverage/ConsensusCoverage/StateCoverage.lean) prove respectively
that two initialized runs have the same key **if and only if** all twelve answers
agree, and that every listed key occurs. The [certificate reader](../consensus-coverage/ConsensusCoverage/CommitMonitor.lean)
uses previous protocol snapshots, not proof witnesses. In particular, delivery of
a signature to a quorum can establish backing before the leader receives the
acknowledgment: testing whether any local commit index is positive would be wrong.

**Step denominator for these states plus the new-primary question: nine rows.**
The [exact table](../consensus-coverage/ConsensusCoverage/FrontierWitnesses.lean)
has six possible source/destination combinations. A new primary can occur within
each of the three states, but cannot create the first backing certificate or
remove the last zero-commit node on the winning step. This gives six rows without
a win and three with a win. Every row has an initialized model execution.

Score saved native captures from the repository root:

```sh
WS=$(python3 lean/relevance/scripts/workspace.py consensus-coverage)
lake -d "$WS/consensus-coverage" build ConsensusCoverage.Projection Consensus.Replay.Reduction
reader="$PWD/lean/consensus-coverage/scripts/proof-coverage.lean"
lake -d "$WS/consensus-coverage" env lean --run "$reader" check
lake -d "$WS/consensus-coverage" env lean --run "$reader" trace lean/consensus/replay/fixtures/valid/replication.ndjson
```

The scorer uses the [native replay checks](replay/README.md), counting states and
steps at model action boundaries. The model witnesses hit **3/3 states and 9/9
projected steps**. The included synthetic replication capture hits **3/3 and 4/9**,
respectively, in nine model actions. Neither score is the full transition denominator.

**Full state-pair denominator: at least six; exact count unknown.** [The full specification](../consensus-coverage/ConsensusCoverage/FullProfile.lean)
uses all 457 generated answers (12 before, 433 about the step, 12 after).
For a pair of full snapshots with no history, the label is the set of whole
answer vectors compatible with that pair on initialized executions. The quotient is
proved finite, but its capacity is not its reachable count. [The projection theorem](../consensus-coverage/ConsensusCoverage/Projection.lean)
proves that the nine rows above are exactly the projected image of those vectors.
It also gives a counterexample to using nine for the full model: sending entries
and stepping down from the same initial state have the same projected row but
different full observations. Five endpoint-only keys are reachable, and this
collision splits one of those keys, so any full table has at least six entries.
The nine history-resolved rows are not themselves a lower bound of nine distinct
*sets* of profiles.

The specification is exact **for the generated predicates**. Each generated step
predicate can existentially choose its own step context; it does not yet retain
a shared action witness across all 433 questions. The shared extractor also
reports 54 unrecorded splits, 41 classified as protocol splits. Thus neither the
finite-universe proof nor the nine-row theorem establishes that the extractor
captures every distinction in the source safety proof.

### Endpoint-only slice

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
validate a trace or cover the rest of the safety proof.

The [historical vote monitor](../consensus-coverage/ConsensusCoverage/GrantMonitor.lean)
is separate from that table. For one fixed voter, candidate, term and vote request,
it computes the election proof's `Granted` predicate exactly. It needs only two bits
between snapshot pairs: whether the candidate has been seen in that term and whether
the grant has been established. A grant implies the candidate was seen, so there are
at most three memory states per query. This does not bound how many different queries
the full proof might need.
