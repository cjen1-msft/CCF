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

[`ConsensusCoverage.Classes`](../consensus-coverage/ConsensusCoverage/Classes.lean) requires
every detected case split in the four coverage roots to be recorded, including splits made
by automation. The generator rejects unrecorded eliminators both in its shared walk and
in a declaration-local walk of the kernel proof closure. A recorded split counts when
at least two branches are live. A dead branch must eliminate a kernel-checked proof
of `False` in its own context. The script-replay result is diagnostic only: the same
script can rely on different hypotheses in different branches.

The current generator emits 516 step questions and 16 state questions (548 coordinates
with both endpoints). The exact family, witness, and support results below are
checked on this schema. Historical search statistics are indicated separately.

**State denominator during replay: three profiles for nonempty clusters.** All sixteen generated
state questions reduce to two facts: is any node's commit index zero, and does
some node's committed prefix fit inside a commit certificate held by the proof?
The two commit-chain questions use the initialized run's chain invariant.
In that order the reachable keys are `10` (no backing yet), `11` (some node still
at zero, backing exists), and `01` (no node at zero). The model also permits
initializing an empty node list under a nonempty voting configuration: this gives
`00`, a fourth reachable state with no possible action. It is not a target for
nonempty implementation runs.

This is not a sample of the state questions. [The reduction](../consensus-coverage/ConsensusCoverage/StateBasis.lean)
covers every constructor of the generated state dispatcher. [`same_answers` and
`exact`](../consensus-coverage/ConsensusCoverage/StateCoverage.lean) prove respectively
that two initialized runs have the same key **if and only if** all sixteen answers
agree, and that every listed key occurs. [`ProofContexts.exact_three`](../consensus-coverage/ConsensusCoverage/ProofContexts.lean)
counts the full sixteen-answer vectors directly: one run with voters and nodes
both fixed to `{0,1,2}` visits all three. No other nonempty deployment adds a
fourth vector. The [certificate reader](../consensus-coverage/ConsensusCoverage/CommitMonitor.lean)
uses previous protocol snapshots, not proof witnesses. In particular, delivery of
a signature to a quorum can establish backing before the leader receives the
acknowledgment: testing whether any local commit index is positive would be wrong.

**State denominator without history: four labels for nonempty clusters.** A single
snapshot can admit `{10}`, `{11}`, `{01}`, or `{10,11}`. For the last label,
[two initialized runs](../consensus-coverage/ConsensusCoverage/HistoryCollision.lean)
reach identical protocol states, including the network queue, then take the same
next action. In one run replication established a commit certificate before the
election advanced; in the other it did not. The
[snapshot table](../consensus-coverage/ConsensusCoverage/SnapshotStates.lean)
has a witness for each label and proves that two snapshots get the same label
if and only if they admit the same whole vectors of answers to all sixteen state
questions. An empty cluster adds only `{00}`. This table characterizes snapshots;
the executable scorer below uses the actual replay history and counts three, not four.

**Step denominator for these states plus the new-primary question: nine rows.**
The [exact table](../consensus-coverage/ConsensusCoverage/FrontierWitnesses.lean)
has six possible source/destination combinations. A new primary can occur within
each of the three states, but cannot create the first backing certificate or
remove the last zero-commit node on the winning step. This gives six rows without
a win and three with a win. Every row has an initialized model execution.

**Multi-node leader coverage: exactly 13 rows.** For a recorded action, consider
the 16 proof questions before, three leader questions about the action, and the
16 questions after. The leader questions ask whether a primary was elected,
whether a node changed state and ended primary, and whether that change was to
an incumbent in the same term. The third answer is determined by the first
two. [Equality of row keys is equivalent to agreement on all 35 answers](../consensus-coverage/ConsensusCoverage/ActionFrontier.lean).

[The 13-row table](../consensus-coverage/ConsensusCoverage/LeaderCoverage.lean)
is exact across deployments with **at least two distinct nodes**, not necessarily
two voters. Each row has an initialized witness. Before the first certificate,
every node's commit index is zero. Since one action updates at most one node,
the step that creates the first certificate cannot also remove the last zero in
a multi-node deployment. A singleton can do both. Counting singletons as well,
there are 14 witnessed leader rows and at most one more possible row.

Score saved native captures from the repository root:

```sh
WS=$(python3 lean/relevance/scripts/workspace.py consensus-coverage)
lake -d "$WS/consensus-coverage" build ConsensusCoverage.LeaderCoverage \
  ConsensusCoverage.CaptureBounds ConsensusCoverage.Families Consensus.Replay.Reduction
reader="$PWD/lean/consensus-coverage/scripts/proof-coverage.lean"
lake -d "$WS/consensus-coverage" env lean --run "$reader" check
lake -d "$WS/consensus-coverage" env lean --run "$reader" trace lean/consensus/replay/fixtures/valid/replication.ndjson
lake -d "$WS/consensus-coverage" env lean --run "$reader" trace \
  lean/consensus/replay/fixtures/valid/duplicate-heartbeat.ndjson \
  lean/consensus/replay/fixtures/valid/signed-heartbeats.ndjson
lake -d "$WS/consensus-coverage" env lean --run "$reader" trace \
  lean/consensus/replay/fixtures/valid/fresh-nomination.ndjson \
  lean/consensus/replay/fixtures/valid/signed-nominations.ndjson
lake -d "$WS/consensus-coverage" env lean --run "$reader" answers lean/consensus/replay/fixtures/valid/replication.ndjson
lake -d "$WS/consensus-coverage" env lean --run "$reader" answers lean/consensus/replay/fixtures/valid/duplicate-heartbeat.ndjson
lake -d "$WS/consensus-coverage" env lean --run "$reader" columns
```

The scorer uses the [native replay checks](replay/README.md), counting states and
steps at model action boundaries. The model witnesses hit **3/3 states and 9/9
projected steps**. The included synthetic replication capture hits **3/3 and 4/9**,
respectively, in nine model actions. On the multi-node leader table, six model
schedules hit **13/13**, and the replication capture hits **5/13**. Singleton
captures do not contribute to this score. None of these scores uses the full
transition denominator.

`trace` also counts distinct **full** labels within the supplied captures.
It reports a range when the count is not determined. The [lower-bound proof](../consensus-coverage/ConsensusCoverage/CaptureBounds.lean)
counts actions together only when each pair disagrees on a known answer; a
`?` never distinguishes two actions. The upper bound is the number of validated
actions. The two heartbeat fixtures together hit **exactly seven distinct full
labels**. Replication hits **exactly nine**. Its two same-term acknowledgments
are distinguished by [the commit-advance proof branch](../consensus-coverage/ConsensusCoverage/AckAdvance.lean):
action 6 leaves the primary at commit index 2; action 9 advances it from 2 to 4.
These counts describe the captures, not the global reachable table.

**Full state-pair denominator: at least six; exact count unknown.** [The full specification](../consensus-coverage/ConsensusCoverage/FullProfile.lean)
uses all 548 generated answers (16 before, 516 about the step, 16 after).
For a pair of full snapshots with no history, the label is the set of whole
answer vectors compatible with that pair on initialized executions. The quotient is
proved finite, but its capacity is not its reachable count. [The projection theorem](../consensus-coverage/ConsensusCoverage/Projection.lean)
proves that the nine rows above are exactly the projected image of those vectors.
It also gives a counterexample to using nine for the full model: sending entries
and stepping down from the same initial state have the same projected row but
different full observations. Five endpoint-only keys are reachable, and this
collision splits one of those keys, so any full table has at least six entries.
The nine history-resolved rows are not themselves a lower bound of nine distinct
_sets_ of profiles.

**Exhaustiveness ledger: ten labels in three closed families; every other
action is in a named open family.** [`Families.classify`](../consensus-coverage/ConsensusCoverage/Families.lean)
assigns each replayed action to exactly one family. A family is closed when
its complete label list is proved, with a witness for every row and no
others. Closed so far: no fresh evidence at all (3 labels), a nomination
whose only fresh evidence is its proposal (3), and a nomination that
establishes a delayed commit before any election (4). `Families.exact`
proves these are exactly ten distinct labels. Every other action falls in
an open family named by its action kind and by which of seven kinds of
evidence are fresh, for example `open:append:0110011`. Labels in open
families are bounded but not enumerated. The table is exhaustive only when
no reachable open family remains.

`trace` prints this breakdown. The replication capture has no action in a
closed family: its nine actions fall in eight open families (three kinds of
append, two of AppendEntries delivery, acknowledgment, backup initialization,
and send). The two heartbeat captures have 3 of 7 actions in closed
families; the two nomination captures 5 of 9.

The explorer reports the same breakdown for its search (`--families`). In
an earlier run of 25,002 steps on the 433-question schema, 6,587 steps were in the three closed families and
18,415 were in 47 open families, which together showed 172 distinct
combinations of the 64 always-known answers. Each open family showed
between 1 and 15 of them and left 80 to 261 step answers undecided. The
most frequent open families were appends, election timeouts, pre-vote
requests and sends. Closing a family means deciding those answers for every
step in it, not only for the steps explored.

[`FamilyPrune.generate`](../consensus-coverage/ConsensusCoverage/FamilyPrune.lean)
produces the negative half of a closure for any family: given an action
kind, the stale evidence kinds and optional facts about the handler, it
certifies which step answers must be false. It reproduces the ten possible
answers of the fresh-nomination family exactly. How much it removes depends
on the family. For an acknowledgment that changes only the leader's record
(`open:appendEntriesResponse:0100000`, two actions of the replication
capture) 234 of 516 answers survive, because a changed node record re-enters
most node invariants. [That family](../consensus-coverage/ConsensusCoverage/AckRead.lean)
splits exactly into retry, accepted without commit advance, and accepted
with advance; six more answers are decided and [four distinct labels are
witnessed](../consensus-coverage/ConsensusCoverage/AckWitnesses.lean), but
208 answers per action remain undecided on those two fixture actions, so the
family is still open.

**Every case is classified: 487 of the 516 step questions are witnessed
and 29 are impossible.** Each step question is one case of one case split
in the safety proof. [`CensusPartition`](../consensus-coverage/ConsensusCoverage/CensusPartition.lean)
proves, for every question `b`:

- `b` is in `witnessed` or in `refuted` (`classified`), and not in both
  (`disjoint`);
- `b` is in `witnessed` if and only if it is true on some initialized step
  (`witnessed_iff`);
- `b` is in `refuted` if and only if it is false on every initialized step
  (`refuted_iff`).

The counts 487 and 29 are theorems. So for every recorded case split of the
proof it is known whether an initialized run can enter each case.

Each witness is a schedule replayed in the kernel.
[`CaseWitnesses`](../consensus-coverage/ConsensusCoverage/CaseWitnesses.lean)
(192 questions) holds schedules found by the bounded search below and read
with the exact readers. [`ReadersWitnesses`](../consensus-coverage/ConsensusCoverage/ReadersWitnesses.lean)
(201) holds one-sided tests run over the certified schedules.
[`CaseWitnessesDeep`](../consensus-coverage/ConsensusCoverage/CaseWitnessesDeep.lean)
(139) and [`CaseWitnessesDeepB`](../consensus-coverage/ConsensusCoverage/CaseWitnessesDeepB.lean)
(112) cover the questions that have no exact reader: for each, a schedule
was written by hand from what the case means, and the case's formula is
proved directly on that step, with the witnesses of its existentials given
explicitly. A few more come from smaller modules listed in
`CensusPartition`. The lists overlap; 487 is the size of their union.

The 29 impossible cases are in
[`CaseUnreachable`](../consensus-coverage/ConsensusCoverage/CaseUnreachable.lean)
(21), [`CaseUnreachableB`](../consensus-coverage/ConsensusCoverage/CaseUnreachableB.lean)
(6) and [`CensusBallots`](../consensus-coverage/ConsensusCoverage/CensusBallots.lean)
(2). They are branches the proof handles but no initialized run reaches.
Some examples: a nomination never changes the actor's own record; a vote
request is never delivered to its sender; a primary's acknowledgment never
finds it in a candidate role; two commit certificates never need the
comparison that would require a second election in a term that already had
a leader; a term lookup at a recorded index never misses. The proofs use
new invariants of initialized runs, among them
[`VoteRequestRoute`](../consensus-coverage/ConsensusCoverage/VoteRequestRoute.lean)
and [`RetiredRoleOrigin`](../consensus-coverage/ConsensusCoverage/RetiredRoleOrigin.lean).

A bounded search never makes a case impossible. The search found 18
exactly readable questions that were false on every step of every model it
completed: six turned out impossible and twelve reachable on schedules
longer than the search covered (a competing candidate, an election
completing after a later one, a primary retiring during a local append).

Classifying each case separately does not give the labels: a label is a
whole vector of answers, and which combinations occur is a separate
question. The bounds on that follow.

**Full recorded-action denominator: at least 250; at least 247 on multi-node deployments.**
The [recorded-action specification](../consensus-coverage/ConsensusCoverage/ActionProfile.lean)
assigns an initialized step exactly one 548-answer vector. All 516 step
questions use [the same, unique context for the recorded action](../consensus-coverage/ConsensusCoverage/ActionContext.lean).
The [explorer](../consensus-coverage/scripts/explore.lean) searches initialized
schedules mechanically, breadth-first and by seeded random walks, optionally
continuing from given schedule prefixes. It distinguishes two steps by a compact
key for the endpoint contexts and
[40 always-known step answers](../consensus-coverage/ConsensusCoverage/JointWitnesses.lean).
The key is unchanged by the four added state questions at each endpoint.
Two earlier runs scored 96,735 steps. [Seventy-four of their schedules](../consensus-coverage/ConsensusCoverage/ExploredWitnesses.lean)
(918 steps) are replayed in the kernel and give 187 distinct combinations.
Each difference is a difference in a full label. Neither run reached a
plateau: the second was still adding about three keys per hundred walks. The
number measures search effort and distinct keys, not the size of
the table. The 22 hand-written schedules alone give 49 and 47 with the same key.

```sh
lake -d "$WS/consensus-coverage" env lean --run "$PWD/lean/consensus-coverage/scripts/explore.lean" \
  --depth 3 --walks 300 --length 20 --seed 20261123 --every 50 --out /tmp/witnesses.lean.txt
```

The explorer can also enumerate a bounded model completely (`--exhaust`).
A step's label depends only on the proof state before it (protocol state
plus ghost), the action and the state after, so histories that reach the
same proof state are merged and the search runs until no new one appears.
In an earlier run with two voters, logs of at most two entries, terms up to three and one copy
of each envelope, the fixpoint has 618 proof states, 858 steps and 76
combinations of the 64 always-known answers. Raising the term bound to four
gives 1,891 states and 93 combinations; raising the log bound to three
instead gives 10,259 states and 113.

The search carries the ghost forward step by step instead of rebuilding
it from the history ([`ExplorerGhost`](../consensus-coverage/ConsensusCoverage/ExplorerGhost.lean);
it agreed with the history readers on every checked step, but is not proved
equal to them), and runs as a native binary built by
[`build-explorer.sh`](../consensus-coverage/scripts/build-explorer.sh).

A second engine ([`scale.lean`](../consensus-coverage/scripts/scale.lean),
[`scale.cpp`](../consensus-coverage/scripts/scale.cpp)) runs at the scale of
an explicit-state model checker. It still calls the Lean model for every
distinct local step and the Lean reader for every distinct label key, but
stores a proof state as three numbers: the node table, the ghost and the set
of messages in flight, each interned by exact comparison. This uses the fact
that [a step](../common/CCF/MultiNodeTransitionSystem.lean) touches the
network only to remove the delivered message and append the sent ones. It
also caches the reader per local step and ghost, which is not proved correct.
`--scale` enumerates states one at a time: about 297,000 states per second
on one core (median of five runs of 49 million states, range 269,000 to
305,000), limited by hash-table lookups for visited states and message sets.
`--symbolic` instead keeps, for each node table and ghost, the whole set of
possible networks as one decision diagram, and `--queue-ladder` computes
every cap on messages in flight in one pass.
[`check-scale.py`](../consensus-coverage/scripts/check-scale.py) checks the
engines against each other and against the Lean-only search above: equal
state counts, step counts and sets of combinations with at most one, two and
three messages in flight.

With two voters, logs of at most two entries, terms up to three and one copy
of each envelope, the model is now searched completely, with no cap on
messages in flight:

| Messages in flight | Proof states    | Steps             | Combinations |
| ------------------ | --------------- | ----------------- | ------------ |
| at most 1          | 618             | 858               | 76           |
| at most 2          | 34,256          | 72,012            | 101          |
| at most 3          | 659,046         | 1,947,551         | 103          |
| at most 5          | 49,306,958      | 229,185,348       | 103          |
| at most 6          | 260,731,160     | 1,422,307,505     | 103          |
| no cap             | 529,465,319,840 | 6,170,227,084,286 | 103          |

Never more than 29 messages are in flight. The rows up to six were also
enumerated one state at a time; the last is symbolic only. So in this model
a third overlapping message adds two combinations and further ones add none.

The other bounds do add combinations, and none of them has been searched
without a cap. Logs of at most three entries give 113, 133, 135 and 135
combinations with at most one to four messages in flight (637,783,694 states
at four). Terms up to four give 93, 127, 128, 128 and 128 with at most one
to five (1,835,550,931 states at five). Three voters give 55 and 100 with at
most two and three (93,981,162 states). The uncapped runs of these three
models were stopped after about ten minutes with states still unexplored.
With at most one message in flight the count also stops growing along the
log bound at four entries (115) and along the term bound at five.

Across all runs, including models with reconfiguration, retirement and a
joining node, [236 combinations have a witness](../consensus-coverage/ConsensusCoverage/BoundedWitnesses.lean)
replayed in the kernel, 233 of them on multi-node deployments. A wider key
adds the answers of the exact readers to those 64; [`CensusWidth`](../consensus-coverage/ConsensusCoverage/CensusWidth.lean)
certifies 250 distinct wider keys, 247 on multi-node deployments, and each
difference is a difference in a full label. Everything else in this
section is a measurement, not a theorem. That equal merge keys imply equal
labels is checked empirically (no disagreement in 1,288,506 pairs of
histories with at most three messages in flight) but not proved. Neither
key is the full label of 548 answers. A bounded model is a
fragment of the protocol: a fixpoint says nothing about longer logs, higher
terms, more nodes or reconfiguration.

The same search counts, for each of the 516 step questions, the steps on
which the readers answer yes, no or unknown. It uses the 188 exact readers
described below, specialized to the search's finite ghost. The `Census*`
modules prove pieces of that specialization against the real history
(observations, vote grants, elections, leader logs and committed keys are
tracked exactly along initialized runs); the whole specialization, and the
merging of states, are not proved, so these counts are measurements. Over
the complete two-voter model 147 questions are true on some step, 49 are
false on every step and 320 are unknown on some step. In 23 completed
models (two and three nodes, with reconfiguration, retirement and a joining
node) 167 questions are true somewhere. The combinations of the wider key
number 144 in the complete two-voter model, against 103 for the 64 answers.

```sh
lake -d "$WS/consensus-coverage" env lean --run "$PWD/lean/consensus-coverage/scripts/explore.lean" \
  --exhaust --voters 0,1 --nodes 0,1 --max-log 2 --max-term 3 --max-copies 1 --out /tmp/bounded.tsv
```

By default `build-explorer.sh` builds the engine without the generated
readers, in about a minute. `--with-readers` links them in for the reader
census; that build takes much longer.

```sh
EXE=$(LEAN_CC=/path/to/gcc16/bin/cc bash lean/consensus-coverage/scripts/build-explorer.sh | tail -n 1)
nice "$EXE" --queue-ladder --max-log 2 --max-term 3 --out /tmp/ladder.tsv
python3 lean/consensus-coverage/scripts/check-scale.py "$EXE" /tmp/scale-check
```

The explorer also tests claims before they are proved. It checked the
invariant below on 25,009 snapshots and looked for a delayed-commit
nomination without a successor among 1,073 successor-less nominations; it
found no counterexample to either, and both were then proved.

In a three-node reconfiguration run, two successive nominations leave every
node record unchanged, yet each establishes a new committed prefix. A
certificate may use only backing from an earlier step: establishing one
prefix makes the next eligible on the following nomination. A third
nomination adds nothing. Counting all nominations with unchanged nodes as the
same step would miss this distinction.

[Unchanged node records preserve all sixteen state answers](../consensus-coverage/ConsensusCoverage/BackingStutter.lean):
they cannot establish the _first_ committed key. Any new key on such a step
must use older backing. There can be no gap in a chain of delayed commits:
if an action adds no key, [the next node-preserving action cannot add one either](../consensus-coverage/ConsensusCoverage/ConsecutiveStutter.lean).

[Repeating the same local input](../consensus-coverage/ConsensusCoverage/RepeatedInput.lean)
at the same node is an exact full-label case. If the first input leaves node
records unchanged, the repeat sends no new envelope value and establishes no
new vote grant. **All 516 step answers are false if and only if the repeat adds
no committed key.** If the first input also added no key, exactly three full
labels are possible across all such repeats, one per state context; all three
have nomination witnesses. Before the first certificate, a repeated nomination
can only have the all-false `10 -> 10` label.

[An upper cover](../consensus-coverage/ConsensusCoverage/ActionCover.lean)
reconstructs every full label from a leader row, the kinds of fresh messages,
and the remaining answers not ruled out for the recorded event. Depending on
the event, 275 to 362 bits remain free in this construction. The cover has
fewer than `2^373` entries, compared with `2^548` unrestricted answer vectors.
It includes impossible combinations and can represent the same label more
than once; its size is not a coverage target.

**Exact slice: three full labels have all 516 step answers false.** They are
`10 -> 10`, `11 -> 11`, and `01 -> 01`. [The upper bound](../consensus-coverage/ConsensusCoverage/ZeroRows.lean)
does not assume the action leaves the snapshot unchanged: removing the last
zero commit index or establishing the first certificate forces a true step
answer. [The converse](../consensus-coverage/ConsensusCoverage/SignedQuiet.lean)
has initialized witnesses for all three: a duplicate heartbeat before backing
exists and two nominations after a signed commit. The two synthetic heartbeat
captures above hit **3/3 of these full labels** in seven validated actions.
In [the signed capture](replay/fixtures/valid/signed-heartbeats.ndjson),
actions 3 and 5 resend the same queued heartbeat on opposite sides of backup
initialization: first `11 -> 11`, then `01 -> 01`.

Membership in this slice is **decidable on every validated action**, even
when the reader cannot fill in all 516 step coordinates. The [four-question
converse](../consensus-coverage/ConsensusCoverage/SignedQuiet.lean) proves that
if a node record changes, an envelope is new, a vote grant is new, or a
committed prefix is new, at least one step answer is true. If none changes,
all 516 step answers are false. An old vote need not be absent: [the grant
reader](../consensus-coverage/ConsensusCoverage/GrantFrontier.lean) checks the
least request accepted by each eligible voter record. Every other request
accepted there is covered by the same old grant. This score does not cover
labels with a positive step answer.

A delivery can also have an all-false label while **removing** an envelope:
in [an initialized heartbeat exchange](../consensus-coverage/ConsensusCoverage/DropWitness.lean),
the primary consumes the only pending zero-index acknowledgment and neither
node changes. The proof needs every _remaining_ envelope to have been present
before, not every old envelope to remain. In the signed nomination capture,
receiving the proposal at the term-zero node is another such delivery (`11 -> 11`).

**Exact nonzero slice: three full labels have the fresh-nomination signature.**
[Seven step answers](../consensus-coverage/ConsensusCoverage/NominationProfile.lean)
are true and the other 509 are false **if and only if** the recorded action
is a nomination, an envelope is new to the queue, and no new vote grant or
committed prefix appears. This test decides membership on every validated
action. Calling the nomination helper as part of an append is not enough:
the positive summary-input answer requires the recorded input itself.
[The table and witnesses](../consensus-coverage/ConsensusCoverage/NominationWitnesses.lean)
show its endpoint stays `10`, `11`, or `01`, and each is reachable. The two nomination fixtures hit
**3/3**. In the first, repeating the nomination before delivery instead hits
the all-false `10 -> 10` label. In the second, delivery removes the first
proposal, allowing the same primary to send a fresh one after the backup
installs its committed prefix.

**Exactly six full labels occur on nominations that add neither a vote grant
nor a committed prefix.** Each of the three pre-state contexts can send a new
proposal or add no new envelope. All six have initialized nomination witnesses;
[`exact_stable`](../consensus-coverage/ConsensusCoverage/NominationWitnesses.lean)
proves that no seventh label occurs under those conditions. The six are already
included in the lower bound. The delayed-commit nominations above fall
outside this table.

**Exactly four full labels occur on delayed-commit nominations before any
election.** The family is a recorded nomination that establishes a new
committed prefix, with no new vote grant and no election recorded so far;
[the test](../consensus-coverage/ConsensusCoverage/DelayedNominationRead.lean)
is executable on every replayed action. [All 516 step answers are
determined](../consensus-coverage/ConsensusCoverage/DelayedNomination.lean):
27 are always true, three more are true exactly when the proposal is new to
the queue, and the remaining 486 are false. Both endpoints are `11` or both
are `01`. Each of the four labels has an initialized witness and `exact`
proves there is no fifth. A single-node deployment cannot be in the family,
and [the primary always has a successor](../consensus-coverage/ConsensusCoverage/DelayedNominationSuccessor.lean).

The last fact uses a new invariant of initialized runs, proved without
changing the safety proof: [commit evidence is ahead of the protocol](../consensus-coverage/ConsensusCoverage/Timely.lean).
A certificate whose base does not exceed the certifying node's own commit
index is already recorded. A delayed commit therefore lies beyond its
leader's commit index, so that leader still counts the old configuration's
members as peers.

`answers` prints one row per validated action, in three bit strings: pre-state,
step, post-state. `columns` names each bit in order. `1` and `0` are proved
answers; `?` is unknown, not false. The [reader](../consensus-coverage/ConsensusCoverage/ReplayAnswers.lean)
decides both endpoints and at least 40 step questions on every action: three
leader questions, [16 fresh-envelope questions](../consensus-coverage/ConsensusCoverage/ReducedQuestions.lean),
[14 questions compiled to finite searches over the actual node records, logs and history](../consensus-coverage/ConsensusCoverage/GuardedQuestions.lean),
[four questions from the rooted- and sorted-log proofs](../consensus-coverage/ConsensusCoverage/ActorLogRows.lean),
and [three questions about a previously unseen committed `(term, prefix)`](../consensus-coverage/ConsensusCoverage/BackingRead.lean).
Invalid captures produce no rows. Do not count distinct strings containing `?`
as full transition coverage.

**186 of the 516 step questions have a generated exact reader.**
[`Readers`](../consensus-coverage/ConsensusCoverage/Readers.lean) compiles a
question's formula into an executable test together with its proof. On every
initialized recorded step the test returns the question's answer
(`read?_at`), and any answer it returns is correct (`read?_correct`). Of the
186, [148 are not among the 40 above](../consensus-coverage/ConsensusCoverage/ReadersCensus.lean),
so 188 step questions are readable in all and 328 are not yet. The generator
works from the formulas, not from question names, so it reruns when the
questions change.

For a question with no exact reader, a one-sided test can still recognize
it. A "yes" test may search any finite list of candidates for the witnesses
of an existential: if it finds some, the case holds, and nothing needs to
be proved about the list. A "no" test still needs a finite guard. `read?`
returns an answer when either test fires and "unknown" otherwise, and
`read?_correct` covers both. These tests are generated in shards
([`ReadersPolarShards`](../consensus-coverage/ConsensusCoverage/ReadersPolarShards.lean))
for the questions whose generation has been verified; most of the 328 do
not have one yet. The exact readers are used by the bounded census above
but not yet by `answers`.

**114 more questions have an exact reader written by hand.** For the
questions the compiler cannot handle, the reader was written from what the
case means and proved equal to the question's answer on every initialized
step: [`HandReadersA`](../consensus-coverage/ConsensusCoverage/HandReadersA.lean)
(75 questions) and [`HandReadersB`](../consensus-coverage/ConsensusCoverage/HandReadersB.lean)
(39), each with `read_correct` and `read_total`. A typical one: the case
`commit_backed_eq_zero_or_pos_inl` holds exactly when the actor becomes
primary, was not already primary in that term, and had commit index zero
before the step. The 29 impossible cases are read as constant false.
[`ReadersTotal.read`](../consensus-coverage/ConsensusCoverage/ReadersTotal.lean)
combines these sources with structural equivalences and the compiled
match-index and accepted-log readers. `read_correct` and `read_total` certify
every returned answer and totality on the 329 covered questions. All 40
unconditional replay readers are included; 187 of the 516 questions remain
unread.

[`case-meanings.tsv`](../consensus-coverage/case-meanings.tsv) describes,
for each of the 311 reachable questions that had no baseline reader, what
the case means on a recorded step. This snapshot predates the compiled
match-index and accepted-log readers. The current roster of cases without
an exact reader is `ReadersTotal.unread`.

The rooted- and sorted-log proofs agree on the acting node: both enter their
actor case exactly when its record changes **or** a new committed key appears.
Their two prefix cases additionally require the actor's post-log to be a prefix
of its pre-log. A delayed-commit nomination satisfies all four despite leaving
every local log unchanged.

For the three commit questions (columns 89-91), the [exact table](../consensus-coverage/ConsensusCoverage/BackingRows.lean)
is `000`, `110`, `101`, `111`: the first bit says a key is new; the other two
say a new key has a certificate starting at zero or one backed by a key from
an earlier step. Both reasons can hold. The replication capture reads `110` on
action 1, `111` on action 8, and `000` elsewhere. The delayed-commit model run
reads `110` on follower delivery and `101` on the next nomination. All four
rows have multi-node witnesses. This table counts commit reasons, not full labels.

The [duplicate-heartbeat fixture](replay/fixtures/valid/duplicate-heartbeat.ndjson)
shows the difference between a complete action and a complete capture. Its
unsigned configuration append sends one heartbeat; the next action sends the
same packet again. The second action grows the queue but gives a **complete
548-answer row**: both endpoints have key `10`, and all 516 step bits are
false. The [proof](../consensus-coverage/ConsensusCoverage/InertProfile.lean)
checks that the node states, queue membership and proof log evidence are unchanged.
The first action still contains unknowns. Separately, [a model witness](../consensus-coverage/ConsensusCoverage/FreshHeartbeat.lean)
sends an empty heartbeat from voter 0 to voter 1 starting with an empty queue.
Its [complete label](../consensus-coverage/ConsensusCoverage/FreshHeartbeatResidual.lean)
has endpoints `10 -> 10` and **23 true, 493 false, zero unknown** step answers.
One true answer concerns the incumbent primary, not the queue. This is one
initialized send, not a classification of all heartbeats.
[Witness elimination](../consensus-coverage/ConsensusCoverage/SolvedWitnesses.lean)
simplifies all 516 predicates with a proof in both directions but does not decide
the remaining existential questions.

[Event support](../consensus-coverage/ConsensusCoverage/EventSupport.lean)
automatically rules out 2,176 combinations of recorded action kind and proof
question across 228 of the 516 step questions. It uses 12 action kinds: five
local input constructors and seven delivered message constructors. On a
validated replay these excluded answers must be false; a non-excluded answer
still needs a witness. This count is not a transition coverage denominator.

[Evidence support](../consensus-coverage/ConsensusCoverage/EvidenceSupport.lean)
names, for every one of the 516 step questions, the fresh proof evidence
without which its answer must be false. There are seven kinds: a new node
record, a new envelope value, and a new fact in each of the five ghost
relations (seen logs, vote grants, elections, leader logs, committed
prefixes). Whether each kind is fresh is decided exactly on every replayed
action (`fresh_iff`). 129 questions need one particular kind and 123 need
one of two; for 176 the certified guard uses all seven. Typical appends and
deliveries introduce several kinds of evidence at once, so exclusion alone
does not complete their labels.
[Delta support](../consensus-coverage/ConsensusCoverage/DeltaSupport.lean)
remains for thirteen questions that a stronger commit test excludes: no
signature anywhere rules out every certificate, not only new keys.

These counts concern the generated questions. The split gate checks that
every detected case split is recorded. The finite-universe proof and the
nine-row projection theorem do not enumerate the full reachable labels.

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
