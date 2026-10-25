# CCF-Raft model

An executable Lean model of CCF's consensus implementation ([`src/consensus/aft/raft.h`](../../src/consensus/aft/raft.h)), safety property statements and a propositional timed liveness model.
It assumes familiarity with the [CCF consensus documentation](../../doc/architecture/consensus/index.rst).
The public liveness statements are a specification checkpoint: timed `commit_liveness` within a `StableWindow`, probabilistic `duelling_leaders_resolve` during a `GoodPeriod`, and the `signature_settles` bridge.
`commit_liveness` is proved, with an explicit window, in [`CCFRaft/Proofs/Timed`](CCFRaft/Proofs/Timed); the other two currently contain `sorry`, and the probability bound is not proved.
The earlier untimed commitment and conditional stable-leadership proofs remain internal; see [the liveness report](LIVENESS.md).

## Source map

| Area                                      | Source                                                                                                                                                                                                                                                 |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Node state, log entries, log queries      | [`Model/NodeState.lean`](CCFRaft/Model/NodeState.lean)                                                                                                                                                                                                 |
| Configurations, quorums, retirement       | [`Model/ClusterConfig.lean`](CCFRaft/Model/ClusterConfig.lean) (`activeConfigurations`, `hasQuorum`, `NodeState.retirement`)                                                                                                                           |
| Messages                                  | [`Model/Messages.lean`](CCFRaft/Model/Messages.lean)                                                                                                                                                                                                   |
| Protocol policy (one node's step)         | [`Model/Node.lean`](CCFRaft/Model/Node.lean) (`Node.step`, `receive`, `act`, `highestCommittableIndex`, `eligiblePeers`)                                                                                                                               |
| Initial states and network composition    | [`Model.lean`](CCFRaft/Model.lean) (`initialNodeState`, `transitionSystem`)                                                                                                                                                                            |
| Safety and liveness theorems, witnesses   | [`Properties.lean`](CCFRaft/Properties.lean)                                                                                                                                                                                                           |
| Liveness events and packet identities     | [`Liveness/Model/Event.lean`](CCFRaft/Liveness/Model/Event.lean)                                                                                                                                                                                       |
| Recorded relational traces and models     | [`Liveness/Model/Trace.lean`](CCFRaft/Liveness/Model/Trace.lean) (`Trace`, `Model`, coherence and validity)                                                                                                                                            |
| Open world accessors and witness world    | [`Liveness/Model/World.lean`](CCFRaft/Liveness/Model/World.lean) (`HasProtocol`, `HasTime`, `HasLive`, `HasNetwork`), [`Liveness/Model/WitnessWorld.lean`](CCFRaft/Liveness/Model/WitnessWorld.lean) (`World`)                                         |
| Protocol model                            | [`Liveness/Model/Protocol.lean`](CCFRaft/Liveness/Model/Protocol.lean)                                                                                                                                                                                 |
| Crash and absolute-time models            | [`Liveness/Model/Crash.lean`](CCFRaft/Liveness/Model/Crash.lean), [`Liveness/Model/Timing.lean`](CCFRaft/Liveness/Model/Timing.lean)                                                                                                                   |
| Packet ledger, delay constraint and sends | [`Liveness/Model/Delivery.lean`](CCFRaft/Liveness/Model/Delivery.lean), [`Liveness/Model/Packets.lean`](CCFRaft/Liveness/Model/Packets.lean)                                                                                                           |
| CCF scheduling assumptions                | [`Liveness/Model/Scheduling.lean`](CCFRaft/Liveness/Model/Scheduling.lean)                                                                                                                                                                             |
| Public liveness import entry points       | [`Liveness/Model.lean`](CCFRaft/Liveness/Model.lean), [`Liveness/Assumptions.lean`](CCFRaft/Liveness/Assumptions.lean)                                                                                                                                 |
| Supporting proofs and executions          | [`Proofs/`](CCFRaft/Proofs), with the shared liveness proof base in [`Proofs/Liveness/`](CCFRaft/Proofs/Liveness) and the liveness proofs in [`Proofs/Replication/`](CCFRaft/Proofs/Replication) and [`Proofs/Leadership/`](CCFRaft/Proofs/Leadership) |
| Action-trace tests and import layering    | [`Tests/CanonicalTraces.lean`](CCFRaft/Tests/CanonicalTraces.lean), [`Tests/Architecture.lean`](CCFRaft/Tests/Architecture.lean)                                                                                                                       |

Transition systems, safety traces, the shared `CCF.Execution.Step` record, effects and network composition come from the local [`ccf_common` package](../common/README.md).
The relational liveness trace is local to this package; the common package is unchanged.
Liveness model components live under `Liveness/Model/` and are reexported by `Liveness/Model.lean`.
Short, single-declaration assumptions are defined directly in [`Liveness/Assumptions.lean`](CCFRaft/Liveness/Assumptions.lean).
Separate assumption modules are reserved for related groups of declarations or definitions exceeding 80 lines: [`StableLeader.lean`](CCFRaft/Liveness/Assumptions/StableLeader.lean), [`QuietStart.lean`](CCFRaft/Liveness/Assumptions/QuietStart.lean), [`FairLoss.lean`](CCFRaft/Liveness/Assumptions/FairLoss.lean), and [`Submitted.lean`](CCFRaft/Liveness/Assumptions/Submitted.lean).
Each node reads membership, quorums and retirement from its own ledger; there is no model-wide configuration after initialization.
Initialization takes a nonempty initial voting membership, whose smallest member starts as primary with the genesis configuration transaction.
Base actions are local inputs (including timeouts) or delivery of a queued message; the base protocol has no clock.
The optional liveness model records an initial world and a finite or infinite sequence of `CCF.Execution.Step W Event` values, each with explicit before-state, action and after-state.
Public statements quantify over any world type `W` with the accessor instances they need and use `Liveness.Trace W Liveness.Event`, independently of any transition system.
`trace.stepAt`, `trace.actionAt` and `trace.stateAt` read the recording directly and return `Option`; state zero is the initial world and state `i + 1` is step `i`'s after-state.
`trace.Coherent` connects the initial world and adjacent recorded endpoints, including finite and zero-step traces.
There is no replay or filtered protocol projection in this interface.

Each `Model W Event` is a TLA-style action: an initial-state predicate and a relation over a recorded step.
Validity against several models is plain conjunction; there is no composition operator, model ordering or variable ownership.
Models may constrain overlapping fields, and contradictory constraints simply admit fewer traces.
Accessor classes let models work with extensible world types while requiring only the fields they inspect.
Lean has no row types, so the open world is spelled as typeclass constraints; the closed `World S` in [`Liveness/Model/WitnessWorld.lean`](CCFRaft/Liveness/Model/WitnessWorld.lean) exists only for witnesses.
Scheduling adds no world variables.

Each public statement conjoins coherence and validity of the protocol, timing, crash and delivery models inline; there is no bundled model predicate.
The protocol model uses `Event.action` to execute local actions and deliveries in `system := Model.transitionSystem config nodes`; crash, drop and idle stutter in the protocol state.
The timing model permits any nondecreasing absolute time, advanced only by idle steps; every other event takes zero time.
The initial absolute time and live set are unrestricted.
The crash model directly projects to the existing `crashSystem`, requiring live actors and permanently removing crashed nodes.
Delivery requires only the receiver to be live, so a sender may crash after sending.
The delivery model starts with an empty pending ledger and zero issued packets; it tags each actual outgoing envelope with the next sequence number and the sending step's before-time as `sentAt`.
Delivery or drop must consume an existing occurrence before this step's outputs are added.
Delivery is FIFO with loss on each source-target channel, as CCF's channel nonce check enforces: a delivered packet is the oldest outstanding one on its channel, while drops are unrestricted.
Equal envelopes remain distinct transmissions, and an occurrence cannot be consumed twice or after a drop.
The optional `boundedDelayModel maxDelay` separately forbids an overdue pending packet to a live target; it permits drops and is not the stronger `Timely` delivery assumption.

`trace.HeartbeatScheduling`, `trace.SignatureScheduling`, `trace.RetirementConfirmedScheduling` and `trace.ElectionScheduling` each take an `Option Real`: `none` requires eventual execution, `some bound` also requires it before the bound elapses (for elections, `none` is no constraint and `some minimum` forbids timeouts within `minimum` of a reset).
The heartbeat obligation is one send pass, a single `sendEntries` step, because CCF's `send_append_entries` runs under the consensus lock.
A pass sends single-term batches from the peer's send frontier through the primary's current log end; CCF also caps batches at `entries_batch_size`, and the model allows any split.
These are read-only predicates on the recorded trace, separate from model validity and network fairness (`FairLoss`).
All four share `Scheduled trace bound Due Fires`, so a bounded obligation implies the unbounded one and is never vacuous on a finite or Zeno trace.
The scheduling predicates and timing bounds are colocated in `Liveness/Model/Scheduling.lean`.
`Bounds` contains timing bounds only, not protocol configuration or node identities.
Generic `Seq.filter` and `Seq.filterMap` helpers remain in [`Liveness/Seq.lean`](CCFRaft/Liveness/Seq.lean), independently of this relational interface.

## Scope

Node join and snapshot installation are not modeled.
The timed commitment statement assumes a bounded stable-primary window and reconfiguration settled at the leader throughout that window: one active configuration and committed confirmation of every completed removal.
Other nodes need not have learned that completion, and no retirement-cleanup deadline is imposed.
The probabilistic election statement and its bridge remain proof obligations.
Explicit deadlines and continuous uniform draws idealize the concrete tick-based timer; the existing conservative `Bounds.electionTimeout` interpretation is unchanged.
`ElectionReset` accounts for represented CCF reset paths, including term adoption, regular-election starts, vote grants and quorum-check step-downs, while retaining message-handler guards and the same-term AppendEntries log-check distinction.

## Validation

With the pinned Lean toolchain available, run from this directory:

```sh
lake exe cache get
lake check --inadvisably-no-sandbox
lake exe check-imports
lake lint
../../scripts/lean-format-checks.sh ccf-raft
```

`lake check` builds the default target with compiler warnings, including `sorry`, treated as errors, before separately replaying the compiled proofs in Lean's kernel and rejecting nonstandard axioms.
The three draft liveness statements currently prevent this strict check from passing; no validation settings are relaxed for this checkpoint.
Kernel tracing reports the declarations checked during compilation; cached modules do not emit fresh compilation traces.
CI runs this before import coverage, formatting, and linting so the initial build and its traces occur in this step.
The build also runs explicit action traces from an initialized network: committing a client request, adding two nodes then electing a new primary and committing another request, and retiring a follower through committed confirmation at the leader.
The reconfiguration trace checks each node's ledger before delivery, after setup, after replication and commitment, after election, and after the new primary's client request.
The retirement trace checks the new settlement predicate against pending membership changes, the lost commit trigger, and an appended but uncommitted confirmation.
These are regression examples, not exhaustive checking.
[`Tests/ElectionReset.lean`](CCFRaft/Tests/ElectionReset.lean) executes local protocol handlers and checks timer-reset classification for both reset and ignored/rejected-message cases.
`lake check` runs without sandboxing here, so build-time code must be trusted.
`CCFRaft.lean` reexports `Properties.lean` and its public imports transitively, while importing tests privately.
The shared `check-imports` command rejects modules missing from that import closure.

## Proofs

`Properties.lean` contains the full theorem and witness-lemma statements, with one-line proof links into `Proofs/`.
`Proofs/Direct/` establishes node-local commit invariants; `Proofs/Safety/` establishes the cross-node history invariant used for election safety and committed-log comparability.
`Proofs/Replication/` proves commit liveness from that invariant, and `Proofs/Leadership/` proves stable leadership; see [the liveness report](LIVENESS.md).
`Proofs/Witnesses.lean` and `Proofs/LivenessWitness.lean` supply concrete executions checked by the kernel.

To list the safety-invariant declarations used by the exported theorems, run `lake env lean scripts/invariant-dependencies.lean`.
