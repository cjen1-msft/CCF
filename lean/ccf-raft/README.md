# CCF-Raft model

An executable Lean model of CCF's consensus implementation ([`src/consensus/aft/raft.h`](../../src/consensus/aft/raft.h)), safety property statements and a propositional timed liveness layer.
It assumes familiarity with the [CCF consensus documentation](../../doc/architecture/consensus/index.rst).
`commit_liveness` states deterministic commit progress under a stable primary, a live quorum, fair-loss links and a submitted request; `stable_leader` states stable leadership from heartbeat, delay and election-timeout bounds, assuming a quiet start and no quorum-check step-down or failed log check; see [the liveness report](LIVENESS.md).
The liveness trace interface is being revised; its existing proofs have not yet been adapted to the new definitions and statements.

## Source map

| Area                                    | Source                                                                                                                                                             |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Node state, log entries, log queries    | [`Model/NodeState.lean`](CCFRaft/Model/NodeState.lean)                                                                                                             |
| Configurations, quorums, retirement     | [`Model/ClusterConfig.lean`](CCFRaft/Model/ClusterConfig.lean) (`activeConfigurations`, `hasQuorum`, `NodeState.retirement`)                                       |
| Messages                                | [`Model/Messages.lean`](CCFRaft/Model/Messages.lean)                                                                                                               |
| Protocol policy (one node's step)       | [`Model/Node.lean`](CCFRaft/Model/Node.lean) (`Node.step`, `receive`, `act`, `highestCommittableIndex`, `eligiblePeers`)                                           |
| Initial states and network composition  | [`Model.lean`](CCFRaft/Model.lean) (`initialNodeState`, `transitionSystem`)                                                                                        |
| Safety and liveness theorems, witnesses | [`Properties.lean`](CCFRaft/Properties.lean)                                                                                                                       |
| Liveness events and packet identities   | [`Liveness/Model/Event.lean`](CCFRaft/Liveness/Model/Event.lean) |
| Crash and timing transition systems     | [`Liveness/Model/Crash.lean`](CCFRaft/Liveness/Model/Crash.lean), [`Liveness/Model/Timing.lean`](CCFRaft/Liveness/Model/Timing.lean) |
| Liveness traces and send occurrences | [`Liveness/Model/Trace.lean`](CCFRaft/Liveness/Model/Trace.lean), [`Liveness/Model/Packets.lean`](CCFRaft/Liveness/Model/Packets.lean) |
| CCF scheduling assumptions | [`Liveness/Model/Scheduling.lean`](CCFRaft/Liveness/Model/Scheduling.lean) |
| Public liveness import entry points | [`Liveness/Model.lean`](CCFRaft/Liveness/Model.lean), [`Liveness/Assumptions.lean`](CCFRaft/Liveness/Assumptions.lean)                                                |
| Supporting proofs and executions        | [`Proofs/`](CCFRaft/Proofs), with the liveness proofs in [`Proofs/Replication/`](CCFRaft/Proofs/Replication) and [`Proofs/Leadership/`](CCFRaft/Proofs/Leadership) |
| Action-trace tests and import layering  | [`Tests/CanonicalTraces.lean`](CCFRaft/Tests/CanonicalTraces.lean), [`Tests/Architecture.lean`](CCFRaft/Tests/Architecture.lean)                                   |

Transition systems, traces, effects and network composition come from the local [`ccf_common` package](../common/README.md).
Liveness model components live under `Liveness/Model/` and are reexported by `Liveness/Model.lean`.
Short, single-declaration assumptions are defined directly in [`Liveness/Assumptions.lean`](CCFRaft/Liveness/Assumptions.lean).
Separate assumption modules are reserved for related groups of declarations or definitions exceeding 80 lines: [`StableLeader.lean`](CCFRaft/Liveness/Assumptions/StableLeader.lean), [`QuietStart.lean`](CCFRaft/Liveness/Assumptions/QuietStart.lean), [`FairLoss.lean`](CCFRaft/Liveness/Assumptions/FairLoss.lean), and [`Submitted.lean`](CCFRaft/Liveness/Assumptions/Submitted.lean).
Each node reads membership, quorums and retirement from its own ledger; there is no model-wide configuration after initialization.
Initialization takes a nonempty initial voting membership, whose smallest member starts as primary with the genesis configuration transaction.
Base actions are local inputs (including timeouts) or delivery of a queued message; the base protocol has no clock.
The optional liveness layer stores an explicit initial state and a finite or infinite sequence of timed events.
`Trace system` is parameterized by its protocol transition system, so the safety and timing projections use the same protocol system.
The shared `trace.timingTrace.actionAt index` reads recorded timed events; `trace.timingTrace.stateAt (timingSystem system) index` and `trace.timingTrace.stepAt (timingSystem system) index` derive states and transitions by deterministic replay, including timestamps and crash-stop availability.
Steps use `CCF.Execution.Step TracedState TimedEvent`, with the underlying event at `step.action.event`; there are no liveness-specific accessor or step-record copies.
`Trace.modelActions` computably maps events to optional model actions without filtering.
Generic `Seq.filter` and `Seq.filterMap` helpers live in [`Liveness/Seq.lean`](CCFRaft/Liveness/Seq.lean), independently of the Raft model.
`Trace.safetyTrace` retains the initial protocol state and the recorded model actions, omitting environment-only events.
Liveness statements explicitly require `trace.safetyTrace.Valid system`, using the same initial-state/action trace type and `Valid` definition as the safety statements, with `system := Model.transitionSystem config nodes` bound once.
`trace.timingTrace.Valid (Liveness.timingSystem system)` applies the same shared validity definition to the initial timed state and all recorded timed events.
The timing system lifts the supplied protocol system's initialization and transitions, leaving the initial clock and live set without additional restrictions.
Shared trace validity checks every recorded action, so a disabled action cannot disappear by truncating replay; no failure-sentinel state or separate enabledness premise is needed.
Elapsed durations have type `NNReal`, so they may be zero but cannot be negative; no separate elapsed-time validity assumption is needed.
`trace.crashTrace.Valid Liveness.crashSystem` applies shared validity to the initial live set and every event, without filtering or changing indices.
It requires local actors, delivery receivers and nodes being crashed to be live, then permanently removes crashed nodes; the initial live set remains unrestricted.
Crash replay explicitly handles crash events after checking the actor is live; timing replay uses `Event.liveAfter` to track availability without enforcing crash validity itself.
Timing replay starts at event index zero with an empty outstanding-packet ledger and generates each send identity as `(step, ordinal)` from the actual outputs.
Delivery and drop must match an outstanding identity and its envelope, consume it once, and cannot consume outputs of their own step.
Identical retransmitted envelopes remain distinct occurrences; packet validity is enforced by `timingTrace.Valid`, without a separate premise.
Untimed progress states `trace.HeartbeatScheduling`, `trace.SignatureScheduling`, and `trace.ConfirmationScheduling` as separate premises; timed leadership uses `model.Timed`.
These encode CCF's background-task scheduling obligations, separately from action-trace validity and network fairness (`FairLoss`).
The scheduling predicates, timing bounds, and timed scheduling model are colocated in `Liveness/Model/Scheduling.lean`.
`LivenessModel` contains timing bounds only, not protocol configuration or node identities.

## Scope

Node join and snapshot installation are not modeled.
Commit liveness assumes a stable primary, which `stable_leader` derives from timing under further assumptions; probabilistic election progress is not modeled.

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
Kernel tracing reports the declarations checked during compilation; cached modules do not emit fresh compilation traces.
CI runs this before import coverage, formatting, and linting so the initial build and its traces occur in this step.
The build also runs two explicit action traces from an initialized network: committing a client request, and adding two nodes then electing a new primary and committing another request.
The reconfiguration trace checks each node's ledger before delivery, after setup, after replication and commitment, after election, and after the new primary's client request.
These are regression examples, not exhaustive checking.
`lake check` runs without sandboxing here, so build-time code must be trusted.
`CCFRaft.lean` reexports `Properties.lean` and its public imports transitively, while importing tests privately.
The shared `check-imports` command rejects modules missing from that import closure.

## Proofs

`Properties.lean` contains the full theorem and witness-lemma statements, with one-line proof links into `Proofs/`.
`Proofs/Direct/` establishes node-local commit invariants; `Proofs/Safety/` establishes the cross-node history invariant used for election safety and committed-log comparability.
`Proofs/Replication/` proves commit liveness from that invariant, and `Proofs/Leadership/` proves stable leadership; see [the liveness report](LIVENESS.md).
`Proofs/Witnesses.lean` and `Proofs/LivenessWitness.lean` supply concrete executions checked by the kernel.

To list the safety-invariant declarations used by the exported theorems, run `lake env lean scripts/invariant-dependencies.lean`.
