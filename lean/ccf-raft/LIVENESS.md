# Deterministic commit liveness and stable leadership

## Recommendation and status

**Specification checkpoint:** [`Properties.lean`](CCFRaft/Properties.lean) now states timed `commit_liveness`, probabilistic `duelling_leaders_resolve`, and `signature_settles`.
`commit_liveness` is proved in [`Proofs/Timed`](CCFRaft/Proofs/Timed) with an explicit window (see [known gaps](#known-gaps-in-the-windowed-statements)).
The other two statements contain `sorry`; the duel constants are provisional, and known gaps remain in the leadership statements.
[Premises the windowed statements need](#premises-the-windowed-statements-need) records the premises added so far, each with a counterexample to its absence.
The window assumptions are in [`Window.lean`](CCFRaft/Liveness/Assumptions/Window.lean), draws and signature commitment in [`Duel.lean`](CCFRaft/Liveness/Assumptions/Duel.lean), and explicit deadlines in [`Timers.lean`](CCFRaft/Liveness/Model/Timers.lean).
The remainder of this report describes the earlier, still-proved internal untimed commitment and conditional leadership results; references to their old public names do not establish the new statements.

`ElectionReset` now also records quorum-check step-down, actual local term increases (new-term adoption or regular-election starts), and same-term regular-vote grants.
Using the actual term transition preserves the protocol's known-peer and message-specific guards, including ignoring AppendEntries responses on non-primaries and not adopting a proposal's term.
The earlier same-term AppendEntries distinction is preserved: a candidate steps down and resets before checking the log, but an established follower does not reset on a failed check.
The [conservative tick/drift interpretation of timing constants](#timing-constants) is unchanged; the new continuous-draw/deadline specification still needs a correspondence argument for concrete CCF clocks.

The liveness definitions use a fully recorded relational trace over the existing multi-node protocol.
This is a TLA-style explicit-state formulation, not a replacement Raft algorithm.
The definitions in [`Liveness/Model.lean`](CCFRaft/Liveness/Model.lean) and [`Liveness/Assumptions.lean`](CCFRaft/Liveness/Assumptions.lean) permit finite or infinite executions and unbounded logs.
`Model.lean` reexports the independent models in `Liveness/Model/`, with their event vocabulary in [`Model/Event.lean`](CCFRaft/Liveness/Model/Event.lean).
The local generic relational trace and `Model` definitions live in [`Model/Trace.lean`](CCFRaft/Liveness/Model/Trace.lean); `lean/common/` is unchanged.
`Assumptions.lean` defines short assumptions inline and imports larger groups of related declarations from `Liveness/Assumptions/`.
CCF's background-task scheduling predicates and timing bounds are colocated in [`Model/Scheduling.lean`](CCFRaft/Liveness/Model/Scheduling.lean).
The main commit assumptions are `StableLeader` in [`StableLeader.lean`](CCFRaft/Liveness/Assumptions/StableLeader.lean), `LiveQuorum` inline in [`Assumptions.lean`](CCFRaft/Liveness/Assumptions.lean), `FairLoss` in [`FairLoss.lean`](CCFRaft/Liveness/Assumptions/FairLoss.lean), and `Submitted` in [`Submitted.lean`](CCFRaft/Liveness/Assumptions/Submitted.lean).
It records an initial world and each step's before-state, event and after-state, reusing `CCF.Execution.Step W Event`.
It does not enumerate executions.

Properties quantify `config` and `nodes` explicitly and bind `system := Model.transitionSystem config nodes` once.
Their single trace has type `Liveness.Trace W Liveness.Event` for any `W` with the required accessor instances, independent of `system`.
`Trace.Coherent` connects the first step to the initial world and each after-state to the next before-state.
`trace.stepAt i` and `trace.actionAt i` directly read recorded values, and `trace.stateAt 0` is the initial world while `trace.stateAt (i + 1)` is step `i`'s after-state.
These are total `Option`-valued accessors, not replay or filtered projections.
An invalid step remains visible rather than truncating the accessible recording.
A zero-step trace retains its initial world, and a finite trace has a final recorded state without a dummy event.

A `Model W Event` consists of `init : W -> Prop` and `next : CCF.Execution.Step W Event -> Prop`.
`trace.Valid model` requires the initial predicate and the next relation at every recorded step.
Validity against several models is plain conjunction.
There is no replay, composition operator, model ordering or variable ownership: overlapping constraints are permitted, and contradictions simply shrink the set of valid traces.
Each model leaves unmentioned fields unconstrained.

[`Model/World.lean`](CCFRaft/Liveness/Model/World.lean) supplies `HasProtocol W S`, `HasTime W`, `HasLive W` and `HasNetwork W`.
Models are generic in the world and request only the accessors they inspect.
Lean has no row types or polymorphic variants, so these classes play the role of an open record; the closed `World S` in [`Model/WitnessWorld.lean`](CCFRaft/Liveness/Model/WitnessWorld.lean) is used only by witnesses.
`HasNetwork` exposes the pending ledger and the count of issued packets; there is no scheduler deadline or last-send variable.

Each public statement conjoins `trace.Coherent` and validity of four models inline:

| Model                  | Initial predicate                | Next relation                                                                                                                                                                                                |
| ---------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `protocolModel system` | `system.init (proto w)`          | Execute `Event.action` in `system`, or preserve `proto` for crash, drop and idle.                                                                                                                            |
| `timingModel`          | `True`                           | `time before <= time after`, with equality unless the event is idle.                                                                                                                                         |
| `crashModel`           | `crashSystem.init (live w)`      | `crashSystem.step (live before) event = some (live after)`.                                                                                                                                                  |
| `deliveryModel system` | `pending w = [] /\ issued w = 0` | Consume an existing packet for delivery or drop, delivering only the oldest outstanding packet on its channel; append this step's actual outgoing packets with fresh sequence numbers, and advance `issued`. |

The protocol model in [`Model/Protocol.lean`](CCFRaft/Liveness/Model/Protocol.lean) preserves the existing `Event.action` mapping, including delivery of the received envelope.
Its protocol state is generic, while its action type is `Model.Action`, as fixed by the existing `Event` vocabulary.
The delivery model uses the concrete Raft state and its recording callback to extract outgoing envelopes.
The timing model in [`Model/Timing.lean`](CCFRaft/Liveness/Model/Timing.lean) permits any initial absolute time; only idle steps advance time, and every other event takes zero time.
The crash model in [`Model/Crash.lean`](CCFRaft/Liveness/Model/Crash.lean) directly projects to the unchanged `crashSystem`.
It requires live actors and permanently removes crashed nodes, with unrestricted initial availability.
Deliveries require only a live receiver, so a sender may crash after sending; a repeated crash is disabled.

The delivery model in [`Model/Delivery.lean`](CCFRaft/Liveness/Model/Delivery.lean) starts from an empty pending ledger.
Actual outputs receive consecutive sequence numbers from `issued`, with `sentAt := time before` of the sending step.
A step happens at its before-time, and only an idle step lets time elapse after it; every timing constraint compares before-times.
Delivery and drop consume an outstanding packet before this step's outputs are registered, rejecting fabrication, early consumption and reuse, including delivery after a drop.
Each source-target channel is FIFO with loss (`Event.InOrder`): a delivered packet is the oldest outstanding packet on its channel, and drops are unrestricted, so a packet overtakes an earlier one only if that one is lost.
This matches CCF's node-to-node channels, whose receivers reject any nonce that is not above the last one received (`Channel::decrypt` in [`src/node/channels.h`](../../src/node/channels.h)).
Messages lost while a channel is established or rekeyed are drops.
Equal envelopes remain distinct transmissions.
`Trace.SentAt index packet` holds when the packet first appears in the ledger after step `index`.
The protocol queue retains untagged dropped envelopes, while the separate ledger prevents consuming the corresponding occurrence again.
Packet accounting imposes no delivery guarantee; `Timely` and `FairLoss` remain separate assumptions.
The optional sixth model, `boundedDelayModel maxDelay`, constrains every pending packet to a live target by `time <= sentAt + maxDelay`, both initially and after each step.
It stores no deadlines and no public statement assumes it; it permits dropping a packet and is weaker than an obligation to deliver it.

Scheduling is stated through separate `trace.HeartbeatScheduling bound`, `trace.SignatureScheduling bound`, `trace.RetirementConfirmedScheduling bound` and `trace.ElectionScheduling minimum` premises in [`Model/Scheduling.lean`](CCFRaft/Liveness/Model/Scheduling.lean).
These encode CCF's periodic sends, signature task, retirement-confirmation handling and election timer.
Each bound is an `Option Real`: `none` requires eventual execution, `some bound` also requires it before the bound elapses; for elections `none` is no constraint and `some minimum` forbids a timeout within `minimum` of a reset.
Commit liveness passes `none` everywhere; stable leadership passes `some heartbeatInterval` and `some (electionTimeout / 2)`.
Scheduling remains a read-only trace predicate, with no world variables, mutable deadline state or model composition.
For a leader-peer pair due at index `i`, a send pass or the end of the obligation must occur from a state at or after `i` whose time is at most `time (stateAt i) + heartbeatInterval`.
A send pass is one `sendEntries` step, because CCF's `send_append_entries` runs under the consensus lock.
It sends single-term batches from the peer's send frontier through the primary's current log end; CCF also caps batches at `entries_batch_size`, and the model allows any split.
`Scheduled trace bound Due Fires` is the shared shape: whenever `Due` holds, it eventually ceases or `Fires` runs, from a state satisfying `Deadline bound`; with `some bound` this still implies the `none` form, so it is never vacuous on finite or Zeno traces.
These predicates inspect recorded steps, protocol states and absolute times; scheduling obligations and deadlines do not follow merely from local model validity.
They are distinct from the network fairness assumption `FairLoss`.
`Bounds` contains only timing bounds, not the initial configuration or node identities.
An intermediate starting point is an explicit index `start` in this execution from boot, not an implicitly chosen reachable initial state.
The generic sequence helpers in [`Liveness/Seq.lean`](CCFRaft/Liveness/Seq.lean) remain independent of this interface.

The proofs are written directly against these statements.
The claims in [`Properties.lean`](CCFRaft/Properties.lean) are:

- `commit_liveness` separately requires heartbeat, signature, and retirement-confirmation scheduling, plus four assumptions: a primary stable from some point on, a live quorum, fair-loss links and a submitted request.
- `stable_leader` derives a stable primary from bounded heartbeat and election scheduling and the premises in [stable leadership](#stable-leadership).
  Some of those premises assume away events rather than derive their absence: quorum-check step-downs, failed log checks, and timeouts of nodes the primary does not send to.
- `commit_liveness_timed` combines them, so it assumes no stable primary.

Every constraint of the environment and every assumption cites the CCF code it models or states a counterexample showing that a theorem needs it, except `Covered`, whose necessity is open.
The counterexamples are prose arguments, except signature starvation, which [`Proofs/LivenessWitness.lean`](CCFRaft/Proofs/LivenessWitness.lean) checks.
The environment constraints are meant to admit every CCF execution, given suitable values of the timing bounds; see [timing constants](#timing-constants).
The environment obliges the primary to eventually append owed retirement confirmations, as CCF's `retired_node_cleanup` does.
The proof also needed two changes to bring the model in line with CCF; see [a lost commit trigger](#a-lost-commit-trigger).
`commit_liveness` states eventual inclusion of a submitted request in the stable primary's committed prefix, not a latency bound, commitment at every replica, or election convergence.
The environment does not assume eventual commitment or eventual quorum acknowledgements.

Proved, reusing the safety invariant from [`Proofs/Safety`](CCFRaft/Proofs/Safety) and depending only on the standard axioms:

| Result                                                         | File                                                                         | Meaning                                                                                                                                                                                                                                                                                                                                             |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `commit_liveness`                                              | [`Proofs/Replication/Commit.lean`](CCFRaft/Proofs/Replication/Commit.lean)   | Untimed eventual commit.                                                                                                                                                                                                                                                                                                                            |
| `signature_commits`                                            | [`Proofs/Replication/Commit.lean`](CCFRaft/Proofs/Replication/Commit.lean)   | Signature commitment, for every signature in the primary's log, whatever its term.                                                                                                                                                                                                                                                                  |
| `confirmation_owed`, `owing_of_exec`                           | [`Proofs/Replication/Owing.lean`](CCFRaft/Proofs/Replication/Owing.lean)     | In every reachable state, a primary that alone makes an uncommitted current-term signature committable owes a retirement confirmation.                                                                                                                                                                                                              |
| `sane_of_exec`                                                 | [`Proofs/Replication/Sane.lean`](CCFRaft/Proofs/Replication/Sane.lean)       | In every reachable state, every confirmation in a node's log follows a removal it has committed, and every re-add follows a confirmation it has committed, with no configuration naming the node in between.                                                                                                                                        |
| `advance_owed`                                                 | [`Proofs/Replication/Confirm.lean`](CCFRaft/Proofs/Replication/Confirm.lean) | Right after a commit scan, such a signature means the scan retired the other members, whose confirmations are then owed.                                                                                                                                                                                                                            |
| `request_committed`                                            | [`Proofs/CommitLiveness.lean`](CCFRaft/Proofs/CommitLiveness.lean)           | Signature commitment implies commit liveness: the submission puts the request in the primary's log, the signature obligation appends a covering current-term signature, and the primary keeps both.                                                                                                                                                 |
| `stable_leader`, `quiet_all`                                   | [`Proofs/Leadership/Stable.lean`](CCFRaft/Proofs/Leadership/Stable.lean)     | `Properties.stable_leader`: the primary's term stays quiet at every index.                                                                                                                                                                                                                                                                          |
| `no_timeout`, `reset_follows`                                  | [`Proofs/Leadership/Stable.lean`](CCFRaft/Proofs/Leadership/Stable.lean)     | While the term is quiet, heartbeats and timely delivery reset every tracked node's election timer often enough that no node of the term times out.                                                                                                                                                                                                  |
| `Quiet.step`                                                   | [`Proofs/Leadership/Quiet.lean`](CCFRaft/Proofs/Leadership/Quiet.lean)       | A step keeps the term quiet, unless it is an election timeout in the term, or the primary nominates a successor, retires or fails a quorum check.                                                                                                                                                                                                   |
| `recent_reset`                                                 | [`Proofs/Leadership/Timers.lean`](CCFRaft/Proofs/Leadership/Timers.lean)     | A timer reset within `gap` of every earlier point has a reset less than `window > gap` before any point `window` after the start.                                                                                                                                                                                                                   |
| `match_reaches`                                                | [`Proofs/Replication/Peer.lean`](CCFRaft/Proofs/Replication/Peer.lean)       | The primary's match index for a live peer that is eligible from some point on, and is reached by productive sends and fair-loss links, eventually covers every position of the primary's log.                                                                                                                                                       |
| `peer_term_le`                                                 | [`Proofs/StablePrimary.lean`](CCFRaft/Proofs/StablePrimary.lean)             | Under `FairLoss`, a live peer that stays eligible for a stable primary never holds a newer term.                                                                                                                                                                                                                                                    |
| `ack_commits_trace`                                            | [`Proofs/StablePrimary.lean`](CCFRaft/Proofs/StablePrimary.lean)             | A successful current-term acknowledgement delivered to the stable primary commits every signature already acknowledged by the commit scan's quorums.                                                                                                                                                                                                |
| `acknowledged_signature_commits`                               | [`Proofs/Liveness.lean`](CCFRaft/Proofs/Liveness.lean)                       | The node-level commit scan, including retirement and successor handling, commits a quorum-acknowledged current-term signature.                                                                                                                                                                                                                      |
| `Admissible.reachable`                                         | [`Proofs/Liveness/Admissible.lean`](CCFRaft/Proofs/Liveness/Admissible.lean) | Every recorded protocol state is reachable in the system.                                                                                                                                                                                                                                                                                           |
| `electionScheduling_of_timerModel`                             | [`Proofs/Liveness/Timers.lean`](CCFRaft/Proofs/Liveness/Timers.lean)         | The deadline timer model implies `ElectionScheduling (some (electionTimeout / 2))`.                                                                                                                                                                                                                                                                 |
| `Admissible.consumed_within`                                   | [`Proofs/Liveness/Delay.lean`](CCFRaft/Proofs/Liveness/Delay.lean)           | Under bounded delay and a diverging clock, a packet outstanding to a live target is consumed, or its target crashes, at a step no later than `maxDelay` after it was sent.                                                                                                                                                                          |
| `Admissible.ids_nodup`                                         | [`Proofs/Liveness/Network.lean`](CCFRaft/Proofs/Liveness/Network.lean)       | Outstanding packets carry distinct sequence numbers, so a packet that leaves the ledger is the one the step consumes.                                                                                                                                                                                                                               |
| `margin_probability`, `settle_probability`, `settle_of_margin` | [`Proofs/Duel/Probability.lean`](CCFRaft/Proofs/Duel/Probability.lean)       | For `0 < n` and `0 <= 2 m <= E`, `n` independent uniform draws in `[E / 2, E]` have a strict lead of `m` with probability at least `marginProbability`, and some round of `rounds` has one with probability at least `settleProbability`. `settle_of_margin` reduces `duelling_leaders_resolve` to showing that a margin round commits a signature. |
| `reliable_suffix_fair_loss`                                    | [`Proofs/Liveness.lean`](CCFRaft/Proofs/Liveness.lean)                       | An eventually reliable suffix satisfies `FairLoss`.                                                                                                                                                                                                                                                                                                 |

`signature_commits` takes a covering current-term signature and supposes that it is never committed.

1. Settling: the commit index then stays below the signature, so the configurations at or before it that remain active are a suffix of a fixed list which only shrinks, and eventually stop changing (`active_settles`).
2. Eligibility: their members then stay eligible peers of the primary, because appends only add active configurations (`eligiblePeers_append`).
3. Catch-up: each such member of the live quorum eventually acknowledges the signature (`match_reaches`).
   Otherwise the peer settles: each change to its log adopts a prefix of the primary's log and increases a bounded potential, and rejections never move the primary's retry index below the agreed prefix, so fair loss eventually delivers the missing entries ([`Proofs/Replication`](CCFRaft/Proofs/Replication)).
4. Trigger: if one of those configurations has a live quorum member other than the primary, its next acknowledgement runs the commit scan, which commits the signature (`ack_commits_trace`).
   Otherwise the primary alone makes the signature committable, so a retirement confirmation is owed (`confirmation_owed`); the primary eventually appends it, and that append runs the commit scan (`append_commits_trace`).

`peer_term_le` discharges the newer-term case that would otherwise block catch-up.

The proofs share a base in [`Proofs/Liveness/`](CCFRaft/Proofs/Liveness).
`Admissible system trace` bundles coherence and the four base model validities; its lemmas give each recorded step's protocol transition or stutter, live actors, packet provenance and reachability.
`StableLeader` and `Submitted` are indexed by the explicit `start`, so each argument runs on the recording from that index rather than on a shifted suffix.
No premise requires an infinite recording: an obligation that stays due must eventually fire, so a primary that stays due to send heartbeats keeps the recording going (`Scheduled.recorded`, `Scheduled.often`).

## Premises the windowed statements need

Each premise below was added after a counterexample showed a windowed statement false without it.
The counterexamples are prose arguments.

| Premise                         | Statement                                       | Counterexample without it                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------- | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TimeDiverges`                  | `commit_liveness`                               | The recording ends, or its clock stops, while the primary's AppendEntries are pending. Bounded delay only stops time from passing a packet's deadline, so nothing need be delivered, and nothing commits.                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Only idle steps advance time    | `commit_liveness`                               | A single-node primary appends and commits the request at time zero in a step that also advances the clock past the end of the window, whatever its length, so no state in the window records the commit.                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Per-channel FIFO delivery       | `commit_liveness`                               | Clients append `k` entries in zero time before the next signature, and the primary sends them to a peer with no backlog as single-entry AppendEntries that arrive in reverse order. Every batch except the earliest arrives before the entry it extends and is rejected, so the peer gains one entry per round trip, and commit latency grows with `k`.                                                                                                                                                                                                                                                                                                  |
| `InTermAt`                      | `commit_liveness`                               | Five nodes A to E: A and E alternately win `2n` terms with the votes of C and D, whose logs stay empty, and each appends one entry per term; A's entries reach B and E's reach nobody. E's probe of B backs off to an AppendEntries from index 0 that stays in flight while B, in term `2n`, has `isNewFollower` set. A wins term `2n + 1` without B, replicates to C, and then D and E crash. At `start`, A, B and C form a live quorum with no backlog, and `Quiet` holds. E's delayed message replaces B's log with E's `n` entries, and each rejection moves A's probe back one entry, so B, which every quorum needs, takes `n` rounds to catch up. |
| `Window.ReconfigurationSettled` | `commit_liveness`                               | A configuration commit can leave the leader alone with a later committable signature but no event rerunning the commit scan. One active configuration is insufficient: its removed nodes may still await committed retirement confirmation.                                                                                                                                                                                                                                                                                                                                                                                                              |
| `0 < competitors`               | `duelling_leaders_resolve`                      | With no participants, `GoodPeriod.quorum` holds when every node is crashed, and then nothing commits, yet `settleProbability` is one for any positive number of rounds.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `0 <= heartbeatInterval`        | `duelling_leaders_resolve`                      | With one competitor in a single-node configuration, `E = 1`, `heartbeatInterval = -1`, `maxDelay = 0` and one round, `settleProbability` is 3, above any probability. Heartbeat scheduling is vacuous without peers, so the premises are satisfiable.                                                                                                                                                                                                                                                                                                                                                                                                    |
| `GoodPeriod.participantsLive`   | `duelling_leaders_resolve`                      | The adversary crashes every node at `start`, which satisfies `GoodPeriod.quorum` vacuously, and nothing commits.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `NoOvershoot`                   | `duelling_leaders_resolve`                      | `Scheduled` counts only from the first recorded point at which a node is due. One idle step can carry the clock past every participant's deadline, so all of them become due at the same point and time out together, however far apart their draws were; repeated every round, no candidate ever gets a head start.                                                                                                                                                                                                                                                                                                                                     |
| `GoodPeriod.noQuorumChecks`     | `duelling_leaders_resolve`, `signature_settles` | The model does not constrain quorum checks, so every new primary of a multi-node configuration may step down before it signs. This is assumed, not derived, for the reason given for `Incumbent.quorumChecks` in [stable leadership](#stable-leadership).                                                                                                                                                                                                                                                                                                                                                                                                |

`Proofs.Liveness.Admissible.consumed_within` shows that `TimeDiverges` and bounded delay together consume every outstanding packet within `maxDelay`, unless its target crashes.

The timed commitment statement requires every participant to have adopted `term` at `start` (`InTermAt`), so that with `LiveQuorum` a live quorum stays in `term` throughout the window.
The voters that elected the leader qualify while they stay live; naming them instead would be too strong, since a reconfiguration in `term` can leave them short of a quorum of the active configuration.
The internal eventual-commit result is proved without this premise.

The timed commitment statement separately requires reconfiguration to be settled at the leader throughout its window: exactly one active configuration and no completed removal awaiting committed confirmation.
An appended but uncommitted confirmation is still unfinished work.
This excludes both inherited cleanup and new pending configuration changes; it does not require followers to have learned that completion.
The retirement trace in [`Tests/CanonicalTraces.lean`](CCFRaft/Tests/CanonicalTraces.lean) reproduces the stranded-signature state and checks that it, pending configuration changes, and uncommitted confirmations are rejected, while completion at the leader alone is accepted.
`RetirementConfirmedScheduling none` remains unbounded for the internal eventual-commit result; the timed statement does not need a cleanup deadline because cleanup is excluded from its window.
The extra settlement premise is not a consequence of `StableWindow` or `GoodPeriod`.

## Known gaps in the windowed statements

`commit_liveness` asserts only that some finite window, chosen from the bounds, delay and backlog but not the trace, suffices.
Its proof, `Proofs.Timed.commit_liveness_timed`, uses `commitDuration`: with signature bound `S`, heartbeat bound `H' = max H 0`, delay `d` and backlog `b`, the window is `max S 0 + 2 * max (ackBound d H' b) 0`, where `ackBound d H' b = 6 d + 4 H' + 2 (b + 1) (2 d + H')`.
A covering signature appears within `max S 0`, and every live participant in the active configuration acknowledges it within one `ackBound`; the second `ackBound` is slack.
The proof uses `Window.StableLeader` only for the primary and for participants' terms.

- `signature_settles`: nothing bounds the participants' election timers at `start`, `StableLeader` also constrains non-participants, and a participant whose log is behind may become a pre-vote candidate, which `Quiet` forbids, even though it cannot depose the primary.
- `duelling_leaders_resolve`: `TimerDraws` gives each participant its `k`-th draw at its own `k`-th reset, and resets need not line up into rounds across participants.
  A margin winner whose log is behind also loses its pre-votes.

## Stable leadership

`Properties.stable_leader` states that `leader` stays the primary of `term` from an explicit index `start` in an execution with `HeartbeatScheduling (some heartbeatInterval)` and `ElectionScheduling (some (electionTimeout / 2))`, with these premises defined in [`Liveness/Assumptions.lean`](CCFRaft/Liveness/Assumptions.lean):

| Premise                | Meaning                                                                                                                                                                        |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `QuietStart`           | The primary is the newest at the start: no node or message is past its term, no pre-vote candidate or vote proposal is in it, and no timer of the term expires within `E / 2`. |
| `Timely`, `0 <= delay` | AppendEntries requests from the primary arrive within `delay`, unless their target crashes. Other messages may be lost or delayed.                                             |
| `Matching`             | Every AppendEntries request from the primary that reaches a node of the term, other than a candidate, passes the node's log check.                                             |
| `H + delay < E / 2`    | A heartbeat interval plus the delay is below the shortest time from a timer reset to a timeout.                                                                                |
| `Covered`              | Every node that times out in the term has been a replication peer of the primary throughout.                                                                                   |
| `Incumbent`            | The primary stays live, its retirement never commits, it gets no stop notice, and it never steps down on a quorum check.                                                       |

A node moves past the term only by a fresh campaign from it, or by receiving a message from past it.
A fresh campaign from the term needs an election timeout, a quorum of pre-votes for a pre-vote candidate of the term, which only an election timeout creates, or a vote proposal for the term, which only the primary sends, by election safety.
The primary keeps its role within its term unless its retirement commits, it fails a quorum check, or it receives a request of its own term, which only it sends.
So by strong induction on the index the term stays quiet, unless a node of the term times out (`Quiet.step`).
The primary sends each tracked peer a heartbeat within `H` of any index, which arrives within `delay`, passes the log check and resets the peer's timer, so a timeout at least `E / 2` after the start has a reset less than `E / 2` before it, which `electionTimers` forbids (`no_timeout`).

The ratio cannot be relaxed in this model, by this argument, which is not checked in Lean.
If `H + delay >= E / 2`, two heartbeats `H` apart, the first delivered at once and the second after `delay`, leave a gap of `H + delay` without a reset, and the timer may fire `E / 2` into it.

Each premise is needed, as its definition's comment argues, except perhaps `Covered`.
Four CCF behaviors explain the premises:

- A failed log check does not reset the election timer.
  `recv_append_entries` calls `restart_election_timeout` only after the `prev_term` check, whereas Raft resets on any AppendEntries from the current leader.
  A follower whose log is shorter than the primary's send index fails the check on every heartbeat until one of its rejections reaches the primary.
  If its rejections are lost, it times out, and if another lagging node grants it a pre-vote, it deposes the primary, so `Matching` is assumed.
  Deriving it would need bounded responses, a bound on the rejections needed to repair a log, and probably a larger ratio.
  This may be worth hardening in CCF.

- Pre-vote does not protect a working primary.
  CCF grants pre-votes whatever leader it knows (`raft.h`, `recv_request_vote_unsafe` checks `leader_id` only for real votes), so a node of the term that times out can gather pre-votes and start the next term.
  The model now departs from CCF here and grants a pre-vote only while the node knows no primary; see "A lagging follower deposes the primary" below.
  So no timer of the term may expire before the primary's heartbeats arrive, and every node that may time out must get heartbeats.
- Quorum checks are not derived from timing, and could not be in this model.
  `Timely` does not bound responses, and bounding them would not suffice either.
  A follower silently ignores an AppendEntries whose `prev_idx` is below its commit index (`recv_append_entries`).
  A stale rejection, handled before the acknowledgement of a later acceptance that raised the follower's commit index, moves the primary's `sent_idx` back below that commit index.
  A send pass is one atomic step through the log end, matching CCF's `send_append_entries`.
  Deriving `Incumbent.quorumChecks` still needs a round-trip bound and a model of the acknowledgement-age check, rather than the protocol's unconstrained step-down action.
- Once a removed node's confirmation commits, the primary stops sending to it (`set_retired_committed`).
  If the node has not learned this, it still times out, but it then also needs a quorum of pre-votes; whether that can happen is open.

## A counterexample to exact-term fairness

An earlier draft keyed every traffic class on an exact term, and commit liveness was false under it.
Take five nodes, a primary `L` in term `T` and a quorum `{L, F1, F2}`.
The other four nodes keep electing in ever higher terms; votes are not fair-loss traffic and links to the two non-quorum nodes are unconstrained.
`F1` and `F2` reject every term-`T` request with a NACK carrying their current, ever newer, term.
Each exact-term class is sent only finitely often, so fair loss allows every NACK to be dropped.
`L` never learns of a newer term and stays primary, a quorum survives, every premise holds, and nothing commits.

Traffic classes now cover a minimum term and every newer one.
A peer stuck above `T` then keeps sending one class of NACK, one is delivered, and `L` steps down, so such executions violate `StableLeader`.
`peer_term_le` proves this.
An alternative is a separate explicit premise that no quorum member exceeds the primary's term, in the style of the duelling-leaders exclusions.

## A counterexample to index-only rejection fairness

With only the classes above, a follower with a stale suffix can starve.
Let the primary `L` in term `T` have log terms `[t1, T, T, T, ...]` and a term-`T` follower `p` have `[t1, t2, t2, t2]`, where `t1 < t2 < T`, and `p` has not yet truncated in term `T`.
A request with previous index 4 is rejected with hint `(t2, false, 4)`, from which `L` backtracks to index 1.
A request with previous index 5 or more is rejected with `(T, false, 4)`, from which `L` retries at index 4.
The network can drop every rejection of the first kind and deliver every one of the second kind, since the second kind matches every upward-closed `response` class the first kind matches.
`L` then never sends entries 2 to 4, so `p` never truncates and never acknowledges anything beyond index 1.

`FairLoss` therefore also includes the textbook fair-loss class: one exact wire message sent infinitely often is delivered infinitely often.
Rejections from a follower whose log and term are stuck are identical, so the low hint is eventually delivered.

## A lost commit trigger

The primary runs its commit scan only after an append or a successful acknowledgement.
A configuration commit can make a later signature committable without either:

1. An older-term primary `A`, with configuration `{L, A}` active, appends configuration `{L}` and a signature.
   `L` receives them, but its acknowledgement is dropped, so neither node commits the change.
2. `L` is elected in term `T` with `A`'s vote, appends signature `h`, and `A` acknowledges it.
3. Before that acknowledgement arrives, `L` appends a request and signature `s`.
   `s` is not yet committable because `{L, A}` is still active.
4. The acknowledgement commits `h`, which retires `{L, A}`.
   `L` alone can now commit `s`, but the scan has already run.

An execution starting just after step 4, with quorum `{L}`, would satisfy every other premise; if `A` then crashes, nothing reruns the scan.
CCF avoids this.
When a commit retires configurations, `aft::Aft::commit` calls `retired_node_cleanup`, which asks the node itself to run `set_retired_committed`.
That transaction records `A`'s retirement, and `replicate` runs `update_commit` when there are no other active nodes.
The liveness model mirrors this with the separate predicate `Trace.RetirementConfirmedScheduling none`: while the primary may append a retirement confirmation, it eventually does so or stops being able to.

`owing_of_exec` shows this always suffices.
The commit scan that made such a signature committable retired the other members, so their confirmations are owed.
None of them has a confirmation in force, because every confirmation in a node's log follows a removal of its node that the node has committed, and no configuration names the node from that removal to the confirmation (`sane_of_exec`).

That needed two model changes, both matching CCF.
First, a configuration that names a node clears that node's earlier confirmations in `retiredCommittedNodes`, like the fresh node record, with `retired_committed` unset, that CCF creates when a deleted node rejoins.
Without this, a node removed, confirmed, re-added and removed again keeps its old confirmation, so nothing is owed, the primary may not confirm it again, and the trigger is lost.
Second, `appendEntry` re-adds a removed node only once its confirmation is committed and still in force, as CCF only deletes, and so lets rejoin, a node whose `retired_committed` status is globally committed (`delete_retired_committed_node` in `src/node/rpc/node_frontend.h`).
Without this, a confirmation could follow a pending re-add and count while the node is active again.
`sane_of_exec` correspondingly shows that every re-add follows a committed confirmation, and no configuration names the node in between.

These proofs also tightened facts in the safety step summary:
`Advance` records that an unchanged commit index means nothing was committable, and that a commit clears the role only when the node's retirement commits; `Kind.append` records that each appended entry passed `appendEntry`'s guards; and `AEOk` records that a request with entries carries its sender's exact commit index.
For stable leadership, `Summary` records why a term rises (`term_cause`), that only an election timeout starts a pre-vote (`pre_vote`), and when a primary keeps its role (`role_keep`); `SendOK` records where vote proposals come from and the term a rejection carries.

## A lagging follower deposes the primary

This is a liveness weakness of CCF itself, not of the model; the model now departs from CCF to exclude it.
Two CCF behaviours combine (`src/consensus/aft/raft.h`):

- `recv_append_entries` calls `restart_election_timeout` only after the `prev_term` check passes; a rejected AppendEntries leaves the follower's timer running.
- `recv_request_vote_unsafe` applies the known-leader check (`leader_id.has_value()`) and the voted-for check to `RegularVote` only.
  A pre-vote is granted to any candidate of the node's term whose committable log is at least as up to date as the node's own, even by a follower that is receiving heartbeats from a live primary.
  Raft's pre-vote, and etcd's lease check, reject such a request while the node has heard from a leader within an election timeout.

Worked example, three nodes `{L, f, g}`, election timeout `E = 7`, so a timer fires between 3.5 and 7 after its reset, heartbeat interval `H = 1` and message delay at most `d = 1`:

1. `L` is the primary of term `t`.
   Its log has 10 entries, and its last signature is entry 8, so entries 9 and 10 are not yet committable.
   `g` holds all 10 entries and accepts every heartbeat.
   `f` holds only the first 8: the AppendEntries carrying entries 9 and 10 was lost, and `f`'s timer was last reset, at time 0, when it accepted entry 8.
   Its timer fires at 3.5.
2. `L` believes it sent entries 9 and 10, so its heartbeat at time 1 carries `prev_idx = 10`.
   `f` fails the `prev_term` check at time 2, replies with a NACK and does not reset its timer.
   The NACK reaches `L` at time 3, so the repairing AppendEntries cannot reach `f` before time 4.
3. At 3.5 `f`'s timer fires.
   `f` becomes a pre-vote candidate of term `t` and sends `RequestPreVote` to `L` and `g`.
4. `g` is a content follower of `L`, but `f`'s last committable entry, 8, is also `g`'s, so `f`'s log counts as up to date, and pre-votes skip the `leader_id` check, so `g` grants.
   `f` has a pre-vote quorum `{f, g}` and becomes a candidate of term `t + 1`.
5. `f`'s `RequestVote` of term `t + 1` reaches `g`.
   `become_aware_of_new_term` calls `become_follower`, which resets `leader_id`, so the regular vote's known-leader check passes too, and `g` grants.
6. `f` is the primary of term `t + 1`, and `L` steps down at its next message from `g`.
   Entries 9 and 10 were never committable, so safety is intact, but a working primary was deposed by the follower it was repairing, while the quorum `{L, g}` was in sync.

A slow or lossy link to one follower can repeat this in every term.

Where it shows up in the proofs:

- `stable_leader` and the windowed `stable_window` take `Matching`, or `WindowMatching`, as a premise: every AppendEntries from the primary delivered to a participant passes the log check.
  That premise rules out step 2.
- `duelling_leaders_resolve` hands over a primary whose voters' logs may be shorter than its own, so its first heartbeats to them can be rejected; the same mechanism then applies in the fresh window.

The model's `handleRequestPreVoteRequest` now grants a pre-vote only while the node knows no primary (`primaryKnown` is false), the counterpart of `leader_id` in `raft.h`.
As in CCF, a node learns the primary only from an AppendEntries that passes the log check, and forgets it on its own timeout, on adopting a new term and on stepping down, so `g` refuses in step 4, and `f`'s election fails.
The fix in CCF would be to apply the `leader_id` check at `raft.h` line 1721 to pre-votes as well.
Until CCF changes, the results do not cover the behaviour in the example.

The change does not protect a primary from a lagging quorum.
If `g` also lacked entries 9 and 10, its timer would fire too; once both have fired, neither knows the primary, their logs are equally up to date, and each grants the other's pre-vote, so one of them deposes `L`.
`Matching`, or a bound on catching up, is therefore still needed when a quorum lags, for example after an election whose voters' logs are behind the winner's.

## Literature

| Source                                                                                                                                                                                       | Relevant definition or result                                                                                                                           | Consequence for this model                                                                                                      |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Alpern and Schneider, [Defining Liveness](https://www.cs.cornell.edu/fbs/publications/DefLiveness.pdf), 1985, sections 2-4                                                                   | A liveness property has no irremediable finite prefix; guaranteed service is a leads-to property.                                                       | Quantify request termination over complete infinite executions, not successful finite examples.                                 |
| Lamport, [The Temporal Logic of Actions](https://lamport.azurewebsites.net/pubs/lamport-actions.pdf), 1994, section 5.3                                                                      | Weak fairness concerns continuously enabled actions; strong fairness concerns actions enabled infinitely often.                                         | Fairness must name the operation or traffic being served, not merely say that some process keeps running.                       |
| Lamport, [Real Time is Really Simple](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/tr-2005-30.pdf), 2005, sections 2.5, 3.3 and 5                                     | An ordinary clock variable and upper/lower execution bounds express timed progress; time divergence and non-Zenoness require attention.                 | Attach real timestamps and deadline predicates to executions without introducing a different protocol semantics.                |
| Kaynar, Lynch, Segala and Vaandrager, [The Theory of Timed I/O Automata](https://groups.csail.mit.edu/tds/papers/Lynch/Monograph-second-edition.pdf), second edition, 2010, examples 5.6-5.7 | Composes a periodic sender, bounded-delay channel and timeout, then adds sender failures; assumes sending interval plus delay is less than the timeout. | This is particularly close to the proposed heartbeat/channel/election-timer decomposition.                                      |
| Dwork, Lynch and Stockmeyer, [Consensus in the Presence of Partial Synchrony](https://groups.csail.mit.edu/tds/papers/Lynch/jacm88.pdf), 1988, introduction                                  | Separates safety from termination under bounds that may hold only after an unknown stabilization time.                                                  | State the stable suffix and its environmental assumptions explicitly; they are not safety invariants or unconditional promises. |
| Ongaro and Ousterhout, [In Search of an Understandable Consensus Algorithm](https://raft.github.io/raft.pdf), 2014, sections 5.3, 5.6, 6 and 8                                               | Separates replication, timing-sensitive elections, joint quorums and client retries.                                                                    | Prove deterministic commit progress conditionally on leadership; do not conflate it with randomized election convergence.       |

For the separation of communication abstractions and timing assumptions, see also Cachin, Guerraoui and Rodrigues, [Introduction to Reliable and Secure Distributed Programming](https://www.distributedprogramming.net/content.shtml), second edition, 2011, sections 2.4-2.7.
The prototype's traffic-class fairness below is a proposed protocol-specific assumption, not a claim that all textbook fair-loss definitions are interchangeable.

Bounded response deadlines are not pure Alpern-Schneider liveness properties: a finite timed prefix can already miss a deadline.
They are environment/scheduler restrictions used to establish the separate request-termination property.

## Execution and transport

`Trace` records an initial world and a sequence of explicit before-state, event and after-state triples.
Each world includes protocol state, absolute time, live identities, pending packets and the next packet sequence number.
An event is a local input, delivery, drop, crash or idle step.
Actual local and delivery events use the unchanged `Model.transitionSystem.step`; other events preserve the protocol state.
`Proofs.Liveness.Admissible.reachable` shows that every recorded protocol state is reachable in that system.

The base network remains a list of envelopes with arbitrary delivery order; the delivery model restricts deliveries to FIFO order on each channel.
A packet is identified by the sequence number the ledger issues when the actual recording callback emits its envelope, with `sentAt` equal to that step's before-time.
Each occurrence can resolve at most once, and cannot resolve before being sent.
Equal message contents therefore do not identify equal transmissions.

Drops are ghost events.
The original model represents loss by never delivering an envelope, so a dropped envelope stays in that model's queue; its tagged occurrence cannot subsequently be delivered.
No synchronized physical clocks, finite state-space bound or executable decision procedure for trace validity is assumed.

Crashes permanently remove an identity from the live set.
Only live nodes can execute local actions or receive messages; a message sent before its sender crashes can still arrive.
There is no same-identity restart, consistent with the [CCF consensus model](../../doc/architecture/consensus/index.rst).
Joining and snapshot installation remain outside the underlying model.

## Constraints and separate assumptions

Each public statement conjoins coherence and the four base model validities inline, independently of any client request.
The optional `boundedDelayModel` is separate, as are these read-only scheduling constraints:

| Constraint              | What it says                                                                                                                                                                                                           | Used by           |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| Replication scheduling  | A due live primary-to-peer obligation eventually resolves with a send pass; the timed variant requires it within `heartbeatInterval`.                                                                                  | both              |
| Signature scheduling    | Unsigned entries, or a latest signature from an earlier term, eventually cause a signature append, unless the obligation ceases.                                                                                       | `commit_liveness` |
| Confirmation scheduling | An owed retirement confirmation is eventually appended, unless it ceases to be owed.                                                                                                                                   | `commit_liveness` |
| Election lower bounds   | An election timeout cannot fire within `E / 2` of a reset classified by `ElectionReset`, including term adoption, election starts, quorum-check step-down, regular-vote grants and the qualifying AppendEntries paths. | `stable_leader`   |

`commit_liveness` states each untimed CCF scheduling obligation separately, without requiring heartbeat deadlines or election-timer bounds.
Constraints that CCF meets but no theorem needs are left out, which strengthens the theorems: positive intervals, divergent time, a signature deadline and a quorum-check timer.
Zero-time steps are allowed, and so are Zeno executions.

The timeout fields currently constrain when existing timeout actions may happen; they do not prove that every expired timer is scheduled.
An upper-bound timeout scheduler and a correspondence proof for CCF's concrete timer-reset bookkeeping are separate work.

The commit property then quantifies over additional, separately defined suffix assumptions:

| Assumption     | Scope                                                                                                                                        |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `StableLeader` | From some index on, the same primary and term persist; that primary is live and not retired-committed. Older-term primaries may still exist. |
| `LiveQuorum`   | From some index on, a live majority of the participants is in every configuration active in the primary's ledger; the majority may change.   |
| `FairLoss`     | Persistent retransmissions of relevant traffic on the working quorum's links yield arbitrarily late deliveries, despite omissions.           |
| `Submitted`    | Once the primary is stable, the request is submitted to it once, or it already has the request.                                              |

`FairLoss` is **not** one of the base models or scheduling predicates.
It permits drops within the working quorum, without a uniform bound on the number of losses.
It classifies attempts as AppendEntries traffic, traffic carrying a specified log position, and responses with a specified success flag and minimum acknowledged index, each from a minimum term upwards, and also as exact wire messages.
Exact-envelope fairness alone can become vacuous as batching and commit advertisements change, while link-level fairness can deliver unrelated heartbeats forever and starve the required data or acknowledgement.
This choice of traffic classes is an explicit assumption; see [the counterexample](#a-counterexample-to-exact-term-fairness) for why classes include newer terms and [the next one](#a-counterexample-to-index-only-rejection-fairness) for why exact messages are included.
Sufficiency is still a proof obligation.

`Reliable` is retained only as a stronger special case.
`Proofs.Liveness.reliable_suffix_fair_loss` proves that any eventually reliable suffix satisfies the separate fair-loss assumption, even if earlier attempts were omitted.
The intended commit property uses `FairLoss`, not `Reliable`.

## CCF-specific obligations

CCF only advances commitment to signatures.
Perfect delivery and stable leadership do not commit an unsigned request.
An already replicated old-term signature is also insufficient for advancing a new primary's current-term commit scan, even when clients correctly refrain from resubmitting an already present request.
The scheduler must eventually append a current-term signature covering that request.

[`Proofs/LivenessWitness.lean`](CCFRaft/Proofs/LivenessWitness.lean) contains an actual infinite valid one-node execution satisfying all the premises of `Properties.commit_liveness` and committing a request (`Properties.commit_liveness_witness`).
It also witnesses the premises of `stable_leader` and `commit_liveness_timed`, with a single node, so no timer is exercised.
`timed_commit_window_witness` (`Properties.commit_liveness_witness`) satisfies the premises and conclusion of the windowed `Properties.commit_liveness` for every nonnegative window length, with positive heartbeat and signature bounds; its append takes no time, so the commit is recorded inside the window.
Since `commit_liveness` chooses a nonnegative length, its premises are satisfiable.
It constructs an infinite stable, reliable execution with a submitted request that never commits because signing is omitted, proves that the signature obligation rejects it, and checks the old-term-signature case.
These witnesses establish consistency and necessary distinctions in small cases, not multi-node commit liveness.
The existing canonical traces continue to exercise actual multi-node commitment and reconfiguration.

`Proofs.Liveness.acknowledged_signature_commits` proves that the actual `advanceCommit` operation succeeds and commits any current-term signature supported by the scan's configuration quorums, including its retirement/successor handling.
It does **not** assume or prove that transport will eventually collect those acknowledgements.

## Timing constants

Keep the bounds abstract.
They are bounds on real time, not CCF's configuration values.
`H` bounds the time a primary takes to finish a due heartbeat send pass; CCF sends once `request_timeout` has elapsed, checked on each `periodic` tick, so `H` must cover `request_timeout`, the tick delay, and the work of issuing every batch through the current log end.
`E / 2` bounds from below the time from a timer reset to a timeout; CCF draws a timeout between half and all of `election_timeout` (`restart_election_timeout`), but counts it in ticks on the node's own clock, and the first tick after a reset also counts the time before it.
So `E` must be at most `election_timeout` minus twice the tick interval, and less if node clocks drift.
With those choices, the timed constraints should admit every CCF execution in which the host ticks on time and the retirement cleanup request succeeds; this is argued from the code, not proved.
`stable_leader` needs `H + delay < E / 2`, which cannot be relaxed by the argument in [stable leadership](#stable-leadership).
`commit_liveness` needs no ratio and no delay bound, only `FairLoss`.
Deriving the quorum checks would also need a round trip within the election timeout, roughly `H + 2 * delay < E`, and slack for silently ignored requests.
Probabilistic election convergence is deliberately deferred.

## Rechecking

Use the commands in [the README](README.md#validation).
