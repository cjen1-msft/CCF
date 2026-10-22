# Deterministic commit liveness and stable leadership

## Recommendation and status

A timed trace restriction over the existing multi-node transition system is workable.
It is a standard explicit-clock/timed-automata construction, not a replacement Raft algorithm.
The prototype in [`Liveness/Model.lean`](CCFRaft/Liveness/Model.lean) and [`Liveness/Assumptions.lean`](CCFRaft/Liveness/Assumptions.lean) permits finite or infinite executions and unbounded logs.
`Liveness/Model.lean` imports the transition systems from [`Model/Timing.lean`](CCFRaft/Liveness/Model/Timing.lean) and [`Model/Crash.lean`](CCFRaft/Liveness/Model/Crash.lean), with their shared event vocabulary in [`Model/Event.lean`](CCFRaft/Liveness/Model/Event.lean).
`Model.lean` reexports the components in `Liveness/Model/`; shared trace definitions live in [`Model/Trace.lean`](CCFRaft/Liveness/Model/Trace.lean).
`Assumptions.lean` defines short assumptions inline and imports larger groups of related declarations from `Liveness/Assumptions/`.
CCF's background-task scheduling predicates, timing bounds, and timed scheduling model are colocated in [`Model/Scheduling.lean`](CCFRaft/Liveness/Model/Scheduling.lean).
The main commit assumptions are `StableLeader` in [`StableLeader.lean`](CCFRaft/Liveness/Assumptions/StableLeader.lean), `LiveQuorum` inline in [`Assumptions.lean`](CCFRaft/Liveness/Assumptions.lean), `FairLoss` in [`FairLoss.lean`](CCFRaft/Liveness/Assumptions/FairLoss.lean), and `Submitted` in [`Submitted.lean`](CCFRaft/Liveness/Assumptions/Submitted.lean).
It records an initial state and timed events, deriving subsequent states by deterministic replay rather than storing transition endpoints.
It does not enumerate executions.

Properties quantify `config` and `nodes` explicitly and bind `system := Model.transitionSystem config nodes` once.
The trace has type `Liveness.Trace system`, tying the safety and timing projections and their replay-based assumptions to that same protocol system.
The shared `CCF.Execution.Trace State Action` records an initial state and a finite or infinite action sequence.
`safetyTrace` retains the initial protocol state and recorded model actions, using generic `Seq.filterMap` to omit environment-only events.
`trace.safetyTrace.Valid system` uses exactly the trace type and `Valid` predicate of the safety properties.
`timingTrace` retains the initial timed state and every recorded timed event.
`trace.timingTrace.Valid (Liveness.timingSystem system)` applies the same shared validity definition to that recording.
Validity requires successful execution of every recorded action, so a disabled action invalidates the trace even when replay stops there.
There is no failure-sentinel state and no separate `alwaysEnabled` premise.
`timingSystem system` lifts initialization and transitions to timed states.
It inherits `system.init` on the protocol state and uses `system.step` for model actions; environment-only events stutter in the protocol state.
It imposes no additional initial-clock or initial-availability restriction.
Elapsed durations have type `NNReal`, so zero is permitted and negative time advances cannot be recorded.
This keeps replay computable and removes the separate `elapsedValid` predicate and premise.
`crashTrace` records the initial live set and every event, preserving timing-trace indices.
`trace.crashTrace.Valid Liveness.crashSystem` uses shared validity to require live actors and permanently remove crashed nodes.
Local steps require their node to be live; delivery requires only the receiver to be live, so a sender may crash after sending.
A crash requires its node to be live, rejecting repeated crashes; drops and idle events leave availability unchanged.
The initial live set is unrestricted.
Crash replay explicitly matches the event after checking its actor is live; a crash removes that actor and other events preserve availability.
Timing replay tracks the same availability updates through `Event.liveAfter` without enforcing crash validity itself.
This replaces the separate `crashedValid` scan.
Timing replay enforces packet accounting directly.
Its state includes the next event index and a ledger of outstanding packets, initialized to zero and empty respectively.
Each protocol step's actual outputs are assigned identities `(step, ordinal)`, including distinct identities for equal envelopes.
Delivery or drop must match an outstanding identity and envelope and removes that occurrence before registering the current step's outputs.
Thus `timingTrace.Valid` rejects fabricated packets, consumption before emission, repeated delivery, and delivery after a drop, without a separate packet-validity premise.
The event index advances for every timed event, preserving the correspondence between packet identities and trace indices.
The untimed protocol queue still contains untagged envelopes; the timing ledger prevents reuse of dropped occurrences even though drops stutter in the protocol state.
Crash validity remains separate because timing replay still permits actions by unavailable nodes.
Packet accounting imposes no delivery guarantee; `Timely` and `FairLoss` remain separate assumptions.
Untimed scheduling is stated through separate `trace.HeartbeatScheduling`, `trace.SignatureScheduling`, and `trace.ConfirmationScheduling` premises.
These encode CCF's periodic sends, signature task, and retirement-confirmation handling, retaining eventual execution without a quantitative deadline.
Timed scheduling is `model.Timed`, defined in [`Model/Scheduling.lean`](CCFRaft/Liveness/Model/Scheduling.lean); it adds heartbeat deadlines and election-timer constraints and reuses the signature and confirmation scheduling predicates.
These inspect the recorded events and the whole timed execution, including protocol states; scheduling obligations and deadlines do not follow merely from local transition validity.
They are distinct from the network fairness assumption `FairLoss`.
`LivenessModel` contains only timing bounds, not the initial configuration or node identities.
An intermediate starting point is an explicit index `start` in this execution from boot, not an implicitly chosen reachable initial state.
A zero-step execution retains its initial state, and a finite execution has a final computed state without a dummy terminal event.
Filtering uses the generic helpers in [`Liveness/Seq.lean`](CCFRaft/Liveness/Seq.lean) and is noncomputable because an infinite sequence of environment-only events need not contain a next model action.
Replay is computable; the noncomputable `Trace.safetyTrace` projection is defined on the theorem side in `Properties.lean`.
The model itself provides computable event mapping (`Trace.modelActions`).
Action lookup uses the shared `trace.timingTrace.actionAt index`; finite-prefix replay uses `trace.timingTrace.stateAt (timingSystem system) index` and `trace.timingTrace.stepAt (timingSystem system) index`.
The shared step type is `CCF.Execution.Step TracedState TimedEvent`, retaining both the event (`step.action.event`) and its elapsed duration (`step.action.elapsed`).
None of these operations depends on the filtered projection, and no liveness-specific accessor or step record duplicates the shared machinery.

The existing proofs predate this trace-interface revision and have not yet been adapted or checked against the revised statements.
The intended claims in [`Properties.lean`](CCFRaft/Properties.lean) are:

- `commit_liveness` separately requires heartbeat, signature, and retirement-confirmation scheduling, plus four assumptions: a primary stable from some point on, a live quorum, fair-loss links and a submitted request.
- `stable_leader` derives a stable primary from the timed environment `LivenessModel.Timed` and the premises in [stable leadership](#stable-leadership).
  Some of those premises assume away events rather than derive their absence: quorum-check step-downs, failed log checks, and timeouts of nodes the primary does not send to.
- `commit_liveness_timed` combines them, so it assumes no stable primary.

Every constraint of the environment and every assumption cites the CCF code it models or states a counterexample showing that a theorem needs it, except `Covered`, whose necessity is open.
The counterexamples are prose arguments, except signature starvation, which [`Proofs/LivenessWitness.lean`](CCFRaft/Proofs/LivenessWitness.lean) checks.
The environment constraints are meant to admit every CCF execution, given suitable values of the timing bounds; see [timing constants](#timing-constants).
The environment obliges the primary to eventually append owed retirement confirmations, as CCF's `retired_node_cleanup` does.
The proof also needed two changes to bring the model in line with CCF; see [a lost commit trigger](#a-lost-commit-trigger).
`commit_liveness` states eventual inclusion of a submitted request in the stable primary's committed prefix, not a latency bound, commitment at every replica, or election convergence.
The environment does not assume eventual commitment or eventual quorum acknowledgements.

Previously proved, reusing the safety invariant from [`Proofs/Safety`](CCFRaft/Proofs/Safety) and depending only on the standard axioms; adaptation to the revised trace interface is pending:

| Result                                   | File                                                                         | Meaning                                                                                                                                                                                                      |
| ---------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `commit_liveness`                        | [`Proofs/Replication/Commit.lean`](CCFRaft/Proofs/Replication/Commit.lean)   | `Properties.commit_liveness`.                                                                                                                                                                                |
| `signature_commits`                      | [`Proofs/Replication/Commit.lean`](CCFRaft/Proofs/Replication/Commit.lean)   | Signature commitment, for every signature in the primary's log, whatever its term.                                                                                                                           |
| `confirmation_owed`, `owing_of_exec`     | [`Proofs/Replication/Owing.lean`](CCFRaft/Proofs/Replication/Owing.lean)     | In every reachable state, a primary that alone makes an uncommitted current-term signature committable owes a retirement confirmation.                                                                       |
| `sane_of_exec`                           | [`Proofs/Replication/Sane.lean`](CCFRaft/Proofs/Replication/Sane.lean)       | In every reachable state, every confirmation in a node's log follows a removal it has committed, and every re-add follows a confirmation it has committed, with no configuration naming the node in between. |
| `advance_owed`                           | [`Proofs/Replication/Confirm.lean`](CCFRaft/Proofs/Replication/Confirm.lean) | Right after a commit scan, such a signature means the scan retired the other members, whose confirmations are then owed.                                                                                     |
| `request_committed`                      | [`Proofs/CommitLiveness.lean`](CCFRaft/Proofs/CommitLiveness.lean)           | Signature commitment implies commit liveness: the submission puts the request in the primary's log, the signature obligation appends a covering current-term signature, and the primary keeps both.          |
| `stable_leader`, `quiet_all`             | [`Proofs/Leadership/Stable.lean`](CCFRaft/Proofs/Leadership/Stable.lean)     | `Properties.stable_leader`: the primary's term stays quiet at every index.                                                                                                                                   |
| `no_timeout`, `reset_follows`            | [`Proofs/Leadership/Stable.lean`](CCFRaft/Proofs/Leadership/Stable.lean)     | While the term is quiet, heartbeats and timely delivery reset every tracked node's election timer often enough that no node of the term times out.                                                           |
| `Quiet.step`                             | [`Proofs/Leadership/Quiet.lean`](CCFRaft/Proofs/Leadership/Quiet.lean)       | A step keeps the term quiet, unless it is an election timeout in the term, or the primary nominates a successor, retires or fails a quorum check.                                                            |
| `recent_reset`                           | [`Proofs/Leadership/Timers.lean`](CCFRaft/Proofs/Leadership/Timers.lean)     | A timer reset within `gap` of every earlier point has a reset less than `window > gap` before any point `window` after the start.                                                                            |
| `match_reaches`                          | [`Proofs/Replication/Peer.lean`](CCFRaft/Proofs/Replication/Peer.lean)       | The primary's match index for a live peer that is eligible from some point on, and is reached by productive sends and fair-loss links, eventually covers every position of the primary's log.                |
| `peer_term_le`                           | [`Proofs/StablePrimary.lean`](CCFRaft/Proofs/StablePrimary.lean)             | Under `FairLoss`, a live peer that stays eligible for a stable primary never holds a newer term.                                                                                                             |
| `ack_commits_trace`                      | [`Proofs/StablePrimary.lean`](CCFRaft/Proofs/StablePrimary.lean)             | A successful current-term acknowledgement delivered to the stable primary commits every signature already acknowledged by the commit scan's quorums.                                                         |
| `acknowledged_signature_commits`         | [`Proofs/Liveness.lean`](CCFRaft/Proofs/Liveness.lean)                       | The node-level commit scan, including retirement and successor handling, commits a quorum-acknowledged current-term signature.                                                                               |
| `reachable`, `reliable_suffix_fair_loss` | [`Proofs/Liveness.lean`](CCFRaft/Proofs/Liveness.lean)                       | Timed executions only visit reachable states; an eventually reliable suffix satisfies `FairLoss`.                                                                                                            |

`signature_commits` takes a covering current-term signature and supposes that it is never committed.

1. Settling: the commit index then stays below the signature, so the configurations at or before it that remain active are a suffix of a fixed list which only shrinks, and eventually stop changing (`active_settles`).
2. Eligibility: their members then stay eligible peers of the primary, because appends only add active configurations (`eligiblePeers_append`).
3. Catch-up: each such member of the live quorum eventually acknowledges the signature (`match_reaches`).
   Otherwise the peer settles: each change to its log adopts a prefix of the primary's log and increases a bounded potential, and rejections never move the primary's retry index below the agreed prefix, so fair loss eventually delivers the missing entries ([`Proofs/Replication`](CCFRaft/Proofs/Replication)).
4. Trigger: if one of those configurations has a live quorum member other than the primary, its next acknowledgement runs the commit scan, which commits the signature (`ack_commits_trace`).
   Otherwise the primary alone makes the signature committable, so a retirement confirmation is owed (`confirmation_owed`); the primary eventually appends it, and that append runs the commit scan (`append_commits_trace`).

`peer_term_le` discharges the newer-term case that would otherwise block catch-up.

## Stable leadership

`Properties.stable_leader` states that `leader` stays the primary of `term` from an explicit index `start` in an execution satisfying `LivenessModel.Timed`, with these premises defined in [`Liveness/Assumptions.lean`](CCFRaft/Liveness/Assumptions.lean):

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
  So no timer of the term may expire before the primary's heartbeats arrive, and every node that may time out must get heartbeats.
- Quorum checks are not derived from timing, and could not be in this model.
  `Timely` does not bound responses, and bounding them would not suffice either.
  A follower silently ignores an AppendEntries whose `prev_idx` is below its commit index (`recv_append_entries`).
  A stale rejection, handled before the acknowledgement of a later acceptance that raised the follower's commit index, moves the primary's `sent_idx` back below that commit index.
  The model lets the primary then advance `sent_idx` by one entry per heartbeat, so the follower can stay silent for longer than an election timeout.
  CCF sends up to the end of its log on every heartbeat (`send_append_entries`), which would bound the silence; deriving `Incumbent.quorumChecks` needs that and a round-trip bound.
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
The liveness model mirrors this with an unbounded obligation, `LivenessModel.Valid.confirmations`: while the primary may append a retirement confirmation, it eventually does so or stops being able to.

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

`Trace` records a protocol state, an event, a real timestamp and the live identities at each natural-number index.
An event is a local input, delivery, drop, crash or idle step.
Actual local and delivery events use the unchanged `Model.transitionSystem.step`; other events preserve the protocol state.
`Proofs.Liveness.reachable` proves that every state in such a valid decorated execution is reachable in the original model.

The base network remains a list of envelopes with arbitrary delivery order.
A packet is identified by its sending step and output ordinal, with its envelope checked against the actual recording callback's output.
Each occurrence can resolve at most once, and cannot resolve before being sent.
Equal message contents therefore do not identify equal transmissions.

Drops are ghost events.
The original model represents loss by never delivering an envelope, so a dropped envelope stays in that model's queue; its tagged occurrence cannot subsequently be delivered.
No FIFO, synchronized physical clocks, finite state-space bound or executable decision procedure for trace validity is assumed.

Crashes permanently remove an identity from the live set.
Only live nodes can execute local actions or receive messages; a message sent before its sender crashes can still arrive.
There is no same-identity restart, consistent with the [CCF consensus model](../../doc/architecture/consensus/index.rst).
Joining and snapshot installation remain outside the underlying model.

## Constraints and separate assumptions

`LivenessModel.Valid trace` constrains the execution independently of a particular client request.

| Constraint              | What it says                                                                                                                                                                                 | Used by           |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| Clock monotonicity      | Time is nondecreasing.                                                                                                                                                                       | `stable_leader`   |
| Replication scheduling  | A persistent live primary-to-peer obligation causes a send within `heartbeatInterval`; if its send frontier has a backlog, the send must carry entries.                                      | both              |
| Signature scheduling    | Unsigned entries, or a latest signature from an earlier term, eventually cause a signature append, unless the obligation ceases.                                                             | `commit_liveness` |
| Confirmation scheduling | An owed retirement confirmation is eventually appended, unless it ceases to be owed.                                                                                                         | `commit_liveness` |
| Election lower bounds   | An election timeout cannot fire within `E / 2` of an earlier reset: a timeout, or an AppendEntries of a newer term, or of the node's term that passes its log check or finds it a candidate. | `stable_leader`   |

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

`FairLoss` is **not** a field of `LivenessModel.Valid`.
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
It constructs an infinite stable, reliable execution with a submitted request that never commits because signing is omitted, proves that the signature obligation rejects it, and checks the old-term-signature case.
These witnesses establish consistency and necessary distinctions in small cases, not multi-node commit liveness.
The existing canonical traces continue to exercise actual multi-node commitment and reconfiguration.

`Proofs.Liveness.acknowledged_signature_commits` proves that the actual `advanceCommit` operation succeeds and commits any current-term signature supported by the scan's configuration quorums, including its retirement/successor handling.
It does **not** assume or prove that transport will eventually collect those acknowledgements.

## Timing constants

Keep the bounds abstract.
They are bounds on real time, not CCF's configuration values.
`H` bounds the time a primary takes to send a due AppendEntries; CCF sends once `request_timeout` has elapsed, checked on each `periodic` tick, so `H` must be at least `request_timeout` plus the tick interval, if the host ticks on time.
`E / 2` bounds from below the time from a timer reset to a timeout; CCF draws a timeout between half and all of `election_timeout` (`restart_election_timeout`), but counts it in ticks on the node's own clock, and the first tick after a reset also counts the time before it.
So `E` must be at most `election_timeout` minus twice the tick interval, and less if node clocks drift.
With those choices, the timed constraints should admit every CCF execution in which the host ticks on time and the retirement cleanup request succeeds; this is argued from the code, not proved.
`stable_leader` needs `H + delay < E / 2`, which cannot be relaxed by the argument in [stable leadership](#stable-leadership).
`commit_liveness` needs no ratio and no delay bound, only `FairLoss`.
Deriving the quorum checks would also need a round trip within the election timeout, roughly `H + 2 * delay < E`, and slack for silently ignored requests.
Probabilistic election convergence is deliberately deferred.

## Rechecking

Use the commands in [the README](README.md#validation).
