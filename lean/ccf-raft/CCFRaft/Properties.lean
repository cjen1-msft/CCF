module

public import CCFRaft.Model
public import CCFRaft.Liveness.Assumptions
public import CCFRaft.Liveness.Seq
public import CCF.Execution

import CCFRaft.Proofs.CommittedLogs
import CCFRaft.Proofs.Direct.CommitFrontier
import CCFRaft.Proofs.Duel.Probability
import CCFRaft.Proofs.Election
import CCFRaft.Proofs.Leadership.AnchorSync
import CCFRaft.Proofs.Leadership.CatchUp
import CCFRaft.Proofs.Leadership.CatchUpWitness
import CCFRaft.Proofs.Leadership.InSync
import CCFRaft.Proofs.Leadership.SettlesWitness
import CCFRaft.Proofs.Leadership.Stable
import CCFRaft.Proofs.LivenessWitness
import CCFRaft.Proofs.Replication.Commit
import CCFRaft.Proofs.Timed.Commit
import CCFRaft.Proofs.Witnesses

@[expose] public section

/-!
Safety and liveness theorems about the Raft model, each paired with a witness
lemma exhibiting a nontrivial execution relevant to that property.
-/

namespace CCFRaft.Properties

abbrev GlobalTrace := CCF.Execution.Trace Model.State Model.Action

open Model.Node

/-- Any two committed logs in a valid trace are prefix-comparable: those of
any two nodes, in any two states of the trace. -/
theorem committed_logs_prefix
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (trace : GlobalTrace),
      forall (stateA stateB : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        (trace.Valid (Model.transitionSystem config nodes)
          /\ stateA ∈ trace.states (Model.transitionSystem config nodes)
          /\ stateB ∈ trace.states (Model.transitionSystem config nodes)
          /\ (left, leftState) ∈ stateA.nodes
          /\ (right, rightState) ∈ stateB.nodes)
        -> leftState.committedLog <+: rightState.committedLog
            \/ rightState.committedLog <+: leftState.committedLog := by
  exact Proofs.CommittedLogs.committed_logs_prefix

/-- Witness: a valid trace has two states in which two distinct nodes have
nonempty committed logs. -/
lemma committed_logs_prefix_witness
    : exists (config : Finset NodeID),
    exists (nodes : List NodeID) (trace : GlobalTrace),
    exists (stateA stateB : Model.State),
    exists (left right : NodeID) (leftState rightState : NodeState),
      trace.Valid (Model.transitionSystem config nodes)
      /\ stateA ∈ trace.states (Model.transitionSystem config nodes)
      /\ stateB ∈ trace.states (Model.transitionSystem config nodes)
      /\ (left, leftState) ∈ stateA.nodes
      /\ (right, rightState) ∈ stateB.nodes
      /\ left ≠ right
      /\ leftState.committedLog ≠ []
      /\ rightState.committedLog ≠ [] := by
  exact Proofs.Witnesses.committed_logs_prefix_witness

/-- A successful network step from a state with unique node IDs preserves each
node's committed prefix. -/
theorem single_node_committed_log_monotonic
    : forall (config : Finset NodeID) (nodes : List NodeID),
      forall (pre post : Model.State),
      forall (nodeId : NodeID) (nodePre nodePost : NodeState),
      forall (action : Model.Action),
        ((pre.nodes.map Prod.fst).Nodup
          /\ (Model.transitionSystem config nodes).step pre action = some post
          /\ (nodeId, nodePre) ∈ pre.nodes
          /\ (nodeId, nodePost) ∈ post.nodes)
        -> nodePre.committedLog <+: nodePost.committedLog := by
  exact Proofs.Direct.single_node_committed_log_monotonic

/-- Witness: a successful step from a state with unique node IDs strictly extends
one node's nonempty committed log. -/
lemma single_node_committed_log_monotonic_witness
    : exists (config : Finset NodeID) (nodes : List NodeID),
    exists (pre post : Model.State),
    exists (nodeId : NodeID) (nodePre nodePost : NodeState),
    exists (action : Model.Action),
      (pre.nodes.map Prod.fst).Nodup
      /\ (Model.transitionSystem config nodes).step pre action = some post
      /\ (nodeId, nodePre) ∈ pre.nodes
      /\ (nodeId, nodePost) ∈ post.nodes
      /\ nodePre.committedLog ≠ []
      /\ nodePre.committedLog.length < nodePost.committedLog.length := by
  exact Proofs.Witnesses.single_node_committed_log_monotonic_witness

/-- No two distinct nodes are primary in the same term. -/
theorem election_safety
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        (trace.Valid (Model.transitionSystem config nodes)
          /\ state ∈ trace.states (Model.transitionSystem config nodes)
          /\ (left, leftState) ∈ state.nodes
          /\ (right, rightState) ∈ state.nodes
          /\ leftState.role = .primary
          /\ rightState.role = .primary
          /\ leftState.currentTerm = rightState.currentTerm)
        -> left = right := by
  exact Proofs.Election.election_safety

/-- Witness: a valid trace has a state in which two nodes are primaries. -/
lemma election_safety_witness
    : exists (config : Finset NodeID),
    exists
    (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
    exists (left right : NodeID) (leftState rightState : NodeState),
      trace.Valid (Model.transitionSystem config nodes)
      /\ state ∈ trace.states (Model.transitionSystem config nodes)
      /\ (left, leftState) ∈ state.nodes
      /\ (right, rightState) ∈ state.nodes
      /\ leftState.role = .primary
      /\ rightState.role = .primary
      /\ left ≠ right := by
  exact Proofs.Witnesses.election_safety_witness

/-- Every positive commit index points to a signature entry. -/
theorem committed_frontier_is_signature
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
      forall (node : NodeID) (nodeState : NodeState),
        (trace.Valid (Model.transitionSystem config nodes)
          /\ state ∈ trace.states (Model.transitionSystem config nodes)
          /\ (node, nodeState) ∈ state.nodes
          /\ 0 < nodeState.commitIndex)
        -> isSignatureAt nodeState.log nodeState.commitIndex = true := by
  exact Proofs.Direct.committed_frontier_is_signature

/-- Witness: a valid trace has a state with a positive commit index. -/
lemma committed_frontier_is_signature_witness
    : exists (config : Finset NodeID),
    exists
    (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
    exists (node : NodeID) (nodeState : NodeState),
      trace.Valid (Model.transitionSystem config nodes)
      /\ state ∈ trace.states (Model.transitionSystem config nodes)
      /\ (node, nodeState) ∈ state.nodes
      /\ 0 < nodeState.commitIndex := by
  exact Proofs.Witnesses.committed_frontier_is_signature_witness

/-- Commit liveness, timed. For any timing bounds, maximum delay and backlog there
is a nonnegative window length `duration`, independent of the trace, with the
following property. Take one coherent recorded relational trace. Assume
coherence and validity of the protocol, timing, crash, delivery (in order on each
channel) and bounded-delay models for `system := Model.transitionSystem config
nodes`, and an unbounded
clock: every packet is then delivered or dropped within `maxDelay`, unless its
target crashes first. Assume that a primary sends due heartbeats
within `bounds.heartbeatInterval` and due signatures within
`bounds.signatureInterval`. Take a stable window from index `start` for
`duration`: `leader` is the uncontested primary of `term`, stays live and
unretired, every configuration active at it keeps a live majority among
`participants`, and no packet between it and a participant is dropped.
Additionally, reconfiguration is settled at the leader throughout the
window: one active configuration and all completed removals confirmed in its
committed ledger. Followers need not have learned this completion. This
excludes waiting for retirement cleanup, which has no scheduling deadline.
If at `start` every participant has adopted `term`, the primary's log beyond its
common prefix with each participant spans at most `backlog` distinct terms, and
the primary holds or appends `request`, then `request` is in the primary's committed prefix within
the window. `commit_liveness_witness` meets the premises for every nonnegative
window length, so they are satisfiable whatever `duration` is.
`signature_settles` and `signature_settles_catchup` yield the stable window;
settled reconfiguration remains a separate premise. -/
theorem commit_liveness
    : forall (config : Finset NodeID) (nodes : List NodeID),
        let system := Model.transitionSystem config nodes
        forall (bounds : Liveness.Bounds) (maxDelay : Real) (backlog : Nat),
          exists duration : Real,
            0 <= duration
            /\ forall (W : Type) [Liveness.HasProtocol W Model.State] [Liveness.HasTime W]
                      [Liveness.HasLive W] [Liveness.HasNetwork W],
                forall (trace : Liveness.Trace W Liveness.Event) (start : Nat),
                forall (leader : NodeID) (term : Nat) (participants : Finset NodeID)
                        (request : ReqID),
                  (trace.Coherent
                    /\ trace.Valid (Liveness.protocolModel system)
                    /\ trace.Valid Liveness.timingModel
                    /\ trace.Valid Liveness.crashModel
                    /\ trace.Valid (Liveness.deliveryModel system)
                    /\ trace.Valid (Liveness.boundedDelayModel maxDelay)
                    /\ Liveness.TimeDiverges trace
                    /\ 0 <= maxDelay
                    /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
                    /\ trace.SignatureScheduling (some bounds.signatureInterval)
                    /\ Liveness.StableWindow trace start duration leader term participants
                    /\ Liveness.Window.ReconfigurationSettled trace start duration leader
                    /\ Liveness.BacklogTerms trace start leader participants backlog
                    /\ Liveness.InTermAt trace start term participants
                    /\ Liveness.SubmittedAt trace start leader request)
                  -> exists index,
                      Liveness.Within trace start duration index
                      /\ Liveness.RequestCommitted trace leader request index := by
  exact Proofs.Timed.commit_liveness_timed

/-- Witness: for every nonnegative window length, a one-node execution with
positive heartbeat and signature bounds meets every premise of `commit_liveness`
and commits its request within the window. -/
lemma commit_liveness_witness
    : let system := Model.transitionSystem {0} [0]
      let bounds : Liveness.Bounds :=
        { heartbeatInterval := 1 / 4, electionTimeout := 4, signatureInterval := 1 / 4 }
      forall duration : Real,
        0 <= duration
        -> exists trace : Liveness.Trace (Liveness.World Model.State) Liveness.Event,
            (trace.Coherent
              /\ trace.Valid (Liveness.protocolModel system)
              /\ trace.Valid Liveness.timingModel
              /\ trace.Valid Liveness.crashModel
              /\ trace.Valid (Liveness.deliveryModel system)
              /\ trace.Valid (Liveness.boundedDelayModel 0)
              /\ Liveness.TimeDiverges trace
              /\ 0 <= (0 : Real)
              /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
              /\ trace.SignatureScheduling (some bounds.signatureInterval)
              /\ Liveness.StableWindow trace 0 duration 0 Model.BOOTSTRAP_TERM {0}
              /\ Liveness.Window.ReconfigurationSettled trace 0 duration 0
              /\ Liveness.BacklogTerms trace 0 0 {0} 0
              /\ Liveness.InTermAt trace 0 Model.BOOTSTRAP_TERM {0}
              /\ Liveness.SubmittedAt trace 0 0 10)
            /\ exists index,
                Liveness.Within trace 0 duration index
                /\ Liveness.RequestCommitted trace 0 10 index := by
  exact Proofs.LivenessWitness.timed_commit_window_witness

/-- Duelling leaders resolve, with probability tending to one in the number of
rounds. Sample `draws`, one uniform timeout offset per round per participant, and
let the adversary choose any execution `family draws` around it: coherent, valid
for the protocol, timing, crash, delivery, bounded-delay and election-timer
models, with the clock unbounded, due heartbeats and signatures sent within their
bounds, due timeouts fired at once, a good period from `start` long enough for
`rounds` rounds, and each participant's `k`-th timer reset after `start` drawing
`draws k i`. If some participant competes, the heartbeat interval is not
negative, and the lead `duelMargin` fits in half an election timeout, then the
probability that some primary commits a signature of its own term within the good
period is at least `settleProbability = 1 - (1 - marginProbability) ^ rounds`,
where `marginProbability = (1 - 2 duelMargin / E) ^ competitors > 0`. No independence of
the adversary from the draws is assumed: each round's margin event forces the
outcome pointwise. -/
theorem duelling_leaders_resolve
    : forall (config : Finset NodeID) (nodes : List NodeID),
        let system := Model.transitionSystem config nodes
        forall (W : Type) [Liveness.HasProtocol W Model.State] [Liveness.HasTime W]
                [Liveness.HasLive W] [Liveness.HasNetwork W] [Liveness.HasTimers W],
        forall (competitors rounds : Nat) (candidates : Fin competitors -> NodeID),
        forall (bounds : Liveness.Bounds) (maxDelay : Real) (start : Nat),
        forall (participants : Finset NodeID),
        forall (family
                : Liveness.Draws competitors rounds -> Liveness.Trace W Liveness.Event),
          let electionTimeout := bounds.electionTimeout
          let margin := Liveness.duelMargin bounds maxDelay
          let duration := rounds * Liveness.roundLength bounds maxDelay
          (Function.Injective candidates
            /\ (forall node, node ∈ participants <-> exists i, candidates i = node)
            /\ 0 < competitors
            /\ 0 <= maxDelay
            /\ 0 <= bounds.heartbeatInterval
            /\ margin < electionTimeout / 2
            /\ (forall draws,
                  let trace := family draws
                  trace.Coherent
                  /\ trace.Valid (Liveness.protocolModel system)
                  /\ trace.Valid Liveness.timingModel
                  /\ trace.Valid Liveness.crashModel
                  /\ trace.Valid (Liveness.deliveryModel system)
                  /\ trace.Valid (Liveness.boundedDelayModel maxDelay)
                  /\ trace.Valid (Liveness.timerModel electionTimeout)
                  /\ Liveness.TimeDiverges trace
                  /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
                  /\ trace.SignatureScheduling (some bounds.signatureInterval)
                  /\ trace.TimeoutScheduling (some 0)
                  /\ Liveness.GoodPeriod trace start duration participants
                  /\ Liveness.TimerDraws trace candidates draws start))
          -> ENNReal.ofReal
                (Liveness.settleProbability competitors rounds margin electionTimeout)
              <= Liveness.uniformDraws competitors rounds electionTimeout
                  {draws |
                    Liveness.SignatureCommitted (family draws) start duration
                  } := by
  intro config nodes system W _ _ _ _ _ competitors rounds candidates bounds maxDelay start
    participants family electionTimeout margin duration premises
  obtain ⟨_, _, competes, delay, heartbeat, fits, _⟩ := premises
  refine Proofs.Duel.settle_of_margin competes
    (show 0 <= bounds.heartbeatInterval + 5 * maxDelay by linarith) fits ?_
  -- Remaining: a round with a margin forces a committed signature.
  intro draws _
  sorry

/-- A fresh primary stays uncontested while the good period lasts, when a quorum
of participants, the anchor, knows it and is in sync with it: the bridge from
`duelling_leaders_resolve` to the window `commit_liveness` consumes, in the common
case. At `start` the term is quiet among `participants`, and `anchor` anchors it
(`Liveness.AnchoredStart`): a quorum of the primary's configurations, containing
the primary, whose nodes are at the term, know the primary and are its
replication peers, with none of their pre-votes of the term in flight or counted.
Every majority of every configuration participants can count votes in meets the
anchor, and no anchor node of the term times out for `fresh`. Every anchor node
is in sync with the primary: its log is a prefix of the primary's, no rejection
from it is in flight, and the primary's requests in flight to it chain from the
end of its log. No anchor node's retirement commits in the window. Then every
heartbeat passes every anchor node's log check, so each anchor node's election
timer is reset within `heartbeatInterval + maxDelay`, before `fresh` runs out,
and none times out in the window. A node that knows the primary grants no
pre-vote, so no participant, lagging or not, gathers a pre-vote quorum and moves
past the term. The result is a stable window over the anchor, which
`commit_liveness` takes with the anchor as its participants, with the term quiet
among all participants. Each premise is needed; `LIVENESS.md` gives the
counterexamples. `signature_settles_catchup` drops the sync premise for a larger
`fresh`. -/
theorem signature_settles
    : forall (config : Finset NodeID) (nodes : List NodeID),
        let system := Model.transitionSystem config nodes
        forall (W : Type) [Liveness.HasProtocol W Model.State] [Liveness.HasTime W]
                [Liveness.HasLive W] [Liveness.HasNetwork W] [Liveness.HasTimers W],
        forall (trace : Liveness.Trace W Liveness.Event) (bounds : Liveness.Bounds),
        forall (maxDelay fresh duration : Real) (start : Nat),
        forall (leader : NodeID) (term : Nat) (participants anchor : Finset NodeID),
          (trace.Coherent
            /\ trace.Valid (Liveness.protocolModel system)
            /\ trace.Valid Liveness.timingModel
            /\ trace.Valid Liveness.crashModel
            /\ trace.Valid (Liveness.deliveryModel system)
            /\ trace.Valid (Liveness.boundedDelayModel maxDelay)
            /\ trace.Valid (Liveness.timerModel bounds.electionTimeout)
            /\ 0 <= maxDelay
            /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
            /\ bounds.heartbeatInterval + maxDelay < fresh
            /\ fresh <= bounds.electionTimeout / 2
            /\ Liveness.AnchoredStart trace start leader term participants anchor fresh
            /\ Liveness.InSync trace start leader term anchor
            /\ Liveness.GoodPeriod trace start duration participants
            /\ Liveness.Window.AnchorActive trace start duration anchor)
          -> Liveness.StableWindow trace start duration leader term anchor
              /\ Liveness.Window.StableTerm trace start duration leader term
                  participants := by
  intro config nodes system W _ _ _ _ _ trace bounds maxDelay fresh duration start leader term
    participants anchor ⟨coherent, protocol, timing, crash, delivery, bounded, timers, nonneg,
      heartbeats, ratio, freshLe, initial, sync, good, active⟩
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  exact Proofs.Leadership.stable_window_anchored (nodes := nodes)
    ⟨coherent, protocol, timing, crash, delivery⟩ timers bounded nonneg heartbeats ratio
    freshLe initial good active sync

/-- Witness: for every nonnegative window length, a one-node execution with
heartbeat interval 1, election timeout 4 and freshness 2, whose node is both the
participants and the anchor, meets every premise of `signature_settles` and has
its conclusion. It resets no timer and times out no node, so every election
deadline stays at 0. -/
lemma signature_settles_witness
    : let system := Model.transitionSystem {0} [0]
      let bounds : Liveness.Bounds :=
        { heartbeatInterval := 1, electionTimeout := 4, signatureInterval := 1 }
      letI : Liveness.HasTimers (Liveness.World Model.State) := ⟨fun _ _ => 0⟩
      forall duration : Real,
        0 <= duration
        -> exists trace : Liveness.Trace (Liveness.World Model.State) Liveness.Event,
            (trace.Coherent
              /\ trace.Valid (Liveness.protocolModel system)
              /\ trace.Valid Liveness.timingModel
              /\ trace.Valid Liveness.crashModel
              /\ trace.Valid (Liveness.deliveryModel system)
              /\ trace.Valid (Liveness.boundedDelayModel 0)
              /\ trace.Valid (Liveness.timerModel bounds.electionTimeout)
              /\ 0 <= (0 : Real)
              /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
              /\ bounds.heartbeatInterval + 0 < 2
              /\ 2 <= bounds.electionTimeout / 2
              /\ Liveness.AnchoredStart trace 0 0 Model.BOOTSTRAP_TERM {0} {0} 2
              /\ Liveness.InSync trace 0 0 Model.BOOTSTRAP_TERM {0}
              /\ Liveness.GoodPeriod trace 0 duration {0}
              /\ Liveness.Window.AnchorActive trace 0 duration {0})
            /\ Liveness.StableWindow trace 0 duration 0 Model.BOOTSTRAP_TERM {0}
            /\ Liveness.Window.StableTerm trace 0 duration 0 Model.BOOTSTRAP_TERM
                {0} := by
  intro system bounds duration nonneg
  obtain ⟨trace, ⟨admissible, timers, bounded, delay, heartbeats, ratio, freshLe, anchored,
      good, active, sync⟩, stable, quiet⟩ :=
    Proofs.Leadership.stable_window_anchored_witness duration nonneg
  exact ⟨trace, ⟨admissible.coherent, admissible.protocol, admissible.timing,
    admissible.crash, admissible.delivery, bounded, timers, delay, heartbeats, ratio, freshLe,
    anchored, sync, good, active⟩, stable, quiet⟩

/-- `signature_settles` while participants catch up: at `start` every participant
is at the term, and the primary's log beyond its common prefix with each
participant spans at most `backlog` distinct terms, with no premise on the
messages in flight. A participant's election timer is reset only by an
AppendEntries that passes its log check, so a lagging participant is reset only
once the primary has repaired its log. From any point, the primary's next
heartbeat goes out within `interval`, the heartbeat interval if positive, and
reaches every participant within `maxDelay`; the repair it starts is acknowledged
within `6 maxDelay + 4 interval + 2 (backlog + 1) (2 maxDelay + interval)`, the
round bound of `commit_liveness`. So with `fresh` above their sum no participant
times out in the window. Each premise is needed; `LIVENESS.md` gives the
counterexamples, including one with `fresh` at `2 interval + 3 maxDelay`.

Reading the ratio: `fresh` is how long after `start` no participant times out, at
most half an election timeout. In that time the primary must repair every lagging
participant and get an acknowledgement back, or the participant times out and
starts an election. Each rejection moves the primary's probe back past a whole
term of its log (the retry hint), so a participant whose unagreed suffix spans
`backlog` terms is repaired within two round trips per term, plus two for the
primary's own new entries. Each round trip costs at most `2 maxDelay + interval`.
A fixed overhead of `7 maxDelay + 5 interval`, for stale traffic to drain and the
next heartbeat to go out and arrive, gives the left-hand side, so the premise just
says repair time < `fresh`. The in-sync bridge `signature_settles` needs only one
heartbeat round: `interval + maxDelay < fresh`. The constants are worst-case sums
along the proof, not tight. -/
theorem signature_settles_catchup
    : forall (config : Finset NodeID) (nodes : List NodeID),
        let system := Model.transitionSystem config nodes
        forall (W : Type) [Liveness.HasProtocol W Model.State] [Liveness.HasTime W]
                [Liveness.HasLive W] [Liveness.HasNetwork W] [Liveness.HasTimers W],
        forall (trace : Liveness.Trace W Liveness.Event) (bounds : Liveness.Bounds),
        forall (maxDelay fresh duration : Real) (backlog start : Nat),
        forall (leader : NodeID) (term : Nat) (participants : Finset NodeID),
          let interval := max bounds.heartbeatInterval 0
          (trace.Coherent
            /\ trace.Valid (Liveness.protocolModel system)
            /\ trace.Valid Liveness.timingModel
            /\ trace.Valid Liveness.crashModel
            /\ trace.Valid (Liveness.deliveryModel system)
            /\ trace.Valid (Liveness.boundedDelayModel maxDelay)
            /\ trace.Valid (Liveness.timerModel bounds.electionTimeout)
            /\ Liveness.TimeDiverges trace
            /\ 0 <= maxDelay
            /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
            /\ 6 * maxDelay
                  + 4 * interval
                  + 2 * ((backlog : Real) + 1) * (2 * maxDelay + interval)
                  + interval
                  + maxDelay
                < fresh
            /\ fresh <= bounds.electionTimeout / 2
            /\ leader ∈ participants
            /\ Liveness.FreshStart trace start leader term participants fresh
            /\ Liveness.LatestMembers trace start leader participants
            /\ Liveness.InTermAt trace start term participants
            /\ Liveness.BacklogTerms trace start leader participants backlog
            /\ Liveness.GoodPeriod trace start duration participants
            /\ Liveness.Window.StaysActive trace start duration leader)
          -> Liveness.StableWindow trace start duration leader term participants := by
  intro config nodes system W _ _ _ _ _ trace bounds maxDelay fresh duration backlog start leader
    term participants interval ⟨coherent, protocol, timing, crash, delivery, bounded, timers,
      diverges, nonneg, heartbeats, ratio, freshLe, leaderIn, initial, members, inTerm, behind,
      good, active⟩
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  exact Proofs.Leadership.stable_window_catchup (nodes := nodes)
    ⟨coherent, protocol, timing, crash, delivery⟩ timers bounded diverges nonneg heartbeats
    ratio freshLe leaderIn initial members good active inTerm behind

/-- Witness: for every nonnegative window length, a one-node execution with
heartbeat interval `1 / 10`, election timeout 4, freshness 2 and backlog 0 meets
every premise of `signature_settles_catchup` and has a stable window. It resets no
timer and times out no node, so every election deadline stays at 0. -/
lemma signature_settles_catchup_witness
    : let system := Model.transitionSystem {0} [0]
      let bounds : Liveness.Bounds :=
        { heartbeatInterval := 1 / 10, electionTimeout := 4, signatureInterval := 1 }
      let interval := max bounds.heartbeatInterval 0
      letI : Liveness.HasTimers (Liveness.World Model.State) := ⟨fun _ _ => 0⟩
      forall duration : Real,
        0 <= duration
        -> exists trace : Liveness.Trace (Liveness.World Model.State) Liveness.Event,
            (trace.Coherent
              /\ trace.Valid (Liveness.protocolModel system)
              /\ trace.Valid Liveness.timingModel
              /\ trace.Valid Liveness.crashModel
              /\ trace.Valid (Liveness.deliveryModel system)
              /\ trace.Valid (Liveness.boundedDelayModel 0)
              /\ trace.Valid (Liveness.timerModel bounds.electionTimeout)
              /\ Liveness.TimeDiverges trace
              /\ 0 <= (0 : Real)
              /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
              /\ 6 * 0
                    + 4 * interval
                    + 2 * (((0 : Nat) : Real) + 1) * (2 * 0 + interval)
                    + interval
                    + 0
                  < 2
              /\ 2 <= bounds.electionTimeout / 2
              /\ 0 ∈ ({0} : Finset NodeID)
              /\ Liveness.FreshStart trace 0 0 Model.BOOTSTRAP_TERM {0} 2
              /\ Liveness.LatestMembers trace 0 0 {0}
              /\ Liveness.InTermAt trace 0 Model.BOOTSTRAP_TERM {0}
              /\ Liveness.BacklogTerms trace 0 0 {0} 0
              /\ Liveness.GoodPeriod trace 0 duration {0}
              /\ Liveness.Window.StaysActive trace 0 duration 0)
            /\ Liveness.StableWindow trace 0 duration 0 Model.BOOTSTRAP_TERM {0} := by
  intro system bounds interval duration nonneg
  obtain ⟨trace, ⟨admissible, timers, bounded, diverges, delay, heartbeats, ratio, freshLe,
      leaderIn, fresh, members, good, active, inTerm, behind⟩, stable⟩ :=
    Proofs.Leadership.CatchUpWitness.stable_window_catchup_witness duration nonneg
  exact ⟨trace, ⟨admissible.coherent, admissible.protocol, admissible.timing,
    admissible.crash, admissible.delivery, bounded, timers, diverges, delay, heartbeats, ratio,
    freshLe, leaderIn, fresh, members, inTerm, behind, good, active⟩, stable⟩

end CCFRaft.Properties
