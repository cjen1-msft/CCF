module

public import CCFRaft.Model
public import CCFRaft.Liveness.Assumptions
public import CCFRaft.Liveness.Seq
public import CCF.Execution

import CCFRaft.Proofs.CommittedLogs
import CCFRaft.Proofs.Direct.CommitFrontier
import CCFRaft.Proofs.Duel.Probability
import CCFRaft.Proofs.Election
import CCFRaft.Proofs.Leadership.Stable
import CCFRaft.Proofs.LivenessWitness
import CCFRaft.Proofs.Replication.Commit
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

/-- Commit liveness, timed. Take one coherent recorded relational trace. Assume
coherence and validity of the protocol, timing, crash, delivery (in order on each
channel) and bounded-delay models for `system := Model.transitionSystem config
nodes`, and an unbounded
clock: every packet is then delivered or dropped within `maxDelay`, unless its
target crashes first. Assume that a primary sends due heartbeats
within `bounds.heartbeatInterval` and due signatures within
`bounds.signatureInterval`. Take a stable window from index `start` for
`commitLatency bounds maxDelay backlog`: `leader` is the uncontested primary of
`term`, stays live and unretired, every configuration active at it keeps a live
majority among `participants`, and no packet between it and a participant is
dropped. Additionally, reconfiguration is settled at the leader throughout the
window: one active configuration and all completed removals confirmed in its
committed ledger. Followers need not have learned this completion. This
excludes waiting for retirement cleanup, which has no scheduling deadline.
If at `start` every participant has adopted `term` and no participant's log
diverges from the primary's by more than `backlog` entries, and the primary holds
or appends `request`, then `request` is in the primary's committed prefix within
the window.
`signature_settles` yields the stable window after `duelling_leaders_resolve`;
settled reconfiguration remains a separate premise. -/
theorem commit_liveness
    : forall (config : Finset NodeID) (nodes : List NodeID),
        let system := Model.transitionSystem config nodes
        forall (W : Type) [Liveness.HasProtocol W Model.State] [Liveness.HasTime W]
                [Liveness.HasLive W] [Liveness.HasNetwork W],
        forall (trace : Liveness.Trace W Liveness.Event) (bounds : Liveness.Bounds),
        forall (maxDelay : Real) (start backlog : Nat),
        forall (leader : NodeID) (term : Nat) (participants : Finset NodeID)
                (request : ReqID),
          let duration := Liveness.commitLatency bounds maxDelay backlog
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
            /\ Liveness.Backlog trace start leader participants backlog
            /\ Liveness.InTermAt trace start term participants
            /\ Liveness.SubmittedAt trace start leader request)
          -> exists index,
              Liveness.Within trace start duration index
              /\ Liveness.RequestCommitted trace leader request index := by
  sorry

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

/-- A primary that has committed a signature of its own term stays uncontested
while the good period lasts and it stays live: the bridge from
`duelling_leaders_resolve` to the window `commit_liveness` consumes. Needs
heartbeats to reset every follower before its timer can fire. -/
theorem signature_settles
    : forall (config : Finset NodeID) (nodes : List NodeID),
        let system := Model.transitionSystem config nodes
        forall (W : Type) [Liveness.HasProtocol W Model.State] [Liveness.HasTime W]
                [Liveness.HasLive W] [Liveness.HasNetwork W] [Liveness.HasTimers W],
        forall (trace : Liveness.Trace W Liveness.Event) (bounds : Liveness.Bounds),
        forall (maxDelay duration : Real) (start : Nat) (point : W),
        forall (leader : NodeID) (term : Nat) (participants : Finset NodeID),
          (trace.Coherent
            /\ trace.Valid (Liveness.protocolModel system)
            /\ trace.Valid Liveness.timingModel
            /\ trace.Valid Liveness.crashModel
            /\ trace.Valid (Liveness.deliveryModel system)
            /\ trace.Valid (Liveness.boundedDelayModel maxDelay)
            /\ trace.Valid (Liveness.timerModel bounds.electionTimeout)
            /\ 0 <= maxDelay
            /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
            /\ bounds.heartbeatInterval + maxDelay < bounds.electionTimeout / 2
            /\ leader ∈ participants
            /\ trace.stateAt start = some point
            /\ Liveness.SignedPrimary point leader term
            /\ Liveness.GoodPeriod trace start duration participants
            /\ Liveness.Window.StaysActive trace start duration leader)
          -> Liveness.StableWindow trace start duration leader term participants := by
  sorry

end CCFRaft.Properties
