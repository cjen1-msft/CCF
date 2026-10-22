module

public import CCFRaft.Model
public import CCFRaft.Liveness.Assumptions
public import CCFRaft.Liveness.Seq
public import CCF.Execution

import CCFRaft.Proofs.CommittedLogs
import CCFRaft.Proofs.Direct.CommitFrontier
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

end CCFRaft.Properties

namespace CCFRaft.Properties

/-- Commit liveness, untimed. Take one coherent recorded relational trace.
Assume coherence and validity of the protocol, timing, crash and delivery
models for `system := Model.transitionSystem config nodes`.
The delivery model enforces packet provenance and single consumption.
Assume separately the unbounded (`none`) heartbeat, signature and confirmation scheduling constraints.
Choose an index `start` in it. Suppose that
from `start` on `leader` is the live primary of `term`, that from some index on a
majority of each of its active configurations is live, and that the links between
`leader` and the participants are fair-loss. Then every request submitted to
`leader` at or after `start` is eventually in its committed prefix. -/
theorem commit_liveness
    : forall (config : Finset NodeID) (nodes : List NodeID),
      let system := Model.transitionSystem config nodes
      forall (W : Type) [Liveness.HasProtocol W Model.State] [Liveness.HasTime W]
        [Liveness.HasLive W] [Liveness.HasNetwork W],
      forall (trace : Liveness.Trace W Liveness.Event) (start : Nat),
      forall (leader : NodeID) (term : Nat) (participants : Finset NodeID),
        (trace.Coherent
          /\ trace.Valid (Liveness.protocolModel system)
          /\ trace.Valid Liveness.timingModel
          /\ trace.Valid Liveness.crashModel
          /\ trace.Valid (Liveness.deliveryModel system)
          /\ trace.HeartbeatScheduling none
          /\ trace.SignatureScheduling none
          /\ trace.ConfirmationScheduling none
          /\ Liveness.StableLeader trace start leader term
          /\ Liveness.LiveQuorum trace leader participants
          /\ Liveness.FairLoss trace (insert leader participants))
        -> forall (request : ReqID),
            Liveness.Submitted trace start leader request
            -> exists index, Liveness.RequestCommitted trace leader request index := by
  intro model trace start leader term participants ⟨valid, stable, live, fair⟩ request submitted
  exact Proofs.Replication.commit_liveness model valid stable live fair submitted

/-- Witness: an execution from boot satisfies every premise of `commit_liveness`
and commits its request. -/
lemma commit_liveness_witness
    : exists (config : Finset NodeID) (nodes : List NodeID),
      let system := Model.transitionSystem config nodes
      exists (trace : Liveness.Trace (Liveness.World Model.State) Liveness.Event) (start : Nat),
    exists (leader : NodeID) (term : Nat) (participants : Finset NodeID) (request : ReqID),
      trace.Coherent
      /\ trace.Valid (Liveness.protocolModel system)
      /\ trace.Valid Liveness.timingModel
      /\ trace.Valid Liveness.crashModel
      /\ trace.Valid (Liveness.deliveryModel system)
      /\ trace.HeartbeatScheduling none
      /\ trace.SignatureScheduling none
      /\ trace.ConfirmationScheduling none
      /\ Liveness.StableLeader trace start leader term
      /\ Liveness.LiveQuorum trace leader participants
      /\ Liveness.FairLoss trace (insert leader participants)
      /\ Liveness.Submitted trace start leader request
      /\ exists index, Liveness.RequestCommitted trace leader request index := by
  exact Proofs.LivenessWitness.commit_liveness_witness

/-- Stable leadership from timing. Take one coherent recorded relational trace.
Assume coherence and validity of the protocol, timing, crash and delivery
models for `system := Model.transitionSystem config nodes`.
The delivery model enforces packet provenance and single consumption.
Assume separately the scheduling constraints: heartbeats within `bounds.heartbeatInterval`, eventual signatures and confirmations, and no election timeout within `bounds.electionTimeout / 2` of a reset.
Choose an index `start` in it at which `leader` is the
newest primary, of `term` (`QuietStart`). Suppose that from `start` on, the
primary's AppendEntries requests arrive within `delay` and pass the log check of
every follower of the term, a heartbeat interval plus `delay` is below half the
election timeout, every node that times out in the term has been a replication
peer of the primary since `start`, and the primary stays live, does not retire,
and neither hands over nor steps down on a quorum check. Then from `start` on,
`leader` is the live primary of `term`. The log checks, the coverage and the
quorum checks are assumed, not derived. -/
theorem stable_leader
    : forall (config : Finset NodeID) (nodes : List NodeID),
      let system := Model.transitionSystem config nodes
      forall (W : Type) [Liveness.HasProtocol W Model.State] [Liveness.HasTime W]
        [Liveness.HasLive W] [Liveness.HasNetwork W],
      forall (trace : Liveness.Trace W Liveness.Event)
      (bounds : Liveness.Bounds) (start : Nat),
      forall (leader : NodeID) (term : Nat) (delay : Real),
        (trace.Coherent
          /\ trace.Valid (Liveness.protocolModel system)
          /\ trace.Valid Liveness.timingModel
          /\ trace.Valid Liveness.crashModel
          /\ trace.Valid (Liveness.deliveryModel system)
          /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
          /\ trace.SignatureScheduling none
          /\ trace.ConfirmationScheduling none
          /\ trace.ElectionScheduling (some (bounds.electionTimeout / 2))
          /\ Liveness.QuietStart trace start leader term bounds.electionTimeout
          /\ Liveness.Timely trace start leader delay
          /\ 0 <= delay
          /\ Liveness.Matching trace start leader term
          /\ bounds.heartbeatInterval + delay < bounds.electionTimeout / 2
          /\ Liveness.Covered trace start leader term
          /\ Liveness.Incumbent trace start leader)
        -> Liveness.StableLeader trace start leader term := by
  intro model trace start leader term delay
    ⟨valid, quiet, timely, nonneg, matching, ratio, covered, incumbent⟩
  exact Proofs.Leadership.stable_leader model valid quiet timely nonneg matching ratio covered
    incumbent

/-- Witness: an execution from boot satisfies every premise of `stable_leader`. -/
lemma stable_leader_witness
    : exists (config : Finset NodeID) (nodes : List NodeID),
      let system := Model.transitionSystem config nodes
      exists (trace : Liveness.Trace (Liveness.World Model.State) Liveness.Event)
      (bounds : Liveness.Bounds) (start : Nat),
    exists (leader : NodeID) (term : Nat) (delay : Real),
      trace.Coherent
      /\ trace.Valid (Liveness.protocolModel system)
      /\ trace.Valid Liveness.timingModel
      /\ trace.Valid Liveness.crashModel
      /\ trace.Valid (Liveness.deliveryModel system)
      /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
      /\ trace.SignatureScheduling none
      /\ trace.ConfirmationScheduling none
      /\ trace.ElectionScheduling (some (bounds.electionTimeout / 2))
      /\ Liveness.QuietStart trace start leader term bounds.electionTimeout
      /\ Liveness.Timely trace start leader delay
      /\ 0 <= delay
      /\ Liveness.Matching trace start leader term
      /\ bounds.heartbeatInterval + delay < bounds.electionTimeout / 2
      /\ Liveness.Covered trace start leader term
      /\ Liveness.Incumbent trace start leader
      /\ Liveness.StableLeader trace start leader term := by
  exact Proofs.LivenessWitness.stable_leader_witness

/-- Commit liveness, timed: `commit_liveness` with the stable primary derived by
`stable_leader` rather than assumed. -/
theorem commit_liveness_timed
    : forall (config : Finset NodeID) (nodes : List NodeID),
      let system := Model.transitionSystem config nodes
      forall (W : Type) [Liveness.HasProtocol W Model.State] [Liveness.HasTime W]
        [Liveness.HasLive W] [Liveness.HasNetwork W],
      forall (trace : Liveness.Trace W Liveness.Event)
      (bounds : Liveness.Bounds) (start : Nat),
      forall (leader : NodeID) (term : Nat) (participants : Finset NodeID) (delay : Real),
        (trace.Coherent
          /\ trace.Valid (Liveness.protocolModel system)
          /\ trace.Valid Liveness.timingModel
          /\ trace.Valid Liveness.crashModel
          /\ trace.Valid (Liveness.deliveryModel system)
          /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
          /\ trace.SignatureScheduling none
          /\ trace.ConfirmationScheduling none
          /\ trace.ElectionScheduling (some (bounds.electionTimeout / 2))
          /\ Liveness.QuietStart trace start leader term bounds.electionTimeout
          /\ Liveness.Timely trace start leader delay
          /\ 0 <= delay
          /\ Liveness.Matching trace start leader term
          /\ bounds.heartbeatInterval + delay < bounds.electionTimeout / 2
          /\ Liveness.Covered trace start leader term
          /\ Liveness.Incumbent trace start leader
          /\ Liveness.LiveQuorum trace leader participants
          /\ Liveness.FairLoss trace (insert leader participants))
        -> forall (request : ReqID),
            Liveness.Submitted trace start leader request
            -> exists index, Liveness.RequestCommitted trace leader request index := by
  intro model trace start leader term participants delay
    ⟨valid, quiet, timely, nonneg, matching, ratio, covered, incumbent, live, fair⟩ request
    submitted
  exact Proofs.Replication.commit_liveness model valid.scheduling
    (Proofs.Leadership.stable_leader model valid quiet timely nonneg matching ratio covered
      incumbent)
    live fair submitted

/-- Witness: an execution from boot satisfies every premise of
`commit_liveness_timed` and commits its request. -/
lemma commit_liveness_timed_witness
    : exists (config : Finset NodeID) (nodes : List NodeID),
      let system := Model.transitionSystem config nodes
      exists (trace : Liveness.Trace (Liveness.World Model.State) Liveness.Event)
      (bounds : Liveness.Bounds) (start : Nat),
    exists (leader : NodeID) (term : Nat) (participants : Finset NodeID) (delay : Real),
    exists (request : ReqID),
      trace.Coherent
      /\ trace.Valid (Liveness.protocolModel system)
      /\ trace.Valid Liveness.timingModel
      /\ trace.Valid Liveness.crashModel
      /\ trace.Valid (Liveness.deliveryModel system)
      /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
      /\ trace.SignatureScheduling none
      /\ trace.ConfirmationScheduling none
      /\ trace.ElectionScheduling (some (bounds.electionTimeout / 2))
      /\ Liveness.QuietStart trace start leader term bounds.electionTimeout
      /\ Liveness.Timely trace start leader delay
      /\ 0 <= delay
      /\ Liveness.Matching trace start leader term
      /\ bounds.heartbeatInterval + delay < bounds.electionTimeout / 2
      /\ Liveness.Covered trace start leader term
      /\ Liveness.Incumbent trace start leader
      /\ Liveness.LiveQuorum trace leader participants
      /\ Liveness.FairLoss trace (insert leader participants)
      /\ Liveness.Submitted trace start leader request
      /\ exists index, Liveness.RequestCommitted trace leader request index := by
  exact Proofs.LivenessWitness.commit_liveness_timed_witness

end CCFRaft.Properties
