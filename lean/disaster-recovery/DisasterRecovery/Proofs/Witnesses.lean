module

import all Init.Control.State
import all Init.Data.List.Sort.Basic

public import DisasterRecovery.Properties
public import DisasterRecovery.Proofs.Local
public import DisasterRecovery.Proofs.Trace

@[expose] public section

namespace DisasterRecovery.Proofs.Witnesses

open CCF
open Model.Local
open DisasterRecovery.Proofs.Local
attribute [local simp] StateT.run

private def initial (config : Model.Config) : Model.State :=
  { nodes := config.protocol.expectedLocations.map fun node => (node, initialNode node) }

private theorem initialized {config : Model.Config} (valid : config.Valid)
    : (Model.transitionSystem config).init (initial config) := by
  refine ⟨valid, ?_, ?_, rfl, ?_⟩
  · simp [initial, Function.comp_def]
  · simpa [initial, Function.comp_def] using valid.2.1
  · intro entry member
    obtain ⟨node, _, rfl⟩ := List.mem_map.mp member
    rfl

private def high : TxID := { view := 1, seqno := 10 }

private def gossip (source target : Location) (txid : TxID) : Model.Envelope :=
  { source, target, payload := .gossip txid }

private def vote : Model.Envelope := { source := "A", target := "A", payload := .vote }

private def quorumConfig : Model.Config :=
  {
    protocol := { instanceId := "quorum-witness", expectedLocations := ["A"] }
    recovered := [("A", high)]
  }

private def quorumActions : List Model.Action :=
  [.local "A" .retry, .deliver (gossip "A" "A" high), .local "A" .retry, .deliver vote]

private def quorumSelected : NodeState :=
  { location := "A", phase := .voting, chosen := some "A", gossips := [("A", high)] }

private def quorumReady : Model.State :=
  { nodes := [("A", quorumSelected)] }

private def quorumVoteSent : Model.State :=
  { quorumReady with network := [vote, gossip "A" "A" high] }

private def quorumOpener : NodeState :=
  { quorumSelected with phase := .opening, openKind := some .quorum, votes := ["A"] }

private def quorumOpened : Model.State :=
  {
    nodes := [("A", quorumOpener)]
    network := [gossip "A" "A" high]
  }

private def quorumTrace : Properties.GlobalTrace :=
  { initial := initial quorumConfig, actions := Stream'.Seq.ofList quorumActions }

private theorem quorum_last
    : quorumTrace.stateAt (Model.transitionSystem quorumConfig) 4
      = some quorumOpened := by
  simp only [Execution.Trace.stateAt_succ, Execution.Trace.stateAt_zero]
  simp [Execution.Trace.actionAt, quorumTrace, quorumActions, Model.transitionSystem,
    MultiNodeTransitionSystem.lift, MultiNodeTransitionSystem.next, quorumConfig, initial,
    MultiNodeTransitionSystem.nodeState,
    Model.protocol, Model.recoveredTxID, Model.receive, step, guard, gossip, vote, high]
  cbv

private theorem quorum_valid : quorumTrace.Valid (Model.transitionSystem quorumConfig) :=
  Trace.valid_of_stateAt_length
    (initialized (by unfold Model.Config.Valid; decide)) quorum_last

private theorem quorum_notified
    : Properties.Trace.NotificationAt quorumConfig quorumTrace 3 "A"
        (.opening .quorum) := by
  refine ⟨quorumVoteSent, quorumOpened, .deliver vote, quorumSelected, quorumOpener,
    { notifications := [.opening .quorum] }, ?_, quorum_last, rfl, ?_, rfl, rfl, rfl, ?_, ?_⟩
  · simp only [Execution.Trace.stateAt_succ, Execution.Trace.stateAt_zero]
    simp [Execution.Trace.actionAt, quorumTrace, quorumActions, Model.transitionSystem,
      MultiNodeTransitionSystem.lift, MultiNodeTransitionSystem.next, quorumConfig, initial,
      MultiNodeTransitionSystem.nodeState,
      Model.protocol, Model.recoveredTxID, Model.receive, step, guard, gossip, vote, high]
    cbv
  · simp [Model.transitionSystem, MultiNodeTransitionSystem.lift,
      MultiNodeTransitionSystem.next, quorumVoteSent, quorumReady, vote,
      MultiNodeTransitionSystem.nodeState,
      Model.protocol, quorumConfig, guard]
    cbv
  · simp [Model.protocol, quorumConfig]
    cbv
  · simp

theorem quorum_opener_unique_witness : Properties.QuorumOpenerUniqueWitness :=
  ⟨quorumConfig, quorumTrace, 3, "A", quorum_valid, quorum_notified⟩

theorem quorum_open_preserves_commit_witness
    : Properties.QuorumOpenPreservesCommitWitness := by
  refine ⟨
    quorumConfig,
    quorumTrace,
    quorumOpened,
    "A",
    quorumOpener,
    quorum_valid,
    Execution.Trace.mem_states_iff.mpr ⟨4, quorum_last⟩,
    by simp [quorumOpened],
    rfl,
    ?_
  ⟩
  intro voter member
  have same : voter = "A" := by simpa [quorumOpener] using member
  subst voter
  refine ⟨
    quorumReady,
    Execution.Trace.mem_states_iff.mpr ⟨2, ?_⟩,
    quorumSelected,
    high,
    by simp [quorumReady],
    by simp [quorumSelected]
  ⟩
  simp only [Execution.Trace.stateAt_succ, Execution.Trace.stateAt_zero]
  simp [Execution.Trace.actionAt, quorumTrace, quorumActions, Model.transitionSystem,
    MultiNodeTransitionSystem.lift, MultiNodeTransitionSystem.next, quorumConfig, initial,
    MultiNodeTransitionSystem.nodeState,
    Model.protocol, Model.recoveredTxID, Model.receive, step, guard, gossip, vote, high]
  cbv

private def fullConfig : Model.Config :=
  {
    protocol :=
      {
        instanceId := "full-gossip-failover-witness", expectedLocations := ["A", "B", "C"]
      }
    recovered :=
      [("A", high), ("B", { view := 1, seqno := 8 }), ("C", { view := 1, seqno := 5 })]
  }

private def fullActions : List Model.Action :=
  [
    .local "A" .retry,
    .local "B" .retry,
    .local "C" .retry,
    .deliver (gossip "A" "A" high),
    .deliver (gossip "B" "A" { view := 1, seqno := 8 }),
    .deliver (gossip "C" "A" { view := 1, seqno := 5 }),
    .deliver (gossip "A" "B" high),
    .deliver (gossip "B" "B" { view := 1, seqno := 8 }),
    .deliver (gossip "C" "B" { view := 1, seqno := 5 }),
    .deliver (gossip "A" "C" high),
    .deliver (gossip "B" "C" { view := 1, seqno := 8 }),
    .deliver (gossip "C" "C" { view := 1, seqno := 5 }),
    .local "A" .retry,
    .deliver vote,
    .local "A" .timeout,
    .local "A" .timeout
  ]

private def fullSelected (node : Location) : NodeState :=
  {
    location := node,
    phase := .voting,
    chosen := some "A",
    gossips := fullConfig.recovered
  }

private def fullGossiped : Model.State :=
  { nodes := [("A", fullSelected "A"), ("B", fullSelected "B"), ("C", fullSelected "C")] }

private def failoverOpener : NodeState :=
  {
    fullSelected "A" with
      phase := .opening
      timeoutState := .opening
      votes := ["A"]
      openKind := some .failover
  }

private def failoverOpened : Model.State :=
  {
    fullGossiped with
      nodes := [("A", failoverOpener), ("B", fullSelected "B"), ("C", fullSelected "C")]
      network := [gossip "A" "A" high, gossip "A" "B" high, gossip "A" "C" high]
  }

private def fullTrace : Properties.GlobalTrace :=
  { initial := initial fullConfig, actions := Stream'.Seq.ofList fullActions }

set_option maxHeartbeats 2000000 in
private theorem full_last
    : fullTrace.stateAt (Model.transitionSystem fullConfig) 16 = some failoverOpened := by
  simp only [Execution.Trace.stateAt_succ, Execution.Trace.stateAt_zero]
  simp [Execution.Trace.actionAt, fullTrace, fullActions, Model.transitionSystem,
    MultiNodeTransitionSystem.lift, MultiNodeTransitionSystem.next, fullConfig, initial,
    MultiNodeTransitionSystem.nodeState,
    Model.protocol, Model.recoveredTxID, Model.receive, step, guard, gossip, vote, high]
  cbv

private theorem full_valid : fullTrace.Valid (Model.transitionSystem fullConfig) :=
  Trace.valid_of_stateAt_length
    (initialized (by unfold Model.Config.Valid; decide)) full_last

theorem full_gossip_preserves_commit_witness
    : Properties.FullGossipPreservesCommitWitness := by
  refine ⟨
    fullConfig,
    fullTrace,
    fullGossiped,
    failoverOpened,
    "A",
    failoverOpener,
    full_valid,
    Execution.Trace.mem_states_iff.mpr ⟨12, ?_⟩,
    ?_,
    Execution.Trace.mem_states_iff.mpr ⟨16, full_last⟩,
    by simp [failoverOpened],
    rfl
  ⟩
  · simp only [Execution.Trace.stateAt_succ, Execution.Trace.stateAt_zero]
    simp [Execution.Trace.actionAt, fullTrace, fullActions, Model.transitionSystem,
      MultiNodeTransitionSystem.lift, MultiNodeTransitionSystem.next, fullConfig, initial,
      MultiNodeTransitionSystem.nodeState,
      Model.protocol, Model.recoveredTxID, Model.receive, step, guard, gossip, vote, high]
    cbv
  · intro node nodeState _ member entry
    simp only [fullGossiped, List.mem_cons, List.not_mem_nil, or_false, Prod.mk.injEq] at member
    rcases member with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;> rfl

private def frozenGossip : Properties.LocalStep :=
  {
    node := "A"
    before := quorumSelected
    action := .receiveGossip "A" high .accepted
    after := quorumSelected
    effects := { notifications := [.rejected "gossip-frozen"] }
  }

theorem gossip_freezes_after_choice_witness
    : Properties.GossipFreezesAfterChoiceWitness := by
  refine ⟨quorumConfig, frozenGossip, "A", high, ?_, rfl, rfl⟩
  simp [MultiNodeTransitionSystem.Protocol.ValidStep, Model.protocol, quorumConfig,
    frozenGossip]
  cbv

private def rejectedGossip : Properties.LocalStep :=
  {
    node := "A"
    before := initialNode "A"
    action := .receiveGossip "A" high .rejected
    after := initialNode "A"
    effects := { notifications := [.rejected "quote-or-certificate"] }
  }

theorem rejected_gossip_stutters_witness : Properties.RejectedGossipStuttersWitness := by
  refine ⟨quorumConfig, rejectedGossip, "A", high, ?_, rfl⟩
  simp [MultiNodeTransitionSystem.Protocol.ValidStep, Model.protocol, quorumConfig,
    rejectedGossip]
  cbv

private def quorumTimeout : Properties.LocalStep :=
  {
    node := "A"
    before := { quorumSelected with votes := ["A"] }
    action := .timeout
    after := { quorumOpener with timeoutState := .voting }
    effects := { notifications := [.opening .quorum] }
  }

theorem quorum_advance_opens_witness : Properties.QuorumAdvanceOpensWitness := by
  refine ⟨quorumConfig, quorumTimeout, ?_, Or.inl rfl, rfl, by decide⟩
  simp [MultiNodeTransitionSystem.Protocol.ValidStep, Model.protocol, quorumConfig,
    quorumTimeout]
  cbv

private def openingTimeout : Properties.LocalStep :=
  {
    node := "A"
    before := { quorumOpener with timeoutState := .opening }
    action := .timeout
    after := { quorumOpener with timeoutState := .opening, phase := .open }
    effects := { notifications := [.completed] }
  }

theorem aligned_opening_timeout_completes_witness
    : Properties.AlignedOpeningTimeoutCompletesWitness := by
  refine ⟨quorumConfig, openingTimeout, ?_, rfl, rfl, rfl⟩
  simp [MultiNodeTransitionSystem.Protocol.ValidStep, Model.protocol, quorumConfig,
    openingTimeout]
  cbv

end DisasterRecovery.Proofs.Witnesses
