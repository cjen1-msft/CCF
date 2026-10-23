module

import all Init.Control.State
import all Init.Data.List.Sort.Basic

public import DisasterRecovery.Properties
public import DisasterRecovery.Proofs.Trace
public import DisasterRecovery.Tests.Initial

@[expose] public section

namespace DisasterRecovery.Tests.QuorumCommit

open CCF
open Model.Local

private def high : TxID := { view := 1, seqno := 10 }
private def low : TxID := { view := 1, seqno := 5 }

private def config : Model.Config :=
  {
    protocol := { instanceId := "quorum-timeout", expectedLocations := ["A", "B", "C"] }
    recovered := [("A", high), ("B", high), ("C", low)]
  }

private def gossip (source target : Location) (txid : TxID) : Model.Envelope :=
  { source, target, payload := .gossip txid }

private def vote (source : Location) : Model.Envelope :=
  { source, target := "C", payload := .vote }

private def heard (node : Location) : NodeState :=
  { location := node, gossips := [("C", low)] }

private def selected (node : Location) : NodeState :=
  { heard node with phase := .voting, timeoutState := .voting, chosen := some "C" }

private def openedC : NodeState :=
  { selected "C" with phase := .opening, votes := ["A", "B"], openKind := some .quorum }

private def snapshot (a b c : NodeState) (network : List Model.Envelope) : Model.State :=
  { nodes := [("A", a), ("B", b), ("C", c)], network }

private def initial : Model.State := Tests.initial config
private def aGossips := [gossip "A" "A" high, gossip "A" "B" high, gossip "A" "C" high]
private def bGossips := [gossip "B" "A" high, gossip "B" "B" high, gossip "B" "C" high]

private def s1 :=
  snapshot (initialNode "A") (initialNode "B") (initialNode "C")
    [gossip "C" "A" low, gossip "C" "B" low, gossip "C" "C" low]

private def s2 :=
  snapshot (heard "A") (initialNode "B") (initialNode "C")
    [gossip "C" "B" low, gossip "C" "C" low]

private def s3 := snapshot (selected "A") (initialNode "B") (initialNode "C") s2.network
private def s4 := { s3 with network := s3.network ++ vote "A" :: aGossips }

private def s5 :=
  snapshot (selected "A") (heard "B") (initialNode "C")
    (gossip "C" "C" low :: vote "A" :: aGossips)

private def s6 := snapshot (selected "A") (selected "B") (initialNode "C") s5.network
private def s7 := { s6 with network := s6.network ++ vote "B" :: bGossips }

private def s8 :=
  snapshot (selected "A") (selected "B") (heard "C")
    (vote "A" :: aGossips ++ vote "B" :: bGossips)

private def s9 := snapshot (selected "A") (selected "B") (selected "C") s8.network

private def s10 :=
  snapshot (selected "A") (selected "B") { selected "C" with votes := ["A"] }
    (aGossips ++ vote "B" :: bGossips)

private def s11 := snapshot (selected "A") (selected "B") openedC (aGossips ++ bGossips)

private def expectedStates : List Model.State :=
  [initial, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11]

private def actions : List Model.Action :=
  [
    .local "C" .retry,
    .deliver (gossip "C" "A" low),
    .local "A" .timeout,
    .local "A" .retry,
    .deliver (gossip "C" "B" low),
    .local "B" .timeout,
    .local "B" .retry,
    .deliver (gossip "C" "C" low),
    .local "C" .timeout,
    .deliver (vote "A"),
    .deliver (vote "B")
  ]

private def trace : Properties.GlobalTrace :=
  { initial, actions := Stream'.Seq.ofList actions }

private theorem initialized : (Model.transitionSystem config).init initial := by
  refine ⟨by unfold Model.Config.Valid; decide, ?_, by decide, rfl, ?_⟩
  · simp [initial, Tests.initial, config]
  · simp [initial, Tests.initial, config, Model.protocol]

set_option maxHeartbeats 1000000 in
private theorem replayed (index : Fin expectedStates.length)
    : trace.stateAt (Model.transitionSystem config) index
      = some expectedStates[index] := by
  induction index using Fin.induction with
  | zero => exact Execution.Trace.stateAt_zero _ _
  | succ index ih =>
      change trace.stateAt (Model.transitionSystem config) (index.val + 1) = _
      rw [Execution.Trace.stateAt_succ]
      erw [ih]
      fin_cases index <;>
        dsimp [Execution.Trace.actionAt, trace, actions, expectedStates]
      all_goals
        dsimp only [Model.transitionSystem, MultiNodeTransitionSystem.lift]
        simp [MultiNodeTransitionSystem.next, MultiNodeTransitionSystem.nodeState,
          Model.protocol, Model.recoveredTxID, Model.receive, step, guard,
          initial, Tests.initial, config, snapshot, s1, s2, s3, s4, s5, s6, s7, s8, s9,
          s10, s11, aGossips, bGossips, gossip, vote, high, low]
      all_goals cbv

private theorem valid : trace.Valid (Model.transitionSystem config) :=
  Proofs.Trace.valid_of_stateAt_length initialized (replayed ⟨11, by decide⟩)

private theorem opened : ("C", openedC) ∈ s11.nodes := by
  simp [s11, snapshot]

private theorem final_in_trace : s11 ∈ trace.states (Model.transitionSystem config) :=
  Execution.Trace.mem_states_iff.mpr ⟨11, replayed ⟨11, by decide⟩⟩

private theorem stale : ¬ Properties.UpToDateWithQuorum config low := by
  unfold Properties.UpToDateWithQuorum
  decide

example
    : trace.Valid (Model.transitionSystem config)
      /\ s11 ∈ trace.states (Model.transitionSystem config)
      /\ ("C", openedC) ∈ s11.nodes
      /\ openedC.openKind = some .quorum
      /\ Model.recoveredTxID config "C" = some low
      /\ ¬ Properties.UpToDateWithQuorum config low :=
  ⟨valid, final_in_trace, opened, rfl, rfl, stale⟩

private theorem missing_own : ¬ Properties.ReceivedOwnGossip config trace "A" := by
  rintro ⟨state, member, current, txid, present, gossipPresent⟩
  obtain ⟨i, found⟩ := Execution.Trace.mem_states_iff.mp member
  have bound : i < expectedStates.length := by
    simpa [expectedStates, actions]
      using Nat.lt_succ_of_le (Proofs.Trace.stateAt_le_length found)
  have listed : expectedStates[i]? = some state :=
    List.getElem?_eq_some_iff.mpr
      ⟨bound, Option.some.inj ((replayed ⟨i, bound⟩).symm.trans found)⟩
  replace member := List.mem_of_getElem? listed
  simp only [expectedStates, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals
    simp [initial, Tests.initial, config, snapshot, s1, s2, s3, s4, s5, s6, s7, s8, s9,
      s10, s11, openedC, selected, heard, initialNode] at present
    subst current
    simp at gossipPresent

example
    : ¬ (forall voter,
          voter ∈ openedC.votes -> Properties.ReceivedOwnGossip config trace voter) :=
  fun own => missing_own (own "A" (by simp [openedC]))

end DisasterRecovery.Tests.QuorumCommit
