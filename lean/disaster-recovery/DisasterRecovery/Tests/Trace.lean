module

import all Init.Control.State
import all Init.Data.List.Sort.Basic

public import DisasterRecovery.Properties
public import DisasterRecovery.Tests.Initial

import DisasterRecovery.Proofs.Trace
import Mathlib.Tactic

@[expose] public section

namespace DisasterRecovery.Tests.Trace

open CCF
open Model.Local
open Properties.Trace

attribute [local simp] StateT.run

private def config : Model.Config :=
  {
    protocol := { instanceId := "trace-tests", expectedLocations := ["A"] }
    recovered := [("A", { view := 1, seqno := 10 })]
  }

private def recovered : TxID := { view := 1, seqno := 10 }
private def unused : Location × NodeState := ("unused", initialNode "unused")

private def initial : Model.State :=
  { Tests.initial config with nodes := [unused, ("A", initialNode "A")] }

private def gossip : Model.Envelope :=
  { source := "A", target := "A", payload := .gossip recovered }

private def vote : Model.Envelope := { source := "A", target := "A", payload := .vote }
private def gossipSent : Model.State := { initial with network := [gossip] }

private def selected : NodeState :=
  { location := "A", phase := .voting, chosen := some "A", gossips := [("A", recovered)] }

private def ready : Model.State := { nodes := [unused, ("A", selected)] }
private def voteSent : Model.State := { ready with network := [vote, gossip] }

private def opening : NodeState :=
  { selected with phase := .opening, openKind := some .quorum, votes := ["A"] }

private def opened : Model.State :=
  { ready with nodes := [unused, ("A", opening)], network := [gossip] }

private def actions : List Model.Action :=
  [.local "A" .retry, .deliver gossip, .local "A" .retry, .deliver vote]

private def trace : Properties.GlobalTrace :=
  { initial, actions := Stream'.Seq.ofList actions }

private def expectedStates : List Model.State :=
  [initial, gossipSent, ready, voteSent, opened]

private theorem initialized : (Model.transitionSystem config).init initial := by
  refine ⟨by unfold Model.Config.Valid; decide, ?_, by decide, rfl, ?_⟩
  · simp [initial, Tests.initial, config]
  · simp [initial, unused, Model.protocol]

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
        simp [Execution.Trace.actionAt, trace, actions, expectedStates,
          Model.transitionSystem, MultiNodeTransitionSystem.lift,
          MultiNodeTransitionSystem.next, MultiNodeTransitionSystem.nodeState,
          Model.protocol, Model.recoveredTxID, Model.receive, step, guard,
          initial, Tests.initial, config, gossipSent, ready, voteSent, opened,
          gossip, vote, recovered, unused]
      all_goals cbv

private theorem valid : trace.Valid (Model.transitionSystem config) :=
  Proofs.Trace.valid_of_stateAt_length initialized (replayed ⟨4, by decide⟩)

private theorem observedOpening
    : NotificationAt config trace 3 "A" (.opening .quorum) := by
  refine ⟨
    voteSent,
    opened,
    .deliver vote,
    selected,
    opening,
    { notifications := [.opening .quorum] },
    replayed ⟨3, by decide⟩,
    replayed ⟨4, by decide⟩,
    rfl,
    ?_,
    rfl,
    rfl,
    rfl,
    ?_,
    by simp
  ⟩
  · simp [Model.transitionSystem, MultiNodeTransitionSystem.lift,
      MultiNodeTransitionSystem.next, voteSent, ready, vote,
      MultiNodeTransitionSystem.nodeState, MultiNodeTransitionSystem.removeOne,
      Model.protocol, config, guard]
    cbv
  · simp [Model.protocol, config]
    cbv

example : (Model.transitionSystem config).Reachable opened :=
  valid.reachable_stateAt (replayed ⟨4, by decide⟩)

example : NotificationAt config trace 3 "A" (.opening .quorum) := observedOpening

example
    : exists openerTxID,
        Model.recoveredTxID config "A" = some openerTxID
        /\ Properties.UpToDateWithQuorum config openerTxID := by
  apply Properties.full_gossip_preserves_commit config trace ready opened "A" opening
  refine ⟨
    valid,
    Execution.Trace.mem_states_iff.mpr ⟨2, replayed ⟨2, by decide⟩⟩,
    ?_,
    Execution.Trace.mem_states_iff.mpr ⟨4, replayed ⟨4, by decide⟩⟩,
    by simp [opened],
    rfl
  ⟩
  intro node nodeState configured member entry
  have nodeEq : node = "A" := by simpa [config] using configured
  subst node
  have stateEq : nodeState = selected := by simpa [ready, unused] using member
  subst nodeState
  rfl

example (notification : Notification)
    : ¬ NotificationAt config trace 4 "A" notification := by
  rintro ⟨_, _, _, _, _, _, _, after, _⟩
  have bound := Proofs.Trace.stateAt_le_length after
  simp [actions] at bound

example (notification : Notification)
    : ¬ NotificationAt config trace 3 "missing-node" notification := by
  rintro ⟨before, _, _, _, _, _, first, _, _, _, _, found, _⟩
  have same : before = voteSent :=
    Option.some.inj (first.symm.trans (replayed ⟨3, by decide⟩))
  subst before
  simp [voteSent, ready, unused, MultiNodeTransitionSystem.nodeState] at found

private def retryTrace : Properties.GlobalTrace :=
  { initial := voteSent, actions := Stream'.Seq.ofList [.local "A" .retry] }

-- An unrecorded vote delivery cannot supply the notification for a retry.
example : ¬ NotificationAt config retryTrace 0 "A" (.opening .quorum) := by
  rintro ⟨before, _, action, nodeBefore, nodeAfter, outputs,
    first, _, recorded, _, _, foundBefore, _, run, notified⟩
  have start : before = voteSent := by simpa [retryTrace] using first.symm
  have recordedAction : action = .local "A" .retry := by
    simpa [Execution.Trace.actionAt, retryTrace] using recorded.symm
  subst before action
  have beforeEq : nodeBefore = selected := by
    simpa [voteSent, ready, unused, MultiNodeTransitionSystem.nodeState]
      using foundBefore.symm
  subst nodeBefore
  simp [Model.protocol, config] at run
  change some (selected, { outgoing := [vote, gossip] }) =
    some (nodeAfter, outputs) at run
  have effects := congrArg Prod.snd (Option.some.inj run)
  dsimp only at effects
  rw [← effects] at notified
  simp at notified

private def quorumBefore : NodeState := { selected with votes := ["A"] }

private def quorumVote : Properties.LocalStep :=
  {
    node := "A",
    before := quorumBefore,
    action := .receiveVote "A" .accepted
    after := { quorumBefore with phase := .opening, openKind := some .quorum }
    effects := { notifications := [.opening .quorum] }
  }

example
    : quorumVote.after.phase = .opening
      /\ quorumVote.after.openKind = some .quorum
      /\ .opening .quorum ∈ quorumVote.effects.notifications :=
  Properties.quorum_advance_opens config quorumVote
    ⟨
      by
        simp [MultiNodeTransitionSystem.Protocol.ValidStep, Model.protocol, config,
          quorumVote]
        cbv,
      Or.inr ⟨"A", rfl⟩,
      rfl,
      by decide
    ⟩

private def quorumTimeout : Properties.LocalStep :=
  {
    quorumVote with
      action := .timeout
      after := { quorumVote.after with timeoutState := .voting }
  }

example
    : quorumTimeout.after.phase = .opening
      /\ quorumTimeout.after.openKind = some .quorum
      /\ .opening .quorum ∈ quorumTimeout.effects.notifications :=
  Properties.quorum_advance_opens config quorumTimeout
    ⟨
      by
        simp [MultiNodeTransitionSystem.Protocol.ValidStep, Model.protocol, config,
          quorumTimeout]
        cbv,
      Or.inl rfl,
      rfl,
      by decide
    ⟩

example
    : ¬ Execution.Trace.Valid (Model.transitionSystem config)
          ({ initial := ready, actions := Stream'.Seq.ofList [.local "A" .retry] }
            : Properties.GlobalTrace) := by
  rintro ⟨⟨_, _, _, _, nodes⟩, _⟩
  have invalid := nodes ("A", selected) (by simp [ready])
  have phase := congrArg NodeState.phase invalid
  cases phase

end DisasterRecovery.Tests.Trace
