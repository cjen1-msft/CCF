-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model

set_option autoImplicit false

/-!
# Slice 2.5: cross-term replication

This layer reuses the slice-two state, messages, and local handlers while
allowing any locally selected leader to append, replicate, and commit entries
in its current term.
-/

namespace CCFRaft.Slice25

variable {TxId : Type}
variable [DecidableEq TxId]

/-- Protocol guard for the one-election cross-term slice. -/
def Enabled
    (state : State TxId) :
    Action TxId -> Prop
  | .clientRequest node txId =>
      (state.nodes node).role = .leader /\
        txId ∉ state.submittedTxIds
  | .appendEntries source destination batchEnd =>
      (state.nodes source).role = .leader /\
        Not (source = destination) /\
        batchEnd =
          min
            ((state.nodes source).sentIndex destination + 1)
            (state.nodes source).log.length
  | .receive source destination =>
      (handleReceive? state source destination).isSome
  | .advanceCommitIndex node =>
      (state.nodes node).role = .leader /\
        (state.nodes node).commitIndex <
          highestCommittableIndex state node
  | .timeout node =>
      (state.nodes node).role = .follower /\
        (state.nodes node).currentTerm = TERM_ONE
  | .requestVote source destination =>
      (state.nodes source).role = .candidate /\
        (state.nodes source).currentTerm = 2 /\
        Not (source = destination)
  | .updateTerm source destination =>
      (newerMessage? state source destination).isSome
  | .becomeLeader node =>
      (state.nodes node).role = .candidate /\
        (state.nodes node).currentTerm = 2 /\
        hasElectionMajority state node

/-- Make every slice-2.5 action guard executable. -/
instance (state : State TxId) (action : Action TxId) :
    Decidable (Enabled state action) := by
  cases action <;> simp only [Enabled] <;> infer_instance

/-- Apply a slice-2.5 action using the shared local protocol handlers. -/
def next
    (state : State TxId) :
    Action TxId -> State TxId
  | .clientRequest node txId =>
      let nodeState := state.nodes node
      let entry := { term := nodeState.currentTerm, txId }
      { state with
        nodes :=
          updateNode state.nodes node
            { nodeState with log := nodeState.log ++ [entry] }
        submittedTxIds := insert txId state.submittedTxIds }
  | .appendEntries source destination batchEnd =>
      let sourceState := state.nodes source
      let request := makeAppendEntriesRequest state source destination batchEnd
      { state with
        nodes :=
          updateNode state.nodes source
            { sourceState with
              sentIndex :=
                updateIndex sourceState.sentIndex destination batchEnd }
        network :=
          enqueueNoDup state.network (.appendEntriesRequest request) }
  | .receive source destination =>
      (handleReceive? state source destination).getD state
  | .advanceCommitIndex node =>
      let nodeState := state.nodes node
      { state with
        nodes :=
          updateNode state.nodes node
            { nodeState with
              commitIndex := highestCommittableIndex state node } }
  | .timeout node =>
      let nodeState := state.nodes node
      { state with
        nodes :=
          updateNode state.nodes node
            { nodeState with
              role := .candidate
              currentTerm := nodeState.currentTerm + 1
              votedFor := some node
              votesGranted := {node} } }
  | .requestVote source destination =>
      let request := makeRequestVoteRequest state source destination
      { state with
        network :=
          enqueueNoDup state.network (.requestVoteRequest request) }
  | .updateTerm source destination =>
      match newerMessage? state source destination with
      | none => state
      | some selected =>
          let nodeState := state.nodes destination
          { state with
            nodes :=
              updateNode state.nodes destination
                { nodeState with
                  role := .follower
                  currentTerm := selected.term
                  votedFor := none
                  isNewFollower := true } }
  | .becomeLeader node =>
      let nodeState := state.nodes node
      { state with
        nodes :=
          updateNode state.nodes node
            { nodeState with
              role := .leader
              sentIndex := fun _ => nodeState.log.length
              matchIndex := fun _ => 0 } }

/-- Package slice 2.5 as an executable transition system. -/
def system : ExecutableTransitionSystem where
  State := State TxId
  Action := Action TxId
  initial := initialState
  Enabled
  enabledDecidable := fun _ _ => inferInstance
  next

/-- Execute a finite list of semantic actions, stopping at the first disabled action. -/
def runActions
    (state : State TxId) :
    List (Action TxId) -> Option (State TxId)
  | [] => some state
  | action :: actions => do
      let nextState <- system.applyAction state action
      runActions nextState actions

/-- States reachable through enabled slice-2.5 actions. -/
abbrev Reachable :=
  (system (TxId := TxId)).Reachable

namespace Reachable

/-- The shared initial state is reachable in slice 2.5. -/
theorem initial :
    Reachable (initialState : State TxId) :=
  ExecutableTransitionSystem.Reachable.initial

/-- Taking an enabled slice-2.5 action preserves reachability. -/
theorem step
    {state : State TxId}
    (reachable : Reachable state)
    {action : Action TxId}
    (enabled : Enabled state action) :
    Reachable (next state action) :=
  ExecutableTransitionSystem.Reachable.step reachable enabled

/-- The state returned by a fully executed action list is reachable. -/
theorem runActionsReachable
    {start final : State TxId}
    {actions : List (Action TxId)}
    (startReachable : Reachable start)
    (ran : runActions start actions = some final) :
    Reachable final := by
  induction actions generalizing start final with
  | nil =>
      simp [runActions] at ran
      subst final
      exact startReachable
  | cons action actions inductionHypothesis =>
      unfold runActions at ran
      cases applied : system.applyAction start action with
      | none =>
          simp [applied] at ran
      | some nextState =>
          have enabled : Enabled start action := by
            unfold ExecutableTransitionSystem.applyAction at applied
            split at applied
            · assumption
            · contradiction
          have nextEq : next start action = nextState := by
            unfold ExecutableTransitionSystem.applyAction at applied
            split at applied
            · exact Option.some.inj applied
            · contradiction
          have nextReachable : Reachable nextState := by
            rw [← nextEq]
            exact step startReachable enabled
          exact
            inductionHypothesis nextReachable
              (by simpa [applied] using ran)

end Reachable

end CCFRaft.Slice25
