-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Slice25Model

set_option autoImplicit false

/-!
# Slice 3: arbitrary terms

This layer keeps the slice-2.5 write and replication semantics while allowing
followers and candidates to start successor elections in any term. Messages
may make another node jump directly across skipped terms through `UpdateTerm`.
-/

namespace CCFRaft.Slice3

variable {TxId : Type}
variable [DecidableEq TxId]

/-- Protocol guard for arbitrary repeated elections and leader writes. -/
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
      ((state.nodes node).role = .follower \/
        (state.nodes node).role = .candidate)
  | .requestVote source destination =>
      (state.nodes source).role = .candidate /\
        Not (source = destination)
  | .updateTerm source destination =>
      (newerMessage? state source destination).isSome
  | .becomeLeader node =>
      (state.nodes node).role = .candidate /\
        hasElectionMajority state node

/-- Make arbitrary-term guards executable. -/
instance (state : State TxId) (action : Action TxId) :
    Decidable (Enabled state action) := by
  cases action <;> simp only [Enabled] <;> infer_instance

/-- Slice 3 reuses the same deterministic local updates as slice 2.5. -/
def next
    (state : State TxId)
    (action : Action TxId) :
    State TxId :=
  Slice25.next state action

/-- Package slice 3 as an executable transition system. -/
def system : ExecutableTransitionSystem where
  State := State TxId
  Action := Action TxId
  initial := initialState
  Enabled
  enabledDecidable := fun _ _ => inferInstance
  next

/-- Execute actions until one is disabled. -/
def runActions
    (state : State TxId) :
    List (Action TxId) -> Option (State TxId)
  | [] => some state
  | action :: actions => do
      let nextState <- system.applyAction state action
      runActions nextState actions

/-- States reachable through arbitrary-term actions. -/
abbrev Reachable :=
  (system (TxId := TxId)).Reachable

namespace Reachable

/-- The shared initial state is reachable in slice 3. -/
theorem initial :
    Reachable (initialState : State TxId) :=
  ExecutableTransitionSystem.Reachable.initial

/-- Taking an enabled arbitrary-term action preserves reachability. -/
theorem step
    {state : State TxId}
    (reachable : Reachable state)
    {action : Action TxId}
    (enabled : Enabled state action) :
    Reachable (next state action) :=
  ExecutableTransitionSystem.Reachable.step reachable enabled

/-- A successfully executed arbitrary-term action list ends in a reachable state. -/
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

end CCFRaft.Slice3
