-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.ModelProofs

set_option autoImplicit false

namespace CCFRaft.RetirementExamples

def node0 : Node := ⟨0, by decide⟩
def node1 : Node := ⟨1, by decide⟩
def node2 : Node := ⟨2, by decide⟩
def node3 : Node := ⟨3, by decide⟩
def node4 : Node := ⟨4, by decide⟩
def node5 : Node := ⟨5, by decide⟩

def removalConfiguration : Finset Node :=
  DEFAULT_BOOTSTRAP_CONFIGURATION.erase node0

def removalEntry : Entry Node (Fin 1) where
  term := TERM_ONE
  content := .reconfiguration removalConfiguration

def signatureEntry : Entry Node (Fin 1) where
  term := TERM_ONE
  content := .signature

def retiredCommittedEntry : Entry Node (Fin 1) where
  term := TERM_ONE
  content := .retiredCommitted {node0}

def peerRemovalEntry : Entry Node (Fin 1) where
  term := TERM_ONE
  content := .reconfiguration
    (DEFAULT_BOOTSTRAP_CONFIGURATION.erase node4)

/-- Self-removal orders retirement at the new configuration index. -/
theorem selfRemovalOrdersRetirement :
    let before := (initialState : State Node (Fin 1))
    let after :=
      next before (.changeConfiguration node0 removalConfiguration)
    Enabled before (.changeConfiguration node0 removalConfiguration) /\
      (after.nodes node0).membershipState = .retirementOrdered /\
      (after.nodes node0).retirementIndex = some 1 := by
  decide

/-- A following signature makes the ordered retirement committable. -/
theorem signingAdvancesRetirement :
    let ordered :=
      refreshRetirementState node0
        { (initialNodeState node0 : NodeState Node (Fin 1)) with
          log := [removalEntry] }
    let signed :=
      refreshRetirementState node0
        { ordered with log := [removalEntry, signatureEntry] }
    signed.membershipState = .retirementSigned /\
      signed.retirementIndex = some 1 /\
      signed.retirementCommittableIndex = some 2 := by
  decide

/-- Committing the signing frontier completes retirement. -/
theorem commitCompletesRetirement :
    let completed :=
      refreshRetirementState node0
        { (initialNodeState node0 : NodeState Node (Fin 1)) with
          log := [removalEntry, signatureEntry]
          commitIndex := 2 }
    completed.membershipState = .retirementCompleted /\
      completed.retirementIndex = some 1 /\
      completed.retirementCommittableIndex = some 2 := by
  decide

/-- Committing a retired-committed record reaches the terminal phase. -/
theorem retiredCommittedEntryFinishesRetirement :
    let retired :=
      refreshRetirementState node0
        { (initialNodeState node0 : NodeState Node (Fin 1)) with
          log :=
            [removalEntry, signatureEntry,
              retiredCommittedEntry, signatureEntry]
          commitIndex := 4 }
    retired.membershipState = .retiredCommitted /\
      retired.retiredCommittedIndex = some 3 := by
  decide

/-- The terminal commit steps down and atomically nominates its successor. -/
theorem retiredCommittedCommitStepsDownSameTerm :
    let leaderState :=
      refreshRetirementState node0
        { (initialNodeState node0 : NodeState Node (Fin 1)) with
          log :=
            [removalEntry, signatureEntry,
              retiredCommittedEntry, signatureEntry]
          commitIndex := 2
          matchIndex := fun peer =>
            if peer ∈ ({node1, node2, node3} : Finset Node) then 4 else 0 }
    let state : State Node (Fin 1) :=
      { (initialState : State Node (Fin 1)) with
        nodes := updateNode initialNodes node0 leaderState }
    let after :=
      next state (.advanceCommitIndexAndProposeVote node0 node1)
    Enabled state (.advanceCommitIndexAndProposeVote node0 node1) /\
      Not (Enabled state (.advanceCommitIndex node0)) /\
      (after.nodes node0).membershipState = .retiredCommitted /\
      (after.nodes node0).role = .follower /\
      (after.nodes node0).currentTerm = leaderState.currentTerm /\
      after.network node1 =
        [.proposeVoteRequest
          (makeProposeVoteRequest state node0 node1)] /\
      Not (
        Enabled after
          (.changeConfiguration node0
            ({node1, node2, node3, node5} : Finset Node))) := by
  decide

/-- Truncating retirement evidence rolls signed to ordered, then active. -/
theorem rollbackRecalculatesRetirement :
    let signed :=
      refreshRetirementState node0
        { (initialNodeState node0 : NodeState Node (Fin 1)) with
          log := [removalEntry, signatureEntry] }
    let ordered :=
      refreshRetirementState node0 { signed with log := [removalEntry] }
    let active :=
      refreshRetirementState node0
        { ordered with log := ([] : List (Entry Node (Fin 1))) }
    ordered.membershipState = .retirementOrdered /\
      ordered.retirementCommittableIndex = none /\
      active.membershipState = .active /\
      active.retirementIndex = none := by
  decide

/-- Leader promotion truncates an unsigned self-removal and restores Active. -/
theorem leaderPromotionRollsBackOrderedRetirement :
    let candidate :=
      refreshRetirementState node0
        { (initialNodeState node0 : NodeState Node (Fin 1)) with
          role := .candidate
          currentTerm := TERM_ONE + 1
          log := [removalEntry]
          votedFor := some node0
          votesGranted :=
            (DEFAULT_BOOTSTRAP_CONFIGURATION.erase node4) }
    let state : State Node (Fin 1) :=
      { (initialState : State Node (Fin 1)) with
        nodes := updateNode initialNodes node0 candidate }
    let after := next state (.becomeLeader node0)
    Enabled state (.becomeLeader node0) /\
      (after.nodes node0).log = [] /\
      (after.nodes node0).membershipState = .active /\
      (after.nodes node0).retirementIndex = none := by
  decide

/-- Leaders continue replication to completed nodes outside active configs. -/
theorem replicationIncludesRetiringNodes :
    let leaderState :=
      refreshRetirementState node0
        { (initialNodeState node0 : NodeState Node (Fin 1)) with
          log := [peerRemovalEntry, signatureEntry]
          commitIndex := 2 }
    let state : State Node (Fin 1) :=
      { (initialState : State Node (Fin 1)) with
        nodes := updateNode initialNodes node0 leaderState
        retirementCompleted :=
          refreshRetirementCompleted
            (fun _ => ∅) node0 leaderState }
    node4 ∉ activeNodeUnion (state.nodes node0) /\
      node4 ∈ state.retirementCompleted node0 /\
      Enabled state (.appendEntries node0 node4 1) := by
  decide

/--
A locally completed retiree remains eligible through its own observer set even
after it has left every active configuration.
-/
theorem completedRetireeCanCampaignOutsideActiveConfiguration :
    let completed :=
      refreshRetirementState node4
        { (initialNodeState node4 : NodeState Node (Fin 1)) with
          role := .follower
          log := [peerRemovalEntry, signatureEntry]
          commitIndex := 2 }
    let capableState : State Node (Fin 1) :=
      { (initialState : State Node (Fin 1)) with
        nodes := updateNode initialNodes node4 completed
        retirementCompleted :=
          refreshRetirementCompleted
            (fun _ => ∅) node4 completed }
    let preVoteState : State Node (Fin 1) :=
      { capableState with
        nodes :=
          updateNode capableState.nodes node4
            { completed with
              role := .preVoteCandidate
              preVotesGranted := removalConfiguration }
        preVoteStatus :=
          Function.update capableState.preVoteStatus node4 .enabled }
    node4 ∉ activeNodeUnion completed /\
      node4 ∈ capableState.retirementCompleted node4 /\
      Enabled capableState (.timeout node4) /\
      Enabled
        { capableState with
          preVoteStatus :=
            Function.update capableState.preVoteStatus node4 .enabled }
        (.becomePreVoteCandidate node4) /\
      Enabled preVoteState (.becomeCandidate node4) := by
  decide

end CCFRaft.RetirementExamples
