-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.LeaderWriteMappingProofs

set_option autoImplicit false

/-!
# Transaction mapping for control actions

Generic commutation and enabledness lemmas for control actions whose
semantics inspect transaction-carrying logs and queues only through structural
projections.
-/

namespace CCFRaft.TransactionMapping

open CCFRaft

variable {Node TxId OtherTxId : Type}

@[simp]
theorem mapEntry_term
    (f : TxId -> OtherTxId)
    (entry : Entry Node TxId) :
    (mapEntry f entry).term = entry.term := rfl

@[simp]
theorem entryAt?_map
    (f : TxId -> OtherTxId)
    (log : List (Entry Node TxId))
    (index : Nat) :
    entryAt? (log.map (mapEntry f)) index =
      (entryAt? log index).map (mapEntry f) := by
  unfold entryAt?
  split <;> simp

@[simp]
theorem termAt_map
    (f : TxId -> OtherTxId)
    (log : List (Entry Node TxId))
    (index : Nat) :
    termAt (log.map (mapEntry f)) index = termAt log index := by
  unfold termAt
  rw [entryAt?_map]
  cases entryAt? log index <;> rfl

@[simp]
theorem isSignatureAt_map
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (log : List (Entry Node TxId))
    (index : Nat) :
    isSignatureAt (log.map (mapEntry f)) index =
      isSignatureAt log index := by
  unfold isSignatureAt
  rw [entryAt?_map]
  cases found : entryAt? log index with
  | none => rfl
  | some entry =>
      rcases entry with ⟨term, content⟩
      cases content <;> rfl

@[simp]
theorem maxCommittableIndex_map
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (log : List (Entry Node TxId)) :
    maxCommittableIndex (log.map (mapEntry f)) =
      maxCommittableIndex log := by
  simp [maxCommittableIndex]

@[simp]
theorem maxCommittableIndexUpTo_map
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (log : List (Entry Node TxId))
    (frontier : Nat) :
    maxCommittableIndexUpTo (log.map (mapEntry f)) frontier =
      maxCommittableIndexUpTo log frontier := by
  rw [maxCommittableIndexUpTo, maxCommittableIndexUpTo, ← List.map_take]
  exact maxCommittableIndex_map f (log.take frontier)

@[simp]
theorem lastCommittableIndex_mapNodeState
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) :
    lastCommittableIndex (mapNodeState f state) =
      lastCommittableIndex state := by
  simp [lastCommittableIndex, mapNodeState]

@[simp]
theorem lastCommittableTerm_mapNodeState
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) :
    lastCommittableTerm (mapNodeState f state) =
      lastCommittableTerm state := by
  rw [lastCommittableTerm, lastCommittableTerm,
    lastCommittableIndex_mapNodeState]
  exact termAt_map f state.log (lastCommittableIndex state)

@[simp]
theorem currentConfiguration_mapNodeState
    [DecidableEq Node]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) :
    currentConfiguration (mapNodeState f state) =
      currentConfiguration state := by
  simp only [currentConfiguration, mapNodeState]
  exact currentConfigurationAt_map f state.log state.commitIndex

@[simp]
theorem activeConfigurations_mapNodeState
    [DecidableEq Node]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) :
    activeConfigurations (mapNodeState f state) =
      activeConfigurations state := by
  unfold activeConfigurations
  rw [currentConfiguration_mapNodeState]
  rw [show (mapNodeState f state).log =
    state.log.map (mapEntry f) by rfl]
  rw [allConfigurations_map]

@[simp]
theorem activeNodeUnion_mapNodeState
    [DecidableEq Node]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) :
    activeNodeUnion (mapNodeState f state) =
      activeNodeUnion state := by
  simp [activeNodeUnion]

@[simp]
theorem highestActiveConfigurationWithNode_mapNodeState
    [DecidableEq Node]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : NodeState Node TxId)
    (node : Node) :
    highestActiveConfigurationWithNode (mapNodeState f state) node =
      highestActiveConfigurationWithNode state node := by
  simp [highestActiveConfigurationWithNode]

@[simp]
theorem campaignEligible_mapNodeState
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (node : Node)
    (state : NodeState Node TxId) :
    campaignEligible node (mapNodeState f state) ↔
      campaignEligible node state := by
  unfold campaignEligible
  rw [activeConfigurations_mapNodeState]
  rw [show (mapNodeState f state).log = state.log.map (mapEntry f) by rfl]
  rw [maxCommittableIndex_map]

@[simp]
theorem acknowledgingNodes_mapState
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (leader : Node)
    (index : Nat) :
    acknowledgingNodes (mapState f state) leader index =
      acknowledgingNodes state leader index := by
  unfold acknowledgingNodes
  rw [mapState_nodes_get, activeNodeUnion_mapNodeState]
  rfl

@[simp]
theorem hasMajorityAt_mapState
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (leader : Node)
    (index : Nat) :
    hasMajorityAt (mapState f state) leader index ↔
      hasMajorityAt state leader index := by
  simp [hasMajorityAt]

@[simp]
theorem hasElectionMajority_mapState
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (candidate : Node) :
    hasElectionMajority (mapState f state) candidate ↔
      hasElectionMajority state candidate := by
  unfold hasElectionMajority
  rw [mapState_nodes_get, activeConfigurations_mapNodeState]
  rfl

@[simp]
theorem hasPreVoteMajority_mapState
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (candidate : Node) :
    hasPreVoteMajority (mapState f state) candidate ↔
      hasPreVoteMajority state candidate := by
  unfold hasPreVoteMajority
  rw [mapState_nodes_get, activeConfigurations_mapNodeState]
  rfl

@[simp]
theorem hasOtherActiveReplica_mapState
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (node : Node) :
    hasOtherActiveReplica (mapState f state) node ↔
      hasOtherActiveReplica state node := by
  simp [hasOtherActiveReplica]

@[simp]
theorem plausibleSuccessor_mapState
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (source destination : Node) :
    plausibleSuccessor (mapState f state) source destination ↔
      plausibleSuccessor state source destination := by
  simp only [plausibleSuccessor, mapState_nodes_get,
    activeNodeUnion_mapNodeState,
    highestActiveConfigurationWithNode_mapNodeState]
  rfl

@[simp]
theorem highestCommittableIndex_mapState
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (leader : Node) :
    highestCommittableIndex (mapState f state) leader =
      highestCommittableIndex state leader := by
  simp [highestCommittableIndex, mapNodeState]

@[simp]
theorem terminalRetirementCommit_mapState
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (node : Node) :
    terminalRetirementCommit (mapState f state) node ↔
      terminalRetirementCommit state node := by
  let advanced : NodeState Node TxId :=
    { state.nodes node with
      commitIndex := highestCommittableIndex state node }
  have mappedAdvanced :
      { (mapState f state).nodes node with
        commitIndex := highestCommittableIndex (mapState f state) node } =
        mapNodeState f advanced := by
    simp [advanced, mapNodeState]
  simp only [terminalRetirementCommit]
  rw [mappedAdvanced, ← mapNodeState_refreshRetirementState]
  rfl

@[simp]
theorem mapNodeState_becomeCandidateNodeState
    (f : TxId -> OtherTxId)
    (state : NodeState Node TxId)
    (node : Node) :
    mapNodeState f (becomeCandidateNodeState state node) =
      becomeCandidateNodeState (mapNodeState f state) node := by
  cases state
  simp [mapNodeState]

@[simp]
theorem mapState_becomeCandidateState
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (node : Node) :
    mapState f (becomeCandidateState state node) =
      becomeCandidateState (mapState f state) node := by
  simp only [becomeCandidateState, mapState, mapNodeStore_get]
  rw [mapNodeStore_updateNode, mapNodeState_becomeCandidateNodeState]

@[simp]
theorem mapState_stepDownState
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (node : Node) :
    mapState f (stepDownState state node) =
      stepDownState (mapState f state) node := by
  simp [stepDownState, mapState, mapNodeStore_updateNode, mapNodeState]

@[simp]
theorem mapState_advanceCommitState
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (node : Node) :
    mapState f (advanceCommitState state node) =
      advanceCommitState (mapState f state) node := by
  let advanced : NodeState Node TxId :=
    { state.nodes node with
      commitIndex := highestCommittableIndex state node }
  have mappedAdvanced :
      { (mapState f state).nodes node with
        commitIndex := highestCommittableIndex (mapState f state) node } =
        mapNodeState f advanced := by
    simp [advanced, mapNodeState]
  let refreshed := refreshRetirementState node advanced
  simp only [advanceCommitState]
  rw [mappedAdvanced]
  simp only [mapState, mapNodeStore_updateNode]
  rw [mapNodeState_refreshRetirementState]
  congr 1
  exact
    (refreshRetirementCompleted_mapNodeState
      f state.retirementCompleted node refreshed).symm

@[simp]
theorem mapState_demoteRetiredCommitted
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (node : Node) :
    mapState f (demoteRetiredCommitted state node) =
      demoteRetiredCommitted (mapState f state) node := by
  unfold demoteRetiredCommitted
  rw [mapState_nodes_get]
  simp only [mapNodeState_membershipState]
  split <;> simp

@[simp]
theorem mapMessage_source
    (f : TxId -> OtherTxId)
    (message : Message Node TxId) :
    (mapMessage f message).source = message.source := by
  cases message <;> rfl

@[simp]
theorem mapMessage_destination
    (f : TxId -> OtherTxId)
    (message : Message Node TxId) :
    (mapMessage f message).destination = message.destination := by
  cases message <;> rfl

@[simp]
theorem mapMessage_term
    (f : TxId -> OtherTxId)
    (message : Message Node TxId) :
    (mapMessage f message).term = message.term := by
  cases message <;> rfl

@[simp]
theorem takeFirstFrom_map
    [DecidableEq Node]
    (f : TxId -> OtherTxId)
    (source : Node)
    (messages : List (Message Node TxId)) :
    takeFirstFrom source (messages.map (mapMessage f)) =
      (takeFirstFrom source messages).map fun selected =>
        (mapMessage f selected.1, selected.2.map (mapMessage f)) := by
  induction messages with
  | nil => rfl
  | cons message messages inductionHypothesis =>
      simp only [List.map_cons, takeFirstFrom, mapMessage_source]
      split
      · rfl
      · rw [inductionHypothesis]
        cases takeFirstFrom source messages <;> rfl

@[simp]
theorem messageSourceAllowed_mapState
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (message : Message Node TxId) :
    messageSourceAllowed (mapState f state) (mapMessage f message) ↔
      messageSourceAllowed state message := by
  cases message <;>
    simp only [mapMessage, messageSourceAllowed, mapState_allocated]

@[simp]
theorem newerMessage?_mapState
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (source destination : Node) :
    newerMessage? (mapState f state) source destination =
      (newerMessage? state source destination).map (mapMessage f) := by
  unfold newerMessage?
  rw [show (mapState f state).network destination =
    (state.network destination).map (mapMessage f) by rfl]
  rw [takeFirstFrom_map]
  rw [mapState_nodes_get]
  generalize takeFirstFrom source (state.network destination) = selected
  cases selected with
  | none => rfl
  | some selected =>
      rcases selected with ⟨message, remaining⟩
      simp only [Option.map_some, Option.bind_some]
      have sameGuard :
          (messageSourceAllowed (mapState f state) (mapMessage f message) /\
              ((mapState f state).nodes destination).currentTerm <
                (mapMessage f message).term) ↔
            (messageSourceAllowed state message /\
              (state.nodes destination).currentTerm < message.term) := by
        simp
      by_cases guard :
          messageSourceAllowed state message /\
            (state.nodes destination).currentTerm < message.term
      · have mappedGuard := sameGuard.mpr guard
        simp [guard, mappedGuard]
      · have mappedGuard :
            ¬(messageSourceAllowed (mapState f state) (mapMessage f message) /\
              ((mapState f state).nodes destination).currentTerm <
                (mapMessage f message).term) :=
          fun mapped => guard (sameGuard.mp mapped)
        simp [guard, mappedGuard]

@[simp]
theorem candidateTransitionEnabled_mapState
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (node : Node) :
    candidateTransitionEnabled (mapState f state) node ↔
      candidateTransitionEnabled state node := by
  simp only [candidateTransitionEnabled, mapState_allocated,
    mapState_nodes_get, activeNodeUnion_mapNodeState,
    campaignEligible_mapNodeState, mapNodeState_role,
    mapNodeState_membershipState]
  rfl

@[simp]
theorem makeRequestVoteRequest_mapState
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (source destination : Node) :
    makeRequestVoteRequest (mapState f state) source destination =
      makeRequestVoteRequest state source destination := by
  simp [makeRequestVoteRequest]

@[simp]
theorem makeRequestPreVote_mapState
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (source destination : Node) :
    makeRequestPreVote (mapState f state) source destination =
      makeRequestPreVote state source destination := by
  simp [makeRequestPreVote]

@[simp]
theorem makeProposeVoteRequest_mapState
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (source destination : Node) :
    makeProposeVoteRequest (mapState f state) source destination =
      makeProposeVoteRequest state source destination := by
  simp [makeProposeVoteRequest]

@[simp]
theorem requestVoteRequest_mem_mapMessage
    [DecidableEq Node]
    (f : TxId -> OtherTxId)
    (request : RequestVoteRequest Node)
    (messages : List (Message Node TxId)) :
    (.requestVoteRequest request :
        Message Node OtherTxId) ∈ messages.map (mapMessage f) ↔
      (.requestVoteRequest request : Message Node TxId) ∈ messages := by
  induction messages with
  | nil => simp
  | cons message messages inductionHypothesis =>
      cases message <;> simp_all [mapMessage]

@[simp]
theorem requestPreVote_mem_mapMessage
    [DecidableEq Node]
    (f : TxId -> OtherTxId)
    (request : RequestPreVote Node)
    (messages : List (Message Node TxId)) :
    (.requestPreVote request :
        Message Node OtherTxId) ∈ messages.map (mapMessage f) ↔
      (.requestPreVote request : Message Node TxId) ∈ messages := by
  induction messages with
  | nil => simp
  | cons message messages inductionHypothesis =>
      cases message <;> simp_all [mapMessage]

@[simp]
theorem proposeVoteRequest_mem_mapMessage
    [DecidableEq Node]
    (f : TxId -> OtherTxId)
    (request : ProposeVoteRequest Node)
    (messages : List (Message Node TxId)) :
    (.proposeVoteRequest request :
        Message Node OtherTxId) ∈ messages.map (mapMessage f) ↔
      (.proposeVoteRequest request : Message Node TxId) ∈ messages := by
  induction messages with
  | nil => simp
  | cons message messages inductionHypothesis =>
      cases message <;> simp_all [mapMessage]

theorem enqueueNoDup_map_of_fixed
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (network : Node -> List (Message Node TxId))
    (message : Message Node TxId)
    (mappedMessage : Message Node OtherTxId)
    (mapped : mapMessage f message = mappedMessage)
    (membership :
      mappedMessage ∈
          (network message.destination).map (mapMessage f) ↔
        message ∈ network message.destination) :
    (fun node => (enqueueNoDup network message node).map (mapMessage f)) =
      enqueueNoDup
        (fun node => (network node).map (mapMessage f))
        mappedMessage := by
  unfold enqueueNoDup
  dsimp
  have destinationEq :
      mappedMessage.destination = message.destination := by
    rw [← mapped, mapMessage_destination]
  rw [destinationEq]
  by_cases present : message ∈ network message.destination
  · have mappedPresent := membership.mpr present
    simp [present, mappedPresent]
  · have mappedPresent :
        mappedMessage ∉
          (network message.destination).map (mapMessage f) :=
      fun found => present (membership.mp found)
    simp only [present, mappedPresent, if_false]
    funext node
    by_cases same : node = message.destination
    · subst node
      simp [updateQueue, mapped]
    · simp [updateQueue, same]

theorem mapState_advanceCommitIndex
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId) (node : Node) :
    mapState f (next state (.advanceCommitIndex node)) =
      next (mapState f state) (.advanceCommitIndex node) := by
  simp [next]

theorem enabled_mapState_advanceCommitIndex_iff
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId) (node : Node) :
    Enabled (mapState f state) (.advanceCommitIndex node) ↔
      Enabled state (.advanceCommitIndex node) := by
  simp only [Enabled, mapState_allocated, mapState_nodes_get,
    highestCommittableIndex_mapState, terminalRetirementCommit_mapState]
  rfl

theorem mapState_timeout
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId) (node : Node) :
    mapState f (next state (.timeout node)) =
      next (mapState f state) (.timeout node) := by
  simpa only [next] using mapState_becomeCandidateState f state node

theorem enabled_mapState_timeout_iff
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId) (node : Node) :
    Enabled (mapState f state) (.timeout node) ↔
      Enabled state (.timeout node) := by
  simp only [Enabled, mapState_allocated, mapState_nodes_get,
    activeNodeUnion_mapNodeState, campaignEligible_mapNodeState,
    mapNodeState_role, mapNodeState_membershipState]
  rfl

theorem mapState_becomePreVoteCandidate
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId) (node : Node) :
    mapState f (next state (.becomePreVoteCandidate node)) =
      next (mapState f state) (.becomePreVoteCandidate node) := by
  simp only [next, mapState, mapNodeStore_get]
  rw [mapNodeStore_updateNode]
  congr

theorem enabled_mapState_becomePreVoteCandidate_iff
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId) (node : Node) :
    Enabled (mapState f state) (.becomePreVoteCandidate node) ↔
      Enabled state (.becomePreVoteCandidate node) := by
  simp only [Enabled, mapState_allocated, mapState_nodes_get,
    activeNodeUnion_mapNodeState, campaignEligible_mapNodeState,
    mapNodeState_role, mapNodeState_membershipState]
  rfl

theorem mapState_becomeCandidate
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId) (node : Node) :
    mapState f (next state (.becomeCandidate node)) =
      next (mapState f state) (.becomeCandidate node) := by
  simpa only [next] using mapState_becomeCandidateState f state node

theorem enabled_mapState_becomeCandidate_iff
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId) (node : Node) :
    Enabled (mapState f state) (.becomeCandidate node) ↔
      Enabled state (.becomeCandidate node) := by
  simp only [Enabled, mapState_allocated, mapState_nodes_get,
    activeNodeUnion_mapNodeState, campaignEligible_mapNodeState,
    hasPreVoteMajority_mapState, mapNodeState_role,
    mapNodeState_membershipState]
  simp only [mapState]

theorem mapState_requestVote
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId)
    (source destination : Node) :
    mapState f (next state (.requestVote source destination)) =
      next (mapState f state) (.requestVote source destination) := by
  simp only [next]
  rw [makeRequestVoteRequest_mapState]
  simp only [mapState]
  congr 1
  apply enqueueNoDup_map_of_fixed f state.network
    (.requestVoteRequest (makeRequestVoteRequest state source destination))
    (.requestVoteRequest (makeRequestVoteRequest state source destination))
  · rfl
  · exact requestVoteRequest_mem_mapMessage f _ _

theorem enabled_mapState_requestVote_iff
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId)
    (source destination : Node) :
    Enabled (mapState f state) (.requestVote source destination) ↔
      Enabled state (.requestVote source destination) := by
  simp only [Enabled, mapState_allocated, mapState_nodes_get,
    mapNodeState_role, activeNodeUnion_mapNodeState]

theorem mapState_requestPreVote
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId)
    (source destination : Node) :
    mapState f (next state (.requestPreVote source destination)) =
      next (mapState f state) (.requestPreVote source destination) := by
  simp only [next]
  rw [makeRequestPreVote_mapState]
  simp only [mapState]
  congr 1
  apply enqueueNoDup_map_of_fixed f state.network
    (.requestPreVote (makeRequestPreVote state source destination))
    (.requestPreVote (makeRequestPreVote state source destination))
  · rfl
  · exact requestPreVote_mem_mapMessage f _ _

theorem enabled_mapState_requestPreVote_iff
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId)
    (source destination : Node) :
    Enabled (mapState f state) (.requestPreVote source destination) ↔
      Enabled state (.requestPreVote source destination) := by
  simp only [Enabled, mapState_allocated, mapState_nodes_get,
    mapNodeState_role, activeNodeUnion_mapNodeState]

theorem mapState_checkQuorum
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId) (node : Node) :
    mapState f (next state (.checkQuorum node)) =
      next (mapState f state) (.checkQuorum node) := by
  simp [next]

theorem enabled_mapState_checkQuorum_iff
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId) (node : Node) :
    Enabled (mapState f state) (.checkQuorum node) ↔
      Enabled state (.checkQuorum node) := by
  simp only [Enabled, mapState_allocated, mapState_nodes_get,
    mapNodeState_role, hasOtherActiveReplica_mapState]

theorem mapState_updateTerm
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId)
    (source destination : Node) :
    mapState f (next state (.updateTerm source destination)) =
      next (mapState f state) (.updateTerm source destination) := by
  simp only [next]
  rw [newerMessage?_mapState]
  cases selected : newerMessage? state source destination with
  | none => rfl
  | some message =>
      simp only [Option.map_some]
      simp only [mapState, mapNodeStore_get]
      rw [mapNodeStore_updateNode]
      congr
      cases state.nodes destination <;> cases message <;> rfl

theorem enabled_mapState_updateTerm_iff
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId)
    (source destination : Node) :
    Enabled (mapState f state) (.updateTerm source destination) ↔
      Enabled state (.updateTerm source destination) := by
  simp only [Enabled, mapState_allocated, newerMessage?_mapState]
  cases newerMessage? state source destination <;> rfl

@[simp]
theorem mapNodeState_becomeLeaderUpdate
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (node : Node)
    (state : NodeState Node TxId) :
    mapNodeState f
        (refreshRetirementState node
          { state with
            role := .leader
            log := state.log.take (maxCommittableIndex state.log)
            sentIndex := fun _ =>
              (state.log.take (maxCommittableIndex state.log)).length
            matchIndex := fun _ => 0 }) =
      refreshRetirementState node
        { mapNodeState f state with
          role := .leader
          log := (mapNodeState f state).log.take
            (maxCommittableIndex (mapNodeState f state).log)
          sentIndex := fun _ =>
            ((mapNodeState f state).log.take
              (maxCommittableIndex (mapNodeState f state).log)).length
          matchIndex := fun _ => 0 } := by
  rw [mapNodeState_refreshRetirementState]
  cases state
  simp [mapNodeState, List.map_take]

theorem mapState_becomeLeader
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId) (node : Node) :
    mapState f (next state (.becomeLeader node)) =
      next (mapState f state) (.becomeLeader node) := by
  simp only [next, mapState, mapNodeStore_get]
  congr 1
  · rw [mapNodeStore_updateNode, mapNodeState_becomeLeaderUpdate]
  · rw [← mapNodeState_becomeLeaderUpdate]
    exact
      (refreshRetirementCompleted_mapNodeState f
        state.retirementCompleted node
          (refreshRetirementState node
            { state.nodes node with
              role := .leader
              log := (state.nodes node).log.take
                (maxCommittableIndex (state.nodes node).log)
              sentIndex := fun _ =>
                ((state.nodes node).log.take
                  (maxCommittableIndex (state.nodes node).log)).length
              matchIndex := fun _ => 0 })).symm

@[simp]
theorem mapNodeState_truncateCommittableRefresh
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (node : Node)
    (state : NodeState Node TxId) :
    mapNodeState f
        (refreshRetirementState node
          { state with
            log := state.log.take (maxCommittableIndex state.log) }) =
      refreshRetirementState node
        { mapNodeState f state with
          log := (mapNodeState f state).log.take
            (maxCommittableIndex (mapNodeState f state).log) } := by
  rw [mapNodeState_refreshRetirementState]
  cases state
  simp [mapNodeState, List.map_take]

theorem enabled_mapState_becomeLeader_iff
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId) (node : Node) :
    Enabled (mapState f state) (.becomeLeader node) ↔
      Enabled state (.becomeLeader node) := by
  simp only [Enabled, mapState_allocated, mapState_nodes_get,
    mapNodeState_role, mapNodeState_membershipState,
    hasElectionMajority_mapState]
  have refreshed :=
    mapNodeState_truncateCommittableRefresh
      f node (state.nodes node)
  have membership :=
    congrArg NodeState.membershipState refreshed
  simp [mapNodeState] at membership
  simp only [mapNodeState]
  rw [maxCommittableIndex_map]
  rw [← membership]

@[simp]
theorem mapState_withNetwork
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (network : Node -> List (Message Node TxId)) :
    mapState f { state with network } =
      { mapState f state with
        network := fun node => (network node).map (mapMessage f) } := rfl

theorem mapState_withNetwork_of
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (mappedState : State Node OtherTxId)
    (network : Node -> List (Message Node TxId))
    (mappedNetwork : Node -> List (Message Node OtherTxId))
    (stateMapped : mapState f state = mappedState)
    (networkMapped :
      (fun node => (network node).map (mapMessage f)) = mappedNetwork) :
    mapState f { state with network } =
      { mappedState with network := mappedNetwork } := by
  subst mappedState
  subst mappedNetwork
  rfl

theorem mapState_proposeVote
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId)
    (source destination : Node) :
    mapState f (next state (.proposeVote source destination)) =
      next (mapState f state) (.proposeVote source destination) := by
  simp only [next]
  rw [makeProposeVoteRequest_mapState]
  simp only [mapState]
  congr 1
  apply enqueueNoDup_map_of_fixed f state.network
    (.proposeVoteRequest (makeProposeVoteRequest state source destination))
    (.proposeVoteRequest (makeProposeVoteRequest state source destination))
  · rfl
  · exact proposeVoteRequest_mem_mapMessage f _ _

theorem enabled_mapState_proposeVote_iff
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId)
    (source destination : Node) :
    Enabled (mapState f state) (.proposeVote source destination) ↔
      Enabled state (.proposeVote source destination) := by
  simp only [Enabled, mapState_allocated, mapState_nodes_get,
    mapNodeState_role, plausibleSuccessor_mapState]

theorem mapState_advanceCommitIndexAndProposeVote
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId)
    (source destination : Node) :
    mapState f
        (next state (.advanceCommitIndexAndProposeVote source destination)) =
      next (mapState f state)
        (.advanceCommitIndexAndProposeVote source destination) := by
  let advanced :=
    demoteRetiredCommitted (advanceCommitState state source) source
  have advancedCommutes :
      mapState f advanced =
        demoteRetiredCommitted
          (advanceCommitState (mapState f state) source) source := by
    simp [advanced]
  simp only [next]
  apply mapState_withNetwork_of f advanced
    (demoteRetiredCommitted
      (advanceCommitState (mapState f state) source) source)
  · exact advancedCommutes
  · rw [makeProposeVoteRequest_mapState]
    have networkMapped :=
      congrArg State.network advancedCommutes
    rw [← networkMapped]
    apply enqueueNoDup_map_of_fixed f advanced.network
      (.proposeVoteRequest (makeProposeVoteRequest state source destination))
      (.proposeVoteRequest (makeProposeVoteRequest state source destination))
    · rfl
    · exact proposeVoteRequest_mem_mapMessage f _ _

theorem enabled_mapState_advanceCommitIndexAndProposeVote_iff
    [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId) (state : State Node TxId)
    (source destination : Node) :
    Enabled (mapState f state)
        (.advanceCommitIndexAndProposeVote source destination) ↔
      Enabled state
        (.advanceCommitIndexAndProposeVote source destination) := by
  simp [Enabled, mapNodeState]

end CCFRaft.TransactionMapping
