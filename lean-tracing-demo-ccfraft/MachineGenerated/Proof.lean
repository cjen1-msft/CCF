-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.ReconfigurationPreservation

set_option autoImplicit false

/-!
# CCFRaft reachable safety API

This module keeps the public reachable-safety names stable while the
implementation proves the reconfiguring transition system.
-/

namespace CCFRaft

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId]
variable [Bootstrap Node]

abbrev ReachableSystemInductiveInvariant (state : State Node TxId) : Prop :=
  SystemInductiveInvariant state

theorem systemInductiveInvariantSafety
    {state : State Node TxId}
    (invariant : ReachableSystemInductiveInvariant state) :
    ConsensusSafety state :=
  ReconfigurationProof.systemInductiveInvariantSafety invariant.1

theorem systemInductiveInvariantLogMatching
    {state : State Node TxId}
    (invariant : ReachableSystemInductiveInvariant state) :
    LogMatching state :=
  ReconfigurationProof.systemInductiveInvariantLogMatching invariant.1

theorem systemInductiveInvariantMonoLog
    {state : State Node TxId}
    (invariant : ReachableSystemInductiveInvariant state) :
    MonoLog state :=
  ReconfigurationProof.systemInductiveInvariantMonoLog invariant.1

theorem systemInductiveInvariantLeaderCompleteness
    {state : State Node TxId}
    (invariant : ReachableSystemInductiveInvariant state) :
    LeaderCompleteness state :=
  ReconfigurationProof.systemInductiveInvariantLeaderCompleteness invariant.1

theorem systemInductiveInvariantCommittedFrontierIsSignature
    {state : State Node TxId}
    (invariant : ReachableSystemInductiveInvariant state) :
    CommittedFrontierIsSignature state :=
  ReconfigurationProof.systemInductiveInvariantCommittedFrontierIsSignature
    invariant.1

theorem initialSystemInductiveInvariant :
    ReachableSystemInductiveInvariant (initialState : State Node TxId) :=
  ReconfigurationProof.initialSystemInductiveInvariant

theorem clientRequestPreservesSystemInductiveInvariant
    (state : State Node TxId)
    (node : Node)
    (txId : TxId)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.clientRequest node txId)) :
    ReachableSystemInductiveInvariant
      (next state (.clientRequest node txId)) :=
  ReconfigurationProof.systemInductiveInvariantPreserved
    state (.clientRequest node txId) invariant enabled

theorem changeConfigurationPreservesSystemInductiveInvariant
    (state : State Node TxId)
    (source : Node)
    (newConfiguration : Finset Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled :
      Enabled state (.changeConfiguration source newConfiguration)) :
    ReachableSystemInductiveInvariant
      (next state (.changeConfiguration source newConfiguration)) :=
  ReconfigurationProof.systemInductiveInvariantPreserved
    state (.changeConfiguration source newConfiguration) invariant enabled

theorem appendRetiredCommittedPreservesSystemInductiveInvariant
    (state : State Node TxId)
    (node : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.appendRetiredCommitted node)) :
    ReachableSystemInductiveInvariant
      (next state (.appendRetiredCommitted node)) :=
  ReconfigurationProof.systemInductiveInvariantPreserved
    state (.appendRetiredCommitted node) invariant enabled

theorem signCommittableMessagesPreservesSystemInductiveInvariant
    (state : State Node TxId)
    (node : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.signCommittableMessages node)) :
    ReachableSystemInductiveInvariant
      (next state (.signCommittableMessages node)) :=
  ReconfigurationProof.systemInductiveInvariantPreserved
    state (.signCommittableMessages node) invariant enabled

theorem requestVotePreservesSystemInductiveInvariant
    (state : State Node TxId)
    (source destination : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.requestVote source destination)) :
    ReachableSystemInductiveInvariant
      (next state (.requestVote source destination)) :=
  ReconfigurationProof.systemInductiveInvariantPreserved
    state (.requestVote source destination) invariant enabled

theorem requestPreVotePreservesSystemInductiveInvariant
    (state : State Node TxId)
    (source destination : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.requestPreVote source destination)) :
    ReachableSystemInductiveInvariant
      (next state (.requestPreVote source destination)) :=
  ReconfigurationProof.systemInductiveInvariantPreserved
    state (.requestPreVote source destination) invariant enabled

theorem proposeVotePreservesSystemInductiveInvariant
    (state : State Node TxId)
    (source destination : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.proposeVote source destination)) :
    ReachableSystemInductiveInvariant
      (next state (.proposeVote source destination)) :=
  ReconfigurationProof.systemInductiveInvariantPreserved
    state (.proposeVote source destination) invariant enabled

theorem checkQuorumPreservesSystemInductiveInvariant
    (state : State Node TxId)
    (node : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.checkQuorum node)) :
    ReachableSystemInductiveInvariant
      (next state (.checkQuorum node)) :=
  ReconfigurationProof.systemInductiveInvariantPreserved
    state (.checkQuorum node) invariant enabled

theorem appendEntriesPreservesSystemInductiveInvariant
    (state : State Node TxId)
    (source destination : Node)
    (batchEnd : Nat)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.appendEntries source destination batchEnd)) :
    ReachableSystemInductiveInvariant
      (next state (.appendEntries source destination batchEnd)) :=
  ReconfigurationProof.systemInductiveInvariantPreserved
    state (.appendEntries source destination batchEnd) invariant enabled

theorem timeoutPreservesSystemInductiveInvariant
    (state : State Node TxId)
    (node : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.timeout node)) :
    ReachableSystemInductiveInvariant (next state (.timeout node)) :=
  ReconfigurationProof.systemInductiveInvariantPreserved
    state (.timeout node) invariant enabled

theorem becomePreVoteCandidatePreservesSystemInductiveInvariant
    (state : State Node TxId)
    (node : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.becomePreVoteCandidate node)) :
    ReachableSystemInductiveInvariant
      (next state (.becomePreVoteCandidate node)) :=
  ReconfigurationProof.systemInductiveInvariantPreserved
    state (.becomePreVoteCandidate node) invariant enabled

theorem becomeCandidatePreservesSystemInductiveInvariant
    (state : State Node TxId)
    (node : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.becomeCandidate node)) :
    ReachableSystemInductiveInvariant
      (next state (.becomeCandidate node)) :=
  ReconfigurationProof.systemInductiveInvariantPreserved
    state (.becomeCandidate node) invariant enabled

theorem updateTermPreservesSystemInductiveInvariant
    (state : State Node TxId)
    (source destination : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.updateTerm source destination)) :
    ReachableSystemInductiveInvariant
      (next state (.updateTerm source destination)) :=
  ReconfigurationProof.systemInductiveInvariantPreserved
    state (.updateTerm source destination) invariant enabled

theorem becomeLeaderPreservesSystemInductiveInvariant
    (state : State Node TxId)
    (node : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.becomeLeader node)) :
    ReachableSystemInductiveInvariant (next state (.becomeLeader node)) :=
  ReconfigurationProof.systemInductiveInvariantPreserved
    state (.becomeLeader node) invariant enabled

theorem advanceCommitPreservesSystemInductiveInvariant
    (state : State Node TxId)
    (node : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.advanceCommitIndex node)) :
    ReachableSystemInductiveInvariant
      (next state (.advanceCommitIndex node)) :=
  ReconfigurationProof.systemInductiveInvariantPreserved
    state (.advanceCommitIndex node) invariant enabled

theorem advanceCommitAndProposeVotePreservesSystemInductiveInvariant
    (state : State Node TxId)
    (source destination : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled :
      Enabled state (.advanceCommitIndexAndProposeVote source destination)) :
    ReachableSystemInductiveInvariant
      (next state (.advanceCommitIndexAndProposeVote source destination)) :=
  ReconfigurationProof.systemInductiveInvariantPreserved
    state (.advanceCommitIndexAndProposeVote source destination)
      invariant enabled

theorem receivePreservesSystemInductiveInvariant
    (state : State Node TxId)
    (source destination : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.receive source destination)) :
    ReachableSystemInductiveInvariant
      (next state (.receive source destination)) :=
  ReconfigurationProof.systemInductiveInvariantPreserved
    state (.receive source destination) invariant enabled

theorem systemInductiveInvariantPreserved
    (state : State Node TxId)
    (action : Action Node TxId)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state action) :
    ReachableSystemInductiveInvariant (next state action) :=
  ReconfigurationProof.systemInductiveInvariantPreserved
    state action invariant enabled

theorem reachableSystemInductiveInvariant
    {state : State Node TxId}
    (reachable : Reachable state) :
    SystemInductiveInvariant state :=
  ReconfigurationProof.reachableSystemInductiveInvariant reachable

theorem reachableCommittedLogsPrefix
    {state : State Node TxId}
    (reachable : Reachable state) :
    CommittedLogsPrefix state :=
  ReconfigurationProof.reachableCommittedLogsPrefix reachable

theorem reachableCommittedFrontierIsSignature
    {state : State Node TxId}
    (reachable : Reachable state) :
    CommittedFrontierIsSignature state :=
  ReconfigurationProof.reachableCommittedFrontierIsSignature reachable

theorem reachableLogMatching
    {state : State Node TxId}
    (reachable : Reachable state) :
    LogMatching state :=
  ReconfigurationProof.reachableLogMatching reachable

theorem reachableMonoLog
    {state : State Node TxId}
    (reachable : Reachable state) :
    MonoLog state :=
  ReconfigurationProof.reachableMonoLog reachable

theorem reachableElectionSafety
    {state : State Node TxId}
    (reachable : Reachable state) :
    ElectionSafety state :=
  ReconfigurationProof.reachableElectionSafety reachable

theorem reachableLeaderCompleteness
    {state : State Node TxId}
    (reachable : Reachable state) :
    LeaderCompleteness state :=
  ReconfigurationProof.reachableLeaderCompleteness reachable

theorem reachableConsensusSafety
    {state : State Node TxId}
    (reachable : Reachable state) :
    ConsensusSafety state :=
  ReconfigurationProof.reachableConsensusSafety reachable

end CCFRaft
