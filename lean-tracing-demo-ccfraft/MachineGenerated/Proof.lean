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
  ReconfigurationProof.systemInductiveInvariantSafety invariant

theorem systemInductiveInvariantLogMatching
    {state : State Node TxId}
    (invariant : ReachableSystemInductiveInvariant state) :
    LogMatching state :=
  ReconfigurationProof.systemInductiveInvariantLogMatching invariant

theorem systemInductiveInvariantMonoLog
    {state : State Node TxId}
    (invariant : ReachableSystemInductiveInvariant state) :
    MonoLog state :=
  ReconfigurationProof.systemInductiveInvariantMonoLog invariant

theorem systemInductiveInvariantLeaderCompleteness
    {state : State Node TxId}
    (invariant : ReachableSystemInductiveInvariant state) :
    LeaderCompleteness state :=
  ReconfigurationProof.systemInductiveInvariantLeaderCompleteness invariant

theorem systemInductiveInvariantCommittedFrontierIsSignature
    {state : State Node TxId}
    (invariant : ReachableSystemInductiveInvariant state) :
    CommittedFrontierIsSignature state :=
  ReconfigurationProof.systemInductiveInvariantCommittedFrontierIsSignature
    invariant

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
  ReconfigurationProof.clientRequestPreservesSystemInductiveInvariant
    state node txId invariant enabled

theorem changeConfigurationPreservesSystemInductiveInvariant
    (state : State Node TxId)
    (source : Node)
    (newConfiguration : Finset Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled :
      Enabled state (.changeConfiguration source newConfiguration)) :
    ReachableSystemInductiveInvariant
      (next state (.changeConfiguration source newConfiguration)) :=
  ReconfigurationProof.changeConfigurationPreservesSystemInductiveInvariant
    state source newConfiguration invariant enabled

theorem signCommittableMessagesPreservesSystemInductiveInvariant
    (state : State Node TxId)
    (node : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.signCommittableMessages node)) :
    ReachableSystemInductiveInvariant
      (next state (.signCommittableMessages node)) :=
  ReconfigurationProof.signCommittableMessagesPreservesSystemInductiveInvariant
    state node invariant enabled

theorem requestVotePreservesSystemInductiveInvariant
    (state : State Node TxId)
    (source destination : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.requestVote source destination)) :
    ReachableSystemInductiveInvariant
      (next state (.requestVote source destination)) :=
  ReconfigurationProof.requestVotePreservesSystemInductiveInvariant
    state source destination invariant enabled

theorem appendEntriesPreservesSystemInductiveInvariant
    (state : State Node TxId)
    (source destination : Node)
    (batchEnd : Nat)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.appendEntries source destination batchEnd)) :
    ReachableSystemInductiveInvariant
      (next state (.appendEntries source destination batchEnd)) :=
  ReconfigurationProof.appendEntriesPreservesSystemInductiveInvariant
    state source destination batchEnd invariant enabled

theorem timeoutPreservesSystemInductiveInvariant
    (state : State Node TxId)
    (node : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.timeout node)) :
    ReachableSystemInductiveInvariant (next state (.timeout node)) :=
  ReconfigurationProof.timeoutPreservesSystemInductiveInvariant
    state node invariant enabled

theorem updateTermPreservesSystemInductiveInvariant
    (state : State Node TxId)
    (source destination : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.updateTerm source destination)) :
    ReachableSystemInductiveInvariant
      (next state (.updateTerm source destination)) :=
  ReconfigurationProof.updateTermPreservesSystemInductiveInvariant
    state source destination invariant enabled

theorem becomeLeaderPreservesSystemInductiveInvariant
    (state : State Node TxId)
    (node : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.becomeLeader node)) :
    ReachableSystemInductiveInvariant (next state (.becomeLeader node)) :=
  ReconfigurationProof.becomeLeaderPreservesSystemInductiveInvariant
    state node invariant enabled

theorem advanceCommitPreservesSystemInductiveInvariant
    (state : State Node TxId)
    (node : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.advanceCommitIndex node)) :
    ReachableSystemInductiveInvariant
      (next state (.advanceCommitIndex node)) :=
  ReconfigurationProof.advanceCommitPreservesSystemInductiveInvariant
    state node invariant enabled

theorem receivePreservesSystemInductiveInvariant
    (state : State Node TxId)
    (source destination : Node)
    (invariant : ReachableSystemInductiveInvariant state)
    (enabled : Enabled state (.receive source destination)) :
    ReachableSystemInductiveInvariant
      (next state (.receive source destination)) :=
  ReconfigurationProof.receivePreservesSystemInductiveInvariant
    state source destination invariant enabled

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
