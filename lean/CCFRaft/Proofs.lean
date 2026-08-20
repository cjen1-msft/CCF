-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.FixedMembershipPreservation

set_option autoImplicit false

/-!
# CCFRaft component invariant API

The fixed-membership preservation proof is isolated behind the checked
equivalence between its positional witnesses and the named component
invariant. New invariant components preserve themselves alongside this base.
-/

namespace CCFRaft

variable {TxId : Type}
variable [DecidableEq TxId]

/-! ## Component invariant API -/

/-- Convert a canonical component invariant to the fixed-membership proof package. -/
theorem systemInductiveInvariantToFixedMembership
    {state : State TxId}
    (invariant : SystemInductiveInvariant state) :
    FixedMembershipSystemInductiveInvariant state :=
  (fixedMembershipSystemInductiveInvariant_iff_system state).mpr invariant

/-- Convert the checked fixed-membership proof package to the canonical invariant. -/
theorem fixedMembershipSystemInductiveInvariantToSystem
    {state : State TxId}
    (invariant : FixedMembershipSystemInductiveInvariant state) :
    SystemInductiveInvariant state :=
  (fixedMembershipSystemInductiveInvariant_iff_system state).mp invariant

/-- Lift one fixed-membership preservation theorem through the fixed-witness equivalence. -/
theorem liftFixedMembershipPreservation
    {before after : State TxId}
    (preserved :
      FixedMembershipSystemInductiveInvariant before ->
        FixedMembershipSystemInductiveInvariant after)
    (invariant : SystemInductiveInvariant before) :
    SystemInductiveInvariant after :=
  fixedMembershipSystemInductiveInvariantToSystem
    (preserved (systemInductiveInvariantToFixedMembership invariant))

/-- The named invariant implies the core public safety properties. -/
theorem systemInductiveInvariantSafety
    {state : State TxId}
    (invariant : SystemInductiveInvariant state) :
    ConsensusSafety state :=
  fixedMembershipSystemInductiveInvariantSafety
    (systemInductiveInvariantToFixedMembership invariant)

/-- The named invariant derives log matching through canonical histories. -/
theorem systemInductiveInvariantLogMatching
    {state : State TxId}
    (invariant : SystemInductiveInvariant state) :
    LogMatching state :=
  fixedMembershipSystemInductiveInvariantLogMatching
    (systemInductiveInvariantToFixedMembership invariant)

/-- The named invariant derives monotone log terms. -/
theorem systemInductiveInvariantMonoLog
    {state : State TxId}
    (invariant : SystemInductiveInvariant state) :
    MonoLog state :=
  fixedMembershipSystemInductiveInvariantMonoLog
    (systemInductiveInvariantToFixedMembership invariant)

/-- The named invariant derives state-local leader completeness. -/
theorem systemInductiveInvariantLeaderCompleteness
    {state : State TxId}
    (invariant : SystemInductiveInvariant state) :
    LeaderCompleteness state :=
  fixedMembershipSystemInductiveInvariantLeaderCompleteness
    (systemInductiveInvariantToFixedMembership invariant)

/-- Every positive committed frontier in the named invariant is a signature. -/
theorem systemInductiveInvariantCommittedFrontierIsSignature
    {state : State TxId}
    (invariant : SystemInductiveInvariant state) :
    CommittedFrontierIsSignature state :=
  fixedMembershipSystemInductiveInvariantCommittedFrontierIsSignature
    (systemInductiveInvariantToFixedMembership invariant)

/-- The deterministic initial state satisfies the named invariant. -/
theorem initialSystemInductiveInvariant :
    SystemInductiveInvariant (initialState : State TxId) :=
  fixedMembershipSystemInductiveInvariantToSystem
    fixedMembershipInitialSystemInductiveInvariant

/-- A client append preserves the named invariant. -/
theorem clientRequestPreservesSystemInductiveInvariant
    (state : State TxId)
    (node : Node)
    (txId : TxId)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state (.clientRequest node txId)) :
    SystemInductiveInvariant (next state (.clientRequest node txId)) :=
  liftFixedMembershipPreservation
    (fun fixedMembership =>
      fixedMembershipClientRequestPreservesSystemInductiveInvariant
        state node txId fixedMembership enabled)
    invariant

/-- A signature append preserves the named invariant. -/
theorem signCommittableMessagesPreservesSystemInductiveInvariant
    (state : State TxId)
    (node : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state (.signCommittableMessages node)) :
    SystemInductiveInvariant
      (next state (.signCommittableMessages node)) :=
  liftFixedMembershipPreservation
    (fun fixedMembership =>
      fixedMembershipSignCommittableMessagesPreservesSystemInductiveInvariant
        state node fixedMembership enabled)
    invariant

/-- Sending RequestVote preserves the named invariant. -/
theorem requestVotePreservesSystemInductiveInvariant
    (state : State TxId)
    (source destination : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state (.requestVote source destination)) :
    SystemInductiveInvariant
      (next state (.requestVote source destination)) :=
  liftFixedMembershipPreservation
    (fun fixedMembership =>
      fixedMembershipRequestVotePreservesSystemInductiveInvariant
        state source destination fixedMembership enabled)
    invariant

/-- Sending AppendEntries preserves the named invariant. -/
theorem appendEntriesPreservesSystemInductiveInvariant
    (state : State TxId)
    (source destination : Node)
    (batchEnd : Nat)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state (.appendEntries source destination batchEnd)) :
    SystemInductiveInvariant
      (next state (.appendEntries source destination batchEnd)) :=
  liftFixedMembershipPreservation
    (fun fixedMembership =>
      fixedMembershipAppendEntriesPreservesSystemInductiveInvariant
        state source destination batchEnd fixedMembership enabled)
    invariant

/-- Starting a new election preserves the named invariant. -/
theorem timeoutPreservesSystemInductiveInvariant
    (state : State TxId)
    (node : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state (.timeout node)) :
    SystemInductiveInvariant (next state (.timeout node)) :=
  liftFixedMembershipPreservation
    (fun fixedMembership =>
      fixedMembershipTimeoutPreservesSystemInductiveInvariant
        state node fixedMembership enabled)
    invariant

/-- Learning a newer term preserves the named invariant. -/
theorem updateTermPreservesSystemInductiveInvariant
    (state : State TxId)
    (source destination : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state (.updateTerm source destination)) :
    SystemInductiveInvariant
      (next state (.updateTerm source destination)) :=
  liftFixedMembershipPreservation
    (fun fixedMembership =>
      fixedMembershipUpdateTermPreservesSystemInductiveInvariant
        state source destination fixedMembership enabled)
    invariant

/-- Leader promotion preserves the named invariant. -/
theorem becomeLeaderPreservesSystemInductiveInvariant
    (state : State TxId)
    (node : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state (.becomeLeader node)) :
    SystemInductiveInvariant (next state (.becomeLeader node)) :=
  liftFixedMembershipPreservation
    (fun fixedMembership =>
      fixedMembershipBecomeLeaderPreservesSystemInductiveInvariant
        state node fixedMembership enabled)
    invariant

/-- Commit advancement preserves the named invariant. -/
theorem advanceCommitPreservesSystemInductiveInvariant
    (state : State TxId)
    (node : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state (.advanceCommitIndex node)) :
    SystemInductiveInvariant
      (next state (.advanceCommitIndex node)) :=
  liftFixedMembershipPreservation
    (fun fixedMembership =>
      fixedMembershipAdvanceCommitPreservesSystemInductiveInvariant
        state node fixedMembership enabled)
    invariant

/-- Processing one queued message preserves the named invariant. -/
theorem receivePreservesSystemInductiveInvariant
    (state : State TxId)
    (source destination : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state (.receive source destination)) :
    SystemInductiveInvariant
      (next state (.receive source destination)) :=
  liftFixedMembershipPreservation
    (fun fixedMembership =>
      fixedMembershipReceivePreservesSystemInductiveInvariant
        state source destination fixedMembership enabled)
    invariant

/-- Every enabled action preserves the named component invariant. -/
theorem systemInductiveInvariantPreserved
    (state : State TxId)
    (action : Action TxId)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state action) :
    SystemInductiveInvariant (next state action) := by
  cases action with
  | clientRequest node txId =>
      exact
        clientRequestPreservesSystemInductiveInvariant
          state node txId invariant enabled
  | signCommittableMessages node =>
      exact
        signCommittableMessagesPreservesSystemInductiveInvariant
          state node invariant enabled
  | appendEntries source destination batchEnd =>
      exact
        appendEntriesPreservesSystemInductiveInvariant
          state source destination batchEnd invariant enabled
  | receive source destination =>
      exact
        receivePreservesSystemInductiveInvariant
          state source destination invariant enabled
  | advanceCommitIndex node =>
      exact
        advanceCommitPreservesSystemInductiveInvariant
          state node invariant enabled
  | timeout node =>
      exact
        timeoutPreservesSystemInductiveInvariant
          state node invariant enabled
  | requestVote source destination =>
      exact
        requestVotePreservesSystemInductiveInvariant
          state source destination invariant enabled
  | updateTerm source destination =>
      exact
        updateTermPreservesSystemInductiveInvariant
          state source destination invariant enabled
  | becomeLeader node =>
      exact
        becomeLeaderPreservesSystemInductiveInvariant
          state node invariant enabled

/-! ## Reachable component safety exports -/

/-- The named component invariant holds in every reachable state. -/
theorem reachableSystemInductiveInvariant
    {state : State TxId}
    (reachable : Reachable state) :
    SystemInductiveInvariant state :=
  ExecutableTransitionSystem.reachableInvariant
    (system (TxId := TxId))
    initialSystemInductiveInvariant
    systemInductiveInvariantPreserved
    reachable

/-- Reachable committed logs are pairwise prefix-comparable. -/
theorem reachableCommittedLogsPrefix
    {state : State TxId}
    (reachable : Reachable state) :
    CommittedLogsPrefix state :=
  (systemInductiveInvariantSafety
    (reachableSystemInductiveInvariant reachable)).committedLogsPrefix

/-- Every positive reachable commit frontier is a signature. -/
theorem reachableCommittedFrontierIsSignature
    {state : State TxId}
    (reachable : Reachable state) :
    CommittedFrontierIsSignature state :=
  systemInductiveInvariantCommittedFrontierIsSignature
    (reachableSystemInductiveInvariant reachable)

/-- Every reachable state satisfies log matching. -/
theorem reachableLogMatching
    {state : State TxId}
    (reachable : Reachable state) :
    LogMatching state :=
  systemInductiveInvariantLogMatching
    (reachableSystemInductiveInvariant reachable)

/-- Entry terms are monotone in every reachable log. -/
theorem reachableMonoLog
    {state : State TxId}
    (reachable : Reachable state) :
    MonoLog state :=
  systemInductiveInvariantMonoLog
    (reachableSystemInductiveInvariant reachable)

/-- Every reachable state has at most one leader per term. -/
theorem reachableElectionSafety
    {state : State TxId}
    (reachable : Reachable state) :
    ElectionSafety state :=
  (systemInductiveInvariantSafety
    (reachableSystemInductiveInvariant reachable)).electionSafety

/-- Higher-term reachable leaders contain lower-term committed logs. -/
theorem reachableLeaderCompleteness
    {state : State TxId}
    (reachable : Reachable state) :
    LeaderCompleteness state :=
  systemInductiveInvariantLeaderCompleteness
    (reachableSystemInductiveInvariant reachable)

/-- Bundle the core reachable consensus-safety properties. -/
theorem reachableConsensusSafety
    {state : State TxId}
    (reachable : Reachable state) :
    ConsensusSafety state :=
  systemInductiveInvariantSafety
    (reachableSystemInductiveInvariant reachable)

end CCFRaft
