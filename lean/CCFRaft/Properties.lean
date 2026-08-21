import CCFRaft.Model

/-!
# Proof-only CCFRaft state

This file contains named proof packages. None of these records participates in
`Model.Action`, `Model.Enabled`, `Model.next`, or executable replay.
-/

set_option autoImplicit false

namespace CCFRaft.Properties

open Model

/-- Causal evidence for one counted vote. -/
structure VoteEvidence where
  term : Nat
  candidate : Node
  voter : Node
  voterCommittableLog : List Entry

/-- Causal evidence for one committed prefix and the quorum that replicated it. -/
structure CommitEvidence where
  term : Nat
  index : Nat
  configuration : Configuration
  quorum : Configuration
  committedLog : List Entry

/-- Proof-only histories used by the inductive invariant. -/
structure GhostState where
  votes : List VoteEvidence
  commits : List CommitEvidence

/-- Public and supporting state invariants, grouped by responsibility. -/
structure StateSafety (state : State) : Prop where
  logSafety : LogInv state
  oneLeaderPerTerm : MoreThanOneLeaderInv state
  candidateFreshTerm : CandidateTermNotInLogInv state
  electionSafety : ElectionSafetyInv state
  logMatching : LogMatchingInv state
  quorumLog : QuorumLogInv state
  leaderCompleteness : LeaderCompletenessInv state
  signatures : SignatureInv state
  messageTerms : MonoTermInv state
  monotonicLogs : MonoLogInv state
  configurations : LogConfigurationConsistentInv state
  replication : ReplicationInv state
  boundedMatchIndex : MatchIndexBoundedByLogInv state

/-- Required one-step temporal properties. -/
structure TransitionSafety
    (before : State)
    (action : Action)
    (after : State) :
    Prop where
  committedAppendOnly : CommittedLogAppendOnlyProp before after
  commitIndexMonotonic : MonotonicCommitIndexProp before after
  termMonotonic : MonotonicTermProp before after
  matchIndexMonotonic :
    MonotonicMatchIndexProp before action after
  commitsCurrentTerm :
    NeverCommitEntryPrevTermsProp before after

/-- Reusable before/after delta for actions that may update current terms. -/
structure TermDelta (before after : State) : Prop where
  monotonic : MonotonicTermProp before after

/-- Reusable before/after delta for actions that may update commit indices. -/
structure CommitIndexDelta (before after : State) : Prop where
  monotonic : MonotonicCommitIndexProp before after

/-- Reusable before/after delta for volatile match indices. -/
structure MatchIndexDelta
    (before : State)
    (action : Action)
    (after : State) :
    Prop where
  monotonic : MonotonicMatchIndexProp before action after

/-- The proof-only invariant carried through reachable states. -/
structure InductiveInvariant (state : State) : Prop where
  ghost : Nonempty GhostState
  safety : StateSafety state

/-- Exact remaining preservation statement for the full selected action set. -/
def FullInductivenessObligation : Prop :=
  forall state action,
    InductiveInvariant state ->
      Enabled state action ->
        InductiveInvariant (next state action)

end CCFRaft.Properties
