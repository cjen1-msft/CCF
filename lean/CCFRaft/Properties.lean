import CCFRaft.Model

/-!
# Proof-only CCFRaft state

This file contains named proof packages. None of these records participates in
`Model.Action`, `Model.Enabled`, `Model.next`, or executable replay.
-/

set_option autoImplicit false

namespace CCFRaft.Properties

open Model

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

/-- Shared monotonic before/after facts produced once for each action. -/
structure MonotonicDelta
    (before : State)
    (action : Action)
    (after : State) :
    Prop where
  terms : TermDelta before after
  commits : CommitIndexDelta before after
  matchIndices : MatchIndexDelta before action after

/--
Successful AppendEntries responses that can update a same-term leader are
bounded by the responder's current log. The forged-ACK fixture in
`Simulation.lean` shows why the inductive proof needs this candidate fact.
-/
def AppendEntriesResponseBoundInv (state : State) : Prop :=
  forall dest source : Node,
    forall message,
      message ∈ state.messages dest source ->
        state.leadershipState dest = .leader ->
          message.term = state.currentTerm dest ->
            state.currentTerm dest = state.currentTerm source ->
              match message.body with
              | .appendEntriesResponse true lastLogIndex =>
                  lastLogIndex <= (state.log source).length
              | _ => True

def increasingConfigurationIndices : List ConfigurationAt -> Prop
  | [] => True
  | [_] => True
  | first :: second :: rest =>
      And
        (first.index < second.index)
        (increasingConfigurationIndices (second :: rest))

/-- Representation invariant for the ordered finite-map projection. -/
def ConfigurationsWellFormedInv (state : State) : Prop :=
  forall node : Node,
    And
      (increasingConfigurationIndices (state.configurations node))
      (forall configuration,
        configuration ∈ state.configurations node ->
          And
            (0 < configuration.index)
            (configuration.index <= (state.log node).length))

/-- Well-formedness of the per-pair `OrderedNoDup` queue representation. -/
def MessageChannelsWellFormed
    (messages : NodeMatrix (List Message)) :
    Prop :=
  forall dest source : Node,
    forall message,
      message ∈ messages dest source ->
        And
          (message.dest = dest)
          (message.source = source)

/-- Representation invariant for the per-pair `OrderedNoDup` projection. -/
def MessagesWellFormedInv (state : State) : Prop :=
  MessageChannelsWellFormed state.messages

/-- The proof-only invariant carried through reachable states. -/
structure InductiveInvariant (state : State) : Prop where
  safety : StateSafety state
  responseBounds : AppendEntriesResponseBoundInv state
  configurationsWellFormed : ConfigurationsWellFormedInv state
  messagesWellFormed : MessagesWellFormedInv state

/-- Exact remaining preservation statement for the full selected action set. -/
def FullInductivenessObligation : Prop :=
  forall state action,
    InductiveInvariant state ->
      Enabled state action ->
        InductiveInvariant (next state action)

/-- Missing initialization proof for the full inductive bundle. -/
def InitialInductiveInvariantObligation : Prop :=
  forall start : Node,
    InductiveInvariant (initialState start)

/-- Missing one-step proofs for the temporal safety properties. -/
def TransitionSafetyObligation : Prop :=
  forall state action,
    InductiveInvariant state ->
      Enabled state action ->
        TransitionSafety state action (next state action)

/-- The three remaining obligations needed for the requested final theorem. -/
def FullSafetyCompletionObligation : Prop :=
  And
    InitialInductiveInvariantObligation
    (And
      FullInductivenessObligation
      TransitionSafetyObligation)

end CCFRaft.Properties
