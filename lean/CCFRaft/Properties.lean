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

def increasingConfigurationIndices
    (configurations : List ConfigurationAt) :
    Prop :=
  configurations.Pairwise fun first second =>
    first.index < second.index

def configurationsBoundedBy
    (configurations : List ConfigurationAt)
    (logLength : Nat) :
    Prop :=
  forall configuration,
    configuration ∈ configurations ->
      And
        (0 < configuration.index)
        (configuration.index <= logLength)

/-- Representation invariant for the ordered finite-map projection. -/
def ConfigurationsWellFormedInv (state : State) : Prop :=
  forall node : Node,
    And
      (increasingConfigurationIndices (state.configurations node))
      (configurationsBoundedBy
        (state.configurations node)
        (state.log node).length)

def logConfigurations (entries : List Entry) : List ConfigurationAt :=
  configurationsInEntries 1 entries

def activeLogConfigurations
    (entries : List Entry)
    (commitIndex : Nat) :
    List ConfigurationAt :=
  let configurations := logConfigurations entries
  configurationsFromIndex
    configurations
    (lastConfigurationToIndex configurations commitIndex)

def ConfigurationsExactInv (state : State) : Prop :=
  forall node : Node,
    state.configurations node =
      activeLogConfigurations (state.log node) (state.commitIndex node)

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

def NoLeaderBeforeInitialTermInv (state : State) : Prop :=
  forall node : Node,
    state.currentTerm node < startTerm ->
      state.leadershipState node != .leader

def ActiveRoleTermInv (state : State) : Prop :=
  forall node : Node,
    state.leadershipState node != .none ->
      startTerm <= state.currentTerm node

def MessageTermAtLeastStartInv (state : State) : Prop :=
  forall dest source : Node,
    forall message,
      message ∈ state.messages dest source ->
        startTerm <= message.term

def MessageEntriesAtLeastStart (message : Message) : Prop :=
  match message.body with
  | .appendEntriesRequest _ _ entries _ =>
      forall entry,
        entry ∈ entries ->
          startTerm <= entry.term
  | _ => True

def MessageEntriesAtLeastStartInv (state : State) : Prop :=
  forall dest source : Node,
    forall message,
      message ∈ state.messages dest source ->
        MessageEntriesAtLeastStart message

def MessageEntriesAtMostMessageTerm (message : Message) : Prop :=
  match message.body with
  | .appendEntriesRequest _ _ entries _ =>
      forall entry,
        entry ∈ entries ->
          entry.term <= message.term
  | _ => True

def AppendEntriesPayloadTermInv (state : State) : Prop :=
  forall dest source : Node,
    forall message,
      message ∈ state.messages dest source ->
        MessageEntriesAtMostMessageTerm message

def LogTermsAtLeastStartInv (state : State) : Prop :=
  forall node : Node,
    forall entry,
      entry ∈ state.log node ->
        startTerm <= entry.term

structure MinimumTermInv (state : State) : Prop where
  activeRoles : ActiveRoleTermInv state
  messages : MessageTermAtLeastStartInv state
  messageEntries : MessageEntriesAtLeastStartInv state
  logs : LogTermsAtLeastStartInv state

def LeaderLogBoundaryInv (state : State) : Prop :=
  forall node : Node,
    state.leadershipState node = .leader ->
      forall lastEntry,
        (state.log node).getLast? = some lastEntry ->
          Or
            (lastEntry.term = state.currentTerm node)
            (lastEntry.content = .signature)

def NodeMonoLogInv (state : State) (node : Node) : Prop :=
  state.log node != [] ->
    And
      (((state.log node).getLast?.map (·.term)).getD 0 <=
        state.currentTerm node)
      (monoLogEntries (state.log node))

def AppendEntriesLogSafetyInv (state : State) : Prop :=
  forall dest source : Node,
    forall message,
      message ∈ state.messages dest source ->
        match message.body with
        | .appendEntriesRequest previousIndex previousTerm entries
            leaderCommitIndex =>
            And
              (appendEntriesAcceptBase
                    state message.dest message.term previousIndex previousTerm =
                  true ->
                appendEntriesNoConflictGuard
                    state message.dest previousIndex entries =
                  true ->
                  NodeMonoLogInv
                    (nextAppendEntriesNoConflict
                      state message previousIndex entries leaderCommitIndex)
                    message.dest)
              (appendEntriesAcceptBase
                    state message.dest message.term previousIndex previousTerm =
                  true ->
                appendEntriesConflictGuard
                    state message.dest previousIndex entries =
                  true ->
                appendEntriesNoConflictGuard
                    (conflictRollback state message.dest previousIndex)
                    message.dest previousIndex entries =
                  true ->
                  NodeMonoLogInv
                    (nextAppendEntriesNoConflict
                      (conflictRollback state message.dest previousIndex)
                      message previousIndex entries leaderCommitIndex)
                    message.dest)
        | _ => True

/-- The proof-only invariant carried through reachable states. -/
structure InductiveInvariant (state : State) : Prop where
  safety : StateSafety state
  responseBounds : AppendEntriesResponseBoundInv state
  configurationsWellFormed : ConfigurationsWellFormedInv state
  configurationsExact : ConfigurationsExactInv state
  messagesWellFormed : MessagesWellFormedInv state
  minimumTerms : MinimumTermInv state
  leaderLogBoundary : LeaderLogBoundaryInv state
  appendEntriesLogSafety : AppendEntriesLogSafetyInv state

/--
The original state-only preservation attempt. This is intentionally not part
of the completion obligation: candidate and message provenance are historical.
-/
def StateOnlyInductivenessAttempt : Prop :=
  forall state action,
    InductiveInvariant state ->
      Enabled state action ->
        InductiveInvariant (next state action)

/-- Replay an explicit action list through the authoritative semantics. -/
def Replays : State -> List Action -> State -> Prop
  | before, [], after =>
      after = before
  | before, action :: actions, after =>
      And
        (Enabled before action)
        (Replays (next before action) actions after)

/-- Exact proof-only action history from a selected initial leader. -/
def ProtocolHistory
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  Replays (initialState start) actions state

structure HistoricalState (state : State) where
  start : InitialConfiguration
  actions : List Action
  history : ProtocolHistory start actions state

structure StateAtWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState state : State) where
  pastActions : List Action
  futureActions : List Action
  actions_eq : actions = pastActions ++ futureActions
  stateHistory : ProtocolHistory start pastActions state
  remainingHistory : Replays state futureActions endState

def StateAt
    (start : InitialConfiguration)
    (actions : List Action)
    (endState state : State) :
    Prop :=
  Nonempty (StateAtWitness start actions endState state)

structure OccurrenceWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState before : State)
    (action : Action) where
  pastActions : List Action
  futureActions : List Action
  actions_eq : actions = pastActions ++ [action] ++ futureActions
  before_history : ProtocolHistory start pastActions before
  enabled : Enabled before action
  after_history : Replays (next before action) futureActions endState

def Occurs
    (start : InitialConfiguration)
    (actions : List Action)
    (endState before : State)
    (action : Action) :
    Prop :=
  Nonempty
    (OccurrenceWitness start actions endState before action)

structure MessageEnqueueWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (dest source : Node)
    (message : Message) where
  before : State
  action : Action
  occurrence :
    Occurs start actions endState before action
  absentBefore :
    message ∉ before.messages dest source
  presentAfter :
    message ∈ (next before action).messages dest source

def MessageHasEnqueueWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (dest source : Node)
    (message : Message) :
    Prop :=
  Nonempty
    (MessageEnqueueWitness
      start actions endState dest source message)

def QueueHistoryConsistent
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall dest source : Node,
    forall message,
      message ∈ state.messages dest source ->
        MessageHasEnqueueWitness
          start actions state dest source message

structure AESendWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (dest source : Node)
    (message : Message) where
  sendState : State
  occurrence :
    Occurs
      start actions endState sendState
      (.appendEntries source dest)
  message_eq :
    message = appendEntriesMessage sendState source dest

def MessageHasAESendWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (dest source : Node)
    (message : Message) :
    Prop :=
  Nonempty
    (AESendWitness
      start actions endState dest source message)

def AppendEntriesRequestHistoryConsistent
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall dest source : Node,
    forall message,
      message ∈ state.messages dest source ->
        match message.body with
        | .appendEntriesRequest _ _ _ _ =>
            MessageHasAESendWitness
              start actions state dest source message
        | _ => True

inductive AEResponseKind where
  | reject
  | alreadyDone
  | noConflict
  | conflictThenAlreadyDone
  | conflictThenNoConflict
  deriving DecidableEq

def AEResponseKind.receiveKind : AEResponseKind -> ReceiveKind
  | .reject => .rejectAppendEntriesRequest
  | .alreadyDone => .appendEntriesAlreadyDone
  | .noConflict => .appendEntriesNoConflict
  | .conflictThenAlreadyDone =>
      .appendEntriesConflictThenAlreadyDone
  | .conflictThenNoConflict =>
      .appendEntriesConflictThenNoConflict

structure AEResponseWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (dest source : Node)
    (response : Message) where
  responseState : State
  request : Message
  previousIndex : Nat
  previousTerm : Nat
  entries : List Entry
  leaderCommitIndex : Nat
  kind : AEResponseKind
  occurrence :
    Occurs
      start actions endState responseState
      (.receive source dest kind.receiveKind)
  request_head :
    headMessage? responseState source dest = some request
  request_body :
    request.body =
      .appendEntriesRequest
        previousIndex previousTerm entries leaderCommitIndex
  response_present :
    response ∈
      (next
        responseState
        (.receive source dest kind.receiveKind)).messages
        dest source

def MessageHasAEResponseWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (dest source : Node)
    (message : Message) :
    Prop :=
  Nonempty
    (AEResponseWitness
      start actions endState dest source message)

def AppendEntriesResponseHistoryConsistent
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall dest source : Node,
    forall message,
      message ∈ state.messages dest source ->
        match message.body with
        | .appendEntriesResponse _ _ =>
            MessageHasAEResponseWitness
              start actions state dest source message
        | _ => True

structure AckWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (dest source : Node)
    (response : Message)
    (lastLogIndex : Nat) where
  origin :
    AEResponseWitness
      start actions endState dest source response
  response_body :
    response.body =
      .appendEntriesResponse true lastLogIndex
  response_term :
    response.term =
      (next
        origin.responseState
        (.receive source dest origin.kind.receiveKind)).currentTerm source
  index_bounded :
    lastLogIndex <=
      ((next
        origin.responseState
        (.receive source dest origin.kind.receiveKind)).log source).length

def MessageHasAckWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (dest source : Node)
    (message : Message)
    (lastLogIndex : Nat) :
    Prop :=
  Nonempty
    (AckWitness
      start actions endState dest source message lastLogIndex)

def SuccessfulAckHistoryConsistent
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall dest source : Node,
    forall message lastLogIndex,
      message ∈ state.messages dest source ->
        message.body =
            .appendEntriesResponse true lastLogIndex ->
          MessageHasAckWitness
            start actions state dest source message lastLogIndex

structure MatchIndexWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (leader follower : Node) where
  handledState : State
  response : Message
  lastLogIndex : Nat
  ack :
    AckWitness
      start actions endState leader follower response lastLogIndex
  handle_occurrence :
    Occurs
      start actions endState handledState
      (.receive leader follower .handleAppendEntriesResponseSuccess)
  response_head :
    headMessage? handledState leader follower = some response
  index_eq :
    endState.matchIndex leader follower = lastLogIndex

def HasMatchIndexWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State)
    (leader follower : Node) :
    Prop :=
  Nonempty
    (MatchIndexWitness
      start actions state leader follower)

def MatchIndexHistoryConsistent
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall leader follower : Node,
    state.leadershipState leader = .leader ->
      0 < state.matchIndex leader follower ->
        HasMatchIndexWitness
          start actions state leader follower

def LeaderIndexInv (state : State) : Prop :=
  forall leader follower : Node,
    state.leadershipState leader = .leader ->
      And
        (state.matchIndex leader follower <=
          state.sentIndex leader follower)
        (state.sentIndex leader follower <=
          (state.log leader).length)

def AcknowledgedPrefixRetainedInv
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall leader follower : Node,
    state.leadershipState leader = .leader ->
      state.currentTerm leader = state.currentTerm follower ->
        forall witness :
            MatchIndexWitness
              start actions state leader follower,
          witness.response.term = state.currentTerm leader ->
            isLogPrefix
              (logPrefix
                ((next
                  witness.ack.origin.responseState
                  (.receive
                    follower
                    leader
                    witness.ack.origin.kind.receiveKind)).log follower)
                witness.lastLogIndex)
              (state.log follower)

def ProtocolHistoryAcknowledgedPrefixRetainedObligation
    (start : InitialConfiguration) :
    Prop :=
  forall {actions state},
    ProtocolHistory start actions state ->
      AcknowledgedPrefixRetainedInv start actions state

structure CurrentMatchIndexPrefixWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (leader follower : Node) where
  matchWitness :
    MatchIndexWitness
      start actions endState leader follower
  response_term :
    matchWitness.response.term =
      endState.currentTerm leader
  retained_prefix :
    isLogPrefix
      (logPrefix
        ((next
          matchWitness.ack.origin.responseState
          (.receive
            follower
            leader
            matchWitness.ack.origin.kind.receiveKind)).log follower)
        matchWitness.lastLogIndex)
      (endState.log follower)

def CurrentMatchIndexPrefixHistoryConsistent
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall leader follower : Node,
    state.leadershipState leader = .leader ->
      state.currentTerm leader = state.currentTerm follower ->
        0 < state.matchIndex leader follower ->
          Nonempty
            (CurrentMatchIndexPrefixWitness
              start actions state leader follower)

def SuccessfulAckHandlingPrefixRetention
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall leader follower handledResponse receivedIndex,
    state.leadershipState leader = .leader ->
      state.currentTerm leader = state.currentTerm follower ->
        headMessage? state leader follower = some handledResponse ->
          handledResponse.body =
              .appendEntriesResponse true receivedIndex ->
            handledResponse.term = state.currentTerm leader ->
              forall response index,
                index =
                    max
                      (state.matchIndex leader follower)
                      receivedIndex ->
                  forall ack :
                      AckWitness
                        start actions state
                        leader follower response index,
                    response.term = state.currentTerm leader ->
                      isLogPrefix
                        (logPrefix
                          ((next
                            ack.origin.responseState
                            (.receive
                              follower
                              leader
                              ack.origin.kind.receiveKind)).log follower)
                          index)
                        (state.log follower)

def MatchIndexPrefixInv (state : State) : Prop :=
  forall leader follower : Node,
    state.leadershipState leader = .leader ->
      state.currentTerm leader = state.currentTerm follower ->
        let index := state.matchIndex leader follower
        And
          (index <= (state.log leader).length)
          (And
            (index <= (state.log follower).length)
            (logPrefix (state.log leader) index =
              logPrefix (state.log follower) index))

structure RVSendWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (dest source : Node)
    (message : Message) where
  sendState : State
  occurrence :
    Occurs
      start actions endState sendState
      (.requestVote source dest)
  message_eq :
    message = requestVoteMessage sendState source dest

def MessageHasRVSendWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (dest source : Node)
    (message : Message) :
    Prop :=
  Nonempty
    (RVSendWitness
      start actions endState dest source message)

structure RVResponseWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (dest source : Node)
    (response : Message) where
  responseState : State
  request : Message
  lastTerm : Nat
  lastIndex : Nat
  isPreVote : Bool
  occurrence :
    Occurs
      start actions endState responseState
      (.receive source dest .handleRequestVoteRequest)
  request_head :
    headMessage? responseState source dest = some request
  request_body :
    request.body =
      .requestVoteRequest lastTerm lastIndex isPreVote
  response_eq :
    response =
      {
        term := responseState.currentTerm source
        source
        dest
        body :=
          .requestVoteResponse
            (requestVoteGranted
              responseState source dest request.term lastTerm lastIndex)
            isPreVote
      }

def MessageHasRVResponseWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (dest source : Node)
    (message : Message) :
    Prop :=
  Nonempty
    (RVResponseWitness
      start actions endState dest source message)

def RequestVoteMessageHistoryConsistent
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall dest source : Node,
    forall message,
      message ∈ state.messages dest source ->
        match message.body with
        | .requestVoteRequest _ _ _ =>
            MessageHasRVSendWitness
              start actions state dest source message
        | .requestVoteResponse _ _ =>
            MessageHasRVResponseWitness
              start actions state dest source message
        | _ => True

structure CountedGrantedVoteWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (candidate voter : Node) where
  countState : State
  response : Message
  responseOrigin :
    RVResponseWitness
      start actions endState candidate voter response
  count_occurrence :
    Occurs
      start actions endState countState
      (.receive candidate voter .handleRequestVoteResponse)
  response_head :
    headMessage? countState candidate voter = some response
  response_body :
    response.body = .requestVoteResponse true false
  candidate_term_eq :
    endState.currentTerm candidate = response.term

def HasCountedGrantedVoteWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State)
    (candidate voter : Node) :
    Prop :=
  Nonempty
    (CountedGrantedVoteWitness
      start actions state candidate voter)

def CountedVoteGrantHistoryConsistent
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall candidate voter : Node,
    Or
        (state.leadershipState candidate = .candidate)
        (state.leadershipState candidate = .leader) ->
      voter ∈ state.votesGranted candidate ->
        voter ≠ candidate ->
          HasCountedGrantedVoteWitness
            start actions state candidate voter

structure CountedVoteLogWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (candidate voter : Node) where
  counted :
    CountedGrantedVoteWitness
      start actions endState candidate voter
  send :
    RVSendWitness
      start actions endState voter candidate
      counted.responseOrigin.request
  log_ok :
    requestVoteLogOK
        counted.responseOrigin.responseState
        voter
        counted.responseOrigin.lastTerm
        counted.responseOrigin.lastIndex =
      true

def HasCountedVoteLogWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State)
    (candidate voter : Node) :
    Prop :=
  Nonempty
    (CountedVoteLogWitness
      start actions state candidate voter)

def CountedVoteLogHistoryConsistent
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall candidate voter : Node,
    Or
        (state.leadershipState candidate = .candidate)
        (state.leadershipState candidate = .leader) ->
      voter ∈ state.votesGranted candidate ->
        voter ≠ candidate ->
          HasCountedVoteLogWitness
            start actions state candidate voter

structure VotedForLogWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (voter candidate : Node) where
  request : Message
  response : Message
  responseOrigin :
    RVResponseWitness
      start actions endState candidate voter response
  send :
    RVSendWitness
      start actions endState voter candidate request
  request_eq :
    request = responseOrigin.request
  log_ok :
    requestVoteLogOK
        responseOrigin.responseState
        voter
        responseOrigin.lastTerm
        responseOrigin.lastIndex =
      true
  voter_term_eq :
    endState.currentTerm voter = response.term

def HasVotedForLogWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State)
    (voter candidate : Node) :
    Prop :=
  Nonempty
    (VotedForLogWitness
      start actions state voter candidate)

def VotedForLogHistoryConsistent
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall voter candidate : Node,
    state.votedFor voter = some candidate ->
      voter ≠ candidate ->
        HasVotedForLogWitness
          start actions state voter candidate

abbrev VoteOwner :=
  Node -> Nat -> Option Node

structure VoteHistoryConsistent
    (state : State)
    (owner : VoteOwner) : Prop where
  currentChoice :
    forall voter : Node,
      owner voter (state.currentTerm voter) =
        state.votedFor voter
  futureEmpty :
    forall voter : Node,
      forall term : Nat,
        state.currentTerm voter < term ->
          owner voter term = none
  countedChoices :
    forall candidate voter : Node,
      Or
          (state.leadershipState candidate = .candidate)
          (state.leadershipState candidate = .leader) ->
        voter ∈ state.votesGranted candidate ->
          owner voter (state.currentTerm candidate) =
            some candidate
  grantedResponses :
    forall dest source : Node,
      forall message,
        message ∈ state.messages dest source ->
          forall isPreVote : Bool,
            message.body =
                .requestVoteResponse true isPreVote ->
              owner source message.term = some dest

def HasVoteHistory (state : State) : Prop :=
  Exists fun owner =>
    VoteHistoryConsistent state owner

def ElectionVotesRecordedInv
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State)
    (owner : VoteOwner) :
    Prop :=
  forall electionState leader,
    Occurs
        start actions state electionState
        (.becomeLeader leader) ->
      forall voter : Node,
        voter ∈ electionState.votesGranted leader ->
          owner voter (electionState.currentTerm leader) =
            some leader

def HistoricalVoteCore
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  Exists fun owner =>
    And
      (VoteHistoryConsistent state owner)
      (ElectionVotesRecordedInv
        start actions state owner)

structure HistoricalElectionVoteCore
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) where
  owner : VoteOwner
  ownerConsistent :
    VoteHistoryConsistent state owner
  electionVotes :
    ElectionVotesRecordedInv
      start actions state owner
  countedVoteLogs :
    CountedVoteLogHistoryConsistent
      start actions state

def CountedVoteUniquenessInv (state : State) : Prop :=
  forall first second voter : Node,
    Or
        (state.leadershipState first = .candidate)
        (state.leadershipState first = .leader) ->
      Or
          (state.leadershipState second = .candidate)
          (state.leadershipState second = .leader) ->
        state.currentTerm first = state.currentTerm second ->
          voter ∈ state.votesGranted first ->
            voter ∈ state.votesGranted second ->
              first = second

structure ElectionWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (leader : Node) where
  electionState : State
  occurrence :
    Occurs
      start actions endState electionState
      (.becomeLeader leader)
  term_eq :
    endState.currentTerm leader =
      electionState.currentTerm leader
  votes_eq :
    endState.votesGranted leader =
      electionState.votesGranted leader

inductive LeaderOriginWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (leader : Node) where
  | initial
      (leader_eq : leader = start)
      (term_eq : endState.currentTerm leader = startTerm)
  | elected
      (witness :
        ElectionWitness start actions endState leader)

def LeaderHasOriginWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State)
    (leader : Node) :
    Prop :=
  Nonempty
    (LeaderOriginWitness start actions state leader)

def LeaderHistoryConsistent
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall leader : Node,
    state.leadershipState leader = .leader ->
      LeaderHasOriginWitness start actions state leader

def HistoricalMonoLogInv
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall historicalState,
    StateAt start actions state historicalState ->
      MonoLogInv historicalState

def TemporalLogMatchingInv
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall firstState secondState,
    StateAt start actions state firstState ->
      StateAt start actions state secondState ->
        forall firstNode secondNode : Node,
          forall index : Nat,
            1 <= index ->
              index <=
                  min
                    (firstState.log firstNode).length
                    (secondState.log secondNode).length ->
                (entryAt? (firstState.log firstNode) index).map (·.term) =
                    (entryAt? (secondState.log secondNode) index).map
                      (·.term) ->
                  logPrefix (firstState.log firstNode) index =
                    logPrefix (secondState.log secondNode) index

def LeaderAppendTermFreshInHistory
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State)
    (leader : Node) :
    Prop :=
  forall historicalState,
    StateAt start actions state historicalState ->
      forall node : Node,
        (entryAt?
            (historicalState.log node)
            ((state.log leader).length + 1)).map
            (·.term) ≠
          some (state.currentTerm leader)

def ActionAppendTermFreshInHistory
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Action -> Prop
  | .clientRequest leader =>
      LeaderAppendTermFreshInHistory
        start actions state leader
  | .signCommittableMessages leader =>
      LeaderAppendTermFreshInHistory
        start actions state leader
  | .changeConfiguration leader _ =>
      LeaderAppendTermFreshInHistory
        start actions state leader
  | _ => True

def HistoricalLogPrefixOrigin
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State)
    (entries : List Entry) :
    Prop :=
  Exists fun historicalState =>
    Exists fun node : Node =>
      And
        (StateAt start actions state historicalState)
        (entries =
          (historicalState.log node).take entries.length)

structure HistoricalLogCore
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) : Prop where
  monoLogs :
    HistoricalMonoLogInv start actions state
  logMatching :
    TemporalLogMatchingInv start actions state
  leaderBoundary :
    LeaderLogBoundaryInv state

def HistoricalAppendTermFreshObligation : Prop :=
  forall start actions state action,
    ProtocolHistory start actions state ->
      Enabled state action ->
        ActionAppendTermFreshInHistory
          start actions state action

def LeaderTermFrontierInv
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall leader : Node,
    state.leadershipState leader = .leader ->
      forall historicalState,
        StateAt start actions state historicalState ->
          forall node : Node,
            forall index : Nat,
              (state.log leader).length < index ->
                (entryAt?
                    (historicalState.log node)
                    index).map (·.term) ≠
                  some (state.currentTerm leader)

def TemporalLeaderUniquenessInv
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall firstState secondState,
    StateAt start actions state firstState ->
      StateAt start actions state secondState ->
        forall firstLeader secondLeader : Node,
          firstState.leadershipState firstLeader = .leader ->
            secondState.leadershipState secondLeader = .leader ->
              firstState.currentTerm firstLeader =
                  secondState.currentTerm secondLeader ->
                firstLeader = secondLeader

def HistoricalElectedTermsNotStartInv
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall electionState leader,
    Occurs
        start actions state electionState
        (.becomeLeader leader) ->
      electionState.currentTerm leader ≠ startTerm

def HistoricalCandidateQuorumFreshInv
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall candidate : Node,
    state.leadershipState candidate = .candidate ->
      allConfigurationsHaveQuorum
          (state.votesGranted candidate)
          (state.configurations candidate) =
        true ->
        forall historicalState,
          StateAt start actions state historicalState ->
            forall node : Node,
              forall entry,
                entry ∈ historicalState.log node ->
                  entry.term != state.currentTerm candidate

def ElectionConfigurationsOverlapInv
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall firstElectionState secondElectionState,
    forall firstLeader secondLeader : Node,
      Occurs
          start actions state firstElectionState
          (.becomeLeader firstLeader) ->
        Occurs
            start actions state secondElectionState
            (.becomeLeader secondLeader) ->
          firstElectionState.currentTerm firstLeader =
              secondElectionState.currentTerm secondLeader ->
            Exists fun firstConfiguration : ConfigurationAt =>
              Exists fun secondConfiguration : ConfigurationAt =>
                And
                  (firstConfiguration ∈
                    firstElectionState.configurations firstLeader)
                  (And
                    (secondConfiguration ∈
                      secondElectionState.configurations secondLeader)
                    (firstConfiguration.nodes =
                      secondConfiguration.nodes))

def TemporalQuorumCandidateConfigurationOverlapInv
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall firstState secondState,
    StateAt start actions state firstState ->
      StateAt start actions state secondState ->
        forall first second : Node,
          firstState.leadershipState first = .candidate ->
            allConfigurationsHaveQuorum
                (firstState.votesGranted first)
                (firstState.configurations first) =
              true ->
              secondState.leadershipState second = .candidate ->
                allConfigurationsHaveQuorum
                    (secondState.votesGranted second)
                    (secondState.configurations second) =
                  true ->
                  firstState.currentTerm first =
                      secondState.currentTerm second ->
                    Exists fun firstConfiguration : ConfigurationAt =>
                      Exists fun secondConfiguration : ConfigurationAt =>
                        And
                          (firstConfiguration ∈
                            firstState.configurations first)
                          (And
                            (secondConfiguration ∈
                              secondState.configurations second)
                            (firstConfiguration.nodes =
                              secondConfiguration.nodes))

def PotentialCandidateQuorum
    (state : State)
    (candidate : Node) :
    Prop :=
  allConfigurationsHaveQuorum
      (votersForCandidateTerm state candidate)
      (state.configurations candidate) =
    true

def TemporalCountedToPotentialCandidateConfigurationOverlapInv
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall countedState potentialState,
    StateAt start actions state countedState ->
      StateAt start actions state potentialState ->
        forall countedCandidate potentialCandidate : Node,
          countedState.leadershipState countedCandidate =
              .candidate ->
            allConfigurationsHaveQuorum
                (countedState.votesGranted countedCandidate)
                (countedState.configurations countedCandidate) =
              true ->
              potentialState.leadershipState potentialCandidate =
                  .candidate ->
                PotentialCandidateQuorum
                    potentialState potentialCandidate ->
                  countedState.currentTerm countedCandidate =
                      potentialState.currentTerm potentialCandidate ->
                    Exists fun countedConfiguration : ConfigurationAt =>
                      Exists fun potentialConfiguration : ConfigurationAt =>
                        And
                          (countedConfiguration ∈
                            countedState.configurations countedCandidate)
                          (And
                            (potentialConfiguration ∈
                              potentialState.configurations
                                potentialCandidate)
                            (countedConfiguration.nodes =
                              potentialConfiguration.nodes))

def PotentialCandidateFormationAction
    (state : State)
    (action : Action)
    (candidate : Node) :
    Prop :=
  (Exists fun timedOut : Node =>
    And
      (action = .timeout timedOut)
      (candidate = timedOut)) ∨
  (Exists fun voter : Node =>
    Exists fun request : Message =>
      Exists fun lastTerm : Nat =>
        Exists fun lastIndex : Nat =>
          And
            (action =
              .receive
                voter candidate .handleRequestVoteRequest)
            (And
              (headMessage? state voter candidate = some request)
              (And
                (request.body =
                  .requestVoteRequest lastTerm lastIndex false)
                (requestVoteGranted
                    state voter candidate request.term
                    lastTerm lastIndex =
                  true))))

def CountedToPotentialCandidateFormationOverlap
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State)
    (action : Action) :
    Prop :=
  forall potentialCandidate : Node,
    PotentialCandidateFormationAction
        state action potentialCandidate ->
      (next state action).leadershipState potentialCandidate =
          .candidate ->
        PotentialCandidateQuorum
            (next state action) potentialCandidate ->
          forall countedState,
            StateAt
                start
                (actions ++ [action])
                (next state action)
                countedState ->
              forall countedCandidate : Node,
                countedState.leadershipState countedCandidate =
                    .candidate ->
                  allConfigurationsHaveQuorum
                      (countedState.votesGranted countedCandidate)
                      (countedState.configurations countedCandidate) =
                    true ->
                    countedState.currentTerm countedCandidate =
                        (next state action).currentTerm
                          potentialCandidate ->
                      Exists fun countedConfiguration : ConfigurationAt =>
                        Exists fun potentialConfiguration : ConfigurationAt =>
                          And
                            (countedConfiguration ∈
                              countedState.configurations
                                countedCandidate)
                            (And
                              (potentialConfiguration ∈
                                (next state action).configurations
                                  potentialCandidate)
                              (countedConfiguration.nodes =
                                potentialConfiguration.nodes))

def CountedToPotentialCandidateFormationOverlapObligation : Prop :=
  forall start actions state action,
    ProtocolHistory start actions state ->
      Enabled state action ->
        CountedToPotentialCandidateFormationOverlap
          start actions state action

structure HistoricalElectionLogCore
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) : Prop where
  logs :
    HistoricalLogCore start actions state
  frontier :
    LeaderTermFrontierInv start actions state
  candidateOverlap :
    TemporalQuorumCandidateConfigurationOverlapInv
      start actions state

structure HistoricalFullElectionLogCore
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) : Prop where
  counted :
    HistoricalElectionLogCore start actions state
  potentialOverlap :
    TemporalCountedToPotentialCandidateConfigurationOverlapInv
      start actions state

def QuorumCandidateFormationAction
    (state : State)
    (action : Action)
    (candidate : Node) :
    Prop :=
  (Exists fun timedOut : Node =>
    And
      (action = .timeout timedOut)
      (candidate = timedOut)) ∨
  (Exists fun source : Node =>
    Exists fun response : Message =>
      And
        (action =
          .receive
            candidate source .handleRequestVoteResponse)
        (And
          (headMessage? state candidate source = some response)
          (response.body = .requestVoteResponse true false)))

def QuorumCandidateFormationOverlap
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State)
    (action : Action) :
    Prop :=
  forall formedCandidate : Node,
    QuorumCandidateFormationAction
        state action formedCandidate ->
      (next state action).leadershipState formedCandidate =
          .candidate ->
        allConfigurationsHaveQuorum
            ((next state action).votesGranted formedCandidate)
            ((next state action).configurations formedCandidate) =
          true ->
          forall otherState,
            StateAt
                start
                (actions ++ [action])
                (next state action)
                otherState ->
              forall otherCandidate : Node,
                otherState.leadershipState otherCandidate =
                    .candidate ->
                  allConfigurationsHaveQuorum
                      (otherState.votesGranted otherCandidate)
                      (otherState.configurations otherCandidate) =
                    true ->
                    (next state action).currentTerm formedCandidate =
                        otherState.currentTerm otherCandidate ->
                      Exists fun formedConfiguration : ConfigurationAt =>
                        Exists fun otherConfiguration : ConfigurationAt =>
                          And
                            (formedConfiguration ∈
                              (next state action).configurations
                                formedCandidate)
                            (And
                              (otherConfiguration ∈
                                otherState.configurations otherCandidate)
                              (formedConfiguration.nodes =
                                otherConfiguration.nodes))

def QuorumCandidateFormationOverlapObligation : Prop :=
  forall start actions state action,
    ProtocolHistory start actions state ->
      Enabled state action ->
        QuorumCandidateFormationOverlap
          start actions state action

def CountedCandidateFormationToPotentialOverlap
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State)
    (action : Action) :
    Prop :=
  forall countedCandidate : Node,
    QuorumCandidateFormationAction
        state action countedCandidate ->
      (next state action).leadershipState countedCandidate =
          .candidate ->
        allConfigurationsHaveQuorum
            ((next state action).votesGranted countedCandidate)
            ((next state action).configurations countedCandidate) =
          true ->
          forall potentialState,
            StateAt
                start
                (actions ++ [action])
                (next state action)
                potentialState ->
              forall potentialCandidate : Node,
                potentialState.leadershipState potentialCandidate =
                    .candidate ->
                  PotentialCandidateQuorum
                      potentialState potentialCandidate ->
                    (next state action).currentTerm countedCandidate =
                        potentialState.currentTerm potentialCandidate ->
                      Exists fun countedConfiguration : ConfigurationAt =>
                        Exists fun potentialConfiguration : ConfigurationAt =>
                          And
                            (countedConfiguration ∈
                              (next state action).configurations
                                countedCandidate)
                            (And
                              (potentialConfiguration ∈
                                potentialState.configurations
                                  potentialCandidate)
                              (countedConfiguration.nodes =
                                potentialConfiguration.nodes))

def CountedCandidateFormationToPotentialOverlapObligation : Prop :=
  forall start actions state action,
    ProtocolHistory start actions state ->
      Enabled state action ->
        CountedCandidateFormationToPotentialOverlap
          start actions state action

def TimeoutConfigurationCompleteness
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State)
    (candidate : Node) :
    Prop :=
  And
    (state.configurations candidate ≠ [])
    (forall historicalState,
      StateAt start actions state historicalState ->
        forall otherCandidate : Node,
          historicalState.leadershipState otherCandidate =
              .candidate ->
            allConfigurationsHaveQuorum
                (historicalState.votesGranted otherCandidate)
                (historicalState.configurations otherCandidate) =
              true ->
              state.currentTerm candidate + 1 =
                  historicalState.currentTerm otherCandidate ->
                Exists fun configuration : ConfigurationAt =>
                  And
                    (configuration ∈
                      historicalState.configurations otherCandidate)
                    (configuration.nodes = {candidate}))

inductive LeaderAppendKind where
  | clientRequest
  | signature
  | reconfiguration (configuration : Configuration)

def LeaderAppendKind.action
    (kind : LeaderAppendKind)
    (leader : Node) :
    Action :=
  match kind with
  | .clientRequest => .clientRequest leader
  | .signature => .signCommittableMessages leader
  | .reconfiguration configuration =>
      .changeConfiguration leader configuration

structure EntryTermLeaderWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState : State)
    (term : Nat) where
  appendState : State
  leader : Node
  kind : LeaderAppendKind
  occurrence :
    Occurs
      start actions endState appendState
      (kind.action leader)
  leader_state :
    appendState.leadershipState leader = .leader
  term_eq :
    appendState.currentTerm leader = term

def HasEntryTermLeaderWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State)
    (term : Nat) :
    Prop :=
  Nonempty
    (EntryTermLeaderWitness
      start actions state term)

def HistoricalEntryTermLeaderOriginInv
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall historicalState,
    StateAt start actions state historicalState ->
      forall node : Node,
        forall entry,
          entry ∈ historicalState.log node ->
            startTerm < entry.term ->
              HasEntryTermLeaderWitness
                start actions state entry.term

def HistoricalSignatureLeaderAtIndexInv
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall historicalState,
    StateAt start actions state historicalState ->
      forall node index term,
        entryAt? (historicalState.log node) index =
            some { term, content := .signature } ->
          startTerm <= term ->
            Exists fun leaderState =>
              Exists fun leader : Node =>
                And
                  (StateAt start actions state leaderState)
                  (And
                    (leaderState.leadershipState leader = .leader)
                    (And
                      (leaderState.currentTerm leader = term)
                      (entryAt? (leaderState.log leader) index =
                        some { term, content := .signature })))

def HistoricalLeaderToCurrentCandidateTermInv
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall historicalState,
    StateAt start actions state historicalState ->
      forall node : Node,
        historicalState.leadershipState node = .leader ->
          state.leadershipState node = .candidate ->
            historicalState.currentTerm node <
              state.currentTerm node

def HistoricalSameLeaderLogPrefixInv
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall historicalState,
    StateAt start actions state historicalState ->
      forall leader : Node,
        historicalState.leadershipState leader = .leader ->
          state.leadershipState leader = .leader ->
            historicalState.currentTerm leader =
                state.currentTerm leader ->
              isLogPrefix
                (historicalState.log leader)
                (state.log leader)

def SignatureCommitBoundary
    (state : State)
    (node : Node)
    (index : Nat) :
    Prop :=
  And
    (0 < index)
    (And
      (index <= state.commitIndex node)
      ((entryAt? (state.log node) index).map (·.content) =
        some .signature))

def committedConfigurationAt?
    (entries : List Entry)
    (index : Nat) :
    Option ConfigurationAt :=
  (configurationsToIndex
    (logConfigurations entries)
    index).getLast?

inductive CommitChoiceOrigin
    (start : InitialConfiguration)
    (actions : List Action)
    (endState choiceState : State)
    (choiceLeader : Node)
    (choiceIndex : Nat) where
  | initial
      (choiceState_eq : choiceState = initialState start)
      (choiceLeader_eq : choiceLeader = start)
      (choiceIndex_eq : choiceIndex = 2)
  | advance
      (occurrence :
        Occurs
          start actions endState choiceState
          (.advanceCommitIndex choiceLeader))
      (choiceIndex_eq :
        choiceIndex =
          highestCommittableIndex choiceState choiceLeader)

namespace CommitChoiceOrigin

def IsInitial
    {start : InitialConfiguration}
    {actions : List Action}
    {endState choiceState : State}
    {choiceLeader : Node}
    {choiceIndex : Nat} :
    CommitChoiceOrigin
      start actions endState choiceState choiceLeader choiceIndex ->
    Prop
  | .initial _ _ _ => True
  | .advance _ _ => False

end CommitChoiceOrigin

structure ChoiceSupportWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (endState choiceState : State)
    (choiceLeader member : Node)
    (choiceIndex choiceTerm : Nat) where
  choiceActions : List Action
  choice_history :
    ProtocolHistory start choiceActions choiceState
  choice_actions_prefix :
    choiceActions <+: actions
  matchWitness :
    MatchIndexWitness
      start choiceActions choiceState choiceLeader member
  index_le_ack :
    choiceIndex <= matchWitness.lastLogIndex
  response_term :
    matchWitness.response.term = choiceTerm

structure ChosenCommitCertificate
    (start : InitialConfiguration)
    (actions : List Action)
    (endState boundaryState : State)
    (owner : Node)
    (index : Nat) where
  boundary_at :
    StateAt start actions endState boundaryState
  boundaryTerm : Nat
  boundary_term :
    (entryAt? (boundaryState.log owner) index).map (·.term) =
      some boundaryTerm
  choiceTerm : Nat
  choiceState : State
  choiceLeader : Node
  choice_at :
    StateAt start actions endState choiceState
  choice_leader :
    choiceState.leadershipState choiceLeader = .leader
  choice_term :
    choiceState.currentTerm choiceLeader = choiceTerm
  choice_term_le_boundary_owner :
    choiceTerm <= boundaryState.currentTerm owner
  choiceIndex : Nat
  choice_origin :
    CommitChoiceOrigin
      start actions endState
      choiceState choiceLeader choiceIndex
  choice_commit_le_boundary :
    choiceState.commitIndex choiceLeader <= index
  choice_progress :
    Or
      choice_origin.IsInitial
      (choiceState.commitIndex choiceLeader < index)
  boundary_le_choice :
    index <= choiceIndex
  boundary_term_le_choice :
    boundaryTerm <= choiceTerm
  chosenPrefix : List Entry
  prefix_eq :
    chosenPrefix = logPrefix (boundaryState.log owner) index
  choice_prefix_eq :
    chosenPrefix = logPrefix (choiceState.log choiceLeader) index
  choiceIndexPrefix : List Entry
  choice_index_prefix_eq :
    choiceIndexPrefix =
      logPrefix (choiceState.log choiceLeader) choiceIndex
  choice_index_entry :
    entryAt? (choiceState.log choiceLeader) choiceIndex =
      some { term := choiceTerm, content := .signature }
  boundary_prefix_le_choice_prefix :
    isLogPrefix chosenPrefix choiceIndexPrefix
  configuration : ConfigurationAt
  configuration_at :
    committedConfigurationAt?
        (boundaryState.log owner) index =
      some configuration
  configuration_le_choice :
    configuration.index <= choiceIndex
  quorum : Configuration
  quorum_ok :
    isQuorum quorum configuration.nodes = true
  support_retained :
    forall member : Node,
      member ∈ quorum ->
        isLogPrefix chosenPrefix (endState.log member)
  watermark_support :
    forall activeConfiguration,
      activeConfiguration ∈
          choiceState.configurations choiceLeader ->
        activeConfiguration.index <= choiceIndex ->
          Exists fun activeQuorum : Configuration =>
            And
              (isQuorum
                  activeQuorum activeConfiguration.nodes =
                true)
              (forall member : Node,
                member ∈ activeQuorum ->
                  isLogPrefix
                    chosenPrefix
                    (endState.log member))
  watermark_causal_support :
    forall activeConfiguration,
      activeConfiguration ∈
          choiceState.configurations choiceLeader ->
        activeConfiguration.index <= choiceIndex ->
          Exists fun activeQuorum : Configuration =>
            And
              (isQuorum
                  activeQuorum activeConfiguration.nodes =
                true)
              (forall member : Node,
                member ∈ activeQuorum ->
                  Or
                    (member = choiceLeader)
                    (Or
                      (And
                        choice_origin.IsInitial
                        (member ∈ start.nodes))
                      (Nonempty
                        (ChoiceSupportWitness
                          start actions endState choiceState
                          choiceLeader member choiceIndex choiceTerm))))
  counted_candidate_barrier :
    forall candidateState,
      StateAt start actions endState candidateState ->
        forall candidate : Node,
          candidateState.leadershipState candidate = .candidate ->
            choiceTerm < candidateState.currentTerm candidate ->
              allConfigurationsHaveQuorum
                  (candidateState.votesGranted candidate)
                  (candidateState.configurations candidate) =
                true ->
                isLogPrefix
                  chosenPrefix
                  (candidateState.log candidate)
  potential_candidate_barrier :
    forall candidateState,
      StateAt start actions endState candidateState ->
        forall candidate : Node,
          candidateState.leadershipState candidate = .candidate ->
            choiceTerm < candidateState.currentTerm candidate ->
              PotentialCandidateQuorum
                  candidateState candidate ->
                isLogPrefix
                  chosenPrefix
                  (candidateState.log candidate)
  higher_term_leaders :
    forall leaderState,
      StateAt start actions endState leaderState ->
        forall leader : Node,
          leaderState.leadershipState leader = .leader ->
            choiceTerm < leaderState.currentTerm leader ->
              isLogPrefix chosenPrefix (leaderState.log leader)

def HasChosenCommitCertificate
    (start : InitialConfiguration)
    (actions : List Action)
    (endState boundaryState : State)
    (owner : Node)
    (index : Nat) :
    Prop :=
  Nonempty
    (ChosenCommitCertificate
      start actions endState boundaryState owner index)

def HistoricalChosenCommitCore
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) :
    Prop :=
  forall boundaryState,
    StateAt start actions state boundaryState ->
      forall owner index,
        SignatureCommitBoundary boundaryState owner index ->
          HasChosenCommitCertificate
            start actions state boundaryState owner index

def HereditaryHistoricalChosenCommitCore
    (start : InitialConfiguration)
    (actions : List Action)
    (_state : State) :
    Prop :=
  forall {prefixActions prefixState},
    prefixActions <+: actions ->
      ProtocolHistory start prefixActions prefixState ->
        HistoricalChosenCommitCore
          start prefixActions prefixState

def RetirementCompletedCommitPositiveInv
    (state : State) :
    Prop :=
  forall owner member : Node,
    member ∈ state.retirementCompleted owner ->
      0 < state.commitIndex owner

structure CandidateChosenConfigurationWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State)
    (candidate : Node) where
  boundaryState : State
  owner : Node
  index : Nat
  boundary :
    SignatureCommitBoundary boundaryState owner index
  certificate :
    ChosenCommitCertificate
      start actions state boundaryState owner index
  configuration_mem :
    certificate.configuration ∈
      state.configurations candidate
  candidate_carries :
    isLogPrefix
      certificate.chosenPrefix
      (state.log candidate)
  choice_term_le_candidate :
    certificate.choiceTerm <= state.currentTerm candidate

def HasCandidateChosenConfigurationWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State)
    (candidate : Node) :
    Prop :=
  Nonempty
    (CandidateChosenConfigurationWitness
      start actions state candidate)

structure CurrentCandidateTimeoutOrigin
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State)
    (candidate : Node) where
  timeoutState : State
  occurrence :
    Occurs
      start actions state timeoutState
      (.timeout candidate)
  candidate_state :
    state.leadershipState candidate = .candidate
  term_eq :
    state.currentTerm candidate =
      timeoutState.currentTerm candidate + 1
  log_eq :
    state.log candidate =
      timeoutState.log candidate
  commit_eq :
    state.commitIndex candidate =
      timeoutState.commitIndex candidate
  configurations_eq :
    state.configurations candidate =
      timeoutState.configurations candidate

structure ChosenCommitCertificateExtension
    {start : InitialConfiguration}
    {beforeActions afterActions : List Action}
    {beforeState afterState boundaryState : State}
    {owner : Node}
    {index : Nat}
    (before :
      ChosenCommitCertificate
        start beforeActions beforeState boundaryState owner index)
    (after :
      ChosenCommitCertificate
        start afterActions afterState boundaryState owner index) : Prop where
  boundaryTerm_eq :
    after.boundaryTerm = before.boundaryTerm
  choiceTerm_eq :
    after.choiceTerm = before.choiceTerm
  choiceState_eq :
    after.choiceState = before.choiceState
  choiceLeader_eq :
    after.choiceLeader = before.choiceLeader
  choiceIndex_eq :
    after.choiceIndex = before.choiceIndex
  chosenPrefix_eq :
    after.chosenPrefix = before.chosenPrefix
  choiceIndexPrefix_eq :
    after.choiceIndexPrefix = before.choiceIndexPrefix
  configuration_eq :
    after.configuration = before.configuration

structure CurrentCandidateChosenConfigurationWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State)
    (candidate : Node) where
  basis :
    CandidateChosenConfigurationWitness
      start actions state candidate
  choice_term_lt_candidate :
    basis.certificate.choiceTerm <
      state.currentTerm candidate

def HasCurrentCandidateChosenConfigurationWitness
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State)
    (candidate : Node) :
    Prop :=
  Nonempty
    (CurrentCandidateChosenConfigurationWitness
      start actions state candidate)

def CandidateElectionBasis
    (state : State)
    (candidate : Node) :
    Prop :=
  Or
    (0 < state.commitIndex candidate)
    (Exists fun configuration : ConfigurationAt =>
      And
        (configuration ∈ state.configurations candidate)
        (And
          (candidate ∈ configuration.nodes)
          (configuration.index <=
            maxCommittableIndex (state.log candidate))))

structure HistoricalCompleteSafetyCore
    (start : InitialConfiguration)
    (actions : List Action)
    (state : State) : Prop where
  electionLogs :
    HistoricalFullElectionLogCore start actions state
  chosenCommits :
    HereditaryHistoricalChosenCommitCore
      start actions state

def HistoricallyReachable
    (start : InitialConfiguration)
    (state : State) :
    Prop :=
  Exists fun actions =>
    ProtocolHistory start actions state

def CausallyReachable
    (start : InitialConfiguration)
    (state : State) :
    Prop :=
  Exists fun actions =>
    And
      (ProtocolHistory start actions state)
      (QueueHistoryConsistent start actions state)

/-- Missing initialization proof for the full inductive bundle. -/
def InitialInductiveInvariantObligation : Prop :=
  forall start : InitialConfiguration,
    InductiveInvariant (initialState start)

/-- Missing one-step proofs for the temporal safety properties. -/
def TransitionSafetyObligation : Prop :=
  forall state action,
    StateSafety state ->
      Enabled state action ->
        TransitionSafety state action (next state action)

def HistoricalSafetyObligation : Prop :=
  forall start state,
    HistoricallyReachable start state ->
      StateSafety state

/-- The remaining obligations needed for the requested final theorem. -/
def FullSafetyCompletionObligation : Prop :=
  And HistoricalSafetyObligation TransitionSafetyObligation

end CCFRaft.Properties
