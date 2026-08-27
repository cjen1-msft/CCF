import CCFRaft.Proofs

/-!
# Executable CCFRaft replays

These replays use `Model.Action`, `Model.Enabled`, and `Model.next`. They are
non-vacuity and bug-finding checks, not safety proofs.
-/

set_option autoImplicit false

namespace CCFRaft.Model

open CCFRaft.Properties
open CCFRaft.Proofs

@[simp]
theorem zeroInitialConfiguration_nodes :
    (0 : InitialConfiguration).nodes = {0} := by
  rfl

@[simp]
theorem zeroInitialConfiguration_leader :
    (0 : InitialConfiguration).leader = 0 := by
  rfl

def runActions (start : InitialConfiguration) :
    State -> List Action -> Option State
  | state, [] => some state
  | state, action :: actions =>
      if actionEnabled state action then
        runActions start (next state action) actions
      else
        none

def runFromInitial
    (start : InitialConfiguration)
    (actions : List Action) :
    Option State :=
  runActions start (initialState start) actions

def continueRun
    (start : InitialConfiguration)
    (state : Option State)
    (actions : List Action) :
    Option State :=
  state.bind fun current => runActions start current actions

def appendRound
    (leader follower : Node)
    (requestKind : ReceiveKind) :
    List Action :=
  [
    .appendEntries leader follower,
    .receive follower leader requestKind,
    .receive leader follower .handleAppendEntriesResponseSuccess
  ]

def freshFollowerCatchUp
    (leader follower : Node)
    (targetLength : Nat) :
    List Action :=
  [
    .appendEntries leader follower,
    .receive follower leader .updateTerm,
    .receive follower leader .rejectAppendEntriesRequest,
    .receive leader follower .handleAppendEntriesResponseFailure
  ] ++
    (List.replicate targetLength
      (appendRound leader follower .appendEntriesNoConflict)).flatten

def existingFollowerCatchUp
    (leader follower : Node)
    (entryCount : Nat) :
    List Action :=
  (List.replicate entryCount
    (appendRound leader follower .appendEntriesNoConflict)).flatten

def heartbeat (leader follower : Node) : List Action :=
  appendRound leader follower .appendEntriesAlreadyDone

def voteRound (candidate voter : Node) : List Action :=
  [
    .requestVote candidate voter,
    .receive voter candidate .updateTerm,
    .receive voter candidate .handleRequestVoteRequest,
    .receive candidate voter .handleRequestVoteResponse
  ]

def configA (_ : Unit) : Configuration :=
  {0, 1, 2, 3, 4}

def configB (_ : Unit) : Configuration :=
  {5, 6, 7, 8, 9}

def configC (_ : Unit) : Configuration :=
  {10, 11, 12, 13, 14}

def initialOne (_ : Unit) : InitialConfiguration :=
  ⟨{0}, 0, by simp⟩

def initialThree (_ : Unit) : InitialConfiguration :=
  ⟨{0, 1, 2}, 0, by simp⟩

def initialFive (_ : Unit) : InitialConfiguration :=
  ⟨{0, 1, 2, 3, 4}, 0, by simp⟩

def dynamicNodeConfiguration (_ : Unit) : Configuration :=
  {0, 16, 17}

def initialConfigurationSmokeTests : Bool :=
  let one := initialState (initialOne ())
  let three := initialState (initialThree ())
  let five := initialState (initialFive ())
  let dynamicAction : Action :=
    .changeConfiguration 0 (dynamicNodeConfiguration ())
  let dynamic := next one dynamicAction
  one.nodes == (initialOne ()).nodes &&
    three.nodes == (initialThree ()).nodes &&
    five.nodes == (initialFive ()).nodes &&
    three.leadershipState 0 == .leader &&
    three.leadershipState 1 == .follower &&
    three.log 0 == three.log 1 &&
    three.commitIndex 2 == 2 &&
    actionEnabled one dynamicAction &&
    decide (16 ∈ dynamic.nodes) &&
    decide (17 ∈ dynamic.nodes) &&
    dynamic.leadershipState 16 == .none &&
    dynamic.log 16 == [] &&
    dynamic.hasJoined 16 &&
    dynamic.sentIndex 0 16 == (one.log 0).length

theorem initialConfigurationSmokeTests_hold :
    initialConfigurationSmokeTests = true := by
  native_decide

def firstConfigurationActions (_ : Unit) : List Action :=
  [
    .changeConfiguration 0 (configA ()),
    .signCommittableMessages 0
  ] ++
    freshFollowerCatchUp 0 1 4 ++
    freshFollowerCatchUp 0 2 4 ++
    [.advanceCommitIndex 0]

def secondConfigurationActions (_ : Unit) : List Action :=
  [
    .changeConfiguration 0 (configB ()),
    .signCommittableMessages 0
  ] ++
    existingFollowerCatchUp 0 1 2 ++
    existingFollowerCatchUp 0 2 2 ++
    freshFollowerCatchUp 0 5 6 ++
    freshFollowerCatchUp 0 6 6 ++
    freshFollowerCatchUp 0 7 6 ++
    [.advanceCommitIndex 0] ++
    heartbeat 0 5

def laterTermElectionActions (_ : Unit) : List Action :=
  [.timeout 5] ++
    voteRound 5 6 ++
    voteRound 5 7 ++
    [.becomeLeader 5]

def thirdConfigurationActions (_ : Unit) : List Action :=
  [
    .changeConfiguration 5 (configC ()),
    .signCommittableMessages 5
  ] ++
    existingFollowerCatchUp 5 6 2 ++
    existingFollowerCatchUp 5 7 2 ++
    freshFollowerCatchUp 5 10 8 ++
    freshFollowerCatchUp 5 11 8 ++
    freshFollowerCatchUp 5 12 8 ++
    [
      .advanceCommitIndex 5,
      .clientRequest 5
    ]

def fullReplayActionCount : Nat :=
  (firstConfigurationActions ()).length +
    (secondConfigurationActions ()).length +
    (laterTermElectionActions ()).length +
    (thirdConfigurationActions ()).length

theorem fullReplayActionCount_is_229 :
    fullReplayActionCount = 229 := by
  decide

def forgedAck : Message :=
  {
    term := startTerm
    source := 1
    dest := 0
    body := .appendEntriesResponse true 100
  }

/--
An inductiveness-only test fixture. `forgedAck` is injected without a send
history, but this file does not prove that `forgedAckState` is unreachable.
The checked facts show only that `MatchIndexBoundedByLogInv` needs a stronger
response invariant; they do not establish a protocol defect.
-/
def forgedAckState : State :=
  let initial := initialState 0
  {
    initial with
    nodes := insert 1 initial.nodes
    currentTerm := updateNode initial.currentTerm 1 startTerm
    messages := enqueue initial.messages forgedAck
  }

def receiveForgedAck : Action :=
  .receive 0 1 .handleAppendEntriesResponseSuccess

theorem forgedAck_enabled :
    Enabled forgedAckState receiveForgedAck := by
  decide

theorem forgedAck_before_bounded :
    MatchIndexBoundedByLogInv forgedAckState := by
  intro leader node leaderState sameTerm
  have leaderIsStart : leader = 0 := by
    by_contra different
    simp [forgedAckState, initialState, different] at leaderState
  subst leader
  by_cases node = 0 <;>
    by_cases node = 1 <;>
      simp [forgedAckState, initialState, *] at sameTerm ⊢

theorem forgedAck_sender_term :
    forgedAck.term <=
      forgedAckState.currentTerm forgedAck.source := by
  decide

theorem forgedAck_after_not_bounded :
    Not
      (MatchIndexBoundedByLogInv
        (next forgedAckState receiveForgedAck)) := by
  intro bounded
  have leader :
      (next forgedAckState receiveForgedAck).leadershipState 0 =
        .leader := by
    decide
  have sameTerm :
      (next forgedAckState receiveForgedAck).currentTerm 0 =
        (next forgedAckState receiveForgedAck).currentTerm 1 := by
    decide
  have matchIndex :
      (next forgedAckState receiveForgedAck).matchIndex 0 1 = 100 := by
    decide
  have logLength :
      ((next forgedAckState receiveForgedAck).log 1).length = 0 := by
    decide
  have violation := bounded 0 1 leader sameTerm
  omega

/--
An inductiveness-only countermodel for state-only election reasoning. Node 1
is made a term-3 candidate while its configuration list remains empty.
`BecomeLeader` is then enabled because the TLA quorum predicate is universal
over that empty list. This state is not claimed to be reachable.
-/
def vacuousElectionState : State :=
  let initial := initialState 0
  {
    initial with
    nodes := insert 1 initial.nodes
    currentTerm :=
      updateNode
        (updateNode initial.currentTerm 0 3)
        1
        3
    leadershipState :=
      updateNode initial.leadershipState 1 .candidate
  }

def vacuousElectionAction : Action :=
  .becomeLeader 1

theorem vacuousElection_enabled :
    Enabled vacuousElectionState vacuousElectionAction := by
  decide

theorem vacuousElection_before_oneLeader :
    MoreThanOneLeaderInv vacuousElectionState := by
  intro first second sameTerm firstLeader secondLeader
  have firstIsStart : first = 0 := by
    by_contra different
    by_cases first = 1 <;>
      simp [vacuousElectionState, initialState, *] at firstLeader
  have secondIsStart : second = 0 := by
    by_contra different
    by_cases second = 1 <;>
      simp [vacuousElectionState, initialState, *] at secondLeader
  exact firstIsStart.trans secondIsStart.symm

theorem vacuousElection_after_not_oneLeader :
    Not
      (MoreThanOneLeaderInv
        (next vacuousElectionState vacuousElectionAction)) := by
  intro oneLeader
  have sameTerm :
      (next vacuousElectionState vacuousElectionAction).currentTerm 0 =
        (next vacuousElectionState vacuousElectionAction).currentTerm 1 := by
    decide
  have firstLeader :
      (next vacuousElectionState vacuousElectionAction).leadershipState 0 =
        .leader := by
    decide
  have secondLeader :
      (next vacuousElectionState vacuousElectionAction).leadershipState 1 =
        .leader := by
    decide
  have := oneLeader 0 1 sameTerm firstLeader secondLeader
  contradiction

/--
An inductiveness-only countermodel for pending AppendEntries log safety.
The queued request is harmless while node 1 is in term 0 and the `none` role,
so the current `AppendEntriesLogSafetyInv` obligation is vacuous. Processing
`UpdateTerm` moves node 1 to term 2 and the follower role without consuming
the request. The same request then becomes acceptable, but its term-3 payload
would produce a log whose last term exceeds the follower current term. The
fixture proves only that the state-only invariant bundle is not inductive; it
does not claim that the fixture state is reachable or that the protocol is
unsafe.
-/
def updateTermUnsafeAppendEntry : Entry :=
  { term := startTerm + 1, content := .entry }

def updateTermUnsafeAppendRequest : Message :=
  {
    term := startTerm
    source := 0
    dest := 1
    body :=
      .appendEntriesRequest 0 0 [updateTermUnsafeAppendEntry] 0
  }

def updateTermUnsafeAppendState : State :=
  let initial := initialState 0
  {
    initial with
    nodes := insert 1 initial.nodes
    messages := enqueue initial.messages updateTermUnsafeAppendRequest
  }

def receiveUpdateTermUnsafeAppend : Action :=
  .receive 1 0 .updateTerm

private theorem updateTermUnsafeAppend_responseBounds :
    AppendEntriesResponseBoundInv updateTermUnsafeAppendState := by
  intro dest source message member
  by_cases destMatches : dest = 1
  · subst dest
    by_cases sourceMatches : source = 0
    · subst source
      simp [updateTermUnsafeAppendState, updateTermUnsafeAppendRequest,
        enqueue, update₂, initialState] at member
      subst message
      simp
    · simp [updateTermUnsafeAppendState, updateTermUnsafeAppendRequest,
        enqueue, update₂, initialState, sourceMatches] at member
  · simp [updateTermUnsafeAppendState, updateTermUnsafeAppendRequest,
      enqueue, update₂, initialState, destMatches] at member

private theorem updateTermUnsafeAppend_appendEntriesLogSafety :
    AppendEntriesLogSafetyInv updateTermUnsafeAppendState := by
  intro dest source message member
  by_cases destMatches : dest = 1
  · subst dest
    by_cases sourceMatches : source = 0
    · subst source
      simp [updateTermUnsafeAppendState, updateTermUnsafeAppendRequest,
        enqueue, update₂, initialState] at member
      subst message
      simp [updateTermUnsafeAppendRequest, appendEntriesAcceptBase,
        updateTermUnsafeAppendState, initialState, startTerm]
    · simp [updateTermUnsafeAppendState, updateTermUnsafeAppendRequest,
        enqueue, update₂, initialState, sourceMatches] at member
  · simp [updateTermUnsafeAppendState, updateTermUnsafeAppendRequest,
      enqueue, update₂, initialState, destMatches] at member

private theorem updateTermUnsafeAppend_messageTerms :
    MessageTermAtLeastStartInv updateTermUnsafeAppendState := by
  intro dest source message member
  by_cases destMatches : dest = 1
  · subst dest
    by_cases sourceMatches : source = 0
    · subst source
      simp [updateTermUnsafeAppendState, updateTermUnsafeAppendRequest,
        enqueue, update₂, initialState] at member
      subst message
      simp
    · simp [updateTermUnsafeAppendState, updateTermUnsafeAppendRequest,
        enqueue, update₂, initialState, sourceMatches] at member
  · simp [updateTermUnsafeAppendState, updateTermUnsafeAppendRequest,
      enqueue, update₂, initialState, destMatches] at member

private theorem updateTermUnsafeAppend_messageEntries :
    MessageEntriesAtLeastStartInv updateTermUnsafeAppendState := by
  intro dest source message member
  by_cases destMatches : dest = 1
  · subst dest
    by_cases sourceMatches : source = 0
    · subst source
      simp [updateTermUnsafeAppendState, updateTermUnsafeAppendRequest,
        enqueue, update₂, initialState] at member
      subst message
      simp [MessageEntriesAtLeastStart, updateTermUnsafeAppendEntry]
    · simp [updateTermUnsafeAppendState, updateTermUnsafeAppendRequest,
        enqueue, update₂, initialState, sourceMatches] at member
  · simp [updateTermUnsafeAppendState, updateTermUnsafeAppendRequest,
      enqueue, update₂, initialState, destMatches] at member

private theorem updateTermUnsafeAppend_stateSafety :
    StateSafety updateTermUnsafeAppendState :=
  {
    logSafety := by
      simpa only [updateTermUnsafeAppendState] using initial_LogInv 0
    oneLeaderPerTerm := by
      simpa only [updateTermUnsafeAppendState] using
        initial_MoreThanOneLeaderInv 0
    candidateFreshTerm := by
      intro candidate candidateState
      by_cases candidate = 0 <;>
        by_cases candidate = 1 <;>
          simp [updateTermUnsafeAppendState, initialState, *] at candidateState
    electionSafety := by
      simpa only [updateTermUnsafeAppendState] using
        initial_ElectionSafetyInv 0
    logMatching := by
      simpa only [updateTermUnsafeAppendState] using initial_LogMatchingInv 0
    quorumLog := by
      simpa only [updateTermUnsafeAppendState] using initial_QuorumLogInv 0
    leaderCompleteness := by
      simpa only [updateTermUnsafeAppendState] using
        initial_LeaderCompletenessInv 0
    signatures := by
      simpa only [updateTermUnsafeAppendState] using initial_SignatureInv 0
    messageTerms := by
      intro dest source queued member
      apply enqueue_preserves_MonoTermInv
        (initialState 0)
        updateTermUnsafeAppendRequest
        (initial_MonoTermInv 0)
        (by decide)
        dest source queued
      simpa only [updateTermUnsafeAppendState] using member
    monotonicLogs := by
      simpa only [updateTermUnsafeAppendState] using initial_MonoLogInv 0
    configurations := by
      simpa only [updateTermUnsafeAppendState] using
        initial_LogConfigurationConsistentInv 0
    replication := by
      simpa only [updateTermUnsafeAppendState] using initial_ReplicationInv 0
    boundedMatchIndex := by
      simpa only [updateTermUnsafeAppendState] using
        initial_MatchIndexBoundedByLogInv 0
  }

private theorem updateTermUnsafeAppend_inductiveInvariant :
    InductiveInvariant updateTermUnsafeAppendState :=
  {
    safety := updateTermUnsafeAppend_stateSafety
    responseBounds := updateTermUnsafeAppend_responseBounds
    configurationsWellFormed := by
      simpa only [updateTermUnsafeAppendState] using
        initial_ConfigurationsWellFormedInv 0
    configurationsExact := by
      simpa only [updateTermUnsafeAppendState] using
        initial_ConfigurationsExactInv 0
    messagesWellFormed := by
      simpa only [MessagesWellFormedInv, updateTermUnsafeAppendState] using
        enqueue_preserves_MessageChannelsWellFormed
          (initialState 0).messages
          updateTermUnsafeAppendRequest
          (initial_MessagesWellFormedInv 0)
    minimumTerms :=
      {
        activeRoles := by
          simpa only [updateTermUnsafeAppendState] using
            (initial_MinimumTermInv 0).activeRoles
        messages := updateTermUnsafeAppend_messageTerms
        messageEntries := updateTermUnsafeAppend_messageEntries
        logs := by
          simpa only [updateTermUnsafeAppendState] using
            (initial_MinimumTermInv 0).logs
      }
    leaderLogBoundary := by
      simpa only [updateTermUnsafeAppendState] using
        initial_LeaderLogBoundaryInv 0
    appendEntriesLogSafety :=
      updateTermUnsafeAppend_appendEntriesLogSafety
  }

theorem receiveUpdateTermUnsafeAppend_enabled :
    Enabled updateTermUnsafeAppendState receiveUpdateTermUnsafeAppend := by
  decide

private theorem updateTermUnsafeAppend_after_not_logSafety :
    Not
      (AppendEntriesLogSafetyInv
        (next updateTermUnsafeAppendState receiveUpdateTermUnsafeAppend)) := by
  intro invariant
  have queued :
      updateTermUnsafeAppendRequest ∈
        (next updateTermUnsafeAppendState receiveUpdateTermUnsafeAppend).messages
          1 0 := by
    simp [next, rawNext, nextReceive, receiveUpdateTermUnsafeAppend,
      updateTermUnsafeAppendState, updateTermUnsafeAppendRequest,
      headMessage?, enqueue, update₂, initialState]
  have safety := invariant 1 0 updateTermUnsafeAppendRequest queued
  simp only [updateTermUnsafeAppendRequest] at safety
  have acceptBase :
      appendEntriesAcceptBase
          (next updateTermUnsafeAppendState receiveUpdateTermUnsafeAppend)
          1
          updateTermUnsafeAppendRequest.term
          0
          0 =
        true := by
    decide
  have noConflict :
      appendEntriesNoConflictGuard
          (next updateTermUnsafeAppendState receiveUpdateTermUnsafeAppend)
          1
          0
          [updateTermUnsafeAppendEntry] =
        true := by
    decide
  have mono := safety.1 acceptBase noConflict
  have nonempty :
      (nextAppendEntriesNoConflict
          (next updateTermUnsafeAppendState receiveUpdateTermUnsafeAppend)
          updateTermUnsafeAppendRequest
          0
          [updateTermUnsafeAppendEntry]
          0).log 1 !=
        [] := by
    decide
  have termBound := (mono nonempty).1
  simp [nextAppendEntriesNoConflict, next, rawNext, nextReceive,
    receiveUpdateTermUnsafeAppend, updateTermUnsafeAppendState,
    updateTermUnsafeAppendRequest, updateTermUnsafeAppendEntry,
    headMessage?, enqueue, update₂, initialState, startTerm] at termBound

/--
The complete state-only invariant bundle admits
`updateTermUnsafeAppendState`, but the enabled `UpdateTerm` step leaves its
AppendEntries request queued and makes the request unsafe. Therefore the
state-only preservation attempt is false. This is an inductiveness-only
countermodel and makes no reachability claim.
-/
theorem updateTermAppendEntries_not_stateOnlyInductive :
    Not StateOnlyInductivenessAttempt := by
  intro preserved
  have after :=
    preserved
      updateTermUnsafeAppendState
      receiveUpdateTermUnsafeAppend
      updateTermUnsafeAppend_inductiveInvariant
      receiveUpdateTermUnsafeAppend_enabled
  exact
    updateTermUnsafeAppend_after_not_logSafety
      after.appendEntriesLogSafety

def acknowledgedAtTerm2Actions : List Action :=
  [
    .changeConfiguration 0 (configA ()),
    .signCommittableMessages 0,
    .appendEntries 0 1,
    .receive 1 0 .updateTerm,
    .receive 1 0 .rejectAppendEntriesRequest,
    .receive 0 1 .handleAppendEntriesResponseFailure,
    .appendEntries 0 1,
    .receive 1 0 .appendEntriesNoConflict,
    .receive 0 1 .handleAppendEntriesResponseSuccess,
    .appendEntries 0 1,
    .receive 1 0 .appendEntriesNoConflict,
    .receive 0 1 .handleAppendEntriesResponseSuccess,
    .appendEntries 0 1,
    .receive 1 0 .appendEntriesNoConflict,
    .receive 0 1 .handleAppendEntriesResponseSuccess,
    .appendEntries 0 1,
    .receive 1 0 .appendEntriesNoConflict,
    .receive 0 1 .handleAppendEntriesResponseSuccess,
    .appendEntries 0 2,
    .receive 2 0 .updateTerm,
    .receive 2 0 .rejectAppendEntriesRequest,
    .receive 0 2 .handleAppendEntriesResponseFailure,
    .appendEntries 0 2,
    .receive 2 0 .appendEntriesNoConflict,
    .receive 0 2 .handleAppendEntriesResponseSuccess,
    .appendEntries 0 2,
    .receive 2 0 .appendEntriesNoConflict,
    .receive 0 2 .handleAppendEntriesResponseSuccess,
    .appendEntries 0 2,
    .receive 2 0 .appendEntriesNoConflict,
    .receive 0 2 .handleAppendEntriesResponseSuccess,
    .appendEntries 0 2,
    .receive 2 0 .appendEntriesNoConflict,
    .receive 0 2 .handleAppendEntriesResponseSuccess,
    .advanceCommitIndex 0,
    .clientRequest 0,
    .appendEntries 0 1,
    .receive 1 0 .appendEntriesNoConflict,
    .receive 0 1 .handleAppendEntriesResponseSuccess
  ]

def acknowledgedAtTerm2State : State :=
  (runFromInitial 0 acknowledgedAtTerm2Actions).get
    (by native_decide)

theorem acknowledgedAtTerm2ActionCount :
    acknowledgedAtTerm2Actions.length = 39 := by
  native_decide

def matchIndexGtSentIndexActions : List Action :=
  acknowledgedAtTerm2Actions ++
  [
    .appendEntries 0 1,
    .timeout 2,
    .requestVote 2 0,
    .receive 0 2 .updateTerm,
    .receive 0 2 .handleRequestVoteRequest,
    .receive 2 0 .handleRequestVoteResponse,
    .requestVote 2 3,
    .receive 3 2 .updateTerm,
    .receive 3 2 .handleRequestVoteRequest,
    .receive 2 3 .handleRequestVoteResponse,
    .becomeLeader 2,
    .clientRequest 2,
    .appendEntries 2 1,
    .receive 1 2 .updateTerm,
    .receive 1 2 .appendEntriesConflictThenNoConflict,
    .receive 1 0 .rejectAppendEntriesRequest,
    .appendEntries 2 0,
    .receive 0 2 .appendEntriesConflictThenNoConflict,
    .timeout 0,
    .requestVote 0 3,
    .receive 3 0 .updateTerm,
    .receive 3 0 .handleRequestVoteRequest,
    .receive 0 3 .handleRequestVoteResponse,
    .requestVote 0 4,
    .receive 4 0 .updateTerm,
    .receive 4 0 .handleRequestVoteRequest,
    .receive 0 4 .handleRequestVoteResponse,
    .becomeLeader 0,
    .clientRequest 0,
    .appendEntries 0 1,
    .receive 1 0 .updateTerm,
    .receive 1 0 .appendEntriesConflictThenNoConflict,
    .receive 0 1 .handleAppendEntriesResponseFailure,
    .receive 0 1 .handleAppendEntriesResponseSuccess
  ]

def matchIndexGtSentIndexState : State :=
  (runFromInitial 0 matchIndexGtSentIndexActions).get
    (by native_decide)

/--
Reachable execution showing that `matchIndex <= sentIndex` is not an
invariant. A delayed old NACK lowers `sentIndex` before a newer success ACK
raises `matchIndex`.
-/
theorem reachable_matchIndex_gt_sentIndex :
    matchIndexGtSentIndexState.matchIndex 0 1 >
      matchIndexGtSentIndexState.sentIndex 0 1 := by
  native_decide

def oldTermAckPrefixCounterexampleActions : List Action :=
  acknowledgedAtTerm2Actions ++
  [
    .timeout 2,
    .requestVote 2 0,
    .receive 0 2 .updateTerm,
    .receive 0 2 .handleRequestVoteRequest,
    .receive 2 0 .handleRequestVoteResponse,
    .requestVote 2 3,
    .receive 3 2 .updateTerm,
    .receive 3 2 .handleRequestVoteRequest,
    .receive 2 3 .handleRequestVoteResponse,
    .becomeLeader 2,
    .clientRequest 2,
    .appendEntries 2 1,
    .receive 1 2 .updateTerm,
    .receive 1 2 .appendEntriesConflictThenNoConflict,
    .appendEntries 2 0,
    .receive 0 2 .appendEntriesConflictThenNoConflict,
    .timeout 0,
    .requestVote 0 3,
    .receive 3 0 .updateTerm,
    .receive 3 0 .handleRequestVoteRequest,
    .receive 0 3 .handleRequestVoteResponse,
    .requestVote 0 4,
    .receive 4 0 .updateTerm,
    .receive 4 0 .handleRequestVoteRequest,
    .receive 0 4 .handleRequestVoteResponse,
    .becomeLeader 0,
    .clientRequest 0,
    .appendEntries 0 1,
    .receive 1 0 .updateTerm,
    .receive 1 0 .appendEntriesConflictThenNoConflict,
    .receive 0 1 .handleAppendEntriesResponseSuccess
  ]

def oldTermAckPrefixCounterexampleState : State :=
  (runFromInitial 0 oldTermAckPrefixCounterexampleActions).get
    (by native_decide)

/--
Reachable execution showing why ACK-prefix retention must be restricted to
the current leader term. The term-2 prefix acknowledged at index 5 is later
overwritten by a term-4 entry at the same index.
-/
theorem reachable_oldTermAckPrefix_overwritten :
    Not
      (isLogPrefix
        (logPrefix (acknowledgedAtTerm2State.log 1) 5)
        (oldTermAckPrefixCounterexampleState.log 1)) := by
  intro prefixProof
  unfold isLogPrefix at prefixProof
  have equal := prefixProof.eq_of_length (by native_decide)
  have unequal :
      logPrefix (acknowledgedAtTerm2State.log 1) 5 ≠
        logPrefix (oldTermAckPrefixCounterexampleState.log 1) 5 := by
    native_decide
  exact unequal equal

def staleVoteResponse : Message :=
  {
    term := 1
    source := 1
    dest := 0
    body := .requestVoteResponse false false
  }

def staleVoteResponseState : State :=
  let initial := initialState 0
  {
    initial with
    nodes := insert 1 initial.nodes
    currentTerm := updateNode initial.currentTerm 1 1
    messages := enqueue initial.messages staleVoteResponse
  }

def outOfStateAppendResponse : Message :=
  {
    term := startTerm
    source := 0
    dest := 1
    body := .appendEntriesResponse true 0
  }

def outOfStateAppendResponseState : State :=
  let initial := initialState 0
  {
    initial with
    nodes := insert 1 initial.nodes
    messages := enqueue initial.messages outOfStateAppendResponse
  }

def candidateAppendRequest : Message :=
  {
    term := startTerm
    source := 0
    dest := 1
    body := .appendEntriesRequest 0 0 [] 0
  }

def candidateAppendRequestState : State :=
  let initial := initialState 0
  {
    initial with
    nodes := insert 1 initial.nodes
    currentTerm := updateNode initial.currentTerm 1 startTerm
    leadershipState := updateNode initial.leadershipState 1 .candidate
    messages := enqueue initial.messages candidateAppendRequest
  }

def conflictAppendRequest : Message :=
  {
    term := 3
    source := 0
    dest := 1
    body :=
      .appendEntriesRequest
        2
        startTerm
        [{ term := 3, content := .entry }]
        2
  }

def conflictAppendRequestState : State :=
  let initial := initialState 0
  let followerLog :=
    startLog 0 ++ [{ term := startTerm, content := .entry }]
  {
    initial with
    nodes := insert 1 initial.nodes
    currentTerm :=
      updateNode (updateNode initial.currentTerm 0 3) 1 3
    leadershipState :=
      updateNode initial.leadershipState 1 .follower
    log := updateNode initial.log 1 followerLog
    commitIndex := updateNode initial.commitIndex 1 2
    configurations :=
      updateNode initial.configurations 1 [{ index := 1, nodes := {0} }]
    messages := enqueue initial.messages conflictAppendRequest
  }

def receiveBranchSmokeTests : Bool :=
  let staleAction : Action :=
    .receive 0 1 .dropRequestVoteResponseStale
  let ignoredAction : Action :=
    .receive 1 0 .dropIgnored
  let outOfStateAction : Action :=
    .receive 1 0 .dropAppendEntriesResponseOutOfState
  let returnAction : Action :=
    .receive 1 0 .returnToFollower
  let conflictAction : Action :=
    .receive 1 0 .appendEntriesConflictThenNoConflict
  actionEnabled staleVoteResponseState staleAction &&
    (next staleVoteResponseState staleAction).messages 0 1 == [] &&
    actionEnabled outOfStateAppendResponseState ignoredAction &&
    actionEnabled outOfStateAppendResponseState outOfStateAction &&
    actionEnabled candidateAppendRequestState returnAction &&
    (next candidateAppendRequestState returnAction).leadershipState 1 ==
      .follower &&
    (next candidateAppendRequestState returnAction).messages 1 0 ==
      [candidateAppendRequest] &&
    actionEnabled conflictAppendRequestState conflictAction &&
    (next conflictAppendRequestState conflictAction).isNewFollower 1 ==
      false &&
    (next conflictAppendRequestState conflictAction).log 1 ==
      startLog 0 ++ [{ term := 3, content := .entry }]

theorem receiveBranchSmokeTests_hold :
    receiveBranchSmokeTests = true := by
  decide

end CCFRaft.Model

def requireReplayState
    (label : String)
    (replay : Unit -> Option CCFRaft.State) :
    IO CCFRaft.State := do
  match replay () with
  | some result => do
      IO.eprintln s!"{label} passed"
      pure result
  | none =>
      throw <| IO.userError s!"{label} reached a disabled action"

open CCFRaft.Model

def inspectInitialState (_ : Unit) : IO Unit := do
  let state := initialState 0
  IO.eprintln s!"initial log length: {(state.log 0).length}"

def runOneAction (_ : Unit) : IO Unit := do
  let result <- requireReplayState "one action" fun _ =>
    runFromInitial 0 [.clientRequest 0]
  if (result.log 0).length = 3 then
    pure ()
  else
    throw <| IO.userError "one action reached the wrong state"

def runCausalCounterexamples (_ : Unit) : IO Unit := do
  let matchState <- requireReplayState "match/sent counterexample" fun _ =>
    runFromInitial 0 matchIndexGtSentIndexActions
  if matchState.matchIndex 0 1 > matchState.sentIndex 0 1 then
    IO.eprintln "reachable matchIndex > sentIndex trace passed"
  else
    throw <| IO.userError "matchIndex did not exceed sentIndex"
  let oldTermState <-
    requireReplayState "old-term ACK counterexample" fun _ =>
      runFromInitial 0 oldTermAckPrefixCounterexampleActions
  if logPrefix (acknowledgedAtTerm2State.log 1) 5 !=
      logPrefix (oldTermState.log 1) 5 then
    IO.eprintln "reachable old-term ACK overwrite trace passed"
  else
    throw <| IO.userError "old-term acknowledged prefix was not overwritten"

def runFirstConfiguration (_ : Unit) : IO Unit := do
  IO.eprintln "starting first configuration"
  let first <- requireReplayState "first configuration" fun _ =>
    runFromInitial 0 (firstConfigurationActions ())
  if first.commitIndex 0 = 4 &&
      currentConfiguration (first.configurations 0) == configA () then
    IO.eprintln "first configuration state passed"
  else
    throw <| IO.userError "first configuration reached the wrong state"

def runFullReplay (_ : Unit) : IO Unit := do
  IO.eprintln "starting first configuration"
  let first <- requireReplayState "first configuration" fun _ =>
    runFromInitial 0 (firstConfigurationActions ())
  IO.eprintln "starting second configuration"
  let second <- requireReplayState "second configuration" fun _ =>
    runActions 0 first (secondConfigurationActions ())
  IO.eprintln "starting later-term election"
  let elected <- requireReplayState "later-term election" fun _ =>
    runActions 0 second (laterTermElectionActions ())
  IO.eprintln "starting third configuration"
  let third <- requireReplayState "third configuration" fun _ =>
    runActions 0 elected (thirdConfigurationActions ())
  if first.commitIndex 0 = 4 &&
      currentConfiguration (first.configurations 0) == configA () &&
      second.commitIndex 0 = 6 &&
      currentConfiguration (second.configurations 0) == configB () &&
      elected.currentTerm 5 = 3 &&
      elected.leadershipState 5 == .leader &&
      currentConfiguration (elected.configurations 5) == configB () &&
      third.commitIndex 5 = 8 &&
      third.leadershipState 5 == .leader &&
      third.membershipState 5 == .retirementCompleted &&
      currentConfiguration (third.configurations 5) == configC () &&
      (third.log 5).length = 9 then
    IO.eprintln "CCFRaft disjoint 5 -> 5 -> 5 replay passed"
  else
    throw <| IO.userError "CCFRaft replay reached the wrong final state"

def main : IO Unit := do
  if initialConfigurationSmokeTests then
    IO.eprintln "initial configuration and dynamic-node smoke tests passed"
  else
    throw <| IO.userError
      "initial configuration or dynamic-node smoke tests failed"
  if receiveBranchSmokeTests then
    IO.eprintln "receive branch smoke tests passed"
  else
    throw <| IO.userError "receive branch smoke tests failed"
  runCausalCounterexamples ()
  runFullReplay ()
