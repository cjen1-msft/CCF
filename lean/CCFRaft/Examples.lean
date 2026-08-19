-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs
import CCFRaft.Slice25Proofs
import CCFRaft.Slice25Simulation
import CCFRaft.Slice3Model

set_option autoImplicit false

/-!
# Slice 1 and 2 non-vacuity examples

This is the public behavior seam for term-one replication and term-two
elections. The examples use the same executable `Enabled`/`next` semantics as
the simulator.
-/

namespace CCFRaft.Examples

/-- Eight transaction IDs are enough for the concrete non-vacuity path. -/
abbrev TxId := Fin 8
/-- The concrete state type used by this example. -/
abbrev RaftState := State TxId

/-- The first follower used to form a majority. -/
def followerOne : Node := ⟨1, by decide⟩
/-- The second follower used to form a majority. -/
def followerTwo : Node := ⟨2, by decide⟩
/-- A voter outside the original term-one replication quorum. -/
def followerThree : Node := ⟨3, by decide⟩
/-- Another voter used to complete a term-two majority. -/
def followerFour : Node := ⟨4, by decide⟩

/-- The empty five-node initial state. -/
def initial : RaftState :=
  initialState

/-- State after the leader accepts transaction zero. -/
def requested : RaftState :=
  next initial (.clientRequest INITIAL_LEADER 0)

/-- State after sending the entry to the first follower. -/
def sentOne : RaftState :=
  next requested (.appendEntries INITIAL_LEADER followerOne 1)

/-- State after the first follower appends the entry and sends an ACK. -/
def receivedOne : RaftState :=
  next sentOne (.receive INITIAL_LEADER followerOne)

/-- State after the leader records the first follower's ACK. -/
def ackedOne : RaftState :=
  next receivedOne (.receive followerOne INITIAL_LEADER)

/-- State after sending the entry to the second follower. -/
def sentTwo : RaftState :=
  next ackedOne (.appendEntries INITIAL_LEADER followerTwo 1)

/-- State after the second follower appends the entry and sends an ACK. -/
def receivedTwo : RaftState :=
  next sentTwo (.receive INITIAL_LEADER followerTwo)

/-- State after the leader records enough ACKs for a majority. -/
def ackedTwo : RaftState :=
  next receivedTwo (.receive followerTwo INITIAL_LEADER)

/-- State after the leader advances its commit index to one. -/
def committed : RaftState :=
  next ackedTwo (.advanceCommitIndex INITIAL_LEADER)

/-- The request, replication, ACK, and quorum-commit path is genuinely reachable. -/
theorem requestReplicateCommitReachable :
    Reachable committed := by
  have requestedReachable : Reachable requested :=
    Reachable.step Reachable.initial (by decide)
  have sentOneReachable : Reachable sentOne :=
    Reachable.step requestedReachable (by decide)
  have receivedOneReachable : Reachable receivedOne :=
    Reachable.step sentOneReachable (by decide)
  have ackedOneReachable : Reachable ackedOne :=
    Reachable.step receivedOneReachable (by decide)
  have sentTwoReachable : Reachable sentTwo :=
    Reachable.step ackedOneReachable (by decide)
  have receivedTwoReachable : Reachable receivedTwo :=
    Reachable.step sentTwoReachable (by decide)
  have ackedTwoReachable : Reachable ackedTwo :=
    Reachable.step receivedTwoReachable (by decide)
  exact Reachable.step ackedTwoReachable (by decide)

/-- The example ends with transaction zero in the committed leader log. -/
theorem committedLogIsNonempty :
    (committed.nodes INITIAL_LEADER).committedLog =
      [{ term := TERM_ONE, txId := 0 }] := by
  decide

/-- The concrete committed state satisfies committed-log prefix safety. -/
theorem exampleCommittedLogsPrefix :
    CommittedLogsPrefix committed :=
  reachableCommittedLogsPrefix requestReplicateCommitReachable

/-- The concrete committed state satisfies Raft log matching. -/
theorem exampleLogMatching :
    LogMatching committed :=
  reachableLogMatching requestReplicateCommitReachable

/-! ## Slice 2 election path -/

/-- State after follower one times out and self-votes in term two. -/
def candidateOne : RaftState :=
  next committed (.timeout followerOne)

/-- State after follower two independently becomes a competing candidate. -/
def candidateTwo : RaftState :=
  next candidateOne (.timeout followerTwo)

/-- Two self-voting candidates form a reachable split vote with no winner. -/
theorem splitVoteHasNoWinner :
    Not (Enabled candidateTwo (.becomeLeader followerOne)) /\
      Not (Enabled candidateTwo (.becomeLeader followerTwo)) := by
  decide

/-! ## Newer-term receive ordering -/

/-- A term-one heartbeat is queued before follower one times out. -/
def heartbeatBeforeTimeout : RaftState :=
  next initial (.appendEntries INITIAL_LEADER followerOne 0)

/-- The follower advances to term two while the old heartbeat remains queued. -/
def timedOutWithHeartbeat : RaftState :=
  next heartbeatBeforeTimeout (.timeout followerOne)

/-- Receiving the stale heartbeat produces a term-two NACK for node zero. -/
def newerNackQueued : RaftState :=
  next timedOutWithHeartbeat (.receive INITIAL_LEADER followerOne)

/-- An overloaded NACK may be handled or may first trigger `UpdateTerm`. -/
theorem newerNackMatchesTlaNondeterminism :
    Enabled newerNackQueued (.updateTerm followerOne INITIAL_LEADER) /\
      Enabled newerNackQueued (.receive followerOne INITIAL_LEADER) := by
  decide

/-- A stale successful ACK is consumed as an ignored response. -/
theorem staleSuccessAckIsDiscarded :
    let nodeState : NodeState TxId :=
      { initialNodeState (TxId := TxId) followerOne with
        role := .follower
        currentTerm := 2 }
    let response : AppendEntriesResponse :=
      { term := TERM_ONE
        success := true
        lastLogIndex := 0
        source := followerTwo
        destination := followerOne }
    handleAppendEntriesResponse? nodeState response = some nodeState := by
  simp [
    handleAppendEntriesResponse?,
    initialNodeState,
    followerOne,
    INITIAL_LEADER,
    TERM_ONE
  ]

/-- A stale NACK still backs up `sentIndex`; its term is match metadata. -/
theorem staleNackIsHandled :
    let nodeState : NodeState TxId :=
      { initialNodeState (TxId := TxId) INITIAL_LEADER with
        role := .leader
        currentTerm := 2
        log :=
          [{ term := TERM_ONE, txId := 0 },
            { term := TERM_ONE, txId := 1 }]
        sentIndex :=
          updateIndex (fun _ => 0) followerTwo 2 }
    let response : AppendEntriesResponse :=
      { term := TERM_ONE
        success := false
        lastLogIndex := 1
        source := followerTwo
        destination := INITIAL_LEADER }
    match handleAppendEntriesResponse? nodeState response with
    | none => False
    | some after => after.sentIndex followerTwo = 1 := by
  simp [
    handleAppendEntriesResponse?,
    initialNodeState,
    findHighestPossibleMatch,
    updateIndex,
    TERM_ONE
  ]
  native_decide

/-- A candidate cannot consume a RequestVote response from a future term. -/
theorem futureVoteResponseRequiresTermUpdate :
    let candidate : NodeState TxId :=
      { initialNodeState (TxId := TxId) followerOne with
        role := .candidate }
    let response : RequestVoteResponse :=
      { term := 2
        voteGranted := true
        source := followerTwo
        destination := followerOne }
    handleRequestVoteResponse? candidate response = none := by
  simp [handleRequestVoteResponse?, initialNodeState, TERM_ONE]

/-- A non-leader may discard a future successful AppendEntries response. -/
theorem futureAckDroppedWhenNotLeader :
    let follower : NodeState TxId :=
      initialNodeState (TxId := TxId) followerOne
    let response : AppendEntriesResponse :=
      { term := 2
        success := true
        lastLogIndex := 0
        source := followerTwo
        destination := followerOne }
    match handleAppendEntriesResponse? follower response with
    | none => False
    | some after =>
        after.role = .follower /\
          after.currentTerm = TERM_ONE := by
  simp [
    handleAppendEntriesResponse?,
    initialNodeState,
    followerOne,
    INITIAL_LEADER,
    TERM_ONE
  ]

/-- A current leader cannot consume a successful ACK from a future term. -/
theorem futureAckRequiresTermUpdateAtLeader :
    let leader : NodeState TxId :=
      initialNodeState (TxId := TxId) INITIAL_LEADER
    let response : AppendEntriesResponse :=
      { term := 2
        success := true
        lastLogIndex := 0
        source := followerTwo
        destination := INITIAL_LEADER }
    handleAppendEntriesResponse? leader response = none := by
  simp [handleAppendEntriesResponse?, initialNodeState, TERM_ONE]

/-- A non-candidate discards a RequestVote response, even from a future term. -/
theorem futureVoteResponseDroppedWhenNotCandidate :
    let follower : NodeState TxId :=
      initialNodeState (TxId := TxId) followerOne
    let response : RequestVoteResponse :=
      { term := 2
        voteGranted := true
        source := followerTwo
        destination := followerOne }
    match handleRequestVoteResponse? follower response with
    | none => False
    | some after =>
        after.role = .follower /\
          after.currentTerm = TERM_ONE := by
  simp [
    handleRequestVoteResponse?,
    initialNodeState,
    followerOne,
    INITIAL_LEADER,
    TERM_ONE
  ]

/-- A stale RequestVote request is consumed and denied in the current term. -/
theorem staleVoteRequestIsDenied :
    let voter : NodeState TxId :=
      { initialNodeState (TxId := TxId) followerTwo with
        currentTerm := 2 }
    let request : RequestVoteRequest :=
      { term := TERM_ONE
        lastLogTerm := 0
        lastLogIndex := 0
        source := followerOne
        destination := followerTwo }
    match handleRequestVoteRequest? voter request with
    | none => False
    | some (_, response) =>
        response.term = 2 /\
          response.voteGranted = false := by
  simp [
    handleRequestVoteRequest?,
    initialNodeState,
    voteLogUpToDate,
    TERM_ONE
  ]

/-- Candidate one sends its first RequestVote request. -/
def voteRequestThree : RaftState :=
  next candidateTwo (.requestVote followerOne followerThree)

/-- Follower three observes the newer term without consuming the request. -/
def termUpdatedThree : RaftState :=
  next voteRequestThree (.updateTerm followerOne followerThree)

/-- Follower three grants candidate one's RequestVote request. -/
def voteGrantedThree : RaftState :=
  next termUpdatedThree (.receive followerOne followerThree)

/-- Candidate one records follower three's granted vote. -/
def voteRecordedThree : RaftState :=
  next voteGrantedThree (.receive followerThree followerOne)

/-- Candidate one sends its second RequestVote request. -/
def voteRequestFour : RaftState :=
  next voteRecordedThree (.requestVote followerOne followerFour)

/-- Follower four observes term two without consuming the request. -/
def termUpdatedFour : RaftState :=
  next voteRequestFour (.updateTerm followerOne followerFour)

/-- Follower four grants candidate one's RequestVote request. -/
def voteGrantedFour : RaftState :=
  next termUpdatedFour (.receive followerOne followerFour)

/-- Candidate one records a three-node majority including its self-vote. -/
def electionMajority : RaftState :=
  next voteGrantedFour (.receive followerFour followerOne)

/-- Candidate one becomes the sole term-two leader. -/
def electedTermTwo : RaftState :=
  next electionMajority (.becomeLeader followerOne)

/-- The competing election trace, including per-node timeouts, is reachable. -/
theorem termTwoElectionReachable :
    Reachable electedTermTwo := by
  have candidateOneReachable : Reachable candidateOne :=
    Reachable.step requestReplicateCommitReachable (by decide)
  have candidateTwoReachable : Reachable candidateTwo :=
    Reachable.step candidateOneReachable (by decide)
  have voteRequestThreeReachable : Reachable voteRequestThree :=
    Reachable.step candidateTwoReachable (by decide)
  have termUpdatedThreeReachable : Reachable termUpdatedThree :=
    Reachable.step voteRequestThreeReachable (by decide)
  have voteGrantedThreeReachable : Reachable voteGrantedThree :=
    Reachable.step termUpdatedThreeReachable (by decide)
  have voteRecordedThreeReachable : Reachable voteRecordedThree :=
    Reachable.step voteGrantedThreeReachable (by decide)
  have voteRequestFourReachable : Reachable voteRequestFour :=
    Reachable.step voteRecordedThreeReachable (by decide)
  have termUpdatedFourReachable : Reachable termUpdatedFour :=
    Reachable.step voteRequestFourReachable (by decide)
  have voteGrantedFourReachable : Reachable voteGrantedFour :=
    Reachable.step termUpdatedFourReachable (by decide)
  have electionMajorityReachable : Reachable electionMajority :=
    Reachable.step voteGrantedFourReachable (by decide)
  exact Reachable.step electionMajorityReachable (by decide)

/-- The successful candidate has exactly the three votes needed to win. -/
theorem electedCandidateHasMajority :
    (electedTermTwo.nodes followerOne).votesGranted =
      {followerOne, followerThree, followerFour} := by
  decide

/-- The competing candidate cannot become leader with only its self-vote. -/
theorem competingCandidateCannotWin :
    Not (Enabled electedTermTwo (.becomeLeader followerTwo)) := by
  decide

/-- The concrete election state satisfies one-leader-per-term safety. -/
theorem exampleElectionSafety :
    ElectionSafety electedTermTwo :=
  reachableElectionSafety termTwoElectionReachable

/-- The elected term-two leader contains the term-one committed entry. -/
theorem electedLeaderContainsTermOneCommit :
    (electedTermTwo.nodes INITIAL_LEADER).committedLog <+:
      (electedTermTwo.nodes followerOne).log := by
  exact
    reachableTermTwoLeaderCompleteness termTwoElectionReachable
      followerOne (by decide) (by decide)

/-! ## Slice 2.5 cross-term replication and conflict -/

/-- A direct term-two append, replication, and commit trace. -/
def slice25HappyActions : List (Action TxId) :=
  [ .clientRequest INITIAL_LEADER 0,
    .appendEntries INITIAL_LEADER followerOne 1,
    .receive INITIAL_LEADER followerOne,
    .receive followerOne INITIAL_LEADER,
    .appendEntries INITIAL_LEADER followerTwo 1,
    .receive INITIAL_LEADER followerTwo,
    .receive followerTwo INITIAL_LEADER,
    .advanceCommitIndex INITIAL_LEADER,
    .timeout followerOne,
    .requestVote followerOne followerTwo,
    .updateTerm followerOne followerTwo,
    .receive followerOne followerTwo,
    .receive followerTwo followerOne,
    .requestVote followerOne followerThree,
    .updateTerm followerOne followerThree,
    .receive followerOne followerThree,
    .receive followerThree followerOne,
    .becomeLeader followerOne,
    .clientRequest followerOne 2,
    .appendEntries followerOne followerTwo 2,
    .receive followerOne followerTwo,
    .receive followerTwo followerOne,
    .appendEntries followerOne INITIAL_LEADER 2,
    .updateTerm followerOne INITIAL_LEADER,
    .receive followerOne INITIAL_LEADER,
    .receive INITIAL_LEADER followerOne,
    .advanceCommitIndex followerOne ]

/-- The direct term-two commit trace has no disabled action. -/
theorem slice25HappyTraceExecutes :
    (Slice25.runActions initial slice25HappyActions).isSome = true := by
  native_decide

/-- The mandatory election, divergence, repair, and cross-term commit trace. -/
def slice25ConflictActions : List (Action TxId) :=
  [ .clientRequest INITIAL_LEADER 0,
    .appendEntries INITIAL_LEADER followerOne 1,
    .receive INITIAL_LEADER followerOne,
    .receive followerOne INITIAL_LEADER,
    .appendEntries INITIAL_LEADER followerTwo 1,
    .receive INITIAL_LEADER followerTwo,
    .receive followerTwo INITIAL_LEADER,
    .advanceCommitIndex INITIAL_LEADER,
    .timeout followerOne,
    .requestVote followerOne followerTwo,
    .updateTerm followerOne followerTwo,
    .receive followerOne followerTwo,
    .receive followerTwo followerOne,
    .requestVote followerOne followerThree,
    .updateTerm followerOne followerThree,
    .receive followerOne followerThree,
    .receive followerThree followerOne,
    .becomeLeader followerOne,
    .clientRequest INITIAL_LEADER 1,
    .appendEntries INITIAL_LEADER followerFour 1,
    .receive INITIAL_LEADER followerFour,
    .appendEntries INITIAL_LEADER followerFour 2,
    .receive INITIAL_LEADER followerFour,
    .clientRequest followerOne 2,
    .appendEntries followerOne followerFour 2,
    .updateTerm followerOne followerFour,
    .receive followerOne followerFour,
    .receive followerFour followerOne,
    .appendEntries followerOne followerTwo 2,
    .receive followerOne followerTwo,
    .receive followerTwo followerOne,
    .advanceCommitIndex followerOne ]

/-- Execute a prefix of the mandatory slice-2.5 trace. -/
def slice25StateAfter (count : Nat) : RaftState :=
  (Slice25.runActions initial (slice25ConflictActions.take count)).getD initial

/-- Node four starts a same-term candidacy after node one is elected. -/
def sameTermCandidate : RaftState :=
  Slice25.next (slice25StateAfter 18) (.timeout followerFour)

/-- The term-two leader sends a heartbeat to that candidate. -/
def sameTermCandidateHeartbeat : RaftState :=
  Slice25.next sameTermCandidate
    (.appendEntries followerOne followerFour 1)

/-- A same-term AppendEntries first makes the candidate a follower without consuming it. -/
theorem sameTermCandidateReturnsToFollower :
    Slice25.Enabled sameTermCandidateHeartbeat
      (.receive followerOne followerFour) /\
      let stepped :=
        Slice25.next sameTermCandidateHeartbeat
          (.receive followerOne followerFour)
      (stepped.nodes followerFour).role = .follower /\
        stepped.network followerFour =
          sameTermCandidateHeartbeat.network followerFour := by
  native_decide

/-- The full trace has no disabled action. -/
theorem slice25ConflictTraceExecutes :
    (Slice25.runActions initial slice25ConflictActions).isSome = true := by
  native_decide

/-- The final state of the checked trace is reachable in slice 2.5. -/
theorem slice25ConflictTraceReachable :
    Slice25.Reachable (slice25StateAfter slice25ConflictActions.length) := by
  cases ran : Slice25.runActions initial slice25ConflictActions with
  | none =>
      have executes := slice25ConflictTraceExecutes
      simp [ran] at executes
  | some final =>
      have reachable : Slice25.Reachable final :=
        Slice25.Reachable.runActionsReachable
          Slice25.Reachable.initial ran
      simpa [slice25StateAfter, ran] using reachable

/-- The divergent trace still satisfies committed-prefix consistency. -/
theorem slice25ConflictCommittedLogsPrefix :
    CommittedLogsPrefix
      (slice25StateAfter slice25ConflictActions.length) :=
  Slice25.reachableCommittedLogsPrefix slice25ConflictTraceReachable

/-- The divergent trace still has at most one leader in each term. -/
theorem slice25ConflictElectionSafety :
    ElectionSafety
      (slice25StateAfter slice25ConflictActions.length) :=
  Slice25.reachableElectionSafety slice25ConflictTraceReachable

/-- Cross-term conflict repair preserves Raft log matching. -/
theorem slice25ConflictLogMatching :
    LogMatching
      (slice25StateAfter slice25ConflictActions.length) :=
  Slice25.reachableLogMatching slice25ConflictTraceReachable

/-- Before repair, node four contains node zero's divergent suffix. -/
theorem divergentFollowerContainsOldEntry :
    ((slice25StateAfter 23).nodes followerFour).log =
      [{ term := TERM_ONE, txId := 0 },
        { term := TERM_ONE, txId := 1 }] := by
  native_decide

/-- Conflict handling replaces the old suffix with the new leader's entry. -/
theorem conflictFollowerContainsTermTwoEntry :
    ((slice25StateAfter 27).nodes followerFour).log =
      [{ term := TERM_ONE, txId := 0 },
        { term := 2, txId := 2 }] := by
  native_decide

/-- The new leader commits its term-two entry and inherited prefix. -/
theorem termTwoCommittedLog :
    ((slice25StateAfter slice25ConflictActions.length).nodes followerOne).committedLog =
      [{ term := TERM_ONE, txId := 0 },
        { term := 2, txId := 2 }] := by
  native_decide

/-- Runtime checks reject a higher-term leader missing the committed prefix. -/
theorem slice25RuntimeChecksLeaderCompleteness :
    let entry : Entry TxId := { term := TERM_ONE, txId := 0 }
    let bad : RaftState :=
      { initial with
        nodes :=
          updateNode
            (updateNode initial.nodes INITIAL_LEADER
              { initial.nodes INITIAL_LEADER with
                role := .follower
                log := [entry]
                commitIndex := 1 })
            followerOne
            { initial.nodes followerOne with
              role := .leader
              currentTerm := 2 } }
    Slice25.Simulation.stateChecks bad = false := by
  native_decide

/-- Scheduler priorities never select heartbeat-only AppendEntries exclusively. -/
theorem slice25SchedulerPrioritisesOnlyProgressingAppends :
    let final := slice25StateAfter slice25ConflictActions.length
    let leader := final.nodes followerOne
    let settled : RaftState :=
      { final with
        nodes :=
          updateNode final.nodes followerOne
            { leader with sentIndex := fun _ => leader.log.length }
        network := fun _ => [] }
    (Slice25.Simulation.preferredChoices settled).all fun choice =>
      match choice with
      | .appendEntries source destination batchEnd =>
          (settled.nodes source).sentIndex destination < batchEnd
      | _ => true := by
  native_decide

/-! ## Slice 3 arbitrary and skipped terms -/

/-- Reachable regression for follower commit beyond a partially verified request. -/
def slice3FollowerOvercommitActions : List (Action TxId) :=
  [ .clientRequest INITIAL_LEADER 0,
    .appendEntries INITIAL_LEADER followerOne 1,
    .receive INITIAL_LEADER followerOne,
    .receive followerOne INITIAL_LEADER,
    .appendEntries INITIAL_LEADER followerTwo 1,
    .receive INITIAL_LEADER followerTwo,
    .receive followerTwo INITIAL_LEADER,
    .appendEntries INITIAL_LEADER followerThree 1,
    .receive INITIAL_LEADER followerThree,
    .receive followerThree INITIAL_LEADER,
    .appendEntries INITIAL_LEADER followerFour 1,
    .receive INITIAL_LEADER followerFour,
    .receive followerFour INITIAL_LEADER,
    .advanceCommitIndex INITIAL_LEADER,
    .appendEntries INITIAL_LEADER followerTwo 1,
    .timeout followerOne,
    .requestVote followerOne followerTwo,
    .updateTerm followerOne followerTwo,
    .receive INITIAL_LEADER followerTwo,
    .receive followerOne followerTwo,
    .requestVote followerOne followerThree,
    .updateTerm followerOne followerThree,
    .receive followerOne followerThree,
    .requestVote followerOne INITIAL_LEADER,
    .updateTerm followerOne INITIAL_LEADER,
    .receive followerOne INITIAL_LEADER,
    .receive followerTwo followerOne,
    .receive followerThree followerOne,
    .becomeLeader followerOne,
    .clientRequest followerOne 1,
    .appendEntries followerOne INITIAL_LEADER 2,
    .receive followerOne INITIAL_LEADER,
    .appendEntries followerOne followerTwo 2,
    .receive followerOne followerTwo,
    .appendEntries followerOne followerThree 2,
    .receive followerOne followerThree,
    .appendEntries followerOne followerFour 2,
    .updateTerm followerOne followerFour,
    .receive followerOne followerFour,
    .clientRequest followerOne 2,
    .appendEntries followerOne followerTwo 3,
    .receive followerOne followerTwo,
    .timeout INITIAL_LEADER,
    .requestVote INITIAL_LEADER followerThree,
    .updateTerm INITIAL_LEADER followerThree,
    .receive INITIAL_LEADER followerThree,
    .requestVote INITIAL_LEADER followerFour,
    .updateTerm INITIAL_LEADER followerFour,
    .receive INITIAL_LEADER followerFour,
    .receive followerThree INITIAL_LEADER,
    .receive followerFour INITIAL_LEADER,
    .becomeLeader INITIAL_LEADER,
    .clientRequest INITIAL_LEADER 3,
    .appendEntries INITIAL_LEADER followerThree 3,
    .receive INITIAL_LEADER followerThree,
    .receive followerThree INITIAL_LEADER,
    .appendEntries INITIAL_LEADER followerFour 3,
    .receive INITIAL_LEADER followerFour,
    .receive followerFour INITIAL_LEADER,
    .advanceCommitIndex INITIAL_LEADER,
    .receive followerTwo INITIAL_LEADER,
    .appendEntries INITIAL_LEADER followerTwo 2,
    .updateTerm INITIAL_LEADER followerTwo,
    .receive INITIAL_LEADER followerTwo ]

/-- The overcommit regression trace contains no disabled action. -/
theorem slice3FollowerOvercommitTraceExecutes :
    (Slice3.runActions initial slice3FollowerOvercommitActions).isSome = true := by
  native_decide

/-- Final state of the follower-overcommit regression. -/
def slice3FollowerOvercommitFinal : RaftState :=
  (Slice3.runActions initial slice3FollowerOvercommitActions).getD initial

/-- Follower commit is bounded by the final request's verified tail. -/
theorem slice3FollowerCommitStopsAtRequestEnd :
    (slice3FollowerOvercommitFinal.nodes followerTwo).commitIndex = 2 /\
      (slice3FollowerOvercommitFinal.nodes followerTwo).committedLog <+:
        (slice3FollowerOvercommitFinal.nodes INITIAL_LEADER).log := by
  native_decide

/-- A delayed ACK lets an isolated lower-term leader commit after a later election. -/
def slice3DelayedAckActions : List (Action TxId) :=
  [ .clientRequest INITIAL_LEADER 0,
    .appendEntries INITIAL_LEADER followerOne 1,
    .receive INITIAL_LEADER followerOne,
    .receive followerOne INITIAL_LEADER,
    .appendEntries INITIAL_LEADER followerTwo 1,
    .receive INITIAL_LEADER followerTwo,
    .timeout followerOne,
    .requestVote followerOne followerThree,
    .updateTerm followerOne followerThree,
    .receive followerOne followerThree,
    .receive followerThree followerOne,
    .requestVote followerOne followerFour,
    .updateTerm followerOne followerFour,
    .receive followerOne followerFour,
    .receive followerFour followerOne,
    .becomeLeader followerOne,
    .receive followerTwo INITIAL_LEADER,
    .advanceCommitIndex INITIAL_LEADER ]

/-- The delayed-ACK stale-leader trace is executable. -/
theorem slice3DelayedAckTraceExecutes :
    (Slice3.runActions initial slice3DelayedAckActions).isSome = true := by
  native_decide

/-- The later leader already contains the prefix committed by the stale leader. -/
theorem slice3DelayedAckLeaderContainsCommit :
    let final :=
      (Slice3.runActions initial slice3DelayedAckActions).getD initial
    (final.nodes INITIAL_LEADER).committedLog <+:
      (final.nodes followerOne).log := by
  native_decide

/-- A skipped term-three election followed by a later term-four commit. -/
def slice3ArbitraryActions : List (Action TxId) :=
  [ .clientRequest INITIAL_LEADER 0,
    .appendEntries INITIAL_LEADER followerOne 1,
    .receive INITIAL_LEADER followerOne,
    .receive followerOne INITIAL_LEADER,
    .appendEntries INITIAL_LEADER followerTwo 1,
    .receive INITIAL_LEADER followerTwo,
    .receive followerTwo INITIAL_LEADER,
    .advanceCommitIndex INITIAL_LEADER,
    .timeout followerOne,
    .timeout followerOne,
    .requestVote followerOne followerTwo,
    .updateTerm followerOne followerTwo,
    .receive followerOne followerTwo,
    .receive followerTwo followerOne,
    .requestVote followerOne followerThree,
    .updateTerm followerOne followerThree,
    .receive followerOne followerThree,
    .receive followerThree followerOne,
    .becomeLeader followerOne,
    .clientRequest followerOne 2,
    .appendEntries followerOne followerTwo 2,
    .receive followerOne followerTwo,
    .receive followerTwo followerOne,
    .appendEntries followerOne INITIAL_LEADER 2,
    .updateTerm followerOne INITIAL_LEADER,
    .receive followerOne INITIAL_LEADER,
    .receive INITIAL_LEADER followerOne,
    .advanceCommitIndex followerOne,
    .timeout followerTwo,
    .requestVote followerTwo INITIAL_LEADER,
    .updateTerm followerTwo INITIAL_LEADER,
    .receive followerTwo INITIAL_LEADER,
    .receive INITIAL_LEADER followerTwo,
    .requestVote followerTwo followerFour,
    .updateTerm followerTwo followerFour,
    .receive followerTwo followerFour,
    .receive followerFour followerTwo,
    .becomeLeader followerTwo,
    .clientRequest followerTwo 3,
    .appendEntries followerTwo followerOne 3,
    .updateTerm followerTwo followerOne,
    .receive followerTwo followerOne,
    .receive followerOne followerTwo,
    .appendEntries followerTwo INITIAL_LEADER 3,
    .receive followerTwo INITIAL_LEADER,
    .receive INITIAL_LEADER followerTwo,
    .advanceCommitIndex followerTwo ]

/-- A second candidate in an already-owned term cannot collect a majority. -/
def slice3SameTermCompetitorActions : List (Action TxId) :=
  slice3ArbitraryActions.take 19 ++
    [ .timeout followerFour,
      .timeout followerFour,
      .requestVote followerFour INITIAL_LEADER,
      .updateTerm followerFour INITIAL_LEADER,
      .receive followerFour INITIAL_LEADER,
      .receive INITIAL_LEADER followerFour,
      .requestVote followerFour followerTwo,
      .receive followerFour followerTwo,
      .receive followerTwo followerFour ]

/-- Majority intersection prevents a second term-three leader. -/
theorem slice3SameTermCompetitorCannotWin :
    let final :=
      (Slice3.runActions initial slice3SameTermCompetitorActions).getD initial
    (Slice3.runActions initial slice3SameTermCompetitorActions).isSome = true /\
      Not (Slice3.Enabled final (.becomeLeader followerFour)) := by
  native_decide

/--
An isolated old ACK may outlive later conflict repair; arbitrary ACK snapshots
must not be treated as permanent voter-log prefixes.
-/
def slice3OverwrittenAckActions : List (Action TxId) :=
  slice25ConflictActions ++
    [ .receive followerFour INITIAL_LEADER,
      .receive followerFour INITIAL_LEADER,
      .timeout followerTwo,
      .requestVote followerTwo followerFour,
      .updateTerm followerTwo followerFour,
      .receive followerTwo followerFour,
      .receive followerFour followerTwo ]

/-- The overwritten ACK voter can later grant from its replacement log. -/
theorem slice3ArbitraryAckHistoryIsNotPersistent :
    let final :=
      (Slice3.runActions initial slice3OverwrittenAckActions).getD initial
    (Slice3.runActions initial slice3OverwrittenAckActions).isSome = true /\
      Not (
        ([{ term := TERM_ONE, txId := 0 },
          { term := TERM_ONE, txId := 1 }] : List (Entry TxId)) <+:
          (final.nodes followerFour).log) /\
      followerFour ∈ (final.nodes followerTwo).votesGranted := by
  native_decide

/-- Execute a prefix of the arbitrary-term trace. -/
def slice3StateAfter (count : Nat) : RaftState :=
  (Slice3.runActions initial (slice3ArbitraryActions.take count)).getD initial

/-- Every action in the skipped-term and repeated-election trace is enabled. -/
theorem slice3ArbitraryTraceExecutes :
    (Slice3.runActions initial slice3ArbitraryActions).isSome = true := by
  native_decide

/-- The checked skipped-term trace ends in a reachable arbitrary-term state. -/
theorem slice3ArbitraryTraceReachable :
    Slice3.Reachable (slice3StateAfter slice3ArbitraryActions.length) := by
  cases ran : Slice3.runActions initial slice3ArbitraryActions with
  | none =>
      have executes := slice3ArbitraryTraceExecutes
      simp [ran] at executes
  | some final =>
      have reachable : Slice3.Reachable final :=
        Slice3.Reachable.runActionsReachable
          Slice3.Reachable.initial ran
      simpa [slice3StateAfter, ran] using reachable

/-- The partitioned candidate skips term two and wins in term three. -/
theorem slice3FirstLeaderSkipsTerm :
    ((slice3StateAfter 19).nodes followerOne).currentTerm = 3 := by
  native_decide

/-- The later leader commits its own term-four entry. -/
theorem slice3TermFourCommitted :
    ((slice3StateAfter slice3ArbitraryActions.length).nodes followerTwo).committedLog =
      [{ term := TERM_ONE, txId := 0 },
        { term := 3, txId := 2 },
        { term := 4, txId := 3 }] := by
  native_decide

end CCFRaft.Examples
