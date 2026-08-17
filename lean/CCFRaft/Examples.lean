-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs

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
  next initial (.clientRequest LEADER 0)

/-- State after sending the entry to the first follower. -/
def sentOne : RaftState :=
  next requested (.appendEntries LEADER followerOne 1)

/-- State after the first follower appends the entry and sends an ACK. -/
def receivedOne : RaftState :=
  next sentOne (.receive LEADER followerOne)

/-- State after the leader records the first follower's ACK. -/
def ackedOne : RaftState :=
  next receivedOne (.receive followerOne LEADER)

/-- State after sending the entry to the second follower. -/
def sentTwo : RaftState :=
  next ackedOne (.appendEntries LEADER followerTwo 1)

/-- State after the second follower appends the entry and sends an ACK. -/
def receivedTwo : RaftState :=
  next sentTwo (.receive LEADER followerTwo)

/-- State after the leader records enough ACKs for a majority. -/
def ackedTwo : RaftState :=
  next receivedTwo (.receive followerTwo LEADER)

/-- State after the leader advances its commit index to one. -/
def committed : RaftState :=
  next ackedTwo (.advanceCommitIndex LEADER)

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
    (committed.nodes LEADER).committedLog =
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
  next initial (.appendEntries LEADER followerOne 0)

/-- The follower advances to term two while the old heartbeat remains queued. -/
def timedOutWithHeartbeat : RaftState :=
  next heartbeatBeforeTimeout (.timeout followerOne)

/-- Receiving the stale heartbeat produces a term-two NACK for node zero. -/
def newerNackQueued : RaftState :=
  next timedOutWithHeartbeat (.receive LEADER followerOne)

/-- An overloaded NACK may be handled or may first trigger `UpdateTerm`. -/
theorem newerNackMatchesTlaNondeterminism :
    Enabled newerNackQueued (.updateTerm followerOne LEADER) /\
      Enabled newerNackQueued (.receive followerOne LEADER) := by
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
    LEADER,
    TERM_ONE
  ]

/-- A stale NACK still backs up `sentIndex`; its term is match metadata. -/
theorem staleNackIsHandled :
    let nodeState : NodeState TxId :=
      { initialNodeState (TxId := TxId) LEADER with
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
        destination := LEADER }
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
    LEADER,
    TERM_ONE
  ]

/-- A current leader cannot consume a successful ACK from a future term. -/
theorem futureAckRequiresTermUpdateAtLeader :
    let leader : NodeState TxId :=
      initialNodeState (TxId := TxId) LEADER
    let response : AppendEntriesResponse :=
      { term := 2
        success := true
        lastLogIndex := 0
        source := followerTwo
        destination := LEADER }
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
    LEADER,
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
    (electedTermTwo.nodes LEADER).committedLog <+:
      (electedTermTwo.nodes followerOne).log := by
  exact
    reachableTermTwoLeaderCompleteness termTwoElectionReachable
      followerOne (by decide) (by decide)

end CCFRaft.Examples
