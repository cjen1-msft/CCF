-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Slice25Model
import CCFRaft.Properties

set_option autoImplicit false

/-!
# Slice 2.5 proof properties

The proof distinguishes two protocol phases.

* Before a term-two leader is promoted, the stronger slice-two invariant is
  still available.  We additionally remember that followers never commit
  beyond node zero and that queued leader-commit snapshots remain bounded.
* After promotion, `oldLog` is the proof-only history of the term-one leader,
  while `base ++ suffix` is the unique term-two leader history.  `base` is a
  prefix of `oldLog`; every entry in `oldLog` is term one and every entry in
  `suffix` is term two.  Current node logs are prefixes of one of these two
  histories.

The histories are logical witnesses only.  They are not fields of the runtime
model and do not change the executable protocol.
-/

namespace CCFRaft.Slice25

variable {TxId : Type}
variable [DecidableEq TxId]

/-- Every entry in a list belongs to the stated term. -/
def EntriesHaveTerm (term : Nat) (entries : List (Entry TxId)) : Prop :=
  forall entry, entry ∈ entries -> entry.term = term

/-- The immutable fields of a request are an exact snapshot of a log prefix. -/
def RequestSnapshots
    (history : List (Entry TxId))
    (request : AppendEntriesRequest TxId) : Prop :=
  request.prevLogIndex <= history.length /\
    request.prevLogIndex + request.entries.length <= history.length /\
    request.prevLogTerm = termAt history request.prevLogIndex /\
    history.take (request.prevLogIndex + request.entries.length) =
      history.take request.prevLogIndex ++ request.entries

/--
A queued AppendEntries request names one of the two proof histories and never
advertises a commit prefix outside the term-two leader's canonical log.
-/
def CrossTermRequestSafe
    (oldLeader newLeader : Node)
    (oldLog newLog : List (Entry TxId))
    (request : AppendEntriesRequest TxId) : Prop :=
  Not (request.source = request.destination) /\
    ((request.term = TERM_ONE /\
        request.source = oldLeader /\
        RequestSnapshots oldLog request /\
        request.leaderCommit <= oldLog.length) \/
      (request.term = 2 /\
        request.source = newLeader /\
        RequestSnapshots newLog request /\
        request.leaderCommit <= newLog.length)) /\
    (if request.term = TERM_ONE then
      oldLog.take request.leaderCommit <+: newLog
    else if request.term = 2 then
      newLog.take request.leaderCommit <+: newLog
    else
      False) /\
    (request.entries = [] ->
      request.leaderCommit <= request.prevLogIndex)

/--
When a term-two request is catching a destination up inside the inherited
base, that destination has already entered term two and is already on the
canonical history.  This excludes an unreachable local-handler shape where a
short base-only request commits a divergent old suffix.
-/
def CrossTermRequestTargetSafe
    (state : State TxId)
    (newLog base : List (Entry TxId))
    (request : AppendEntriesRequest TxId) : Prop :=
  request.term = 2 ->
    request.prevLogIndex < base.length ->
      (state.nodes request.destination).currentTerm = 2 /\
        (state.nodes request.destination).log <+: newLog

/--
Successful responses are bounded by the history of their destination leader.
Term-one responses from election voters are additionally bounded by the
term-two leader's inherited base.
-/
def CrossTermResponseSafe
    (oldLeader newLeader : Node)
    (oldLog newLog base : List (Entry TxId))
    (electionVoters : Finset Node)
    (response : AppendEntriesResponse) : Prop :=
  Not (response.source = response.destination) /\
    (response.destination = oldLeader \/
      response.destination = newLeader) /\
    (response.term = TERM_ONE \/ response.term = 2) /\
    (response.success = true ->
      ((response.destination = oldLeader /\
          response.lastLogIndex <= oldLog.length /\
          (response.source ∈ electionVoters ->
            response.lastLogIndex <= base.length)) \/
        (response.destination = newLeader /\
          response.lastLogIndex <= newLog.length)))

/--
A response which can move the new leader's send cursor inside the inherited
base comes from a term-two node already on the canonical history.
-/
def CrossTermResponseCatchupSafe
    (state : State TxId)
    (newLeader : Node)
    (newLog base : List (Entry TxId))
    (response : AppendEntriesResponse) : Prop :=
  response.destination = newLeader ->
    response.lastLogIndex < base.length ->
      (state.nodes response.source).currentTerm = 2 /\
        (state.nodes response.source).log <+: newLog

/-- Vote requests remain term-two, self-voting candidate snapshots. -/
def CrossTermVoteRequestSafe
    (state : State TxId)
    (request : RequestVoteRequest) : Prop :=
  request.term = 2 /\
    Not (request.source = request.destination) /\
    (state.nodes request.source).currentTerm = 2 /\
    (state.nodes request.source).votedFor = some request.source

/-- A granted queued vote is backed by the voter's persistent local choice. -/
def CrossTermVoteResponseSafe
    (state : State TxId)
    (response : RequestVoteResponse) : Prop :=
  response.term = 2 /\
    Not (response.source = response.destination) /\
    (response.voteGranted = true ->
      (state.nodes response.source).votedFor = some response.destination)

/-- Every queued message is addressed correctly and carries safe proof data. -/
def CrossTermNetworkSafe
    (state : State TxId)
    (oldLeader newLeader : Node)
    (oldLog newLog base : List (Entry TxId))
    (electionVoters : Finset Node) : Prop :=
  forall destination message,
    message ∈ state.network destination ->
      message.destination = destination /\
        match message with
        | .appendEntriesRequest request =>
            CrossTermRequestSafe
              oldLeader newLeader oldLog newLog request
        | .appendEntriesResponse response =>
            CrossTermResponseSafe
              oldLeader newLeader oldLog newLog base electionVoters response
        | .requestVoteRequest request =>
            CrossTermVoteRequestSafe state request
        | .requestVoteResponse response =>
            CrossTermVoteResponseSafe state response

/-- Before promotion, followers have not committed beyond node zero. -/
def PreFollowerCommitsCovered (state : State TxId) : Prop :=
  forall node,
    (state.nodes node).committedLog <+:
      (state.nodes INITIAL_LEADER).committedLog

/-- Before promotion, queued term-one commit snapshots remain currently valid. -/
def PreQueuedCommitBounded (state : State TxId) : Prop :=
  forall destination message,
    message ∈ state.network destination ->
      match message with
      | .appendEntriesRequest request =>
          request.leaderCommit <= (state.nodes INITIAL_LEADER).commitIndex /\
            (request.entries = [] ->
              request.leaderCommit <= request.prevLogIndex)
      | _ => True

/-- The pre-promotion phase: slice two plus explicit commit-frontier facts. -/
structure PreElectionInvariant (state : State TxId) : Prop where
  /- Protocol phase. -/
  noTermTwoLeader :
    forall node,
      (state.nodes node).role = .leader ->
        Not ((state.nodes node).currentTerm = 2)
  /- Reused slice-two state and message facts. -/
  sliceTwo : CCFRaft.SystemInductiveInvariant state
  /- Commit propagation facts needed at the phase boundary. -/
  followerCommitsCovered : PreFollowerCommitsCovered state
  queuedCommitBounded : PreQueuedCommitBounded state

/--
The post-promotion invariant.  The deliberately explicit groups make each
cross-term argument visible rather than minimizing the inductive state.
-/
structure CrossTermFacts
    (state : State TxId)
    (oldLeader newLeader : Node)
    (oldLog base suffix : List (Entry TxId)) : Prop where
  /- History shape and node-log coverage. -/
  oldEntriesTermOne : EntriesHaveTerm TERM_ONE oldLog
  suffixEntriesTermTwo : EntriesHaveTerm 2 suffix
  basePrefixOld : base <+: oldLog
  newLeaderLog :
    (state.nodes newLeader).log = base ++ suffix
  logsCovered :
    forall node,
      (state.nodes node).log <+: oldLog \/
        (state.nodes node).log <+: base ++ suffix

  /- Local bounds and represented terms. -/
  commitIndicesBounded : CommitIndicesBounded state
  currentTermsValid : CurrentTermsValid state
  entriesDoNotExceedCurrentTerm :
    forall node entry,
      entry ∈ (state.nodes node).log ->
        entry.term <= (state.nodes node).currentTerm

  /- The two possible leaders and the frozen election quorum. -/
  oldLeaderIsInitial : oldLeader = INITIAL_LEADER
  leadersDistinct : Not (oldLeader = newLeader)
  oldLeaderOwnsHistory :
    (state.nodes oldLeader).role = .leader ->
      (state.nodes oldLeader).currentTerm = TERM_ONE ->
        (state.nodes oldLeader).log = oldLog
  newLeaderRole : (state.nodes newLeader).role = .leader
  newLeaderTerm : (state.nodes newLeader).currentTerm = 2
  termOneLeaderUnique :
    forall node,
      (state.nodes node).role = .leader ->
      (state.nodes node).currentTerm = TERM_ONE ->
        node = oldLeader
  termTwoLeaderUnique :
    forall node,
      (state.nodes node).role = .leader ->
      (state.nodes node).currentTerm = 2 ->
        node = newLeader
  electionMajority :
    (state.nodes newLeader).votesGranted.card * 2 > NODE_COUNT
  electionVotersChooseLeader :
    forall voter,
      voter ∈ (state.nodes newLeader).votesGranted ->
        (state.nodes voter).votedFor = some newLeader
  candidatesSelfVote :
    CandidatesSelfVote state
  votedForTermTwo : VotedForTermTwo state
  votesGrantedSound :
    forall candidate voter,
      voter ∈ (state.nodes candidate).votesGranted ->
        (state.nodes voter).votedFor = some candidate

  /- Replication snapshots and leader-local progress indices. -/
  networkSafe :
    CrossTermNetworkSafe
      state oldLeader newLeader oldLog (base ++ suffix) base
        (state.nodes newLeader).votesGranted
  oldSentIndicesBounded :
    forall node,
      (state.nodes oldLeader).sentIndex node <= oldLog.length
  oldMatchIndicesBounded :
    forall node,
      (state.nodes oldLeader).matchIndex node <= oldLog.length
  oldElectionMatchBound :
    forall voter,
      voter ∈ (state.nodes newLeader).votesGranted ->
        (state.nodes oldLeader).matchIndex voter <= base.length
  newSentIndicesBounded :
    forall node,
      (state.nodes newLeader).sentIndex node <=
        (base ++ suffix).length
  newMatchIndicesBounded :
    forall node,
      (state.nodes newLeader).matchIndex node <=
        (base ++ suffix).length

  /-
  Every old-term quorum is contained in the inherited base.  This is the
  majority-intersection fact that prevents node zero from committing a
  divergent term-one suffix after the term-two election.
  -/
  oldMajoritiesCovered :
    forall index,
      index <= oldLog.length ->
      hasMajorityAt state oldLeader index ->
        index <= base.length

  /- All committed prefixes fit in the unique term-two leader history. -/
  committedLogsCovered :
    forall node,
      (state.nodes node).committedLog <+:
        (state.nodes newLeader).log
  /-
  A send cursor below the inherited base is only produced by a response from
  a term-two node already following the canonical history.
  -/
  newCatchupLogs :
    forall node,
      (state.nodes newLeader).sentIndex node < base.length ->
        (state.nodes node).currentTerm = 2 /\
          (state.nodes node).log <+: base ++ suffix
  queuedRequestTargetsSafe :
    forall destination message,
      message ∈ state.network destination ->
        match message with
        | .appendEntriesRequest request =>
            CrossTermRequestTargetSafe state (base ++ suffix) base request
        | _ => True
  queuedResponseCatchupSafe :
    forall destination message,
      message ∈ state.network destination ->
        match message with
        | .appendEntriesResponse response =>
            CrossTermResponseCatchupSafe
              state newLeader (base ++ suffix) base response
        | _ => True

/-- Existentially package the proof-only post-election histories. -/
def CrossTermInvariant (state : State TxId) : Prop :=
  Exists fun oldLeader =>
    Exists fun newLeader =>
      Exists fun oldLog =>
        Exists fun base =>
          Exists fun suffix =>
            CrossTermFacts
              state oldLeader newLeader oldLog base suffix

/-- The two documented phases form the slice-2.5 inductive invariant. -/
inductive SystemInductiveInvariant (state : State TxId) : Prop
  | pre (invariant : PreElectionInvariant state)
  | crossTerm (invariant : CrossTermInvariant state)

/-- A CCF-style statement: every term-two leader contains node zero's commit. -/
def LeaderCompleteness (state : State TxId) : Prop :=
  forall leader,
    (state.nodes leader).role = .leader ->
    (state.nodes leader).currentTerm = 2 ->
      (state.nodes INITIAL_LEADER).committedLog <+:
        (state.nodes leader).log

/-- Public safety facts exported by the slice-2.5 proof layer. -/
structure ConsensusSafety (state : State TxId) : Prop where
  committedLogsPrefix : CommittedLogsPrefix state
  logMatching : LogMatching state
  monoLog : MonoLog state
  electionSafety : ElectionSafety state
  leaderCompleteness : LeaderCompleteness state

end CCFRaft.Slice25
