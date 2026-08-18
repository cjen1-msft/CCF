-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model

set_option autoImplicit false

namespace CCFRaft

variable {TxId : Type}
variable [DecidableEq TxId]

/-- Every node's commit index points within its current log. -/
def CommitIndicesBounded (state : State TxId) : Prop :=
  forall node,
    (state.nodes node).commitIndex <= (state.nodes node).log.length

/-- Every node log is a prefix of the fixed leader's log. -/
def LogsPrefixLeader (state : State TxId) : Prop :=
  forall node,
    (state.nodes node).log <+: (state.nodes INITIAL_LEADER).log

/-- Every reachable log entry belongs to the single modeled term. -/
def TermsAreOne (state : State TxId) : Prop :=
  forall node entry,
    entry ∈ (state.nodes node).log ->
      entry.term = TERM_ONE

/-- No transaction ID appears twice in the leader log. -/
def LeaderTxIdsUnique (state : State TxId) : Prop :=
  ((state.nodes INITIAL_LEADER).log.map Entry.txId).Nodup

/-- Every leader-log transaction was allocated by the external client input. -/
def LeaderTxIdsSubmitted (state : State TxId) : Prop :=
  forall entry,
    entry ∈ (state.nodes INITIAL_LEADER).log ->
      entry.txId ∈ state.submittedTxIds

/-- A queued request is a faithful snapshot of a leader log prefix. -/
def RequestMatchesLeader
    (state : State TxId)
    (request : AppendEntriesRequest TxId) : Prop :=
  request.source = INITIAL_LEADER /\
    Not (request.destination = INITIAL_LEADER) /\
    request.term = TERM_ONE /\
    request.prevLogIndex <= (state.nodes INITIAL_LEADER).log.length /\
    request.prevLogIndex + request.entries.length <=
      (state.nodes INITIAL_LEADER).log.length /\
    request.prevLogTerm =
      termAt (state.nodes INITIAL_LEADER).log request.prevLogIndex /\
    (state.nodes INITIAL_LEADER).log.take
        (request.prevLogIndex + request.entries.length) =
      (state.nodes INITIAL_LEADER).log.take request.prevLogIndex ++ request.entries

/-- A queued response targets the leader and stays within its current log. -/
def ResponseMatchesLeader
    (state : State TxId)
    (response : AppendEntriesResponse) : Prop :=
  response.destination = INITIAL_LEADER /\
    Not (response.source = INITIAL_LEADER) /\
    response.term ∈ ({TERM_ONE, 2} : Finset Nat) /\
    response.lastLogIndex <= (state.nodes INITIAL_LEADER).log.length /\
    (response.success = true ->
      (state.nodes INITIAL_LEADER).log.take response.lastLogIndex =
        (state.nodes response.source).log.take response.lastLogIndex)

/-- Make request-snapshot consistency executable for bounded simulation. -/
instance (state : State TxId) (request : AppendEntriesRequest TxId) :
    Decidable (RequestMatchesLeader state request) := by
  unfold RequestMatchesLeader
  infer_instance

/-- Make response-snapshot consistency executable for bounded simulation. -/
instance (state : State TxId) (response : AppendEntriesResponse) :
    Decidable (ResponseMatchesLeader state response) := by
  unfold ResponseMatchesLeader
  infer_instance

/-- Every queued message has the right destination and safe snapshot metadata. -/
def QueuedRequestsMatchLeader (state : State TxId) : Prop :=
  forall destination message,
    message ∈ state.network destination ->
      message.destination = destination /\
        match message with
        | .appendEntriesRequest request =>
            RequestMatchesLeader state request
        | .appendEntriesResponse response =>
            ResponseMatchesLeader state response
        | .requestVoteRequest _ => True
        | .requestVoteResponse _ => True

/-- A queued vote request is a current snapshot of its candidate's log. -/
def RequestVoteRequestSafe
    (state : State TxId)
    (request : RequestVoteRequest) : Prop :=
  request.term = 2 /\
    Not (request.source = request.destination) /\
    (state.nodes request.source).currentTerm = 2 /\
    (state.nodes request.source).votedFor = some request.source /\
    request.lastLogTerm =
      termAt
        (state.nodes request.source).log
        (state.nodes request.source).log.length /\
    request.lastLogIndex = (state.nodes request.source).log.length

/-- A queued granted vote records a voter whose log is a candidate prefix. -/
def RequestVoteResponseSafe
    (state : State TxId)
    (response : RequestVoteResponse) : Prop :=
  response.term = 2 /\
    Not (response.source = response.destination) /\
    (state.nodes response.source).currentTerm = 2 /\
    (state.nodes response.destination).currentTerm = 2 /\
    (response.voteGranted = true ->
      (state.nodes response.source).votedFor = some response.destination /\
        (state.nodes response.source).log <+:
          (state.nodes response.destination).log)

/-- Make RequestVote request snapshot checks executable. -/
instance (state : State TxId) (request : RequestVoteRequest) :
    Decidable (RequestVoteRequestSafe state request) := by
  unfold RequestVoteRequestSafe
  infer_instance

/-- Make RequestVote response snapshot checks executable. -/
instance (state : State TxId) (response : RequestVoteResponse) :
    Decidable (RequestVoteResponseSafe state response) := by
  unfold RequestVoteResponseSafe
  infer_instance

/-- Every queued vote message satisfies its snapshot correspondence facts. -/
def QueuedVoteMessagesSafe (state : State TxId) : Prop :=
  forall destination message,
    message ∈ state.network destination ->
      match message with
      | .requestVoteRequest request => RequestVoteRequestSafe state request
      | .requestVoteResponse response => RequestVoteResponseSafe state response
      | _ => True

/-- The leader never records sending past the end of its log. -/
def SentIndicesBounded (state : State TxId) : Prop :=
  forall node,
    (state.nodes INITIAL_LEADER).sentIndex node <=
      (state.nodes INITIAL_LEADER).log.length

/-- The leader never records a follower match past its own log. -/
def MatchIndicesBounded (state : State TxId) : Prop :=
  forall node,
    (state.nodes INITIAL_LEADER).matchIndex node <=
      (state.nodes INITIAL_LEADER).log.length

/-- Nodes remain in either the original term or the single election term. -/
def CurrentTermsValid (state : State TxId) : Prop :=
  forall node,
    (state.nodes node).currentTerm = TERM_ONE \/
      (state.nodes node).currentTerm = 2

/-- Any leader still in term one is the initial node-zero leader. -/
def TermOneLeaderIsInitial (state : State TxId) : Prop :=
  forall node,
    (state.nodes node).role = .leader ->
      (state.nodes node).currentTerm = TERM_ONE ->
        node = INITIAL_LEADER

/-- While node zero remains in term one, it remains the original leader. -/
def InitialNodeTermOneIsLeader (state : State TxId) : Prop :=
  (state.nodes INITIAL_LEADER).currentTerm = TERM_ONE ->
    (state.nodes INITIAL_LEADER).role = .leader

/-- Every candidate is in term two and has voted for itself. -/
def CandidatesSelfVote (state : State TxId) : Prop :=
  forall node,
    (state.nodes node).role = .candidate ->
      (state.nodes node).currentTerm = 2 /\
        (state.nodes node).votedFor = some node /\
        node ∈ (state.nodes node).votesGranted

/-- Recording any vote implies that voter has entered term two. -/
def VotedForTermTwo (state : State TxId) : Prop :=
  forall voter candidate,
    (state.nodes voter).votedFor = some candidate ->
      (state.nodes voter).currentTerm = 2

/-- Every recorded vote is backed by the voter's local vote and log relation. -/
def VotesGrantedSound (state : State TxId) : Prop :=
  forall candidate voter,
    voter ∈ (state.nodes candidate).votesGranted ->
      (state.nodes candidate).currentTerm = 2 /\
      (state.nodes voter).votedFor = some candidate /\
        (state.nodes voter).log <+: (state.nodes candidate).log

/-- Every term-two leader was promoted from a locally recorded majority. -/
def TermTwoLeadersHaveMajority (state : State TxId) : Prop :=
  forall node,
    (state.nodes node).role = .leader ->
      (state.nodes node).currentTerm = 2 ->
        hasElectionMajority state node

/-- A leader match index denotes a prefix actually present on that follower. -/
def MatchIndexDescribesPrefix (state : State TxId) : Prop :=
  forall node,
    (state.nodes INITIAL_LEADER).log.take
        ((state.nodes INITIAL_LEADER).matchIndex node) =
      (state.nodes node).log.take
        ((state.nodes INITIAL_LEADER).matchIndex node)

/-- A nonzero node-zero commit frontier is still backed by a current majority. -/
def InitialLeaderCommitHasMajority (state : State TxId) : Prop :=
  (state.nodes INITIAL_LEADER).commitIndex = 0 \/
    hasMajorityAt state INITIAL_LEADER (state.nodes INITIAL_LEADER).commitIndex

/-- Node zero never returns to candidacy after its fixed term-one leadership. -/
def InitialNodeNotCandidate (state : State TxId) : Prop :=
  Not ((state.nodes INITIAL_LEADER).role = .candidate)

/-- No two distinct nodes lead in the same term. -/
def ElectionSafety (state : State TxId) : Prop :=
  forall left right,
    (state.nodes left).role = .leader ->
      (state.nodes right).role = .leader ->
        (state.nodes left).currentTerm =
          (state.nodes right).currentTerm ->
          left = right

/-- Every term-two leader contains node zero's term-one committed prefix. -/
def TermTwoLeaderCompleteness (state : State TxId) : Prop :=
  forall leader,
    (state.nodes leader).role = .leader ->
      (state.nodes leader).currentTerm = 2 ->
        (state.nodes INITIAL_LEADER).committedLog <+:
          (state.nodes leader).log

/-- Supporting facts proved together because actions preserve them jointly. -/
structure SystemInductiveInvariant (state : State TxId) : Prop where
  /-- Within term --/
  commitIndicesBounded : CommitIndicesBounded state
  logsPrefixLeader : LogsPrefixLeader state
  termsAreOne : TermsAreOne state
  leaderTxIdsUnique : LeaderTxIdsUnique state
  leaderTxIdsSubmitted : LeaderTxIdsSubmitted state
  queuedRequestsMatchLeader : QueuedRequestsMatchLeader state
  queuedVoteMessagesSafe : QueuedVoteMessagesSafe state
  sentIndicesBounded : SentIndicesBounded state
  matchIndicesBounded : MatchIndicesBounded state
  /-- over one term --/
  currentTermsValid : CurrentTermsValid state
  termOneLeaderIsInitial : TermOneLeaderIsInitial state
  initialNodeTermOneIsLeader : InitialNodeTermOneIsLeader state
  candidatesSelfVote : CandidatesSelfVote state
  votedForTermTwo : VotedForTermTwo state
  votesGrantedSound : VotesGrantedSound state
  termTwoLeadersHaveMajority : TermTwoLeadersHaveMajority state
  matchIndexDescribesPrefix : MatchIndexDescribesPrefix state
  initialLeaderCommitHasMajority : InitialLeaderCommitHasMajority state
  initialNodeNotCandidate : InitialNodeNotCandidate state

/-- Every node's committed prefix can only grow across one transition. -/
def CommittedLogMonotonicity
    (before after : State TxId) : Prop :=
  forall node,
    (before.nodes node).committedLog <+:
      (after.nodes node).committedLog

/-- Any two node-local committed logs are prefix-comparable. -/
def CommittedLogsPrefix (state : State TxId) : Prop :=
  forall left right,
    (state.nodes left).committedLog <+:
        (state.nodes right).committedLog \/
      (state.nodes right).committedLog <+:
        (state.nodes left).committedLog

/-- Equal index and term identify the same complete log prefix. -/
def LogMatching (state : State TxId) : Prop :=
  forall left right index leftEntry rightEntry,
    entryAt? (state.nodes left).log index = some leftEntry ->
      entryAt? (state.nodes right).log index = some rightEntry ->
        leftEntry.term = rightEntry.term ->
          (state.nodes left).log.take index =
            (state.nodes right).log.take index

/-- Equal index and term identify the same opaque transaction ID. -/
def SameIndexSameTermSameTxId (state : State TxId) : Prop :=
  forall left right index leftEntry rightEntry,
    entryAt? (state.nodes left).log index = some leftEntry ->
      entryAt? (state.nodes right).log index = some rightEntry ->
        leftEntry.term = rightEntry.term ->
          leftEntry.txId = rightEntry.txId

/-- Entry terms do not decrease as log indices increase. -/
def MonoLog (state : State TxId) : Prop :=
  forall node earlier later earlierEntry laterEntry,
    earlier < later ->
      entryAt? (state.nodes node).log earlier = some earlierEntry ->
        entryAt? (state.nodes node).log later = some laterEntry ->
          earlierEntry.term <= laterEntry.term

/-- A frame property saying an action changes only its acting node. -/
def OtherNodesUnchanged
    (acting : Node)
    (before after : State TxId) : Prop :=
  forall node,
    Not (node = acting) ->
      after.nodes node = before.nodes node

/-- The public state-safety guarantees exported by slice two. -/
structure ConsensusSafety (state : State TxId) : Prop where
  committedLogsPrefix : CommittedLogsPrefix state
  logMatching : LogMatching state
  sameIndexSameTermSameTxId : SameIndexSameTermSameTxId state
  monoLog : MonoLog state
  electionSafety : ElectionSafety state
  termTwoLeaderCompleteness : TermTwoLeaderCompleteness state

end CCFRaft
