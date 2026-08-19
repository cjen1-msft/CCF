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

/-- No two distinct nodes lead in the same term. -/
def ElectionSafety (state : State TxId) : Prop :=
  forall left right,
    (state.nodes left).role = .leader ->
      (state.nodes right).role = .leader ->
        (state.nodes left).currentTerm =
          (state.nodes right).currentTerm ->
          left = right

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

/-- Entry terms do not decrease as log indices increase. -/
def MonoLog (state : State TxId) : Prop :=
  forall node earlier later earlierEntry laterEntry,
    earlier < later ->
      entryAt? (state.nodes node).log earlier = some earlierEntry ->
        entryAt? (state.nodes node).log later = some laterEntry ->
          earlierEntry.term <= laterEntry.term

end CCFRaft

/-!
# Arbitrary-term Raft proof properties

Arbitrary-term Raft permits arbitrarily many elections, so the proof cannot
name one old history and one new history. The invariant below keeps the core
safety statements explicit and records the state-local evidence used by the
Raft election and replication arguments.

The proof-only vote history is not runtime state.  It remembers the unique
candidate selected by each voter in each term after `votedFor` is cleared by a
later `UpdateTerm`.
-/

namespace CCFRaft

variable {TxId : Type}
variable [DecidableEq TxId]

/-- A proof-only record of the candidate selected by a voter in a term. -/
abbrev VoteHistory := Node -> Nat -> Option Node

/-- A proof-only canonical owner for each term once that term is elected. -/
abbrev TermOwners := Nat -> Option Node

/-- Immutable proof-only data frozen when one candidate is promoted. -/
structure ElectionRecord (TxId : Type) where
  leader : Node
  quorum : Finset Node
  promotionLog : List (Entry TxId)
  candidateLog : Node -> List (Entry TxId)
  voterLog : Node -> List (Entry TxId)

/-- At most one frozen promotion record is retained for each term. -/
abbrev ElectionHistory (TxId : Type) :=
  Nat -> Option (ElectionRecord TxId)

/-- Immutable proof-only evidence retained after a successful ACK is dequeued. -/
structure ProcessedAckSnapshot (TxId : Type) where
  term : Nat
  index : Nat
  history : List (Entry TxId)

/-- Latest processed successful ACK evidence for each leader/peer pair. -/
abbrev ProcessedAckHistory (TxId : Type) :=
  Node -> Node -> Option (ProcessedAckSnapshot TxId)

/--
Proof-only evidence for one actual commit.  `commitFrontier` is the original
current-term quorum frontier; `supportedLength` may be a shorter prefix copied
to a follower without changing the actual commit term or ACK evidence.
-/
structure CommitEvidence (TxId : Type) where
  commitTerm : Nat
  committer : Node
  history : List (Entry TxId)
  commitFrontier : Nat
  supportedLength : Nat
  ackQuorum : Finset Node
  memberHistory : Node -> List (Entry TxId)

/-- Retain the same actual commit evidence while supporting a shorter prefix. -/
def CommitEvidence.restrict
    (evidence : CommitEvidence TxId)
    (supportedLength : Nat) :
    CommitEvidence TxId :=
  { evidence with supportedLength }

/-- Current proof-only commit evidence retained by each node. -/
abbrev NodeCommitEvidence (TxId : Type) :=
  Node -> Option (CommitEvidence TxId)

/-- Commit evidence advertised by each immutable AppendEntries request. -/
abbrev RequestCommitEvidence (TxId : Type) :=
  AppendEntriesRequest TxId -> Option (CommitEvidence TxId)

/-- Entry terms do not decrease inside one proof-only history. -/
def MonoHistory (history : List (Entry TxId)) : Prop :=
  forall earlier later earlierEntry laterEntry,
    earlier < later ->
      entryAt? history earlier = some earlierEntry ->
        entryAt? history later = some laterEntry ->
          earlierEntry.term <= laterEntry.term

/-- One immutable log snapshot agrees with the canonical history of each entry. -/
def HistoryCanonical
    (canonicalHistory : Nat -> List (Entry TxId))
    (history : List (Entry TxId)) : Prop :=
  forall index entry,
    entryAt? history index = some entry ->
      entryAt? (canonicalHistory entry.term) index = some entry /\
        history.take index =
          (canonicalHistory entry.term).take index

/-- Every log entry is from a term already observed by its local node. -/
def EntriesDoNotExceedCurrentTerm (state : State TxId) : Prop :=
  forall node entry,
    entry ∈ (state.nodes node).log ->
      entry.term <= (state.nodes node).currentTerm

/-- Node terms never fall below the bootstrap term. -/
def CurrentTermsPositive (state : State TxId) : Prop :=
  forall node, TERM_ONE <= (state.nodes node).currentTerm

/-- Candidates start each election with exactly their own persistent vote. -/
def CandidatesSelfVote (state : State TxId) : Prop :=
  forall node,
    (state.nodes node).role = .candidate ->
      (state.nodes node).votedFor = some node /\
        node ∈ (state.nodes node).votesGranted

/-- Every runtime candidacy is for a post-bootstrap term. -/
def CandidatesAboveBootstrap (state : State TxId) : Prop :=
  forall node,
    (state.nodes node).role = .candidate ->
      TERM_ONE < (state.nodes node).currentTerm

/-- Active leaders are either the bootstrap leader or retain their election quorum. -/
def LeadersHaveElectionMajority (state : State TxId) : Prop :=
  forall node,
    (state.nodes node).role = .leader ->
      ((node = INITIAL_LEADER /\
          (state.nodes node).currentTerm = TERM_ONE) \/
        hasElectionMajority state node)

/-- Every active leader keeps both replication cursors inside its own log. -/
def LeaderProgressBounded (state : State TxId) : Prop :=
  forall leader,
    (state.nodes leader).role = .leader ->
      forall peer,
        (state.nodes leader).sentIndex peer <=
            (state.nodes leader).log.length /\
          (state.nodes leader).matchIndex peer <=
            (state.nodes leader).log.length

/--
The proof history agrees with the runtime vote in the current term, is empty
in future terms, and justifies every vote counted by an active candidate or
leader.
-/
structure VoteHistoryFacts
    (state : State TxId)
    (history : VoteHistory) : Prop where
  bootstrapEmpty :
    forall voter,
      history voter TERM_ONE = none
  current :
    forall voter,
      history voter (state.nodes voter).currentTerm =
        (state.nodes voter).votedFor
  future :
    forall voter term,
      (state.nodes voter).currentTerm < term ->
        history voter term = none
  counted :
    forall candidate voter,
      ((state.nodes candidate).role = .candidate \/
        (state.nodes candidate).role = .leader) ->
      voter ∈ (state.nodes candidate).votesGranted ->
        history voter (state.nodes candidate).currentTerm = some candidate

/-- The unique synthetic key used to retain a granted vote after dequeue. -/
def grantedVoteKey
    (voter : Node)
    (term : Nat)
    (candidate : Node) :
    RequestVoteResponse :=
  { term
    voteGranted := true
    source := voter
    destination := candidate }

/-- The immutable fields of an AppendEntries request snapshot one history. -/
def RequestSnapshots
    (history : List (Entry TxId))
    (request : AppendEntriesRequest TxId) : Prop :=
  request.prevLogIndex + request.entries.length <= history.length /\
    request.prevLogTerm = termAt history request.prevLogIndex /\
    history.take (request.prevLogIndex + request.entries.length) =
      history.take request.prevLogIndex ++ request.entries

/--
An advertised commit is still represented by the source's current committed
log.  This survives delayed delivery because committed logs are append-only.
-/
def RequestCommitStillPresent
    (state : State TxId)
    (history : List (Entry TxId))
    (request : AppendEntriesRequest TxId) : Prop :=
  history.take request.leaderCommit <+:
    (state.nodes request.source).committedLog

/--
A successful response remembers an immutable source-log history.  While the
response is processable by its same-term destination leader, that history is
still a prefix of the leader's current append-only log.
-/
def SuccessfulResponseSnapshot
    (state : State TxId)
    (history : List (Entry TxId))
    (response : AppendEntriesResponse) : Prop :=
  response.success = true ->
    response.lastLogIndex <= history.length /\
      response.term <=
        (state.nodes response.destination).currentTerm /\
      (response.term =
          (state.nodes response.destination).currentTerm ->
        (state.nodes response.destination).role = .leader /\
          history <+: (state.nodes response.destination).log)

/--
Queued messages retain their immutable log/vote snapshots.  The witness
functions are proof-only maps keyed by complete message values.
-/
structure NetworkHistoryFacts
    (state : State TxId)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (voteRequestHistory : RequestVoteRequest -> List (Entry TxId))
    (voteCandidateHistory : RequestVoteResponse -> List (Entry TxId))
    (voteVoterHistory : RequestVoteResponse -> List (Entry TxId))
    (votes : VoteHistory) : Prop where
  addressed :
    forall destination message,
      message ∈ state.network destination ->
        message.destination = destination
  appendRequest :
    forall destination request,
      Message.appendEntriesRequest request ∈ state.network destination ->
        RequestSnapshots (appendHistory request) request /\
          request.leaderCommit <= (appendHistory request).length /\
          (request.entries = [] ->
            request.leaderCommit <= request.prevLogIndex) /\
          RequestCommitStillPresent state (appendHistory request) request
  appendResponse :
    forall destination response,
      Message.appendEntriesResponse response ∈ state.network destination ->
        SuccessfulResponseSnapshot
          state (responseHistory response) response
  voteRequest :
    forall destination request,
      Message.requestVoteRequest request ∈ state.network destination ->
        request.lastLogIndex = (voteRequestHistory request).length /\
          request.lastLogTerm =
            termAt
              (voteRequestHistory request)
              (voteRequestHistory request).length /\
          TERM_ONE < request.term /\
          request.term <=
            (state.nodes request.source).currentTerm /\
          (request.term =
              (state.nodes request.source).currentTerm ->
            ((state.nodes request.source).role = .candidate \/
              (state.nodes request.source).role = .leader) ->
              voteRequestHistory request <+:
                (state.nodes request.source).log)
  voteResponse :
    forall destination response,
      Message.requestVoteResponse response ∈ state.network destination ->
        response.voteGranted = true ->
          response.term <=
              (state.nodes response.destination).currentTerm /\
            votes response.source response.term = some response.destination /\
            voteLogUpToDate
              { (state.nodes response.source) with
                log := voteVoterHistory response }
              { term := response.term
                lastLogTerm :=
                  termAt
                    (voteCandidateHistory response)
                    (voteCandidateHistory response).length
                lastLogIndex := (voteCandidateHistory response).length
                source := response.destination
                destination := response.source }

/-- Whether a granted same-term response is still queued at its candidate. -/
def queuedGrantedVote
    (state : State TxId)
    (candidate voter : Node) : Prop :=
  Exists fun response =>
    Message.requestVoteResponse response ∈ state.network candidate /\
      response.voteGranted = true /\
      response.term = (state.nodes candidate).currentTerm /\
      response.source = voter /\
      response.destination = candidate

/--
Processed votes and granted same-term responses still in flight are two
representations of the same election evidence.
-/
noncomputable def effectiveElectionVoters
    (state : State TxId)
    (candidate : Node) : Finset Node := by
  classical
  exact
    Finset.univ.filter fun voter =>
      voter ∈ (state.nodes candidate).votesGranted \/
        queuedGrantedVote state candidate voter

/-- A strict quorum of processed or queued granted votes. -/
def hasEffectiveElectionMajority
    (state : State TxId)
    (candidate : Node) : Prop :=
  (effectiveElectionVoters state candidate).card * 2 > NODE_COUNT

noncomputable instance
    (state : State TxId)
    (candidate : Node) :
    Decidable (hasEffectiveElectionMajority state candidate) := by
  exact Classical.propDecidable _

/--
A node is currently eligible when the exact canonical RequestVote generated
from the candidate's current term and log would pass the grant predicate.
-/
def currentlyEligibleElectionVoter
    (state : State TxId)
    (candidate voter : Node) : Prop :=
  let request := makeRequestVoteRequest state candidate voter
  request.term = (state.nodes voter).currentTerm /\
    voteLogUpToDate (state.nodes voter) request /\
    ((state.nodes voter).votedFor = none \/
      (state.nodes voter).votedFor = some candidate)

/--
Potential voters combine persistent processed/in-flight evidence with
nodes whose current state would grant the candidate's canonical request.
This is the source-side election evidence which exists before send or grant.
-/
noncomputable def potentialElectionVoters
    (state : State TxId)
    (candidate : Node) : Finset Node := by
  classical
  exact
    Finset.univ.filter fun voter =>
      voter ∈ effectiveElectionVoters state candidate \/
        currentlyEligibleElectionVoter state candidate voter

/-- A strict quorum of persistent or currently eligible election voters. -/
def hasPotentialElectionMajority
    (state : State TxId)
    (candidate : Node) : Prop :=
  (potentialElectionVoters state candidate).card * 2 > NODE_COUNT

noncomputable instance
    (state : State TxId)
    (candidate : Node) :
    Decidable (hasPotentialElectionMajority state candidate) := by
  exact Classical.propDecidable _

/--
Election supporters after arbitrary local term/vote updates.  Effective
supporters retain their frozen vote snapshots; all other supporters are
classified only by the log-freshness check which a canonical vote request
would perform.
-/
noncomputable def relaxedElectionVoters
    (state : State TxId)
    (candidate : Node) : Finset Node := by
  classical
  let request := makeRequestVoteRequest state candidate candidate
  exact
    Finset.univ.filter fun voter =>
      voter ∈ effectiveElectionVoters state candidate \/
        ((state.nodes voter).currentTerm <=
            (state.nodes candidate).currentTerm /\
          voteLogUpToDate (state.nodes voter) request)

/--
Supporters for a future election term.  The candidate itself is always a
supporter; every other supporter must currently be no newer than the target
term and consider the unchanged candidate log up to date.
-/
noncomputable def futureElectionVoters
    (state : State TxId)
    (candidate : Node)
    (targetTerm : Nat) : Finset Node := by
  classical
  let request :=
    { makeRequestVoteRequest state candidate candidate with
      term := targetTerm }
  exact
    Finset.univ.filter fun voter =>
      voter = candidate \/
        ((state.nodes voter).currentTerm <= targetTerm /\
          voteLogUpToDate (state.nodes voter) request)

/--
Each processed or queued vote has a persistent proof-only snapshot.  The
synthetic key lets response dequeue retain the candidate/voter histories and
their original RequestVote up-to-date check without adding runtime state.
-/
def GrantedVoteSnapshots
    (state : State TxId)
    (votes : VoteHistory)
    (voteCandidateHistory : RequestVoteResponse -> List (Entry TxId))
    (voteVoterHistory : RequestVoteResponse -> List (Entry TxId)) : Prop :=
  forall candidate voter,
    ((state.nodes candidate).role = .candidate \/
      (state.nodes candidate).role = .leader) ->
    voter ∈ effectiveElectionVoters state candidate ->
      let response :=
        grantedVoteKey
          voter (state.nodes candidate).currentTerm candidate
      votes voter (state.nodes candidate).currentTerm = some candidate /\
        (voter = candidate \/
          (voteCandidateHistory response <+: (state.nodes candidate).log /\
            response.term <= (state.nodes voter).currentTerm /\
            voteLogUpToDate
              { (state.nodes voter) with
                log := voteVoterHistory response }
              { term := response.term
                lastLogTerm :=
                  termAt
                    (voteCandidateHistory response)
                    (voteCandidateHistory response).length
                lastLogIndex := (voteCandidateHistory response).length
                source := response.destination
                destination := response.source }))

/-- Active election snapshots retain canonical agreement for both log views. -/
def GrantedVoteCanonicalSnapshots
    (state : State TxId)
    (canonicalHistory : Nat -> List (Entry TxId))
    (voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)) : Prop :=
  forall candidate voter,
    ((state.nodes candidate).role = .candidate \/
      (state.nodes candidate).role = .leader) ->
    voter ∈ effectiveElectionVoters state candidate ->
      voter = candidate \/
        (HistoryCanonical
            canonicalHistory
            (voteCandidateHistory
              (grantedVoteKey
                voter (state.nodes candidate).currentTerm candidate)) /\
          MonoHistory
            (voteCandidateHistory
              (grantedVoteKey
                voter (state.nodes candidate).currentTerm candidate)) /\
          HistoryCanonical
            canonicalHistory
            (voteVoterHistory
              (grantedVoteKey
                voter (state.nodes candidate).currentTerm candidate)) /\
          MonoHistory
            (voteVoterHistory
              (grantedVoteKey
                voter (state.nodes candidate).currentTerm candidate)))

/-- Voters whose retained term-indexed choices name one candidate. -/
noncomputable def historicalElectionVoters
    (votes : VoteHistory)
    (term : Nat)
    (candidate : Node) : Finset Node := by
  classical
  exact Finset.univ.filter fun voter =>
    votes voter term = some candidate

/-- A strict quorum of persistent voter choices elected one term owner. -/
def hasHistoricalElectionMajority
    (votes : VoteHistory)
    (term : Nat)
    (candidate : Node) : Prop :=
  (historicalElectionVoters votes term candidate).card * 2 > NODE_COUNT

noncomputable instance
    (votes : VoteHistory)
    (term : Nat)
    (candidate : Node) :
    Decidable (hasHistoricalElectionMajority votes term candidate) := by
  exact Classical.propDecidable _

/--
Term ownership is proof-only election history.  Leaders claim their term when
promoted. Canonical histories identify the owner of every represented entry,
while election records retain the provenance of every owned term.
-/
structure TermOwnershipFacts
    (state : State TxId)
    (votes : VoteHistory)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (canonicalHistory : Nat -> List (Entry TxId))
    (owners : TermOwners) : Prop where
  bootstrap :
    owners TERM_ONE = some INITIAL_LEADER
  activeLeader :
    forall leader,
      (state.nodes leader).role = .leader ->
        owners (state.nodes leader).currentTerm = some leader
  logEntryAgreement :
    forall node index entry,
      entryAt? (state.nodes node).log index = some entry ->
        entryAt? (canonicalHistory entry.term) index = some entry /\
          (state.nodes node).log.take index =
            (canonicalHistory entry.term).take index
  queuedHistoryEntryAgreement :
    forall destination request,
      Message.appendEntriesRequest request ∈ state.network destination ->
        forall index entry,
          entryAt? (appendHistory request) index = some entry ->
            entryAt? (canonicalHistory entry.term) index = some entry /\
              (appendHistory request).take index =
                (canonicalHistory entry.term).take index
  activeLeaderHistory :
    forall leader,
      (state.nodes leader).role = .leader ->
        canonicalHistory (state.nodes leader).currentTerm =
          (state.nodes leader).log
  canonicalEntryOwner :
    forall term index entry,
      entryAt? (canonicalHistory term) index = some entry ->
        Exists fun owner => owners entry.term = some owner
  canonicalMonoLog :
    forall term, MonoHistory (canonicalHistory term)
  ownerProgress :
    forall term owner,
      owners term = some owner ->
        term <= (state.nodes owner).currentTerm /\
          (term = (state.nodes owner).currentTerm ->
            (state.nodes owner).role = .leader)
  queuedAppendMetadata :
    forall destination request,
      Message.appendEntriesRequest request ∈ state.network destination ->
        owners request.term = some request.source /\
          forall entry,
            entry ∈ appendHistory request ->
              entry.term <= request.term
  queuedActiveSourceHistory :
    forall destination request,
      Message.appendEntriesRequest request ∈ state.network destination ->
        request.term = (state.nodes request.source).currentTerm ->
        (state.nodes request.source).role = .leader ->
          appendHistory request <+: (state.nodes request.source).log

/--
Every non-bootstrap owned term retains the exact quorum and log snapshots
which elected it.  These immutable records support induction across elections
which happened before an old prefix became fully quorum-supported.
-/
structure ElectionHistoryFacts
    (state : State TxId)
    (votes : VoteHistory)
    (canonicalHistory : Nat -> List (Entry TxId))
    (owners : TermOwners)
    (elections : ElectionHistory TxId) : Prop where
  recordOwned :
    forall term record,
      elections term = some record ->
        owners term = some record.leader
  ownerRecorded :
    forall term owner,
      owners term = some owner ->
        ((term = TERM_ONE /\ owner = INITIAL_LEADER) \/
          Exists fun record =>
            elections term = some record /\
              record.leader = owner)
  postBootstrap :
    forall term record,
      elections term = some record ->
        TERM_ONE < term
  majority :
    forall term record,
      elections term = some record ->
        record.quorum.card * 2 > NODE_COUNT
  voted :
    forall term record voter,
      elections term = some record ->
        voter ∈ record.quorum ->
          votes voter term = some record.leader
  promotionCanonical :
    forall term record,
      elections term = some record ->
        record.promotionLog <+: canonicalHistory term
  promotionEntriesBeforeTerm :
    forall term record,
      elections term = some record ->
        forall entry,
          entry ∈ record.promotionLog ->
            entry.term < term
  candidatePrefix :
    forall term record voter,
      elections term = some record ->
        voter ∈ record.quorum ->
          record.candidateLog voter <+: record.promotionLog
  candidateCanonical :
    forall term record voter,
      elections term = some record ->
        voter ∈ record.quorum ->
          HistoryCanonical
            canonicalHistory (record.candidateLog voter)
  voterCanonical :
    forall term record voter,
      elections term = some record ->
        voter ∈ record.quorum ->
          HistoryCanonical
            canonicalHistory (record.voterLog voter)
  upToDate :
    forall term record voter,
      elections term = some record ->
        voter ∈ record.quorum ->
          voteLogUpToDate
            { (state.nodes voter) with
              log := record.voterLog voter }
            { term
              lastLogTerm :=
                termAt
                  (record.candidateLog voter)
                  (record.candidateLog voter).length
              lastLogIndex := (record.candidateLog voter).length
              source := record.leader
              destination := voter }

/-- Every queued leader history contains that term's promotion snapshot. -/
def ElectionQueuedHistoryFacts
    (state : State TxId)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (elections : ElectionHistory TxId) : Prop :=
  forall destination request,
    Message.appendEntriesRequest request ∈ state.network destination ->
      forall record,
        elections request.term = some record ->
          record.promotionLog <+: appendHistory request

/--
Every locally committed log is represented in every strict majority.  This is
the fixed-configuration form of `QuorumLogInv` from `ccfraft.tla`.
-/
def QuorumLog (state : State TxId) : Prop :=
  forall node (quorum : Finset Node),
    quorum.card * 2 > NODE_COUNT ->
      Exists fun witness =>
        witness ∈ quorum /\
          (state.nodes node).committedLog <+:
            (state.nodes witness).log

/-- Whether one queued successful response acknowledges an index for a leader. -/
def queuedSuccessfulAck
    (state : State TxId)
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (leader peer : Node)
    (index : Nat) : Prop :=
  Exists fun response =>
    Message.appendEntriesResponse response ∈ state.network leader /\
      response.success = true /\
      response.term = (state.nodes leader).currentTerm /\
      response.source = peer /\
      response.destination = leader /\
      index <= response.lastLogIndex /\
      responseHistory response <+: (state.nodes leader).log

/--
Processed match indices and same-term successful responses still queued at the
leader are two representations of the same acknowledgement evidence.
-/
noncomputable def effectiveAckers
    (state : State TxId)
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (leader : Node)
    (index : Nat) : Finset Node := by
  classical
  exact
    Finset.univ.filter fun node =>
      node = leader \/
        (state.nodes leader).matchIndex node >= index \/
        queuedSuccessfulAck state responseHistory leader node index

/-- A strict quorum of processed or queued successful acknowledgements. -/
def hasEffectiveMajorityAt
    (state : State TxId)
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (leader : Node)
    (index : Nat) : Prop :=
  (effectiveAckers state responseHistory leader index).card * 2 > NODE_COUNT

noncomputable instance
    (state : State TxId)
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (leader : Node)
    (index : Nat) :
    Decidable
      (hasEffectiveMajorityAt state responseHistory leader index) := by
  exact Classical.propDecidable _

/-- A request can produce a successful ACK directly or after candidate step-down. -/
def canProduceAppendAckAt
    (node : NodeState TxId)
    (request : AppendEntriesRequest TxId)
    (index : Nat) : Prop :=
  (Exists fun nextNode =>
    Exists fun response =>
      handleAppendEntriesRequest? node request =
          some (nextNode, response) /\
        response.success = true /\
        index <= response.lastLogIndex) \/
  (Exists fun follower =>
    Exists fun nextNode =>
      Exists fun response =>
        returnToFollowerState? node request = some follower /\
          handleAppendEntriesRequest? follower request =
            some (nextNode, response) /\
          response.success = true /\
          index <= response.lastLogIndex)

/--
A queued request reserves one future acknowledgement while it can still be
accepted, either directly or after the protocol's same-term candidate
step-down.  The request snapshot records the leader prefix acknowledged.
-/
def queuedAppendReserve
    (state : State TxId)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (leader peer : Node)
    (index : Nat) : Prop :=
  Exists fun request =>
    Message.appendEntriesRequest request ∈ state.network peer /\
      request.source = leader /\
      request.destination = peer /\
      request.term = (state.nodes leader).currentTerm /\
      canProduceAppendAckAt (state.nodes peer) request index /\
      appendHistory request <+: (state.nodes leader).log

/--
Potential supporters combine materialised acknowledgements with queued
requests which can still materialise one.  This is proof-only Raft
committability, independent of `commitIndex` and CCF signature committability.
-/
noncomputable def potentialAckers
    (state : State TxId)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (leader : Node)
    (index : Nat) : Finset Node := by
  classical
  exact
    Finset.univ.filter fun node =>
      node ∈ effectiveAckers state responseHistory leader index \/
        queuedAppendReserve state appendHistory leader node index

/-- A strict quorum of materialised or still-reserved acknowledgements. -/
def hasPotentialMajorityAt
    (state : State TxId)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (leader : Node)
    (index : Nat) : Prop :=
  (potentialAckers state appendHistory responseHistory leader index).card * 2 >
    NODE_COUNT

noncomputable instance
    (state : State TxId)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (leader : Node)
    (index : Nat) :
    Decidable
      (hasPotentialMajorityAt
        state appendHistory responseHistory leader index) := by
  exact Classical.propDecidable _

/--
An ACK supporter which later participates in an election either still had the
acknowledged prefix in its frozen voter log, or some strictly intermediate
elected term had already lost that prefix.  The latter alternative is what a
least-counterexample induction rules out.
-/
def AckerElectionHistory
    (state : State TxId)
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (elections : ElectionHistory TxId) : Prop :=
  forall source index,
    (state.nodes source).role = .leader ->
    termAt (state.nodes source).log index =
        (state.nodes source).currentTerm ->
      forall term record voter,
        elections term = some record ->
        voter ∈ record.quorum ->
        voter ∈ effectiveAckers state responseHistory source index ->
        (state.nodes source).currentTerm < term ->
          (state.nodes source).log.take index <+:
              record.voterLog voter \/
            Exists fun earlierTerm =>
              Exists fun earlierRecord =>
                (state.nodes source).currentTerm < earlierTerm /\
                  earlierTerm < term /\
                  elections earlierTerm = some earlierRecord /\
                  Not (
                    (state.nodes source).log.take index <+:
                      earlierRecord.promotionLog)

/-- Some elected term up to a bound is the first known loss of one prefix. -/
def EarlierBadElection
    (state : State TxId)
    (elections : ElectionHistory TxId)
    (source : Node)
    (index bound : Nat) : Prop :=
  Exists fun badTerm =>
    Exists fun badRecord =>
      (state.nodes source).currentTerm < badTerm /\
        badTerm <= bound /\
        elections badTerm = some badRecord /\
        Not (
          (state.nodes source).log.take index <+:
            badRecord.promotionLog)

/--
A materialised ACK remains in the supporter's current log unless an elected
intermediate term has already omitted it.
-/
def AckerCurrentHistory
    (state : State TxId)
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (elections : ElectionHistory TxId) : Prop :=
  forall source index,
    (state.nodes source).role = .leader ->
    termAt (state.nodes source).log index =
        (state.nodes source).currentTerm ->
      forall voter,
        voter ∈ effectiveAckers state responseHistory source index ->
          (state.nodes source).log.take index <+:
              (state.nodes voter).log \/
            EarlierBadElection
              state elections source index
                (state.nodes voter).currentTerm

/--
When a non-self voter records a higher-term vote, every earlier ACK prefix is
present in that immutable voter snapshot unless an already elected
intermediate term omitted it.
-/
def AckerVoteHistory
    (state : State TxId)
    (votes : VoteHistory)
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (voteVoterHistory : RequestVoteResponse -> List (Entry TxId))
    (elections : ElectionHistory TxId) : Prop :=
  forall source index,
    (state.nodes source).role = .leader ->
    termAt (state.nodes source).log index =
        (state.nodes source).currentTerm ->
      forall voter voteTerm candidate,
        voter ∈ effectiveAckers state responseHistory source index ->
        votes voter voteTerm = some candidate ->
        Not (voter = candidate) ->
        (state.nodes source).currentTerm < voteTerm ->
          (state.nodes source).log.take index <+:
              voteVoterHistory
                (grantedVoteKey voter voteTerm candidate) \/
            EarlierBadElection
              state elections source index voteTerm

/--
Each positive active-leader match frontier is justified by an immutable
successful-ACK history.  A zero frontier has no processed evidence.
-/
structure ProcessedAckHistoryFacts
    (state : State TxId)
    (history : ProcessedAckHistory TxId) : Prop where
  zero :
    forall leader,
      (state.nodes leader).role = .leader ->
        forall peer,
          (state.nodes leader).matchIndex peer = 0 ->
            history leader peer = none
  positive :
    forall leader,
      (state.nodes leader).role = .leader ->
        forall peer,
          0 < (state.nodes leader).matchIndex peer ->
            Exists fun snapshot =>
              history leader peer = some snapshot /\
                snapshot.term =
                  (state.nodes leader).currentTerm /\
                snapshot.index =
                  (state.nodes leader).matchIndex peer /\
                snapshot.index <= snapshot.history.length /\
                snapshot.history.take snapshot.index =
                  (state.nodes leader).log.take snapshot.index

/-- One evidence value exactly justifies the supplied committed prefix. -/
def CommitEvidence.Valid
    (evidence : CommitEvidence TxId)
    (supportedPrefix : List (Entry TxId)) : Prop :=
  evidence.commitFrontier <= evidence.history.length /\
    termAt evidence.history evidence.commitFrontier =
      evidence.commitTerm /\
    evidence.supportedLength <= evidence.commitFrontier /\
    evidence.history.take evidence.supportedLength =
      supportedPrefix /\
    evidence.ackQuorum.card * 2 > NODE_COUNT /\
    forall member,
      member ∈ evidence.ackQuorum ->
        evidence.commitFrontier <=
            (evidence.memberHistory member).length /\
          (evidence.memberHistory member).take
              evidence.commitFrontier =
            evidence.history.take evidence.commitFrontier

/--
Evidence is known only when it occupies a live proof-state slot: either
it supports a node's current nonempty committed log, or it is attached to a
currently queued nonempty AppendEntries commit advertisement.
-/
def KnownCommitEvidence
    (state : State TxId)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (nodeEvidence : NodeCommitEvidence TxId)
    (requestEvidence : RequestCommitEvidence TxId)
    (evidence : CommitEvidence TxId)
    (supportedPrefix : List (Entry TxId)) : Prop :=
  (Exists fun node =>
    0 < (state.nodes node).commitIndex /\
      nodeEvidence node = some evidence /\
      supportedPrefix = (state.nodes node).committedLog) \/
  (Exists fun destination =>
    Exists fun request =>
      Message.appendEntriesRequest request ∈ state.network destination /\
        0 < request.leaderCommit /\
        requestEvidence request = some evidence /\
        supportedPrefix =
          (appendHistory request).take request.leaderCommit)

/--
Current nonempty commits and queued nonempty leader-commit advertisements
carry proof-only evidence.  Empty prefixes use `none`.
-/
structure CommitEvidenceFacts
    (state : State TxId)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (nodeEvidence : NodeCommitEvidence TxId)
    (requestEvidence : RequestCommitEvidence TxId) : Prop where
  nodeZero :
    forall node,
      (state.nodes node).commitIndex = 0 ->
        nodeEvidence node = none
  nodePositive :
    forall node,
      0 < (state.nodes node).commitIndex ->
        Exists fun evidence =>
          nodeEvidence node = some evidence /\
            evidence.Valid (state.nodes node).committedLog /\
            evidence.supportedLength =
              (state.nodes node).commitIndex /\
            evidence.commitTerm <=
              (state.nodes node).currentTerm
  requestZero :
    forall destination request,
      Message.appendEntriesRequest request ∈ state.network destination ->
        request.leaderCommit = 0 ->
          requestEvidence request = none
  requestPositive :
    forall destination request,
      Message.appendEntriesRequest request ∈ state.network destination ->
        0 < request.leaderCommit ->
          Exists fun evidence =>
            requestEvidence request = some evidence /\
              evidence.Valid
                ((appendHistory request).take request.leaderCommit) /\
              evidence.supportedLength = request.leaderCommit /\
              evidence.commitTerm <= request.term

/--
Per-ACK prospective closure retained with each live commit witness.  These
member-wise facts are stronger than a current majority statement: they remain
usable when one newly eligible voter creates the first election majority.
-/
structure ProspectiveCommitEvidenceFacts
    (state : State TxId)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (nodeEvidence : NodeCommitEvidence TxId)
    (requestEvidence : RequestCommitEvidence TxId)
    (elections : ElectionHistory TxId) : Prop where
  commitTermPositive :
    forall evidence supportedPrefix,
      KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix ->
        TERM_ONE <= evidence.commitTerm
  electionClosure :
    forall evidence supportedPrefix,
      KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix ->
        forall term record,
          elections term = some record ->
          evidence.commitTerm < term ->
            evidence.history.take evidence.commitFrontier <+:
              record.promotionLog
  currentMember :
    forall evidence supportedPrefix,
      KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix ->
        forall member,
          member ∈ evidence.ackQuorum ->
            evidence.history.take evidence.commitFrontier <+:
              (state.nodes member).log
  sameTermQueuedComparable :
    forall evidence supportedPrefix,
      KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix ->
        forall destination request,
          Message.appendEntriesRequest request ∈
            state.network destination ->
          evidence.commitTerm = request.term ->
            appendHistory request <+: evidence.history \/
              evidence.history.take evidence.commitFrontier <+:
                appendHistory request
  relaxedSupporterCarriesFrontier :
    forall evidence supportedPrefix,
      KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix ->
        forall candidate member,
          (state.nodes candidate).role = .candidate ->
          evidence.commitTerm < (state.nodes candidate).currentTerm ->
          (forall entry,
            entry ∈ (state.nodes candidate).log ->
              entry.term < (state.nodes candidate).currentTerm) ->
          member ∈ evidence.ackQuorum ->
          member ∈ relaxedElectionVoters state candidate ->
            evidence.history.take evidence.commitFrontier <+:
              (state.nodes candidate).log

/--
Any current-term prefix already acknowledged by a majority is compatible with
every committed log.  This covers delayed ACK processing by an isolated old
leader.
-/
def PotentialCommitSafe
    (state : State TxId)
    (responseHistory : AppendEntriesResponse -> List (Entry TxId)) : Prop :=
  forall leader index,
    (state.nodes leader).role = .leader ->
    termAt (state.nodes leader).log index =
        (state.nodes leader).currentTerm ->
    hasEffectiveMajorityAt state responseHistory leader index ->
      forall node,
        (state.nodes leader).log.take index <+:
            (state.nodes node).committedLog \/
          (state.nodes node).committedLog <+:
            (state.nodes leader).log.take index

/--
Every higher-term election winner already contains each lower-term prefix that
an active leader could commit from its recorded acknowledgements.  This is the
delayed-ACK bridge needed when an old leader commits after a newer election.
-/
def PotentialCommitElectionSafe
    (state : State TxId)
    (responseHistory : AppendEntriesResponse -> List (Entry TxId)) : Prop :=
  forall source index,
    (state.nodes source).role = .leader ->
    termAt (state.nodes source).log index =
        (state.nodes source).currentTerm ->
    hasEffectiveMajorityAt state responseHistory source index ->
      forall winner,
        ((state.nodes winner).role = .leader \/
          ((state.nodes winner).role = .candidate /\
          hasEffectiveElectionMajority state winner)) ->
        (state.nodes source).currentTerm <
            (state.nodes winner).currentTerm ->
          (state.nodes source).log.take index <+:
            (state.nodes winner).log

/--
Every current-term prefix that an active leader could commit is already
represented in every strict quorum.  Advancing `commitIndex` therefore
preserves `QuorumLog` even when ACK processing is delayed.
-/
def PotentialCommitQuorumLog
    (state : State TxId)
    (responseHistory : AppendEntriesResponse -> List (Entry TxId)) : Prop :=
  forall source index,
    (state.nodes source).role = .leader ->
    termAt (state.nodes source).log index =
        (state.nodes source).currentTerm ->
    hasEffectiveMajorityAt state responseHistory source index ->
      forall quorum : Finset Node,
        quorum.card * 2 > NODE_COUNT ->
          Exists fun witness =>
            witness ∈ quorum /\
              (state.nodes source).log.take index <+:
                (state.nodes witness).log

/--
Any two current-term prefixes already acknowledged by strict majorities are
prefix-comparable.  This lets one such prefix become committed without
invalidating delayed commit evidence retained by another active leader.
-/
def PotentialCommitsComparable
    (state : State TxId)
    (responseHistory : AppendEntriesResponse -> List (Entry TxId)) : Prop :=
  forall left leftIndex,
    (state.nodes left).role = .leader ->
    termAt (state.nodes left).log leftIndex =
        (state.nodes left).currentTerm ->
    hasEffectiveMajorityAt state responseHistory left leftIndex ->
      forall right rightIndex,
        (state.nodes right).role = .leader ->
        termAt (state.nodes right).log rightIndex =
            (state.nodes right).currentTerm ->
        hasEffectiveMajorityAt state responseHistory right rightIndex ->
          (state.nodes left).log.take leftIndex <+:
              (state.nodes right).log.take rightIndex \/
            (state.nodes right).log.take rightIndex <+:
              (state.nodes left).log.take leftIndex

/--
A candidate which already has a winning quorum is ready for promotion: it
contains every committed prefix belonging to a node in a lower term.
-/
def WinningCandidateCompleteness (state : State TxId) : Prop :=
  forall candidate,
    (state.nodes candidate).role = .candidate ->
    hasEffectiveElectionMajority state candidate ->
      forall node,
        Not (candidate = node) ->
        (state.nodes candidate).currentTerm >
            (state.nodes node).currentTerm ->
          (state.nodes node).committedLog <+:
            (state.nodes candidate).log

/--
A candidate which can win has no entry from its election term anywhere yet.
This is the arbitrary-term form of `CandidateTermNotInLogInv`.
-/
def CandidateTermNotInLogs (state : State TxId) : Prop :=
  forall candidate,
    (state.nodes candidate).role = .candidate ->
    hasEffectiveElectionMajority state candidate ->
      forall node index entry,
        entryAt? (state.nodes node).log index = some entry ->
          Not (entry.term = (state.nodes candidate).currentTerm)

/--
An active leader contains the complete prefix through every entry carrying its
term.  This prevents a later client append from colliding at an existing
same-term index.
-/
def LeaderTermDominance (state : State TxId) : Prop :=
  forall leader,
    (state.nodes leader).role = .leader ->
      forall node index entry,
        entryAt? (state.nodes node).log index = some entry ->
        entry.term = (state.nodes leader).currentTerm ->
          index <= (state.nodes leader).log.length /\
            (state.nodes node).log.take index =
              (state.nodes leader).log.take index

/--
The current TLA state-local leader-completeness formula.  Leaders need contain
the committed logs of strictly lower-term peers, not those of newer peers.
-/
def LeaderCompleteness (state : State TxId) : Prop :=
  forall leader,
    (state.nodes leader).role = .leader ->
      forall node,
        Not (leader = node) ->
        (state.nodes leader).currentTerm >
            (state.nodes node).currentTerm ->
          (state.nodes node).committedLog <+:
            (state.nodes leader).log

/--
The arbitrary-term invariant stores only primitive safety evidence.  Local
bounds constrain node state; network and vote histories freeze message and
ballot snapshots; canonical histories, election records, and temporal ACK
facts retain ballot ancestry and commit support; processed ACK history retains
the replicated-prefix evidence needed by later steps.  Public consistency and
completeness properties are derived from these witnesses rather than stored.
-/
structure InvariantFacts
    (state : State TxId)
    (votes : VoteHistory)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (voteRequestHistory : RequestVoteRequest -> List (Entry TxId))
    (voteCandidateHistory : RequestVoteResponse -> List (Entry TxId))
    (voteVoterHistory : RequestVoteResponse -> List (Entry TxId)) : Prop where
  /- Local node bounds and role obligations. -/
  commitIndicesBounded : CommitIndicesBounded state
  currentTermsPositive : CurrentTermsPositive state
  entriesDoNotExceedCurrentTerm : EntriesDoNotExceedCurrentTerm state
  candidatesSelfVote : CandidatesSelfVote state
  leadersHaveElectionMajority : LeadersHaveElectionMajority state
  leaderProgressBounded : LeaderProgressBounded state

  /- Immutable network and persistent-vote snapshots. -/
  voteHistory :
    VoteHistoryFacts state votes
  networkHistory :
    NetworkHistoryFacts
      state appendHistory responseHistory
        voteRequestHistory voteCandidateHistory voteVoterHistory votes

  /- Canonical ballot ancestry, commit support, and temporal evidence. -/
  historicalSafetyEvidence :
    Exists fun owners =>
      Exists fun canonicalHistory =>
        Exists fun elections =>
          Exists fun nodeEvidence =>
            Exists fun requestEvidence =>
          TermOwnershipFacts
              state votes appendHistory canonicalHistory owners /\
            ElectionHistoryFacts
              state votes canonicalHistory owners elections /\
            GrantedVoteCanonicalSnapshots
              state canonicalHistory
                voteCandidateHistory voteVoterHistory /\
            AckerCurrentHistory
              state responseHistory elections /\
            AckerVoteHistory
              state votes responseHistory voteVoterHistory elections /\
            AckerElectionHistory
              state responseHistory elections /\
            ElectionQueuedHistoryFacts
              state appendHistory elections /\
            CommitEvidenceFacts
              state appendHistory nodeEvidence requestEvidence /\
            ProspectiveCommitEvidenceFacts
              state appendHistory nodeEvidence requestEvidence elections

  /- Effective-voter snapshots retained for active ballots. -/
  grantedVoteSnapshots :
    GrantedVoteSnapshots
      state votes voteCandidateHistory voteVoterHistory

  /- Processed successful-ACK history for replicated-prefix recovery. -/
  processedAckHistory :
    Exists fun history => ProcessedAckHistoryFacts state history

/-- Existentially package all proof-only histories. -/
def SystemInductiveInvariant (state : State TxId) : Prop :=
  Exists fun votes =>
    Exists fun appendHistory =>
      Exists fun responseHistory =>
        Exists fun voteRequestHistory =>
        Exists fun voteCandidateHistory =>
          Exists fun voteVoterHistory =>
            InvariantFacts
              state votes appendHistory responseHistory voteRequestHistory
                voteCandidateHistory voteVoterHistory

/-- Core public safety contains only committed-log consistency and uniqueness. -/
structure ConsensusSafety (state : State TxId) : Prop where
  committedLogsPrefix : CommittedLogsPrefix state
  electionSafety : ElectionSafety state

end CCFRaft
