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
    (state.nodes node).log <+: (state.nodes LEADER).log

/-- Every reachable log entry belongs to the single modeled term. -/
def TermsAreOne (state : State TxId) : Prop :=
  forall node entry,
    entry ∈ (state.nodes node).log ->
      entry.term = TERM_ONE

/-- No transaction ID appears twice in the leader log. -/
def LeaderTxIdsUnique (state : State TxId) : Prop :=
  ((state.nodes LEADER).log.map Entry.txId).Nodup

/-- Every leader-log transaction was allocated by the external client input. -/
def LeaderTxIdsSubmitted (state : State TxId) : Prop :=
  forall entry,
    entry ∈ (state.nodes LEADER).log ->
      entry.txId ∈ state.submittedTxIds

/-- A queued request is a faithful snapshot of a leader log prefix. -/
def RequestMatchesLeader
    (state : State TxId)
    (request : AppendEntriesRequest TxId) : Prop :=
  request.source = LEADER /\
    Not (request.destination = LEADER) /\
    request.term = TERM_ONE /\
    request.prevLogIndex <= (state.nodes LEADER).log.length /\
    request.prevLogIndex + request.entries.length <=
      (state.nodes LEADER).log.length /\
    request.prevLogTerm =
      termAt (state.nodes LEADER).log request.prevLogIndex /\
    (state.nodes LEADER).log.take
        (request.prevLogIndex + request.entries.length) =
      (state.nodes LEADER).log.take request.prevLogIndex ++ request.entries

/-- A queued response targets the leader and stays within its current log. -/
def ResponseMatchesLeader
    (state : State TxId)
    (response : AppendEntriesResponse) : Prop :=
  response.destination = LEADER /\
    Not (response.source = LEADER) /\
    response.term = TERM_ONE /\
    response.lastLogIndex <= (state.nodes LEADER).log.length

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

/-- The leader never records sending past the end of its log. -/
def SentIndicesBounded (state : State TxId) : Prop :=
  forall node,
    (state.nodes LEADER).sentIndex node <=
      (state.nodes LEADER).log.length

/-- The leader never records a follower match past its own log. -/
def MatchIndicesBounded (state : State TxId) : Prop :=
  forall node,
    (state.nodes LEADER).matchIndex node <=
      (state.nodes LEADER).log.length

/-- Node zero remains leader and all other nodes remain followers. -/
def RolesFixed (state : State TxId) : Prop :=
  forall node,
    (state.nodes node).role =
      if node = LEADER then .leader else .follower

/-- Every node remains in term one. -/
def CurrentTermsAreOne (state : State TxId) : Prop :=
  forall node,
    (state.nodes node).currentTerm = TERM_ONE

/-- Supporting facts proved together because actions preserve them jointly. -/
structure SystemInductiveInvariant (state : State TxId) : Prop where
  commitIndicesBounded : CommitIndicesBounded state
  logsPrefixLeader : LogsPrefixLeader state
  termsAreOne : TermsAreOne state
  leaderTxIdsUnique : LeaderTxIdsUnique state
  leaderTxIdsSubmitted : LeaderTxIdsSubmitted state
  queuedRequestsMatchLeader : QueuedRequestsMatchLeader state
  sentIndicesBounded : SentIndicesBounded state
  matchIndicesBounded : MatchIndicesBounded state
  rolesFixed : RolesFixed state
  currentTermsAreOne : CurrentTermsAreOne state

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

/-- The public state-safety guarantees exported by slice one. -/
structure ConsensusSafety (state : State TxId) : Prop where
  committedLogsPrefix : CommittedLogsPrefix state
  logMatching : LogMatching state
  sameIndexSameTermSameTxId : SameIndexSameTermSameTxId state
  monoLog : MonoLog state

end CCFRaft
