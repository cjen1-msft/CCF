-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model

set_option autoImplicit false

namespace CCFRaft

variable {TxId : Type}
variable [DecidableEq TxId]

def CommitIndicesBounded (state : State TxId) : Prop :=
  forall node,
    (state.nodes node).commitIndex <= (state.nodes node).log.length

def LogsPrefixLeader (state : State TxId) : Prop :=
  forall node,
    (state.nodes node).log <+: (state.nodes LEADER).log

def TermsAreOne (state : State TxId) : Prop :=
  forall node entry,
    entry ∈ (state.nodes node).log ->
      entry.term = TERM_ONE

def LeaderTxIdsUnique (state : State TxId) : Prop :=
  ((state.nodes LEADER).log.map Entry.txId).Nodup

def LeaderTxIdsSubmitted (state : State TxId) : Prop :=
  forall entry,
    entry ∈ (state.nodes LEADER).log ->
      entry.txId ∈ state.submittedTxIds

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

def ResponseMatchesLeader
    (state : State TxId)
    (response : AppendEntriesResponse) : Prop :=
  response.destination = LEADER /\
    Not (response.source = LEADER) /\
    response.term = TERM_ONE /\
    response.lastLogIndex <= (state.nodes LEADER).log.length

instance (state : State TxId) (request : AppendEntriesRequest TxId) :
    Decidable (RequestMatchesLeader state request) := by
  unfold RequestMatchesLeader
  infer_instance

instance (state : State TxId) (response : AppendEntriesResponse) :
    Decidable (ResponseMatchesLeader state response) := by
  unfold ResponseMatchesLeader
  infer_instance

def QueuedRequestsMatchLeader (state : State TxId) : Prop :=
  forall destination message,
    message ∈ state.network destination ->
      message.destination = destination /\
        match message with
        | .appendEntriesRequest request =>
            RequestMatchesLeader state request
        | .appendEntriesResponse response =>
            ResponseMatchesLeader state response

def SentIndicesBounded (state : State TxId) : Prop :=
  forall node,
    (state.nodes LEADER).sentIndex node <=
      (state.nodes LEADER).log.length

def MatchIndicesBounded (state : State TxId) : Prop :=
  forall node,
    (state.nodes LEADER).matchIndex node <=
      (state.nodes LEADER).log.length

def RolesFixed (state : State TxId) : Prop :=
  forall node,
    (state.nodes node).role =
      if node = LEADER then .leader else .follower

def CurrentTermsAreOne (state : State TxId) : Prop :=
  forall node,
    (state.nodes node).currentTerm = TERM_ONE

structure CoreInvariant (state : State TxId) : Prop where
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

def CommittedLogMonotonicity
    (before after : State TxId) : Prop :=
  forall node,
    (before.nodes node).committedLog <+:
      (after.nodes node).committedLog

def CommittedLogsPrefix (state : State TxId) : Prop :=
  forall left right,
    (state.nodes left).committedLog <+:
        (state.nodes right).committedLog \/
      (state.nodes right).committedLog <+:
        (state.nodes left).committedLog

def LogMatching (state : State TxId) : Prop :=
  forall left right index leftEntry rightEntry,
    entryAt? (state.nodes left).log index = some leftEntry ->
      entryAt? (state.nodes right).log index = some rightEntry ->
        leftEntry.term = rightEntry.term ->
          (state.nodes left).log.take index =
            (state.nodes right).log.take index

def SameIndexSameTermSameTxId (state : State TxId) : Prop :=
  forall left right index leftEntry rightEntry,
    entryAt? (state.nodes left).log index = some leftEntry ->
      entryAt? (state.nodes right).log index = some rightEntry ->
        leftEntry.term = rightEntry.term ->
          leftEntry.txId = rightEntry.txId

def MonoLog (state : State TxId) : Prop :=
  forall node earlier later earlierEntry laterEntry,
    earlier < later ->
      entryAt? (state.nodes node).log earlier = some earlierEntry ->
        entryAt? (state.nodes node).log later = some laterEntry ->
          earlierEntry.term <= laterEntry.term

def OtherNodesUnchanged
    (acting : Node)
    (before after : State TxId) : Prop :=
  forall node,
    Not (node = acting) ->
      after.nodes node = before.nodes node

structure ConsensusSafety (state : State TxId) : Prop where
  committedLogsPrefix : CommittedLogsPrefix state
  logMatching : LogMatching state
  sameIndexSameTermSameTxId : SameIndexSameTermSameTxId state
  monoLog : MonoLog state

end CCFRaft
