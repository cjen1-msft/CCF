-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.Runtime.Simulation

set_option autoImplicit false

/-!
# Canonical checking support for the naive full-state witness

The generated witness checker supplies raw bounded records. This module decodes
those records into `Simulation.SimState` and `Simulation.SimAction`, then replays
them only through the canonical executable transition system.
-/

namespace CCFRaft.NaiveFullStateWitness

open CCFRaft.Simulation

variable [Bootstrap Node]

def LOG_CAPACITY : Nat := 7
def QUEUE_CAPACITY : Nat := 4
def ACTION_COUNT : Nat := 43

structure RawEntrySlot where
  index : Nat
  active : Bool
  term : Nat
  tag : String
  tagValue : Nat
  transactionId : Nat
  configurationMembership : List Bool
  retiredMembership : List Bool

structure RawNode where
  node : Nat
  role : String
  roleValue : Nat
  currentTerm : Nat
  logLength : Nat
  commitIndex : Nat
  isNewFollower : Bool
  votedForHasValue : Bool
  votedForValue : Nat
  votesGrantedMembership : List Bool
  preVotesGrantedMembership : List Bool
  membershipState : String
  membershipStateValue : Nat
  retirementIndexHasValue : Bool
  retirementIndexValue : Nat
  retirementCommittableIndexHasValue : Bool
  retirementCommittableIndexValue : Nat
  retiredCommittedIndexHasValue : Bool
  retiredCommittedIndexValue : Nat
  retirementCompletedMembership : List Bool
  sentIndex : List Nat
  matchIndex : List Nat
  logCapacity : Nat
  logSlots : List RawEntrySlot

structure RawQueueSlot where
  slot : Nat
  active : Bool
  tag : String
  tagValue : Nat
  source : Nat
  destination : Nat
  term : Nat
  prevLogIndex : Nat
  prevLogTerm : Nat
  leaderCommit : Nat
  entryPresent : Bool
  entryTerm : Nat
  entryTag : String
  entryTagValue : Nat
  entryTransactionId : Nat
  entryConfigurationMembership : List Bool
  entryRetiredMembership : List Bool
  responseSuccess : Bool
  responseLastLogIndex : Nat
  voteLastCommittableTerm : Nat
  voteLastCommittableIndex : Nat
  voteGranted : Bool

structure RawQueue where
  destination : Nat
  length : Nat
  capacity : Nat
  slots : List RawQueueSlot

structure RawInitialState where
  nodes : List RawNode
  network : List RawQueue
  submittedTransactionMembership : List Bool
  hasJoinedMembership : List Bool
  preVoteStatusEnabled : List Bool

structure RawAction where
  action : Nat
  kind : String
  kindValue : Nat
  source : Nat
  destination : Nat
  parameter : Nat
  transaction : Nat
  configurationMembership : List Bool

def expectEq
    {A : Type}
    [DecidableEq A]
    [Repr A]
    (field : String)
    (actual expected : A) :
    Except String Unit :=
  if actual = expected then
    pure ()
  else
    throw
      s!"{field}: expected {reprStr expected}, decoded {reprStr actual}"

def expectTrue (field : String) (condition : Bool) : Except String Unit :=
  if condition then
    pure ()
  else
    throw s!"{field}: check failed"

def nodeOfNat (field : String) (value : Nat) : Except String Node :=
  if inBounds : value < NODE_COUNT then
    pure (Fin.mk value inBounds)
  else
    throw s!"{field}: node {value} is outside Fin {NODE_COUNT}"

def txOfNat (field : String) (value : Nat) : Except String TxId :=
  if inBounds : value < TX_COUNT then
    pure (Fin.mk value inBounds)
  else
    throw s!"{field}: transaction {value} is outside Fin {TX_COUNT}"

def decodeNodeMembership
    (field : String)
    (membership : List Bool) :
    Except String (Finset Node) := do
  expectEq s!"{field}.length" membership.length NODE_COUNT
  pure
    ((allNodes.filter fun node => membership[node.val]!).toFinset)

/-- Encode one finite node set in identifier order. -/
def encodeNodeMembership (nodes : Finset Node) : List Bool :=
  allNodes.map fun node => decide (node ∈ nodes)

/-- Encode the speculative vote set stored by one node. -/
def encodePreVotesGranted
    (state : NodeState Node TxId) :
    List Bool :=
  encodeNodeMembership state.preVotesGranted

/-- Encode immutable per-node pre-vote mode in identifier order. -/
def encodePreVoteStatus
    (status : Node -> PreVoteStatus) :
    List Bool :=
  allNodes.map fun node => decide (status node = .enabled)

/-- Decode the raw pre-vote enable bit used by full-state witnesses. -/
def decodePreVoteStatus (enabled : Bool) : PreVoteStatus :=
  if enabled then .enabled else .capable

omit [Bootstrap Node] in
@[simp]
theorem decodePreVoteStatus_encode (status : PreVoteStatus) :
    decodePreVoteStatus (decide (status = .enabled)) = status := by
  cases status <;> decide

def decodeTxMembership
    (field : String)
    (membership : List Bool) :
    Except String (Finset TxId) := do
  expectEq s!"{field}.length" membership.length TX_COUNT
  pure
    ((allTxIds.filter fun txId => membership[txId.val]!).toFinset)

def expectNoMembers (field : String) (membership : List Bool) :
    Except String Unit := do
  expectEq s!"{field}.length" membership.length NODE_COUNT
  expectTrue field (membership.all fun present => !present)

def decodeActiveEntry
    (field : String)
    (term tagValue transactionId : Nat)
    (tag : String)
    (configurationMembership retiredMembership : List Bool) :
    Except String (Entry Node TxId) := do
  match tagValue with
  | 1 =>
      expectEq s!"{field}.tag" tag "transaction"
      expectNoMembers
        s!"{field}.configuration_membership"
        configurationMembership
      expectNoMembers s!"{field}.retired_membership" retiredMembership
      let txId <- txOfNat s!"{field}.transaction_id" transactionId
      pure { term, content := .transaction txId }
  | 2 =>
      expectEq s!"{field}.tag" tag "signature"
      expectEq s!"{field}.transaction_id" transactionId 0
      expectNoMembers
        s!"{field}.configuration_membership"
        configurationMembership
      expectNoMembers s!"{field}.retired_membership" retiredMembership
      pure { term, content := .signature }
  | 3 =>
      expectEq s!"{field}.tag" tag "reconfiguration"
      expectEq s!"{field}.transaction_id" transactionId 0
      let configuration <-
        decodeNodeMembership
          s!"{field}.configuration_membership"
          configurationMembership
      expectTrue
        s!"{field}.configuration_membership"
        (decide configuration.Nonempty)
      expectNoMembers s!"{field}.retired_membership" retiredMembership
      pure { term, content := .reconfiguration configuration }
  | 4 =>
      expectEq s!"{field}.tag" tag "retiredCommitted"
      expectEq s!"{field}.transaction_id" transactionId 0
      expectNoMembers
        s!"{field}.configuration_membership"
        configurationMembership
      let retired <-
        decodeNodeMembership
          s!"{field}.retired_membership"
          retiredMembership
      expectTrue
        s!"{field}.retired_membership"
        (decide retired.Nonempty)
      pure { term, content := .retiredCommitted retired }
  | _ =>
      throw
        s!"{field}.tag: unsupported active entry tag {tagValue} ({tag})"

def validateUnusedEntry
    (field : String)
    (term tagValue transactionId : Nat)
    (tag : String)
    (configurationMembership retiredMembership : List Bool) :
    Except String Unit := do
  expectEq s!"{field}.term" term 0
  expectEq s!"{field}.tag" tag "unused"
  expectEq s!"{field}.tag_value" tagValue 0
  expectEq s!"{field}.transaction_id" transactionId 0
  expectNoMembers
    s!"{field}.configuration_membership"
    configurationMembership
  expectNoMembers s!"{field}.retired_membership" retiredMembership

def decodeRole
    (field role : String)
    (roleValue : Nat) :
    Except String Role :=
  match roleValue with
  | 0 => expectEq field role "none" *> pure .none
  | 1 => expectEq field role "follower" *> pure .follower
  | 2 => expectEq field role "candidate" *> pure .candidate
  | 3 => expectEq field role "leader" *> pure .leader
  | 4 => expectEq field role "preVoteCandidate" *> pure .preVoteCandidate
  | _ => throw s!"{field}: unsupported role tag {roleValue} ({role})"

def decodeMembershipState
    (field value : String)
    (tag : Nat) :
    Except String MembershipState :=
  match tag with
  | 0 => expectEq field value "active" *> pure .active
  | 1 =>
      expectEq field value "retirementOrdered" *>
        pure .retirementOrdered
  | 2 =>
      expectEq field value "retirementSigned" *>
        pure .retirementSigned
  | 3 =>
      expectEq field value "retirementCompleted" *>
        pure .retirementCompleted
  | 4 =>
      expectEq field value "retiredCommitted" *>
        pure .retiredCommitted
  | _ => throw s!"{field}: unsupported membership tag {tag} ({value})"

def decodeOptionalIndex
    (field : String)
    (present : Bool)
    (value : Nat) :
    Except String (Option Nat) :=
  if present then
    pure (some value)
  else do
    expectEq s!"{field}.value" value 0
    pure none

def decodeNode (expectedNode : Nat) (raw : RawNode) :
    Except String (NodeState Node TxId × Finset Node) := do
  let fieldPrefix := s!"S0.nodes[{expectedNode}]"
  expectEq s!"{fieldPrefix}.node" raw.node expectedNode
  expectEq s!"{fieldPrefix}.log_capacity" raw.logCapacity LOG_CAPACITY
  expectEq
    s!"{fieldPrefix}.log_slots.length"
    raw.logSlots.length
    LOG_CAPACITY
  expectTrue s!"{fieldPrefix}.log_length" (raw.logLength <= LOG_CAPACITY)
  let role <- decodeRole s!"{fieldPrefix}.role" raw.role raw.roleValue
  let mut log : List (Entry Node TxId) := []
  for slot in raw.logSlots do
    let slotField := s!"{fieldPrefix}.log_slots[{slot.index}]"
    expectTrue s!"{slotField}.index" (1 <= slot.index)
    expectTrue s!"{slotField}.index" (slot.index <= LOG_CAPACITY)
    let shouldBeActive := decide (slot.index <= raw.logLength)
    expectEq s!"{slotField}.active" slot.active shouldBeActive
    if slot.active then
      let entry <-
        decodeActiveEntry
          slotField
          slot.term
          slot.tagValue
          slot.transactionId
          slot.tag
          slot.configurationMembership
          slot.retiredMembership
      log := log ++ [entry]
    else
      validateUnusedEntry
        slotField
        slot.term
        slot.tagValue
        slot.transactionId
        slot.tag
        slot.configurationMembership
        slot.retiredMembership
  expectEq s!"{fieldPrefix}.decoded_log_length" log.length raw.logLength
  expectEq
    s!"{fieldPrefix}.votes_granted_membership.length"
    raw.votesGrantedMembership.length
    NODE_COUNT
  expectEq
    s!"{fieldPrefix}.sent_index.length"
    raw.sentIndex.length
    NODE_COUNT
  expectEq
    s!"{fieldPrefix}.match_index.length"
    raw.matchIndex.length
    NODE_COUNT
  let votesGranted <-
    decodeNodeMembership
      s!"{fieldPrefix}.votes_granted_membership"
      raw.votesGrantedMembership
  let preVotesGranted <-
    decodeNodeMembership
      s!"{fieldPrefix}.pre_votes_granted_membership"
      raw.preVotesGrantedMembership
  let membershipState <-
    decodeMembershipState
      s!"{fieldPrefix}.membership_state"
      raw.membershipState
      raw.membershipStateValue
  let retirementIndex <-
    decodeOptionalIndex
      s!"{fieldPrefix}.retirement_index"
      raw.retirementIndexHasValue
      raw.retirementIndexValue
  let retirementCommittableIndex <-
    decodeOptionalIndex
      s!"{fieldPrefix}.retirement_committable_index"
      raw.retirementCommittableIndexHasValue
      raw.retirementCommittableIndexValue
  let retiredCommittedIndex <-
    decodeOptionalIndex
      s!"{fieldPrefix}.retired_committed_index"
      raw.retiredCommittedIndexHasValue
      raw.retiredCommittedIndexValue
  let retirementCompleted <-
    decodeNodeMembership
      s!"{fieldPrefix}.retirement_completed_membership"
      raw.retirementCompletedMembership
  let votedFor <-
    if raw.votedForHasValue then
      some <$>
        nodeOfNat s!"{fieldPrefix}.voted_for.value" raw.votedForValue
    else
      expectEq s!"{fieldPrefix}.voted_for.value" raw.votedForValue 0
      pure none
  pure (
    {
      role
      currentTerm := raw.currentTerm
      log
      commitIndex := raw.commitIndex
      sentIndex := fun peer => raw.sentIndex[peer.val]!
      matchIndex := fun peer => raw.matchIndex[peer.val]!
      isNewFollower := raw.isNewFollower
      votedFor
      votesGranted
      preVotesGranted
      membershipState
      retirementIndex
      retirementCommittableIndex
      retiredCommittedIndex
    },
    retirementCompleted)

def validateUnusedQueueSlot
    (field : String)
    (raw : RawQueueSlot) :
    Except String Unit := do
  expectEq s!"{field}.tag" raw.tag "unused"
  expectEq s!"{field}.tag_value" raw.tagValue 0
  expectEq s!"{field}.source" raw.source 0
  expectEq s!"{field}.destination" raw.destination 0
  expectEq s!"{field}.term" raw.term 0
  expectEq s!"{field}.prev_log_index" raw.prevLogIndex 0
  expectEq s!"{field}.prev_log_term" raw.prevLogTerm 0
  expectEq s!"{field}.leader_commit" raw.leaderCommit 0
  expectEq s!"{field}.entry_present" raw.entryPresent false
  expectEq s!"{field}.entry_term" raw.entryTerm 0
  expectEq s!"{field}.entry_tag" raw.entryTag "unused"
  expectEq s!"{field}.entry_tag_value" raw.entryTagValue 0
  expectEq s!"{field}.entry_transaction_id" raw.entryTransactionId 0
  expectNoMembers
    s!"{field}.entry_configuration_membership"
    raw.entryConfigurationMembership
  expectNoMembers
    s!"{field}.entry_retired_membership"
    raw.entryRetiredMembership
  expectEq s!"{field}.response_success" raw.responseSuccess false
  expectEq s!"{field}.response_last_log_index" raw.responseLastLogIndex 0
  expectEq
    s!"{field}.vote_last_committable_term"
    raw.voteLastCommittableTerm
    0
  expectEq
    s!"{field}.vote_last_committable_index"
    raw.voteLastCommittableIndex
    0
  expectEq s!"{field}.vote_granted" raw.voteGranted false

def decodeQueueSlot
    (field : String)
    (raw : RawQueueSlot) :
    Except String (Message Node TxId) := do
  let source <- nodeOfNat s!"{field}.source" raw.source
  let destination <- nodeOfNat s!"{field}.destination" raw.destination
  match raw.tagValue with
  | 1 =>
      expectEq s!"{field}.tag" raw.tag "appendEntriesRequest"
      expectEq s!"{field}.response_success" raw.responseSuccess false
      expectEq s!"{field}.response_last_log_index" raw.responseLastLogIndex 0
      expectEq
        s!"{field}.vote_last_committable_term"
        raw.voteLastCommittableTerm
        0
      expectEq
        s!"{field}.vote_last_committable_index"
        raw.voteLastCommittableIndex
        0
      expectEq s!"{field}.vote_granted" raw.voteGranted false
      let entries <-
        if raw.entryPresent then
          let entry <-
            decodeActiveEntry
              s!"{field}.entry"
              raw.entryTerm
              raw.entryTagValue
              raw.entryTransactionId
              raw.entryTag
              raw.entryConfigurationMembership
              raw.entryRetiredMembership
          pure [entry]
        else
          validateUnusedEntry
            s!"{field}.entry"
            raw.entryTerm
            raw.entryTagValue
            raw.entryTransactionId
            raw.entryTag
            raw.entryConfigurationMembership
            raw.entryRetiredMembership
          pure []
      pure (.appendEntriesRequest {
        term := raw.term
        prevLogIndex := raw.prevLogIndex
        prevLogTerm := raw.prevLogTerm
        entries
        leaderCommit := raw.leaderCommit
        source
        destination
      })
  | 2 =>
      expectEq s!"{field}.tag" raw.tag "appendEntriesResponse"
      expectEq s!"{field}.prev_log_index" raw.prevLogIndex 0
      expectEq s!"{field}.prev_log_term" raw.prevLogTerm 0
      expectEq s!"{field}.leader_commit" raw.leaderCommit 0
      expectEq s!"{field}.entry_present" raw.entryPresent false
      validateUnusedEntry
        s!"{field}.entry"
        raw.entryTerm
        raw.entryTagValue
        raw.entryTransactionId
        raw.entryTag
        raw.entryConfigurationMembership
        raw.entryRetiredMembership
      expectEq
        s!"{field}.vote_last_committable_term"
        raw.voteLastCommittableTerm
        0
      expectEq
        s!"{field}.vote_last_committable_index"
        raw.voteLastCommittableIndex
        0
      expectEq s!"{field}.vote_granted" raw.voteGranted false
      pure (.appendEntriesResponse {
        term := raw.term
        success := raw.responseSuccess
        lastLogIndex := raw.responseLastLogIndex
        source
        destination
      })
  | 3 =>
      expectEq s!"{field}.tag" raw.tag "requestVoteRequest"
      expectEq s!"{field}.prev_log_index" raw.prevLogIndex 0
      expectEq s!"{field}.prev_log_term" raw.prevLogTerm 0
      expectEq s!"{field}.leader_commit" raw.leaderCommit 0
      expectEq s!"{field}.entry_present" raw.entryPresent false
      validateUnusedEntry
        s!"{field}.entry"
        raw.entryTerm
        raw.entryTagValue
        raw.entryTransactionId
        raw.entryTag
        raw.entryConfigurationMembership
        raw.entryRetiredMembership
      expectEq s!"{field}.response_success" raw.responseSuccess false
      expectEq s!"{field}.response_last_log_index" raw.responseLastLogIndex 0
      expectEq s!"{field}.vote_granted" raw.voteGranted false
      pure (.requestVoteRequest {
        term := raw.term
        lastCommittableTerm := raw.voteLastCommittableTerm
        lastCommittableIndex := raw.voteLastCommittableIndex
        source
        destination
      })
  | 4 =>
      expectEq s!"{field}.tag" raw.tag "requestVoteResponse"
      expectEq s!"{field}.prev_log_index" raw.prevLogIndex 0
      expectEq s!"{field}.prev_log_term" raw.prevLogTerm 0
      expectEq s!"{field}.leader_commit" raw.leaderCommit 0
      expectEq s!"{field}.entry_present" raw.entryPresent false
      validateUnusedEntry
        s!"{field}.entry"
        raw.entryTerm
        raw.entryTagValue
        raw.entryTransactionId
        raw.entryTag
        raw.entryConfigurationMembership
        raw.entryRetiredMembership
      expectEq s!"{field}.response_success" raw.responseSuccess false
      expectEq s!"{field}.response_last_log_index" raw.responseLastLogIndex 0
      expectEq
        s!"{field}.vote_last_committable_term"
        raw.voteLastCommittableTerm
        0
      expectEq
        s!"{field}.vote_last_committable_index"
        raw.voteLastCommittableIndex
        0
      pure (.requestVoteResponse {
        term := raw.term
        voteGranted := raw.voteGranted
        source
        destination
      })
  | 5 =>
      expectEq s!"{field}.tag" raw.tag "requestPreVote"
      expectEq s!"{field}.prev_log_index" raw.prevLogIndex 0
      expectEq s!"{field}.prev_log_term" raw.prevLogTerm 0
      expectEq s!"{field}.leader_commit" raw.leaderCommit 0
      expectEq s!"{field}.entry_present" raw.entryPresent false
      validateUnusedEntry
        s!"{field}.entry"
        raw.entryTerm
        raw.entryTagValue
        raw.entryTransactionId
        raw.entryTag
        raw.entryConfigurationMembership
        raw.entryRetiredMembership
      expectEq s!"{field}.response_success" raw.responseSuccess false
      expectEq s!"{field}.response_last_log_index" raw.responseLastLogIndex 0
      expectEq s!"{field}.vote_granted" raw.voteGranted false
      pure (.requestPreVote {
        term := raw.term
        lastCommittableTerm := raw.voteLastCommittableTerm
        lastCommittableIndex := raw.voteLastCommittableIndex
        source
        destination
      })
  | 6 =>
      expectEq s!"{field}.tag" raw.tag "requestPreVoteResponse"
      expectEq s!"{field}.prev_log_index" raw.prevLogIndex 0
      expectEq s!"{field}.prev_log_term" raw.prevLogTerm 0
      expectEq s!"{field}.leader_commit" raw.leaderCommit 0
      expectEq s!"{field}.entry_present" raw.entryPresent false
      validateUnusedEntry
        s!"{field}.entry"
        raw.entryTerm
        raw.entryTagValue
        raw.entryTransactionId
        raw.entryTag
        raw.entryConfigurationMembership
        raw.entryRetiredMembership
      expectEq s!"{field}.response_success" raw.responseSuccess false
      expectEq s!"{field}.response_last_log_index" raw.responseLastLogIndex 0
      expectEq
        s!"{field}.vote_last_committable_term"
        raw.voteLastCommittableTerm
        0
      expectEq
        s!"{field}.vote_last_committable_index"
        raw.voteLastCommittableIndex
        0
      pure (.requestPreVoteResponse {
        term := raw.term
        voteGranted := raw.voteGranted
        source
        destination
      })
  | 7 =>
      expectEq s!"{field}.tag" raw.tag "proposeVoteRequest"
      expectEq s!"{field}.prev_log_index" raw.prevLogIndex 0
      expectEq s!"{field}.prev_log_term" raw.prevLogTerm 0
      expectEq s!"{field}.leader_commit" raw.leaderCommit 0
      expectEq s!"{field}.entry_present" raw.entryPresent false
      validateUnusedEntry
        s!"{field}.entry"
        raw.entryTerm
        raw.entryTagValue
        raw.entryTransactionId
        raw.entryTag
        raw.entryConfigurationMembership
        raw.entryRetiredMembership
      expectEq s!"{field}.response_success" raw.responseSuccess false
      expectEq s!"{field}.response_last_log_index" raw.responseLastLogIndex 0
      expectEq
        s!"{field}.vote_last_committable_term"
        raw.voteLastCommittableTerm
        0
      expectEq
        s!"{field}.vote_last_committable_index"
        raw.voteLastCommittableIndex
        0
      expectEq s!"{field}.vote_granted" raw.voteGranted false
      pure (.proposeVoteRequest {
        term := raw.term
        source
        destination
      })
  | _ =>
      throw
        s!"{field}.tag: unsupported active message tag {raw.tagValue} ({raw.tag})"

def decodeQueue (expectedDestination : Nat) (raw : RawQueue) :
    Except String (List (Message Node TxId)) := do
  let fieldPrefix := s!"S0.network[{expectedDestination}]"
  expectEq s!"{fieldPrefix}.destination" raw.destination expectedDestination
  expectEq s!"{fieldPrefix}.capacity" raw.capacity QUEUE_CAPACITY
  expectEq
    s!"{fieldPrefix}.slots.length"
    raw.slots.length
    QUEUE_CAPACITY
  expectTrue s!"{fieldPrefix}.length" (raw.length <= QUEUE_CAPACITY)
  let mut queue : List (Message Node TxId) := []
  for slot in raw.slots do
    let field := s!"{fieldPrefix}.slots[{slot.slot}]"
    expectTrue s!"{field}.slot" (slot.slot < QUEUE_CAPACITY)
    let shouldBeActive := decide (slot.slot < raw.length)
    expectEq s!"{field}.active" slot.active shouldBeActive
    if slot.active then
      let message <- decodeQueueSlot field slot
      expectEq
        s!"{field}.destination_queue"
        (Message.destination message).val
        expectedDestination
      queue := queue ++ [message]
    else
      validateUnusedQueueSlot field slot
  expectEq s!"{fieldPrefix}.decoded_length" queue.length raw.length
  pure queue

def decodeInitialState (raw : RawInitialState) :
    Except String SimState := do
  expectEq "S0.nodes.length" raw.nodes.length NODE_COUNT
  expectEq "S0.network.length" raw.network.length NODE_COUNT
  expectEq
    "S0.pre_vote_status_enabled.length"
    raw.preVoteStatusEnabled.length
    NODE_COUNT
  let mut nodes : List (NodeState Node TxId) := []
  let mut retirementCompleted : List (Finset Node) := []
  for indexed in raw.nodes.zipIdx do
    let decoded <- decodeNode indexed.2 indexed.1
    nodes := nodes ++ [decoded.1]
    retirementCompleted := retirementCompleted ++ [decoded.2]
  let mut network : List (List (Message Node TxId)) := []
  for indexed in raw.network.zipIdx do
    let queue <- decodeQueue indexed.2 indexed.1
    network := network ++ [queue]
  let submittedTxIds <-
    decodeTxMembership
      "S0.submitted_transaction_membership"
      raw.submittedTransactionMembership
  let hasJoined <-
    decodeNodeMembership
      "S0.has_joined_membership"
      raw.hasJoinedMembership
  if nodes.length = NODE_COUNT then
    if network.length = NODE_COUNT then
      pure {
        nodes :=
          NodeStore.ofFinset hasJoined fun node =>
            (nodes[node.val]?).getD freshNodeState
        network := fun node => (network[node.val]?).getD []
        submittedTxIds
        hasJoined
        preVoteStatus :=
          fun node =>
            decodePreVoteStatus raw.preVoteStatusEnabled[node.val]!
        retirementCompleted :=
          fun node => (retirementCompleted[node.val]?).getD ∅
      }
    else
      throw "S0.network.length: decoded queue count changed"
  else
    throw "S0.nodes.length: decoded node count changed"

def decodeAction (expectedAction : Nat) (raw : RawAction) :
    Except String SimAction := do
  let fieldPrefix := s!"action {expectedAction}"
  expectEq s!"{fieldPrefix}.number" raw.action expectedAction
  let source <- nodeOfNat s!"{fieldPrefix}.source" raw.source
  let destination <- nodeOfNat s!"{fieldPrefix}.destination" raw.destination
  let noConfiguration := do
    expectNoMembers
      s!"{fieldPrefix}.configuration_membership"
      raw.configurationMembership
  match raw.kindValue with
  | 1 =>
      expectEq s!"{fieldPrefix}.kind" raw.kind "clientRequest"
      expectEq s!"{fieldPrefix}.destination" raw.destination 0
      expectEq s!"{fieldPrefix}.parameter" raw.parameter 0
      noConfiguration
      let txId <- txOfNat s!"{fieldPrefix}.transaction" raw.transaction
      pure (.clientRequest source txId)
  | 2 =>
      expectEq s!"{fieldPrefix}.kind" raw.kind "changeConfiguration"
      expectEq s!"{fieldPrefix}.destination" raw.destination 0
      expectEq s!"{fieldPrefix}.parameter" raw.parameter 0
      expectEq s!"{fieldPrefix}.transaction" raw.transaction 0
      let configuration <-
        decodeNodeMembership
          s!"{fieldPrefix}.configuration_membership"
          raw.configurationMembership
      expectTrue
        s!"{fieldPrefix}.configuration_membership"
        (decide configuration.Nonempty)
      pure (.changeConfiguration source configuration)
  | 3 =>
      expectEq s!"{fieldPrefix}.kind" raw.kind "signCommittableMessages"
      expectEq s!"{fieldPrefix}.destination" raw.destination 0
      expectEq s!"{fieldPrefix}.parameter" raw.parameter 0
      expectEq s!"{fieldPrefix}.transaction" raw.transaction 0
      noConfiguration
      pure (.signCommittableMessages source)
  | 4 =>
      expectEq s!"{fieldPrefix}.kind" raw.kind "appendEntries"
      expectEq s!"{fieldPrefix}.transaction" raw.transaction 0
      noConfiguration
      pure (.appendEntries source destination raw.parameter)
  | 5 =>
      expectEq s!"{fieldPrefix}.kind" raw.kind "receive"
      expectEq s!"{fieldPrefix}.parameter" raw.parameter 0
      expectEq s!"{fieldPrefix}.transaction" raw.transaction 0
      noConfiguration
      pure (.receive source destination)
  | 6 =>
      expectEq s!"{fieldPrefix}.kind" raw.kind "advanceCommitIndex"
      expectEq s!"{fieldPrefix}.destination" raw.destination 0
      expectEq s!"{fieldPrefix}.parameter" raw.parameter 0
      expectEq s!"{fieldPrefix}.transaction" raw.transaction 0
      noConfiguration
      pure (.advanceCommitIndex source)
  | 7 =>
      expectEq s!"{fieldPrefix}.kind" raw.kind "timeout"
      expectEq s!"{fieldPrefix}.destination" raw.destination 0
      expectEq s!"{fieldPrefix}.parameter" raw.parameter 0
      expectEq s!"{fieldPrefix}.transaction" raw.transaction 0
      noConfiguration
      pure (.timeout source)
  | 8 =>
      expectEq s!"{fieldPrefix}.kind" raw.kind "requestVote"
      expectEq s!"{fieldPrefix}.parameter" raw.parameter 0
      expectEq s!"{fieldPrefix}.transaction" raw.transaction 0
      noConfiguration
      pure (.requestVote source destination)
  | 9 =>
      expectEq s!"{fieldPrefix}.kind" raw.kind "updateTerm"
      expectEq s!"{fieldPrefix}.parameter" raw.parameter 0
      expectEq s!"{fieldPrefix}.transaction" raw.transaction 0
      noConfiguration
      pure (.updateTerm source destination)
  | 10 =>
      expectEq s!"{fieldPrefix}.kind" raw.kind "becomeLeader"
      expectEq s!"{fieldPrefix}.destination" raw.destination 0
      expectEq s!"{fieldPrefix}.parameter" raw.parameter 0
      expectEq s!"{fieldPrefix}.transaction" raw.transaction 0
      noConfiguration
      pure (.becomeLeader source)
  | 11 =>
      expectEq s!"{fieldPrefix}.kind" raw.kind "becomePreVoteCandidate"
      expectEq s!"{fieldPrefix}.destination" raw.destination 0
      expectEq s!"{fieldPrefix}.parameter" raw.parameter 0
      expectEq s!"{fieldPrefix}.transaction" raw.transaction 0
      noConfiguration
      pure (.becomePreVoteCandidate source)
  | 12 =>
      expectEq s!"{fieldPrefix}.kind" raw.kind "becomeCandidate"
      expectEq s!"{fieldPrefix}.destination" raw.destination 0
      expectEq s!"{fieldPrefix}.parameter" raw.parameter 0
      expectEq s!"{fieldPrefix}.transaction" raw.transaction 0
      noConfiguration
      pure (.becomeCandidate source)
  | 13 =>
      expectEq s!"{fieldPrefix}.kind" raw.kind "requestPreVote"
      expectEq s!"{fieldPrefix}.parameter" raw.parameter 0
      expectEq s!"{fieldPrefix}.transaction" raw.transaction 0
      noConfiguration
      pure (.requestPreVote source destination)
  | 14 =>
      expectEq s!"{fieldPrefix}.kind" raw.kind "checkQuorum"
      expectEq s!"{fieldPrefix}.destination" raw.destination 0
      expectEq s!"{fieldPrefix}.parameter" raw.parameter 0
      expectEq s!"{fieldPrefix}.transaction" raw.transaction 0
      noConfiguration
      pure (.checkQuorum source)
  | 15 =>
      expectEq s!"{fieldPrefix}.kind" raw.kind "appendRetiredCommitted"
      expectEq s!"{fieldPrefix}.destination" raw.destination 0
      expectEq s!"{fieldPrefix}.parameter" raw.parameter 0
      expectEq s!"{fieldPrefix}.transaction" raw.transaction 0
      noConfiguration
      pure (.appendRetiredCommitted source)
  | 16 =>
      expectEq s!"{fieldPrefix}.kind" raw.kind "proposeVote"
      expectEq s!"{fieldPrefix}.parameter" raw.parameter 0
      expectEq s!"{fieldPrefix}.transaction" raw.transaction 0
      noConfiguration
      pure (.proposeVote source destination)
  | 17 =>
      expectEq
        s!"{fieldPrefix}.kind"
        raw.kind
        "advanceCommitIndexAndProposeVote"
      expectEq s!"{fieldPrefix}.parameter" raw.parameter 0
      expectEq s!"{fieldPrefix}.transaction" raw.transaction 0
      noConfiguration
      pure (.advanceCommitIndexAndProposeVote source destination)
  | _ =>
      throw
        s!"{fieldPrefix}.kind: unsupported action tag {raw.kindValue} ({raw.kind})"

def decodeActions (raw : List RawAction) :
    Except String (Array SimAction) := do
  expectEq "actions.length" raw.length ACTION_COUNT
  let mut actions : Array SimAction := #[]
  for indexed in raw.zipIdx do
    let action <- decodeAction (indexed.2 + 1) indexed.1
    actions := actions.push action
  pure actions

def stateCheckFailure (context : String) (state : SimState) : String :=
  match allNodes.find? fun node =>
    (state.nodes node).commitIndex > (state.nodes node).log.length with
  | some node => s!"{context}.nodes[{node.val}].commitIndex"
  | none =>
      match allNodes.find? fun node =>
        let nodeState := state.nodes node
        nodeState.commitIndex > 0 &&
          match entryAt? nodeState.log nodeState.commitIndex with
          | some entry => !(entry.content == .signature)
          | none => true with
      | some node => s!"{context}.nodes[{node.val}].commitIndex"
      | none => s!"{context}.stateChecks"

def ensureStateChecks (context : String) (state : SimState) :
    Except String Unit :=
  if stateChecks state then
    pure ()
  else
    throw s!"{stateCheckFailure context state}: canonical stateChecks failed"

def replayCanonical
    (initial : SimState)
    (actions : Array SimAction) :
    Except String (Array SimState) := do
  let mut current := compactState initial
  ensureStateChecks "S0" current
  let mut states := #[current]
  for indexed in actions.toList.zipIdx do
    let number := indexed.2 + 1
    let action := indexed.1
    let some nextState :=
      (system (TxId := TxId)).applyAction current action
      | match action with
        | .advanceCommitIndex node =>
            throw
              s!"action {number}: canonical system.applyAction rejected advanceCommitIndex; node={
                node.val} role={reprStr (current.nodes node).role} commit={
                (current.nodes node).commitIndex} highest={
                highestCommittableIndex current node} logLength={
                (current.nodes node).log.length} signature2={
                isSignatureAt (current.nodes node).log 2} term2={
                termAt (current.nodes node).log 2} majority2={
                decide (hasMajorityAt current node 2)} configurations={
                reprStr ((activeConfigurations (current.nodes node)).map fun configuration =>
                  (configuration.index,
                    (allNodes.filter fun member =>
                      Membership.mem configuration.nodes member).map Fin.val))} acknowledgements={
                reprStr ((allNodes.filter fun member =>
                  Membership.mem (acknowledgingNodes current node 2) member).map Fin.val)}"
        | _ =>
            throw
              s!"action {number}: canonical system.applyAction rejected the action"
    let after := compactState nextState
    ensureStateChecks s!"action {number}.after" after
    expectTrue s!"action {number}.edgeChecks" (edgeChecks current after)
    current := after
    states := states.push after
  pure states

def stateAt
    (states : Array SimState)
    (step : Nat)
    (field : String) :
    Except String SimState :=
  match states[step]? with
  | some state => pure state
  | none => throw s!"{field}: state S{step} is absent"

def actionAt
    (actions : Array SimAction)
    (number : Nat)
    (field : String) :
    Except String SimAction :=
  if number = 0 then
    throw s!"{field}: action numbering starts at one"
  else
    match actions[number - 1]? with
    | some action => pure action
    | none => throw s!"{field}: action {number} is absent"

def actionKind : SimAction -> String
  | .clientRequest .. => "clientRequest"
  | .changeConfiguration .. => "changeConfiguration"
  | .appendRetiredCommitted .. => "appendRetiredCommitted"
  | .signCommittableMessages .. => "signCommittableMessages"
  | .appendEntries .. => "appendEntries"
  | .receive .. => "receive"
  | .advanceCommitIndex .. => "advanceCommitIndex"
  | .timeout .. => "timeout"
  | .becomePreVoteCandidate .. => "becomePreVoteCandidate"
  | .becomeCandidate .. => "becomeCandidate"
  | .requestVote .. => "requestVote"
  | .requestPreVote .. => "requestPreVote"
  | .checkQuorum .. => "checkQuorum"
  | .updateTerm .. => "updateTerm"
  | .becomeLeader .. => "becomeLeader"
  | .proposeVote .. => "proposeVote"
  | .advanceCommitIndexAndProposeVote .. =>
      "advanceCommitIndexAndProposeVote"

def actionSource : SimAction -> Node
  | .clientRequest node _ => node
  | .changeConfiguration source _ => source
  | .appendRetiredCommitted node => node
  | .signCommittableMessages node => node
  | .appendEntries source _ _ => source
  | .receive source _ => source
  | .advanceCommitIndex node => node
  | .timeout node => node
  | .becomePreVoteCandidate node => node
  | .becomeCandidate node => node
  | .requestVote source _ => source
  | .requestPreVote source _ => source
  | .checkQuorum node => node
  | .updateTerm source _ => source
  | .becomeLeader node => node
  | .proposeVote source _ => source
  | .advanceCommitIndexAndProposeVote source _ => source

def actionDestination? : SimAction -> Option Node
  | .appendEntries _ destination _ => some destination
  | .receive _ destination => some destination
  | .requestVote _ destination => some destination
  | .requestPreVote _ destination => some destination
  | .updateTerm _ destination => some destination
  | .proposeVote _ destination => some destination
  | .advanceCommitIndexAndProposeVote _ destination => some destination
  | _ => none

def actionParameter? : SimAction -> Option Nat
  | .appendEntries _ _ batchEnd => some batchEnd
  | _ => none

def actionConfiguration? : SimAction -> Option (Finset Node)
  | .changeConfiguration _ configuration => some configuration
  | _ => none

def queueMessageAt
    (states : Array SimState)
    (step destination slot : Nat)
    (field : String) :
    Except String (Message Node TxId) := do
  let state <- stateAt states step field
  let destination <- nodeOfNat s!"{field}.destination" destination
  match (state.network destination)[slot]? with
  | some message => pure message
  | none =>
      throw
        s!"{field}: queue {destination.val} slot {slot} is absent at S{step}"

def queueTailAt
    (states : Array SimState)
    (step destination : Nat)
    (field : String) :
    Except String (Message Node TxId) := do
  let state <- stateAt states step field
  let destination <- nodeOfNat s!"{field}.destination" destination
  match (state.network destination).getLast? with
  | some message => pure message
  | none => throw s!"{field}: queue {destination.val} is empty at S{step}"

def appendRequest
    (field : String)
    (message : Message Node TxId) :
    Except String (AppendEntriesRequest Node TxId) :=
  match message with
  | .appendEntriesRequest request => pure request
  | _ => throw s!"{field}: expected AppendEntries request"

def appendResponse
    (field : String)
    (message : Message Node TxId) :
    Except String (AppendEntriesResponse Node) :=
  match message with
  | .appendEntriesResponse response => pure response
  | _ => throw s!"{field}: expected AppendEntries response"

def messageKind : Message Node TxId -> String
  | .appendEntriesRequest .. => "appendEntriesRequest"
  | .appendEntriesResponse .. => "appendEntriesResponse"
  | .requestVoteRequest .. => "requestVoteRequest"
  | .requestVoteResponse .. => "requestVoteResponse"
  | .requestPreVote .. => "requestPreVote"
  | .requestPreVoteResponse .. => "requestPreVoteResponse"
  | .proposeVoteRequest .. => "proposeVoteRequest"

/-- Encode every full-state queue message with its stable raw tag. -/
def messageTag : Message Node TxId -> Nat
  | .appendEntriesRequest .. => 1
  | .appendEntriesResponse .. => 2
  | .requestVoteRequest .. => 3
  | .requestVoteResponse .. => 4
  | .requestPreVote .. => 5
  | .requestPreVoteResponse .. => 6
  | .proposeVoteRequest .. => 7

def appendRequestEnd (request : AppendEntriesRequest Node TxId) : Nat :=
  request.prevLogIndex + request.entries.length

def appendRequestEndTerm (request : AppendEntriesRequest Node TxId) : Nat :=
  match request.entries.getLast? with
  | some entry => entry.term
  | none => request.prevLogTerm

def previewAppendRequest
    (states : Array SimState)
    (actions : Array SimAction)
    (number : Nat)
    (field : String) :
    Except String (AppendEntriesRequest Node TxId) := do
  let state <- stateAt states (number - 1) field
  let action <- actionAt actions number field
  match action with
  | .appendEntries source destination batchEnd =>
      pure (makeAppendEntriesRequest state source destination batchEnd)
  | _ => throw s!"{field}: action {number} is not appendEntries"

def entryTermAt
    (states : Array SimState)
    (step node index : Nat)
    (field : String) :
    Except String Nat := do
  let state <- stateAt states step field
  let node <- nodeOfNat s!"{field}.node" node
  match entryAt? (state.nodes node).log index with
  | some entry => pure entry.term
  | none => throw s!"{field}: node {node.val} log index {index} is absent at S{step}"

def configurationAt
    (states : Array SimState)
    (step node index : Nat)
    (field : String) :
    Except String (Finset Node) := do
  let state <- stateAt states step field
  let node <- nodeOfNat s!"{field}.node" node
  match entryAt? (state.nodes node).log index with
  | some { content := .reconfiguration configuration, .. } => pure configuration
  | _ =>
      throw
        s!"{field}: node {node.val} log index {index} is not a reconfiguration"

def containsTransaction (state : SimState) (node : Node) (txId : TxId) : Bool :=
  (state.nodes node).log.any fun entry =>
    decide (entry.content = .transaction txId)

end CCFRaft.NaiveFullStateWitness
