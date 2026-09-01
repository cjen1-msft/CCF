-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.ExecutableTransitionSystem
import Mathlib

set_option autoImplicit false

/-!
# Arbitrary-term reconfiguring Raft model

Followers and candidates may repeatedly start successor-term elections, and
messages may move another node directly across skipped terms. Protocol handlers
receive only the acting node's local state and immutable message snapshots.

Configuration retirement is not yet represented: membership is derived from
each node's log, while `hasJoined` only prevents a removed node from being
added again.
-/

namespace CCFRaft

/-- Number of nodes in the fixed world available to configurations. -/
def NODE_COUNT : Nat := 15
/-- Default node identifiers used by bounded simulation and existing traces. -/
abbrev Node := Fin NODE_COUNT

/--
Static inputs used only to construct the initial state and implicit
configuration. They are not stored in runtime `State`.
-/
class Bootstrap (Node : Type) [DecidableEq Node] where
  configuration : Finset Node
  leader : Node
  leader_mem : Membership.mem configuration leader

/-- The canonical five-node bootstrap configuration used by existing traces. -/
def DEFAULT_BOOTSTRAP_CONFIGURATION : Finset Node :=
  Finset.univ.filter fun node => node.val < 5

/-- Node zero, the canonical bootstrap leader used by existing traces. -/
def DEFAULT_BOOTSTRAP_LEADER : Node := Fin.mk 0 (by decide)

/-- Preserve the historical `{0,1,2,3,4}` bootstrap unless locally overridden. -/
instance defaultBootstrap : Bootstrap Node where
  configuration := DEFAULT_BOOTSTRAP_CONFIGURATION
  leader := DEFAULT_BOOTSTRAP_LEADER
  leader_mem := by decide

/-- The selected initial leader. -/
def INITIAL_LEADER
    {Node : Type}
    [DecidableEq Node]
    [bootstrap : Bootstrap Node] :
    Node :=
  bootstrap.leader
/-- Initial bootstrap term. -/
def TERM_ONE : Nat := 1
/-- The selected implicit projected configuration at log index zero. -/
def INITIAL_CONFIGURATION
    {Node : Type}
    [DecidableEq Node]
    [bootstrap : Bootstrap Node] :
    Finset Node :=
  bootstrap.configuration

/-- Every valid bootstrap configuration contains its selected leader. -/
theorem initialLeader_mem_initialConfiguration
    {Node : Type}
    [DecidableEq Node]
    [bootstrap : Bootstrap Node] :
    Membership.mem
      (INITIAL_CONFIGURATION (Node := Node))
      (INITIAL_LEADER (Node := Node)) :=
  bootstrap.leader_mem

/-- Every valid bootstrap configuration is nonempty. -/
theorem initialConfiguration_nonempty
    {Node : Type}
    [DecidableEq Node]
    [bootstrap : Bootstrap Node] :
    (INITIAL_CONFIGURATION (Node := Node)).Nonempty := by
  exact
    Exists.intro
      (INITIAL_LEADER (Node := Node))
      (initialLeader_mem_initialConfiguration (Node := Node))

/-- Leadership roles represented by the model. -/
inductive Role where
  /-- A node that has not yet observed a configuration adding it. -/
  | none
  /-- A replica that receives AppendEntries messages. -/
  | follower
  /-- A node soliciting votes in its current term. -/
  | candidate
  /-- The single node that accepts requests and sends AppendEntries. -/
  | leader
  deriving DecidableEq, Repr

/-- Payload kinds represented by the Raft projection. -/
inductive EntryContent (Node TxId : Type) where
  /-- An ordinary client transaction with its external identifier. -/
  | transaction (txId : TxId)
  /-- A signature over the preceding log prefix. -/
  | signature
  /-- A new configuration, stored at a one-based physical log index. -/
  | reconfiguration (nodes : Finset Node)
  deriving DecidableEq

/-- A transaction or signature stored in a Raft log. -/
structure Entry (Node TxId : Type) where
  term : Nat
  content : EntryContent Node TxId
  deriving DecidableEq

/-- Immutable AppendEntries data captured when a leader sends a request. -/
structure AppendEntriesRequest (Node TxId : Type) where
  term : Nat
  prevLogIndex : Nat
  prevLogTerm : Nat
  entries : List (Entry Node TxId)
  leaderCommit : Nat
  source : Node
  destination : Node
  deriving DecidableEq

/-- ACK or NACK returned after processing an AppendEntries request. -/
structure AppendEntriesResponse (Node : Type) where
  term : Nat
  success : Bool
  lastLogIndex : Nat
  source : Node
  destination : Node
  deriving DecidableEq, Repr

/-! RequestVote messages carry the candidate's last committable position. -/

/-- Candidate log summary sent to a potential voter. -/
structure RequestVoteRequest (Node : Type) where
  term : Nat
  lastCommittableTerm : Nat
  lastCommittableIndex : Nat
  source : Node
  destination : Node
  deriving DecidableEq, Repr

/-- A voter's granted or rejected RequestVote response. -/
structure RequestVoteResponse (Node : Type) where
  term : Nat
  voteGranted : Bool
  source : Node
  destination : Node
  deriving DecidableEq, Repr

/-- Network messages used by replication and elections. -/
inductive Message (Node TxId : Type) where
  /-- A leader-to-follower replication request. -/
  | appendEntriesRequest (request : AppendEntriesRequest Node TxId)
  /-- A follower-to-leader acknowledgement or rejection. -/
  | appendEntriesResponse (response : AppendEntriesResponse Node)
  /-- A candidate-to-voter RequestVote request. -/
  | requestVoteRequest (request : RequestVoteRequest Node)
  /-- A voter-to-candidate RequestVote response. -/
  | requestVoteResponse (response : RequestVoteResponse Node)
  deriving DecidableEq

variable {Node TxId : Type}

namespace Message

/-- Read a message's sender without inspecting any node state. -/
def source : Message Node TxId -> Node
  | .appendEntriesRequest request => request.source
  | .appendEntriesResponse response => response.source
  | .requestVoteRequest request => request.source
  | .requestVoteResponse response => response.source

/-- Read a message's intended recipient. -/
def destination : Message Node TxId -> Node
  | .appendEntriesRequest request => request.destination
  | .appendEntriesResponse response => response.destination
  | .requestVoteRequest request => request.destination
  | .requestVoteResponse response => response.destination

/-- Term snapshot carried by any message kind. -/
def term : Message Node TxId -> Nat
  | .appendEntriesRequest request => request.term
  | .appendEntriesResponse response => response.term
  | .requestVoteRequest request => request.term
  | .requestVoteResponse response => response.term

end Message

/-- Protocol state stored locally by one node. -/
structure NodeState (Node TxId : Type) where
  role : Role
  currentTerm : Nat
  log : List (Entry Node TxId)
  commitIndex : Nat
  sentIndex : Node -> Nat
  matchIndex : Node -> Nat
  isNewFollower : Bool
  votedFor : Option Node
  votesGranted : Finset Node

namespace NodeState

/-- The prefix of a node's log up to its local commit index. -/
def committedLog
    (state : NodeState Node TxId) :
    List (Entry Node TxId) :=
  state.log.take state.commitIndex

end NodeState

/-- The fresh local state assigned when a configuration first adds a node. -/
def freshNodeState : NodeState Node TxId where
  role := .none
  currentTerm := 0
  log := []
  commitIndex := 0
  sentIndex := fun _ => 0
  matchIndex := fun _ => 0
  isNewFollower := true
  votedFor := none
  votesGranted := ∅

/-- Finite storage for node-local protocol state. -/
structure NodeStore (Node TxId : Type) where
  entries : Finmap (fun _ : Node => NodeState Node TxId)

namespace NodeStore

variable [DecidableEq Node]

/-- Read an allocated node state. -/
def node? (nodes : NodeStore Node TxId) (node : Node) :
    Option (NodeState Node TxId) :=
  nodes.entries.lookup node

/-- Read a node state, using the inert fresh state for an unallocated node. -/
def get (nodes : NodeStore Node TxId) (node : Node) :
    NodeState Node TxId :=
  (nodes.node? node).getD freshNodeState

instance : CoeFun (NodeStore Node TxId) (fun _ => Node -> NodeState Node TxId) where
  coe := get

/-- Whether storage has been allocated for a node identity. -/
def allocated (nodes : NodeStore Node TxId) (node : Node) : Prop :=
  nodes.node? node |>.isSome

instance (nodes : NodeStore Node TxId) (node : Node) :
    Decidable (nodes.allocated node) :=
  inferInstanceAs (Decidable (nodes.node? node |>.isSome))

/-- Insert or replace one allocated node state. -/
def set
    (nodes : NodeStore Node TxId)
    (node : Node)
    (value : NodeState Node TxId) :
    NodeStore Node TxId :=
  ⟨nodes.entries.insert node value⟩

/-- A store with no allocated node identities. -/
def empty : NodeStore Node TxId :=
  ⟨∅⟩

/-- Allocate a finite set of keys with values computed from each key. -/
def ofFinset
    (keys : Finset Node)
    (value : Node -> NodeState Node TxId) :
    NodeStore Node TxId :=
  let entries :=
    keys.1.map fun node => Sigma.mk node (value node)
  ⟨{
    entries
    nodupKeys := by
      rw [← Multiset.nodup_keys]
      simpa [entries, Multiset.keys] using keys.2
  }⟩

/-- Add fresh states for a finite set without replacing existing states. -/
def allocate
    (nodes : NodeStore Node TxId)
    (added : Finset Node) :
    NodeStore Node TxId :=
  ⟨nodes.entries ∪ (ofFinset added fun _ => freshNodeState).entries⟩

@[simp]
theorem node?_set_same
    (nodes : NodeStore Node TxId)
    (node : Node)
    (value : NodeState Node TxId) :
    (nodes.set node value).node? node = some value := by
  simp [node?, set]

@[simp]
theorem node?_set_of_ne
    (nodes : NodeStore Node TxId)
    (node candidate : Node)
    (value : NodeState Node TxId)
    (different : Not (candidate = node)) :
    (nodes.set node value).node? candidate = nodes.node? candidate := by
  simp [node?, set, Finmap.lookup_insert_of_ne, different]

@[simp]
theorem get_set_same
    (nodes : NodeStore Node TxId)
    (node : Node)
    (value : NodeState Node TxId) :
    nodes.set node value node = value := by
  simp [get]

@[simp]
theorem get_set_of_ne
    (nodes : NodeStore Node TxId)
    (node candidate : Node)
    (value : NodeState Node TxId)
    (different : Not (candidate = node)) :
    nodes.set node value candidate = nodes candidate := by
  simp [get, node?_set_of_ne, different]

@[simp]
theorem node?_ofFinset_of_mem
    (keys : Finset Node)
    (value : Node -> NodeState Node TxId)
    (node : Node)
    (member : node ∈ keys) :
    (ofFinset keys value).node? node = some (value node) := by
  rw [node?, Finmap.lookup_eq_some_iff]
  simp [ofFinset, member]

@[simp]
theorem node?_ofFinset_of_not_mem
    (keys : Finset Node)
    (value : Node -> NodeState Node TxId)
    (node : Node)
    (notMember : node ∉ keys) :
    (ofFinset keys value).node? node = none := by
  rw [node?, Finmap.lookup_eq_none]
  simpa [ofFinset, Finmap.mem_def, Multiset.keys] using notMember

@[simp]
theorem get_ofFinset
    (keys : Finset Node)
    (value : Node -> NodeState Node TxId)
    (node : Node) :
    ofFinset keys value node =
      if node ∈ keys then value node else freshNodeState := by
  simp only [get]
  split <;> simp_all

@[simp]
theorem node?_allocate_of_allocated
    (nodes : NodeStore Node TxId)
    (added : Finset Node)
    (node : Node)
    (allocated : nodes.allocated node) :
    (nodes.allocate added).node? node = nodes.node? node := by
  change (nodes.node? node).isSome at allocated
  rw [Option.isSome_iff_exists] at allocated
  rcases allocated with ⟨value, found⟩
  simp only [node?, allocate]
  rw [Finmap.lookup_union_left (Finmap.mem_of_lookup_eq_some found)]

@[simp]
theorem node?_allocate_of_not_allocated_of_mem
    (nodes : NodeStore Node TxId)
    (added : Finset Node)
    (node : Node)
    (notAllocated : Not (nodes.allocated node))
    (member : node ∈ added) :
    (nodes.allocate added).node? node = some freshNodeState := by
  have missing : nodes.node? node = none := by
    cases found : nodes.node? node <;>
      simp_all [NodeStore.allocated]
  have notIn : node ∉ nodes.entries := by
    rw [← Finmap.lookup_eq_none]
    exact missing
  simp only [node?, allocate]
  rw [Finmap.lookup_union_right notIn]
  exact node?_ofFinset_of_mem added (fun _ => freshNodeState) node member

end NodeStore

/-- Global state: allocated nodes, queues, transaction IDs, and join history. -/
structure State (Node TxId : Type) where
  nodes : NodeStore Node TxId
  network : Node -> List (Message Node TxId)
  submittedTxIds : Finset TxId
  hasJoined : Finset Node

variable [DecidableEq Node] [DecidableEq TxId]

/-- Read an allocated local state from the global state. -/
def State.node? (state : State Node TxId) (node : Node) :
    Option (NodeState Node TxId) :=
  state.nodes.node? node

/-- Whether the global state has allocated storage for a node identity. -/
def State.allocated (state : State Node TxId) (node : Node) : Prop :=
  state.nodes.allocated node

instance (state : State Node TxId) (node : Node) :
    Decidable (state.allocated node) :=
  inferInstanceAs (Decidable (state.nodes.allocated node))

/-- Replace one node state while leaving every other node unchanged. -/
def updateNode
    (nodes : NodeStore Node TxId)
    (node : Node)
    (value : NodeState Node TxId) :
    NodeStore Node TxId :=
  nodes.set node value

/-- Reading the node just updated returns the new value. -/
@[simp]
theorem updateNode_same
    (nodes : NodeStore Node TxId)
    (node : Node)
    (value : NodeState Node TxId) :
    updateNode nodes node value node = value := by
  simp [updateNode]

/-- Reading another node after an update returns its old value. -/
@[simp]
theorem updateNode_of_ne
    (nodes : NodeStore Node TxId)
    (node candidate : Node)
    (value : NodeState Node TxId)
    (different : Not (candidate = node)) :
    updateNode nodes node value candidate = nodes candidate := by
  simp [updateNode, different]

/-- Replace one peer index in a node-local index table. -/
def updateIndex
    (indices : Node -> Nat)
    (node : Node)
    (value : Nat) :
    Node -> Nat :=
  Function.update indices node value

/-- Reading the updated peer index returns the new value. -/
@[simp]
theorem updateIndex_same
    (indices : Node -> Nat)
    (node : Node)
    (value : Nat) :
    updateIndex indices node value node = value := by
  simp [updateIndex]

/-- Updating one peer index leaves all other peer indices unchanged. -/
@[simp]
theorem updateIndex_of_ne
    (indices : Node -> Nat)
    (node candidate : Node)
    (value : Nat)
    (different : Not (candidate = node)) :
    updateIndex indices node value candidate = indices candidate := by
  simp [updateIndex, different]

/-- Replace the FIFO queue for one destination. -/
def updateQueue
    (network : Node -> List (Message Node TxId))
    (destination : Node)
    (queue : List (Message Node TxId)) :
    Node -> List (Message Node TxId) :=
  Function.update network destination queue

/-- Reading the replaced destination queue returns the new queue. -/
@[simp]
theorem updateQueue_same
    (network : Node -> List (Message Node TxId))
    (destination : Node)
    (queue : List (Message Node TxId)) :
    updateQueue network destination queue destination = queue := by
  simp [updateQueue]

/-- Replacing one destination queue leaves other queues unchanged. -/
@[simp]
theorem updateQueue_of_ne
    (network : Node -> List (Message Node TxId))
    (destination candidate : Node)
    (queue : List (Message Node TxId))
    (different : Not (candidate = destination)) :
    updateQueue network destination queue candidate = network candidate := by
  simp [updateQueue, different]

variable [Bootstrap Node]

/-- Initialize bootstrap members in term one and all other nodes unused. -/
def initialNodeState (node : Node) : NodeState Node TxId where
  role :=
    if node = INITIAL_LEADER then
      .leader
    else if node ∈ INITIAL_CONFIGURATION then
      .follower
    else
      .none
  currentTerm := if node ∈ INITIAL_CONFIGURATION then TERM_ONE else 0
  log := []
  commitIndex := 0
  sentIndex := fun _ => 0
  matchIndex := fun _ => 0
  isNewFollower := true
  votedFor := none
  votesGranted := ∅

/-- Allocate local states for exactly the bootstrap configuration. -/
def initialNodes : NodeStore Node TxId :=
  NodeStore.ofFinset INITIAL_CONFIGURATION initialNodeState

/-- Initialize bootstrap members, queues, and allocated transaction IDs. -/
def initialState : State Node TxId where
  nodes := initialNodes
  network := fun _ => []
  submittedTxIds := ∅
  hasJoined := INITIAL_CONFIGURATION

/-- A configuration paired with its projected one-based log index. -/
structure Configuration (Node : Type) where
  index : Nat
  nodes : Finset Node
  deriving DecidableEq

/-- The projected bootstrap configuration, which has no physical log entry. -/
def implicitConfiguration : Configuration Node where
  index := 0
  nodes := INITIAL_CONFIGURATION

/-- Collect physical reconfiguration entries with their one-based indices. -/
def configurationsInLogFrom :
    Nat -> List (Entry Node TxId) -> List (Configuration Node)
  | _, [] => []
  | index, entry :: entries =>
      let remaining := configurationsInLogFrom (index + 1) entries
      match entry.content with
      | .reconfiguration nodes => { index, nodes } :: remaining
      | _ => remaining

/-- All physical reconfiguration entries in a log. -/
def configurationsInLog
    (log : List (Entry Node TxId)) :
    List (Configuration Node) :=
  configurationsInLogFrom 1 log

/-- All configurations known from a log, including implicit configuration 0. -/
def allConfigurations
    (log : List (Entry Node TxId)) :
    List (Configuration Node) :=
  implicitConfiguration :: configurationsInLog log

/-- The latest configuration represented in a node's current log. -/
def latestConfiguration
    (state : NodeState Node TxId) :
    Configuration Node :=
  (configurationsInLog state.log).foldl (fun _ configuration => configuration)
    implicitConfiguration

/-- The latest reconfiguration in a log at or before a supplied frontier. -/
def currentConfigurationAt
    (log : List (Entry Node TxId))
    (commitIndex : Nat) : Configuration Node :=
  (configurationsInLog log).foldl
    (fun current configuration =>
      if configuration.index <= commitIndex then configuration else current)
    implicitConfiguration

/-- The latest reconfiguration at or before the node's local commit frontier. -/
def currentConfiguration
    (state : NodeState Node TxId) :
    Configuration Node :=
  currentConfigurationAt state.log state.commitIndex

/--
The current configuration and all later pending configurations known from the
node's log.
-/
def activeConfigurations
    (state : NodeState Node TxId) :
    List (Configuration Node) :=
  let current := currentConfiguration state
  (allConfigurations state.log).filter fun configuration =>
    current.index <= configuration.index

/-- Union of every node in a node's current or pending configurations. -/
def activeNodeUnion (state : NodeState Node TxId) : Finset Node :=
  (activeConfigurations state).foldl
    (fun nodes configuration => nodes ∪ configuration.nodes)
    ∅

/-- Read a one-based log index, returning `none` for index zero or past the end. -/
def entryAt? (log : List (Entry Node TxId)) (index : Nat) : Option (Entry Node TxId) :=
  if index = 0 then none else log[index - 1]?

/-- Read the term at a one-based index, using zero when no entry exists. -/
def termAt (log : List (Entry Node TxId)) (index : Nat) : Nat :=
  (entryAt? log index).map Entry.term |>.getD 0

/-- Check whether a one-based log position contains a signature. -/
def isSignatureAt (log : List (Entry Node TxId)) (index : Nat) : Bool :=
  match entryAt? log index with
  | some entry => decide (entry.content = .signature)
  | none => false

/-- Return the one-based index of the latest signature, or zero if absent. -/
def maxCommittableIndex (log : List (Entry Node TxId)) : Nat :=
  (List.range (log.length + 1)).foldl
    (fun best index =>
      if isSignatureAt log index then max best index else best)
    0

/--
A node may campaign once some known configuration containing it has reached
the node's signed log frontier. Configuration zero therefore admits bootstrap
members even before the first physical signature.
-/
def campaignEligible
    (node : Node)
    (state : NodeState Node TxId) : Prop :=
  (activeConfigurations state).any fun configuration =>
    decide (
      node ∈ configuration.nodes /\
        configuration.index <= maxCommittableIndex state.log)

instance (node : Node) (state : NodeState Node TxId) :
    Decidable (campaignEligible node state) := by
  unfold campaignEligible
  infer_instance

/-- Return the term of the latest signature, or zero if absent. -/
def maxCommittableTerm (log : List (Entry Node TxId)) : Nat :=
  termAt log (maxCommittableIndex log)

/-- Return the latest signature no later than a supplied log frontier. -/
def maxCommittableIndexUpTo
    (log : List (Entry Node TxId))
    (frontier : Nat) : Nat :=
  maxCommittableIndex (log.take frontier)

/-- Include a node's persisted commit frontier in its election snapshot. -/
def lastCommittableIndex (state : NodeState Node TxId) : Nat :=
  max state.commitIndex (maxCommittableIndex state.log)

/-- Return the term at a node's last committable election position. -/
def lastCommittableTerm (state : NodeState Node TxId) : Nat :=
  termAt state.log (lastCommittableIndex state)

/-- Select the log entries between the previous index and chosen batch end. -/
def messageEntries
    (log : List (Entry Node TxId))
    (previousIndex batchEnd : Nat) :
    List (Entry Node TxId) :=
  (log.drop previousIndex).take (batchEnd - previousIndex)

/-- Append a message unless an exactly equal message is already queued. -/
def enqueueNoDup
    (network : Node -> List (Message Node TxId))
    (message : Message Node TxId) :
    Node -> List (Message Node TxId) :=
  let destination := message.destination
  let queue := network destination
  if message ∈ queue then
    network
  else
    updateQueue network destination (queue ++ [message])

/-- Remove the first message from a source while preserving all other order. -/
def takeFirstFrom
    (source : Node) :
    List (Message Node TxId) ->
      Option (Message Node TxId × List (Message Node TxId))
  | [] => none
  | message :: tail =>
      if message.source = source then
        some (message, tail)
      else
        match takeFirstFrom source tail with
        | none => none
        | some (selected, remaining) =>
            some (selected, message :: remaining)

/-- Check that a request's previous index and term match the follower log. -/
def logOk
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) : Prop :=
  request.prevLogIndex = 0 \/
    (request.prevLogIndex <= state.log.length /\
      termAt state.log request.prevLogIndex = request.prevLogTerm)

/-- Check whether a heartbeat or all requested entry terms are already present. -/
def alreadyDone
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) : Prop :=
  request.entries = [] \/
    (request.prevLogIndex + request.entries.length <= state.log.length /\
      ((state.log.drop request.prevLogIndex).take request.entries.length).map
          Entry.term =
        request.entries.map Entry.term)

/-- Number of request entries that overlap the follower's existing suffix. -/
def overlapLength
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) : Nat :=
  min request.entries.length
    (state.log.length - request.prevLogIndex)

/-- Detect a differing term in the overlapping part of a request. -/
def hasTermConflict
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) : Prop :=
  Not (request.entries = []) /\
    Not (
      ((state.log.drop request.prevLogIndex).take
          (overlapLength state request)).map Entry.term =
        (request.entries.take (overlapLength state request)).map Entry.term)

/-- Check that a request safely extends a matching follower prefix. -/
def noConflictExtension
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) : Prop :=
  Not (request.entries = []) /\
    request.prevLogIndex <= state.log.length /\
    state.log.length < request.prevLogIndex + request.entries.length /\
    (state.log.drop request.prevLogIndex).take
        (state.log.length - request.prevLogIndex) =
      request.entries.take (state.log.length - request.prevLogIndex)

/-- Make the previous-entry consistency guard executable. -/
instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    Decidable (logOk state request) := by
  unfold logOk
  infer_instance

/-- Make the already-applied request guard executable. -/
instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    Decidable (alreadyDone state request) := by
  unfold alreadyDone
  infer_instance

/-- Make term-conflict detection executable. -/
instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    Decidable (hasTermConflict state request) := by
  unfold hasTermConflict
  infer_instance

/-- Make no-conflict extension detection executable. -/
instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    Decidable (noConflictExtension state request) := by
  unfold noConflictExtension
  infer_instance

/-- Advance commit only to a signature in the verified request frontier. -/
def committedFromLeader
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    (newLog : List (Entry Node TxId)) : Nat :=
  max state.commitIndex
    (maxCommittableIndexUpTo newLog
      (min request.leaderCommit
        (request.prevLogIndex + request.entries.length)))

/-- Construct a successful response for an applied request. -/
def successResponse
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    (lastLogIndex : Nat) :
    AppendEntriesResponse Node where
  term := state.currentTerm
  success := true
  lastLogIndex
  source := request.destination
  destination := request.source

/-- Find the highest local index whose term could match a rejected request. -/
def findHighestPossibleMatch
    (log : List (Entry Node TxId))
    (index term : Nat) : Nat :=
  (List.range (min index log.length + 1)).foldl
    (fun best candidate =>
      if candidate > 0 /\ termAt log candidate <= term then
        max best candidate
      else
        best)
    0

/-- Construct source-compatible NACK metadata for stale or inconsistent requests. -/
def failureResponse
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    AppendEntriesResponse Node :=
  if request.term < state.currentTerm then
    { term := state.currentTerm
      success := false
      lastLogIndex := state.log.length
      source := request.destination
      destination := request.source }
  else
    let previousTerm :=
      if request.prevLogIndex = 0 then
        0
      else if request.prevLogIndex > state.log.length then
        0
      else
        termAt state.log state.log.length
    if previousTerm = 0 then
      { term := state.currentTerm
        success := false
        lastLogIndex := state.log.length
        source := request.destination
        destination := request.source }
    else
      let lastLogIndex :=
        findHighestPossibleMatch
          state.log request.prevLogIndex request.prevLogTerm
      { term :=
          if lastLogIndex = 0 then
            TERM_ONE
          else
            termAt state.log lastLogIndex
        success := false
        lastLogIndex
        source := request.destination
        destination := request.source }

/-- Reject stale-term requests or requests whose previous entry does not match. -/
def rejectAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  if request.term < state.currentTerm \/
      (request.term = state.currentTerm /\
        state.role = .follower /\
        Not (logOk state request)) then
    some (state, failureResponse state request)
  else
    none

/-- ACK a request whose entries are already present, possibly learning commit. -/
def appendEntriesAlreadyDone?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  if alreadyDone state request then
    let commitIndex := committedFromLeader state request state.log
    let nextState := { state with commitIndex }
    some
      (nextState,
        successResponse nextState request
          (request.prevLogIndex + request.entries.length))
  else
    none

/-- Truncate a conflicting uncommitted suffix without consuming the request. -/
def conflictAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId) :=
  if hasTermConflict state request /\ state.isNewFollower then
    some
      { state with
        log := state.log.take request.prevLogIndex
        isNewFollower := false }
  else
    none

/-- Append a matching extension and return an ACK. -/
def noConflictAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  if noConflictExtension state request then
    let newLog := state.log.take request.prevLogIndex ++ request.entries
    let commitIndex := committedFromLeader state request newLog
    let nextState := { state with log := newLog, commitIndex }
    some (nextState, successResponse nextState request newLog.length)
  else
    none

/-- Apply the accepted-request branches, composing truncation with retry. -/
def acceptAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  if request.term = state.currentTerm /\
      state.role = .follower /\
      logOk state request /\
      request.prevLogIndex >= state.commitIndex then
    match appendEntriesAlreadyDone? state request with
    | some result => some result
    | none =>
        match noConflictAppendEntriesRequest? state request with
        | some result => some result
        | none =>
            match conflictAppendEntriesRequest? state request with
            | none => none
            | some truncated =>
                match appendEntriesAlreadyDone? truncated request with
                | some result => some result
                | none => noConflictAppendEntriesRequest? truncated request
  else
    none

/-- Prefer rejection when required; otherwise run the accepted-request logic. -/
def handleAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  match rejectAppendEntriesRequest? state request with
  | some result => some result
  | none => acceptAppendEntriesRequest? state request

/-- A same-term candidate steps down before retrying the unchanged request. -/
def returnToFollowerState?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId) :=
  if request.term = state.currentTerm /\
      state.role = .candidate then
    some { state with role := .follower, isNewFollower := true }
  else
    none

/-- Update leader match or sent indices from an ACK or NACK. -/
def handleAppendEntriesResponse?
    (state : NodeState Node TxId)
    (response : AppendEntriesResponse Node) :
    Option (NodeState Node TxId) :=
  if response.success = true /\
      response.term = state.currentTerm /\
      state.role = .leader then
    some
      { state with
        matchIndex :=
          updateIndex
            state.matchIndex
            response.source
            (max (state.matchIndex response.source) response.lastLogIndex) }
  else if response.success = false then
    let possible :=
      findHighestPossibleMatch state.log response.lastLogIndex response.term
    some
      { state with
        sentIndex :=
          updateIndex
            state.sentIndex
            response.source
            (max
              (min possible (state.sentIndex response.source))
              (state.matchIndex response.source)) }
  else if state.role != .leader then
    some state
  else if response.term < state.currentTerm then
    some state
  else
    none

/-- Compare a candidate log summary with a voter's local log. -/
def voteLogUpToDate
    (state : NodeState Node TxId)
    (request : RequestVoteRequest Node) : Prop :=
  request.lastCommittableTerm > maxCommittableTerm state.log \/
    (request.lastCommittableTerm = maxCommittableTerm state.log /\
      request.lastCommittableIndex >= maxCommittableIndex state.log)

instance (state : NodeState Node TxId) (request : RequestVoteRequest Node) :
    Decidable (voteLogUpToDate state request) := by
  unfold voteLogUpToDate
  infer_instance

/-- Handle a current-term RequestVote request and construct the reply. -/
def handleRequestVoteRequest?
    (state : NodeState Node TxId)
    (request : RequestVoteRequest Node) :
    Option (NodeState Node TxId × RequestVoteResponse Node) :=
  if request.term <= state.currentTerm then
    let grant : Bool :=
      decide (
        request.term = state.currentTerm /\
          voteLogUpToDate state request /\
          (state.votedFor = none \/
            state.votedFor = some request.source))
    let nextState :=
      if grant then { state with votedFor := some request.source } else state
    some
      (nextState,
        { term := state.currentTerm
          voteGranted := grant
          source := request.destination
          destination := request.source })
  else
    none

/-- Tally or discard a RequestVote response at the candidate. -/
def handleRequestVoteResponse?
    (state : NodeState Node TxId)
    (response : RequestVoteResponse Node) :
    Option (NodeState Node TxId) :=
  if response.term < state.currentTerm then
    some state
  else if state.role != .candidate then
    some state
  else if response.term = state.currentTerm then
    if response.voteGranted then
      some
        { state with
          votesGranted := insert response.source state.votesGranted }
    else
      some state
  else
    none

/-- Build a RequestVote message from candidate-local state. -/
def makeRequestVoteRequest
    (state : State Node TxId)
    (source destination : Node) :
    RequestVoteRequest Node :=
  let sourceState := state.nodes source
  { term := sourceState.currentTerm
    lastCommittableTerm := lastCommittableTerm sourceState
    lastCommittableIndex := lastCommittableIndex sourceState
    source
    destination }

/-- Requests may introduce an unknown sender; responses require a known peer. -/
def messageSourceAllowed
    (state : State Node TxId)
    (message : Message Node TxId) : Prop :=
  match message with
  | .appendEntriesRequest _ => True
  | .requestVoteRequest _ => True
  | .appendEntriesResponse response => state.allocated response.source
  | .requestVoteResponse response => state.allocated response.source

instance
    (state : State Node TxId)
    (message : Message Node TxId) :
    Decidable (messageSourceAllowed state message) := by
  cases message <;> simp only [messageSourceAllowed] <;> infer_instance

/-- Return the selected message exactly when it carries a newer term. -/
def newerMessage?
    (state : State Node TxId)
    (source destination : Node) :
    Option (Message Node TxId) := do
  let (selected, _) <- takeFirstFrom source (state.network destination)
  if messageSourceAllowed state selected /\
      (state.nodes destination).currentTerm < selected.term then
    some selected
  else
    none

/-- Consume a request and enqueue its response without duplicates. -/
def reply
    (network : Node -> List (Message Node TxId))
    (requestDestination : Node)
    (remaining : List (Message Node TxId))
    (response : AppendEntriesResponse Node) :
    Node -> List (Message Node TxId) :=
  enqueueNoDup
    (updateQueue network requestDestination remaining)
    (.appendEntriesResponse response)

/-- Process the first queued message from a chosen source at a destination. -/
def handleReceive?
    (state : State Node TxId)
    (source destination : Node) :
    Option (State Node TxId) :=
  match takeFirstFrom source (state.network destination) with
  | none => none
  | some (message, remaining) =>
      if message.destination != destination then
        none
      else
        match message with
        | .appendEntriesRequest request =>
            match returnToFollowerState? (state.nodes destination) request with
            | some nextNode =>
                some
                  { state with
                    nodes := updateNode state.nodes destination nextNode }
            | none =>
                match handleAppendEntriesRequest? (state.nodes destination) request with
                | none => none
                | some (nextNode, response) =>
                    some
                      { state with
                        nodes := updateNode state.nodes destination nextNode
                        network :=
                          reply state.network destination remaining response }
        | .appendEntriesResponse response =>
            if state.allocated response.source then
              match
                handleAppendEntriesResponse? (state.nodes destination) response
              with
              | none => none
              | some nextNode =>
                  some
                    { state with
                      nodes := updateNode state.nodes destination nextNode
                      network :=
                        updateQueue state.network destination remaining }
            else
              some
                { state with
                  network :=
                    updateQueue state.network destination remaining }
        | .requestVoteRequest request =>
            match handleRequestVoteRequest? (state.nodes destination) request with
            | none => none
            | some (nextNode, response) =>
                some
                  { state with
                    nodes := updateNode state.nodes destination nextNode
                    network :=
                      enqueueNoDup
                        (updateQueue state.network destination remaining)
                        (.requestVoteResponse response) }
        | .requestVoteResponse response =>
            if state.allocated response.source then
              match
                handleRequestVoteResponse? (state.nodes destination) response
              with
              | none => none
              | some nextNode =>
                  some
                    { state with
                      nodes := updateNode state.nodes destination nextNode
                      network :=
                        updateQueue state.network destination remaining }
            else
              some
                { state with
                  network :=
                    updateQueue state.network destination remaining }

/-- Snapshot leader-local replication state into an AppendEntries request. -/
def makeAppendEntriesRequest
    (state : State Node TxId)
    (source destination : Node)
    (batchEnd : Nat) :
    AppendEntriesRequest Node TxId :=
  let sourceState := state.nodes source
  let previousIndex := sourceState.sentIndex destination
  { term := sourceState.currentTerm
    prevLogIndex := previousIndex
    prevLogTerm := termAt sourceState.log previousIndex
    entries := messageEntries sourceState.log previousIndex batchEnd
    leaderCommit := sourceState.commitIndex
    source
    destination }

/-- Nodes locally known by the leader to acknowledge a candidate index. -/
def acknowledgingNodes
    (state : State Node TxId)
    (leader : Node)
    (index : Nat) :
    Finset Node :=
  (activeNodeUnion (state.nodes leader)).filter fun node =>
    node = leader \/
      (state.nodes leader).matchIndex node >= index

/-- True when a support set contains a strict majority of one configuration. -/
def hasConfigurationMajority
    (support : Finset Node)
    (configuration : Configuration Node) : Prop :=
  (support ∩ configuration.nodes).card * 2 > configuration.nodes.card

instance (support : Finset Node) (configuration : Configuration Node) :
    Decidable (hasConfigurationMajority support configuration) := by
  unfold hasConfigurationMajority
  infer_instance

/-- True when every configuration governing an index has replication support. -/
def hasMajorityAt
    (state : State Node TxId)
    (leader : Node)
    (index : Nat) : Prop :=
  (activeConfigurations (state.nodes leader)).all fun configuration =>
    decide (
      configuration.index <= index ->
        hasConfigurationMajority
          (acknowledgingNodes state leader index)
          configuration)

/-- Make the per-active-configuration replication predicate executable. -/
instance (state : State Node TxId) (leader : Node) (index : Nat) :
    Decidable (hasMajorityAt state leader index) := by
  unfold hasMajorityAt
  infer_instance

/-- True when votes form a strict majority in every active configuration. -/
def hasElectionMajority
    (state : State Node TxId)
    (candidate : Node) : Prop :=
  (activeConfigurations (state.nodes candidate)).all fun configuration =>
    decide (
      hasConfigurationMajority
        (state.nodes candidate).votesGranted
        configuration)

instance (state : State Node TxId) (candidate : Node) :
    Decidable (hasElectionMajority state candidate) := by
  unfold hasElectionMajority
  infer_instance

/-- Greatest newer current-term signature acknowledged by a majority. -/
def highestCommittableIndex
    (state : State Node TxId)
    (leader : Node) : Nat :=
  let leaderState := state.nodes leader
  (List.range (leaderState.log.length + 1)).foldl
    (fun best index =>
      if index > leaderState.commitIndex /\
          isSignatureAt leaderState.log index = true /\
          termAt leaderState.log index = leaderState.currentTerm /\
          hasMajorityAt state leader index then
        max best index
      else
        best)
    0

/-- Explicit witnesses for every source of transition nondeterminism. -/
inductive Action (Node TxId : Type) where
  /-- Submit a fresh external transaction to a node. -/
  | clientRequest (node : Node) (txId : TxId)
  /-- Append a new nonempty configuration to a leader's log. -/
  | changeConfiguration (source : Node) (newConfiguration : Finset Node)
  /-- Append a signature over a leader's nonempty log. -/
  | signCommittableMessages (node : Node)
  /-- Send the next entry or a heartbeat from one node to another. -/
  | appendEntries (source destination : Node) (batchEnd : Nat)
  /-- Process the first queued message from a selected source. -/
  | receive (source destination : Node)
  /-- Advance a leader to its locally computed quorum commit frontier. -/
  | advanceCommitIndex (node : Node)
  /-- Locally start a successor-term election and vote for oneself. -/
  | timeout (node : Node)
  /-- Send a RequestVote message from a candidate to another node. -/
  | requestVote (source destination : Node)
  /-- Observe a newer message term without consuming the message. -/
  | updateTerm (source destination : Node)
  /-- Promote a candidate after its local vote set reaches a majority. -/
  | becomeLeader (node : Node)
  deriving DecidableEq

/-- Protocol guard for arbitrary repeated elections and leader writes. -/
def Enabled
    (state : State Node TxId) :
    Action Node TxId -> Prop
  | .clientRequest node txId =>
      state.allocated node /\
        (state.nodes node).role = .leader /\
        txId ∉ state.submittedTxIds
  | .changeConfiguration source newConfiguration =>
      let sourceState := state.nodes source
      let previousConfiguration := (latestConfiguration sourceState).nodes
      let addedNodes := newConfiguration \ previousConfiguration
      state.allocated source /\
        sourceState.role = .leader /\
        newConfiguration.Nonempty /\
        Not (newConfiguration = previousConfiguration) /\
        ∀ node ∈ addedNodes, node ∉ state.hasJoined
  | .signCommittableMessages node =>
      state.allocated node /\
        (state.nodes node).role = .leader /\
        Not ((state.nodes node).log = [])
  | .appendEntries source destination batchEnd =>
      state.allocated source /\
        state.allocated destination /\
        (state.nodes source).role = .leader /\
        Not (source = destination) /\
        destination ∈ activeNodeUnion (state.nodes source) /\
        batchEnd =
          min
            ((state.nodes source).sentIndex destination + 1)
            (state.nodes source).log.length
  | .receive source destination =>
      state.allocated destination /\
        (handleReceive? state source destination).isSome
  | .advanceCommitIndex node =>
      state.allocated node /\
        (state.nodes node).role = .leader /\
        (state.nodes node).commitIndex <
          highestCommittableIndex state node
  | .timeout node =>
      state.allocated node /\
        ((state.nodes node).role = .follower \/
        (state.nodes node).role = .candidate) /\
        node ∈ activeNodeUnion (state.nodes node) /\
        campaignEligible node (state.nodes node)
  | .requestVote source destination =>
      state.allocated source /\
        state.allocated destination /\
        (state.nodes source).role = .candidate /\
        Not (source = destination) /\
        destination ∈ activeNodeUnion (state.nodes source)
  | .updateTerm source destination =>
      state.allocated destination /\
        (newerMessage? state source destination).isSome
  | .becomeLeader node =>
      state.allocated node /\
        (state.nodes node).role = .candidate /\
        hasElectionMajority state node

/-- Make every action guard directly executable. -/
instance (state : State Node TxId) (action : Action Node TxId) :
    Decidable (Enabled state action) := by
  cases action <;> simp only [Enabled] <;> infer_instance

/-- Deterministically apply the state update selected by an action witness. -/
def next
    (state : State Node TxId) :
    Action Node TxId -> State Node TxId
  | .clientRequest node txId =>
      let nodeState := state.nodes node
      let entry :=
        { term := nodeState.currentTerm
          content := EntryContent.transaction txId }
      { state with
        nodes :=
          updateNode state.nodes node
            { nodeState with log := nodeState.log ++ [entry] }
        submittedTxIds := insert txId state.submittedTxIds }
  | .changeConfiguration source newConfiguration =>
      let sourceState := state.nodes source
      let previousConfiguration := (latestConfiguration sourceState).nodes
      let addedNodes := newConfiguration \ previousConfiguration
      let entry : Entry Node TxId :=
        { term := sourceState.currentTerm
          content := .reconfiguration newConfiguration }
      { state with
        nodes :=
          updateNode (state.nodes.allocate addedNodes) source
            { sourceState with
              log := sourceState.log ++ [entry]
              sentIndex := fun peer =>
                if peer ∈ addedNodes then
                  sourceState.log.length
                else
                  sourceState.sentIndex peer }
        hasJoined := state.hasJoined ∪ addedNodes }
  | .signCommittableMessages node =>
      let nodeState := state.nodes node
      let entry : Entry Node TxId :=
        { term := nodeState.currentTerm
          content := .signature }
      { state with
        nodes :=
          updateNode state.nodes node
            { nodeState with log := nodeState.log ++ [entry] } }
  | .appendEntries source destination batchEnd =>
      let sourceState := state.nodes source
      let request := makeAppendEntriesRequest state source destination batchEnd
      { state with
        nodes :=
          updateNode state.nodes source
            { sourceState with
              sentIndex :=
                updateIndex sourceState.sentIndex destination batchEnd }
        network :=
          enqueueNoDup state.network (.appendEntriesRequest request) }
  | .receive source destination =>
      (handleReceive? state source destination).getD state
  | .advanceCommitIndex node =>
      let nodeState := state.nodes node
      { state with
        nodes :=
          updateNode state.nodes node
            { nodeState with
              commitIndex := highestCommittableIndex state node } }
  | .timeout node =>
      let nodeState := state.nodes node
      { state with
        nodes :=
          updateNode state.nodes node
            { nodeState with
              role := .candidate
              currentTerm := nodeState.currentTerm + 1
              votedFor := some node
              votesGranted := {node} } }
  | .requestVote source destination =>
      let request := makeRequestVoteRequest state source destination
      { state with
        network :=
          enqueueNoDup state.network (.requestVoteRequest request) }
  | .updateTerm source destination =>
      match newerMessage? state source destination with
      | none => state
      | some selected =>
          let nodeState := state.nodes destination
          { state with
            nodes :=
              updateNode state.nodes destination
                { nodeState with
                  role :=
                    if nodeState.role = .follower then
                      .follower
                    else
                      .follower
                  currentTerm := selected.term
                  votedFor := none
                  isNewFollower := true } }
  | .becomeLeader node =>
      let nodeState := state.nodes node
      let log := nodeState.log.take (maxCommittableIndex nodeState.log)
      { state with
        nodes :=
          updateNode state.nodes node
            { nodeState with
              role := .leader
              log
              sentIndex := fun _ => log.length
              matchIndex := fun _ => 0 } }

/-- Package arbitrary-term Raft as a reusable executable transition system. -/
def system [DecidableEq TxId] : ExecutableTransitionSystem where
  State := State Node TxId
  Action := Action Node TxId
  initial := initialState
  Enabled
  enabledDecidable := fun _ _ => inferInstance
  next

/-- Execute actions until one is disabled. -/
def runActions
    (state : State Node TxId) :
    List (Action Node TxId) -> Option (State Node TxId)
  | [] => some state
  | action :: actions => do
      let nextState <- system.applyAction state action
      runActions nextState actions

/-- States reachable through enabled arbitrary-term Raft actions. -/
abbrev Reachable [DecidableEq TxId] :=
  (system (Node := Node) (TxId := TxId)).Reachable

namespace Reachable

/-- The Raft initial state is reachable. -/
theorem initial :
    Reachable (initialState : State Node TxId) :=
  ExecutableTransitionSystem.Reachable.initial

/-- Taking an enabled action from a reachable state preserves reachability. -/
theorem step
    {state : State Node TxId}
    (reachable : Reachable state)
    {action : Action Node TxId}
    (enabled : Enabled state action) :
    Reachable (next state action) :=
  ExecutableTransitionSystem.Reachable.step reachable enabled

/-- A successfully executed action list ends in a reachable state. -/
theorem runActionsReachable
    {start final : State Node TxId}
    {actions : List (Action Node TxId)}
    (startReachable : Reachable start)
    (ran : runActions start actions = some final) :
    Reachable final := by
  induction actions generalizing start final with
  | nil =>
      simp [runActions] at ran
      subst final
      exact startReachable
  | cons action actions inductionHypothesis =>
      unfold runActions at ran
      cases applied : system.applyAction start action with
      | none =>
          simp [applied] at ran
      | some nextState =>
          have enabled : Enabled start action := by
            unfold ExecutableTransitionSystem.applyAction at applied
            split at applied
            · assumption
            · contradiction
          have nextEq : next start action = nextState := by
            unfold ExecutableTransitionSystem.applyAction at applied
            split at applied
            · exact Option.some.inj applied
            · contradiction
          have nextReachable : Reachable nextState := by
            rw [← nextEq]
            exact step startReachable enabled
          exact
            inductionHypothesis nextReachable
              (by simpa [applied] using ran)

end Reachable

end CCFRaft
