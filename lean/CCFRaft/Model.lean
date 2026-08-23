import Mathlib.Data.Finset.Card
import Mathlib.Data.Finset.Union
import Mathlib.Data.Fin.Basic
import Mathlib.Data.Fintype.Basic

import CCFRaft.ExecutableTransitionSystem

/-!
# Executable CCF Raft model

This file ports the selected scope of `tla/consensus/ccfraft.tla`. The task
fixes the world at 15 nodes. `tla/consensus/MCccfraft.cfg` selects the
`OrderedNoDup` network guarantee.

The projection omits pre-vote, `TypeRetired`, `AppendRetiredCommitted`,
`CheckQuorum`, `SigTermProposeVote`, and `ProposeVoteRequest`. Pre-vote status
is fixed to `PreVoteDisabled`, so every generated vote request has
`isPreVote = false`. The retirement phases caused by reconfiguration remain
in the state because they affect the required actions. Without `TypeRetired`,
`RetiredCommitted` is unreachable.

`Network.tla` stores one destination queue containing messages from every
source. `MessagesTo` exposes only the first message for a selected
source-destination pair. The Lean model stores those observable FIFO
subsequences directly as one deduplicated queue per pair. This preserves the
ordering and duplicate suppression visible to every required action.
-/

set_option autoImplicit false

namespace CCFRaft

/-- The fixed TLA `Servers` world. -/
abbrev Node := Fin 15

structure NodeMap (α : Type) where
  values : Vector α 15

namespace NodeMap

variable {α : Type}

def ofFn (f : Node -> α) : NodeMap α :=
  ⟨Vector.ofFn f⟩

def const (value : α) : NodeMap α :=
  ofFn fun _ => value

def get (values : NodeMap α) (node : Node) : α :=
  values.values.get node

instance : CoeFun (NodeMap α) (fun _ => Node -> α) where
  coe := get

def set (values : NodeMap α) (node : Node) (value : α) : NodeMap α :=
  ⟨values.values.set node.val value node.isLt⟩

@[simp]
theorem ofFn_apply
    (values : Node -> α)
    (node : Node) :
    ofFn values node = values node := by
  change (Vector.ofFn values)[node.val] = values node
  simp [Vector.ofFn]

@[simp]
theorem const_apply
    (value : α)
    (node : Node) :
    const value node = value := by
  simp [const]

@[simp]
theorem set_same
    (values : NodeMap α)
    (node : Node)
    (value : α) :
    values.set node value node = value := by
  change (values.values.set node.val value node.isLt)[node.val] = value
  simp

@[simp]
theorem set_ne
    (values : NodeMap α)
    (updated selected : Node)
    (value : α)
    (different : Not (selected = updated)) :
    values.set updated value selected = values selected := by
  change
    (values.values.set updated.val value updated.isLt)[selected.val] =
      values.values[selected.val]
  have differentValues : Not (updated.val = selected.val) := by
    exact fun equal => different (Fin.ext equal.symm)
  rw [
    Vector.getElem_set_ne
      updated.isLt
      selected.isLt
      differentValues
  ]

end NodeMap

abbrev NodeMatrix (α : Type) := NodeMap (NodeMap α)

/-- A nonempty check is part of `ChangeConfiguration`, not this type. -/
abbrev Configuration := Finset Node

inductive LeadershipState where
  | follower
  | candidate
  | leader
  | none
  deriving BEq, DecidableEq, Repr

inductive MembershipState where
  | active
  | retirementOrdered
  | retirementSigned
  | retirementCompleted
  | retiredCommitted
  deriving BEq, DecidableEq, Repr

inductive EntryContent where
  | entry
  | signature
  | reconfiguration (configuration : Configuration)
  deriving BEq, DecidableEq

structure Entry where
  term : Nat
  content : EntryContent
  deriving BEq, DecidableEq

inductive MessageBody where
  | requestVoteRequest
      (lastCommittableTerm : Nat)
      (lastCommittableIndex : Nat)
      (isPreVote : Bool)
  | requestVoteResponse
      (voteGranted : Bool)
      (isPreVote : Bool)
  | appendEntriesRequest
      (prevLogIndex : Nat)
      (prevLogTerm : Nat)
      (entries : List Entry)
      (commitIndex : Nat)
  | appendEntriesResponse
      (success : Bool)
      (lastLogIndex : Nat)
  deriving BEq, DecidableEq

structure Message where
  term : Nat
  source : Node
  dest : Node
  body : MessageBody
  deriving BEq, DecidableEq

structure ConfigurationAt where
  index : Nat
  nodes : Configuration
  deriving BEq, DecidableEq

/--
The executable projection of the TLA variables. Configuration lists are kept
in increasing log-index order by `next`.
-/
structure State where
  currentTerm : NodeMap Nat
  leadershipState : NodeMap LeadershipState
  membershipState : NodeMap MembershipState
  votedFor : NodeMap (Option Node)
  isNewFollower : NodeMap Bool
  log : NodeMap (List Entry)
  commitIndex : NodeMap Nat
  votesGranted : NodeMap (Finset Node)
  sentIndex : NodeMatrix Nat
  matchIndex : NodeMatrix Nat
  configurations : NodeMap (List ConfigurationAt)
  hasJoined : NodeMap Bool
  retirementCompleted : NodeMap (Finset Node)
  messages : NodeMatrix (List Message)

namespace Model

def startTerm : Nat := 2

def updateNode
    {α : Type}
    (f : NodeMap α)
    (node : Node)
    (value : α) :
    NodeMap α :=
  f.set node value

def update₂
    {α : Type}
    (f : NodeMatrix α)
    (i j : Node)
    (value : α) :
    NodeMatrix α :=
  updateNode f i (updateNode (f i) j value)

def entryAt? (entries : List Entry) (index : Nat) : Option Entry :=
  if index = 0 then
    none
  else
    entries[index - 1]?

def logPrefix (entries : List Entry) (index : Nat) : List Entry :=
  entries.take index

def subsequence
    (entries : List Entry)
    (first last : Nat) :
    List Entry :=
  if first = 0 || last < first then
    []
  else
    (entries.drop (first - 1)).take (last + 1 - first)

def indices (entries : List Entry) : List Nat :=
  (List.range entries.length).map Nat.succ

def lastIndexWhere
    (predicate : Entry -> Bool)
    (entries : List Entry) :
    Nat :=
  (indices entries).foldl
    (fun result index =>
      match entryAt? entries index with
      | some entry => if predicate entry then index else result
      | none => result)
    0

def maxCommittableIndex (entries : List Entry) : Nat :=
  lastIndexWhere
    (fun entry => entry.content matches .signature)
    entries

def maxCommittableIndexAt
    (entries : List Entry)
    (index : Nat) :
    Nat :=
  maxCommittableIndex (logPrefix entries (min index entries.length))

def maxCommittableTerm (entries : List Entry) : Nat :=
  match entryAt? entries (maxCommittableIndex entries) with
  | some entry => entry.term
  | none => 0

def findHighestPossibleMatch
    (entries : List Entry)
    (index term : Nat) :
    Nat :=
  lastIndexWhere
    (fun entry => decide (entry.term <= term))
    (logPrefix entries (min index entries.length))

def committed (state : State) (node : Node) : List Entry :=
  logPrefix (state.log node) (state.commitIndex node)

def committable (state : State) (node : Node) : List Entry :=
  logPrefix (state.log node) (maxCommittableIndex (state.log node))

def lastCommittableIndex (state : State) (node : Node) : Nat :=
  max (state.commitIndex node) (maxCommittableIndex (state.log node))

def lastCommittableTerm (state : State) (node : Node) : Nat :=
  match entryAt? (state.log node) (lastCommittableIndex state node) with
  | some entry => entry.term
  | none => 0

def configurationAt?
    (configurations : List ConfigurationAt)
    (index : Nat) :
    Option Configuration :=
  (configurations.find? fun configuration => configuration.index = index).map
    (·.nodes)

def serverSet (configurations : List ConfigurationAt) : Configuration :=
  configurations.foldl
    (fun nodes configuration => nodes ∪ configuration.nodes)
    ∅

def currentConfiguration
    (configurations : List ConfigurationAt) :
    Configuration :=
  configurations.head?.map (·.nodes) |>.getD ∅

def maxConfiguration
    (configurations : List ConfigurationAt) :
    Configuration :=
  configurations.getLast?.map (·.nodes) |>.getD ∅

def nextConfigurationIndex?
    (configurations : List ConfigurationAt) :
    Option Nat :=
  (configurations.drop 1).head?.map (·.index)

def configurationsToIndex
    (configurations : List ConfigurationAt)
    (index : Nat) :
    List ConfigurationAt :=
  configurations.filter fun configuration => configuration.index <= index

def lastConfigurationToIndex
    (configurations : List ConfigurationAt)
    (index : Nat) :
    Nat :=
  configurations.foldl
    (fun result configuration =>
      if configuration.index <= index then
        max result configuration.index
      else
        result)
    0

def configurationsFromIndex
    (configurations : List ConfigurationAt)
    (index : Nat) :
    List ConfigurationAt :=
  configurations.filter fun configuration => index <= configuration.index

def isInServerSet
    (state : State)
    (candidate server : Node) :
    Bool :=
  candidate ∈ serverSet (state.configurations server)

def isQuorum
    (votes configuration : Configuration) :
    Bool :=
  decide (votes ⊆ configuration) &&
    decide (configuration.card < votes.card * 2)

def allConfigurationsHaveQuorum
    (votes : Configuration)
    (configurations : List ConfigurationAt) :
    Bool :=
  configurations.all fun configuration =>
    isQuorum (votes ∩ configuration.nodes) configuration.nodes

def logReconfigurationAt?
    (entries : List Entry)
    (index : Nat) :
    Option Configuration :=
  match entryAt? entries index with
  | some { content := .reconfiguration configuration, .. } =>
      some configuration
  | _ => none

def reconfigurationIndices
    (entries : List Entry)
    (node : Node)
    (containsNode : Bool) :
    List Nat :=
  (indices entries).filter fun index =>
    match logReconfigurationAt? entries index with
    | some configuration =>
        decide ((node ∈ configuration) = containsNode)
    | none => false

def maxNat (values : List Nat) : Nat :=
  values.foldl max 0

def minPositive (values : List Nat) : Nat :=
  values.foldl
    (fun result value =>
      if result = 0 then value else min result value)
    0

def retirementIndexLog
    (entries : List Entry)
    (node : Node) :
    Nat :=
  let included := reconfigurationIndices entries node true
  if included.isEmpty then
    0
  else
    let lastIncluded := maxNat included
    minPositive <|
      (reconfigurationIndices entries node false).filter
        (fun index => lastIncluded < index)

def calcMembershipState
    (entries : List Entry)
    (commitIndex : Nat)
    (node : Node) :
    MembershipState :=
  let retirementIndex := retirementIndexLog entries node
  if retirementIndex = 0 then
    .active
  else if retirementIndex <= commitIndex then
    .retirementCompleted
  else if retirementIndex < maxCommittableIndex entries then
    .retirementSigned
  else
    .retirementOrdered

def nodesInConfigurationsBefore
    (configurations : List ConfigurationAt)
    (index : Nat) :
    Configuration :=
  configurations.foldl
    (fun result configuration =>
      if configuration.index < index then
        result ∪ configuration.nodes
      else
        result)
    ∅

def nextRetirementCompleted
    (current : Configuration)
    (configurations : List ConfigurationAt)
    (nextCommitIndex : Nat) :
    Configuration :=
  let currentIndex :=
    lastConfigurationToIndex configurations nextCommitIndex
  if currentIndex = 0 then
    current
  else
    let removed :=
      nodesInConfigurationsBefore configurations currentIndex \
        (configurationAt? configurations currentIndex).getD ∅
    current ∪ removed

def configurationsInEntriesAux
    (index : Nat) :
    List Entry -> List ConfigurationAt
  | [] => []
  | entry :: entries =>
      let tail := configurationsInEntriesAux (index + 1) entries
      match entry.content with
      | .reconfiguration configuration =>
          { index, nodes := configuration } :: tail
      | _ => tail

def configurationsInEntries
    (firstIndex : Nat)
    (entries : List Entry) :
    List ConfigurationAt :=
  configurationsInEntriesAux firstIndex entries

def upsertConfiguration
    (configurations : List ConfigurationAt)
    (update : ConfigurationAt) :
    List ConfigurationAt :=
  match configurations with
  | [] => [update]
  | configuration :: rest =>
      if update.index < configuration.index then
        update :: configuration :: rest
      else if update.index = configuration.index then
        update :: rest
      else
        configuration :: upsertConfiguration rest update

def overrideConfigurations
    (configurations updates : List ConfigurationAt) :
    List ConfigurationAt :=
  updates.foldl upsertConfiguration configurations

def enqueue
    (messages : NodeMatrix (List Message))
    (message : Message) :
    NodeMatrix (List Message) :=
  let channel := messages message.dest message.source
  let nextChannel :=
    if channel.any fun queued => queued == message then
      channel
    else
      channel ++ [message]
  update₂ messages message.dest message.source nextChannel

def discard
    (messages : NodeMatrix (List Message))
    (message : Message) :
    NodeMatrix (List Message) :=
  update₂ messages message.dest message.source
    ((messages message.dest message.source).erase message)

def reply
    (messages : NodeMatrix (List Message))
    (response request : Message) :
    NodeMatrix (List Message) :=
  discard (enqueue messages response) request

def headMessage?
    (state : State)
    (dest source : Node) :
    Option Message :=
  (state.messages dest source).head?

def startLog (start : Node) : List Entry :=
  [
    {
      term := startTerm
      content := .reconfiguration {start}
    },
    {
      term := startTerm
      content := .signature
    }
  ]

/-- The literal singleton `InitReconfigurationVars` choice, parameterized by its leader. -/
def initialState (start : Node) : State :=
  let initialLog := startLog start
  {
    currentTerm :=
      NodeMap.ofFn fun node => if node = start then startTerm else 0
    leadershipState :=
      NodeMap.ofFn fun node => if node = start then .leader else .none
    membershipState := NodeMap.const .active
    votedFor := NodeMap.const none
    isNewFollower := NodeMap.const true
    log := NodeMap.ofFn fun node => if node = start then initialLog else []
    commitIndex :=
      NodeMap.ofFn fun node => if node = start then initialLog.length else 0
    votesGranted := NodeMap.const ∅
    sentIndex :=
      NodeMap.ofFn fun node =>
        NodeMap.const (if node = start then initialLog.length else 0)
    matchIndex := NodeMap.const (NodeMap.const 0)
    configurations :=
      NodeMap.ofFn fun node =>
        if node = start then
          [{ index := 1, nodes := {start} }]
        else
          []
    hasJoined := NodeMap.ofFn fun node => node = start
    retirementCompleted := NodeMap.const ∅
    messages := NodeMap.const (NodeMap.const [])
  }

inductive ReceiveKind where
  | dropIgnored
  | updateTerm
  | handleRequestVoteRequest
  | handleRequestVoteResponse
  | dropRequestVoteResponseOutOfState
  | dropRequestVoteResponseStale
  | rejectAppendEntriesRequest
  | returnToFollower
  | appendEntriesAlreadyDone
  | appendEntriesNoConflict
  | appendEntriesConflictThenAlreadyDone
  | appendEntriesConflictThenNoConflict
  | handleAppendEntriesResponseSuccess
  | handleAppendEntriesResponseFailure
  | dropAppendEntriesResponseOutOfState
  | dropAppendEntriesResponseStale
  deriving BEq, DecidableEq, Repr

/--
Every source of nondeterminism in the selected TLA `Next` relation is an
explicit constructor argument. Receive branches stay distinct where the TLA
disjunction permits more than one response to the same message.
-/
inductive Action where
  | timeout (node : Node)
  | requestVote (source dest : Node)
  | appendEntries (source dest : Node)
  | becomeLeader (node : Node)
  | clientRequest (node : Node)
  | signCommittableMessages (node : Node)
  | changeConfiguration (node : Node) (configuration : Configuration)
  | advanceCommitIndex (node : Node)
  | receive (dest source : Node) (kind : ReceiveKind)
  deriving BEq, DecidableEq

def candidateEligible (state : State) (node : Node) : Bool :=
  (state.membershipState node != .retiredCommitted) &&
    (((state.configurations node).any fun configuration =>
      decide (node ∈ configuration.nodes) &&
        decide
          (configuration.index <= maxCommittableIndex (state.log node))) ||
      decide (node ∈ state.retirementCompleted node))

def requestVoteMessage
    (state : State)
    (source dest : Node) :
    Message :=
  {
    term := state.currentTerm source
    source
    dest
    body :=
      .requestVoteRequest
        (lastCommittableTerm state source)
        (lastCommittableIndex state source)
        false
  }

def appendEntriesMessage
    (state : State)
    (source dest : Node) :
    Message :=
  let previousIndex := state.sentIndex source dest
  let previousTerm :=
    (entryAt? (state.log source) previousIndex).map (·.term) |>.getD 0
  let firstIndex := previousIndex + 1
  let lastIndex := min (state.log source).length firstIndex
  {
    term := state.currentTerm source
    source
    dest
    body :=
      .appendEntriesRequest
        previousIndex
        previousTerm
        (subsequence (state.log source) firstIndex lastIndex)
        (state.commitIndex source)
  }

def hasConsensusWatermark
    (state : State)
    (leader : Node)
    (index : Nat) :
    Bool :=
  (state.configurations leader).all fun configuration =>
    if configuration.index <= index then
      let agreeing :=
        configuration.nodes.filter fun node =>
          index <= state.matchIndex leader node
      let voters :=
        if leader ∈ configuration.nodes then
          insert leader agreeing
        else
          agreeing
      isQuorum voters configuration.nodes
    else
      true

def highestCommittableIndex
    (state : State)
    (leader : Node) :
    Nat :=
  (indices (state.log leader)).foldl
    (fun result index =>
      match entryAt? (state.log leader) index with
      | some entry =>
          if state.commitIndex leader < index &&
              entry.term = state.currentTerm leader &&
              entry.content = .signature &&
              hasConsensusWatermark state leader index then
            max result index
          else
            result
      | none => result)
    0

def requestVoteLogOK
    (state : State)
    (dest : Node)
    (lastTerm lastIndex : Nat) :
    Bool :=
  decide (maxCommittableTerm (state.log dest) < lastTerm) ||
    (decide (maxCommittableTerm (state.log dest) = lastTerm) &&
      decide (maxCommittableIndex (state.log dest) <= lastIndex))

def requestVoteGranted
    (state : State)
    (dest source : Node)
    (messageTerm lastTerm lastIndex : Nat) :
    Bool :=
  decide (messageTerm = state.currentTerm dest) &&
    requestVoteLogOK state dest lastTerm lastIndex &&
    decide
      (Or
        (state.votedFor dest = none)
        (state.votedFor dest = some source))

def appendEntriesLogOK
    (state : State)
    (dest : Node)
    (previousIndex previousTerm : Nat) :
    Bool :=
  previousIndex = 0 ||
    (decide (previousIndex <= (state.log dest).length) &&
      match entryAt? (state.log dest) previousIndex with
      | some entry => decide (entry.term = previousTerm)
      | none => false)

def appendEntriesAlreadyDoneGuard
    (state : State)
    (dest : Node)
    (previousIndex : Nat)
    (entries : List Entry) :
    Bool :=
  entries.isEmpty ||
    (decide
        (previousIndex + entries.length <= (state.log dest).length) &&
      decide
        ((((state.log dest).drop previousIndex).take entries.length).map
            (fun entry => entry.term) =
          entries.map fun entry => entry.term))

def appendEntriesNoConflictGuard
    (state : State)
    (dest : Node)
    (previousIndex : Nat)
    (entries : List Entry) :
    Bool :=
  !entries.isEmpty &&
    decide (previousIndex <= (state.log dest).length) &&
    decide
      ((state.log dest).length < previousIndex + entries.length) &&
    let overlap := (state.log dest).length - previousIndex
    decide
      (((state.log dest).drop previousIndex).take overlap =
        entries.take overlap)

def appendEntriesConflictGuard
    (state : State)
    (dest : Node)
    (previousIndex : Nat)
    (entries : List Entry) :
    Bool :=
  !entries.isEmpty &&
    state.isNewFollower dest &&
    (((state.log dest).drop previousIndex).zip entries).any fun pair =>
      pair.1.term != pair.2.term

def conflictRollback
    (state : State)
    (dest : Node)
    (previousIndex : Nat) :
    State :=
  let nextLog := (state.log dest).take previousIndex
  {
    state with
    log := updateNode state.log dest nextLog
    configurations :=
      updateNode state.configurations dest
        (configurationsToIndex
          (state.configurations dest)
          nextLog.length)
    membershipState :=
      updateNode state.membershipState dest
        (calcMembershipState nextLog (state.commitIndex dest) dest)
    isNewFollower :=
      updateNode state.isNewFollower dest false
  }

def appendEntriesAcceptBase
    (state : State)
    (dest : Node)
    (messageTerm previousIndex previousTerm : Nat) :
    Bool :=
  decide (messageTerm = state.currentTerm dest) &&
    (state.leadershipState dest == .follower ||
      state.leadershipState dest == .none) &&
    appendEntriesLogOK state dest previousIndex previousTerm &&
    decide (state.commitIndex dest <= previousIndex)

def appendEntriesRejectResponse?
    (state : State)
    (message : Message)
    (previousIndex previousTerm : Nat) :
    Option Message :=
  let dest := message.dest
  let source := message.source
  if state.currentTerm dest < message.term then
    none
  else if message.term < state.currentTerm dest then
    some
      {
        term := state.currentTerm dest
        source := dest
        dest := source
        body := .appendEntriesResponse false (state.log dest).length
      }
  else if state.leadershipState dest != .follower ||
      appendEntriesLogOK state dest previousIndex previousTerm then
    none
  else
    let comparisonTerm :=
      if previousIndex = 0 || (state.log dest).length < previousIndex then
        0
      else
        (state.log dest).getLast?.map (·.term) |>.getD 0
    if comparisonTerm = previousTerm then
      none
    else if comparisonTerm = 0 then
      some
        {
          term := state.currentTerm dest
          source := dest
          dest := source
          body := .appendEntriesResponse false (state.log dest).length
        }
    else
      let lastIndex :=
        findHighestPossibleMatch
          (state.log dest)
          previousIndex
          previousTerm
      let responseTerm :=
        if lastIndex = 0 then
          startTerm
        else
          (entryAt? (state.log dest) lastIndex).map (·.term) |>.getD
            startTerm
      some
        {
          term := responseTerm
          source := dest
          dest := source
          body := .appendEntriesResponse false lastIndex
        }

def dropIgnoredEnabled (state : State) (message : Message) : Bool :=
  let isRequestVoteRequest :=
    match message.body with
    | .requestVoteRequest .. => true
    | _ => false
  let isAppendEntriesRequest :=
    match message.body with
    | .appendEntriesRequest .. => true
    | _ => false
  let startsBeforeCommit :=
    match message.body with
    | .appendEntriesRequest previousIndex .. =>
        decide (previousIndex < state.commitIndex message.dest)
    | _ => false
  !isRequestVoteRequest &&
    (((state.leadershipState message.dest == .none) &&
        !isAppendEntriesRequest) ||
      ((state.leadershipState message.dest != .none) &&
        !isInServerSet state message.source message.dest) ||
      ((state.membershipState message.dest == .retiredCommitted) &&
        !isAppendEntriesRequest) ||
      startsBeforeCommit)

def updateTermEnabled (state : State) (message : Message) : Bool :=
  decide (state.currentTerm message.dest < message.term)

def receiveBranchEnabled
    (state : State)
    (message : Message)
    (kind : ReceiveKind) :
    Bool :=
  match kind, message.body with
  | .dropIgnored, _ =>
      dropIgnoredEnabled state message
  | .updateTerm, _ =>
      updateTermEnabled state message
  | .handleRequestVoteRequest,
      .requestVoteRequest _ _ _ =>
      decide (message.term <= state.currentTerm message.dest)
  | .handleRequestVoteResponse,
      .requestVoteResponse _ isPreVote =>
      decide (message.term = state.currentTerm message.dest) &&
        !isPreVote &&
        state.leadershipState message.dest == .candidate
  | .dropRequestVoteResponseOutOfState,
      .requestVoteResponse _ isPreVote =>
      isPreVote || state.leadershipState message.dest != .candidate
  | .dropRequestVoteResponseStale,
      .requestVoteResponse _ _ =>
      decide (message.term < state.currentTerm message.dest)
  | .rejectAppendEntriesRequest,
      .appendEntriesRequest previousIndex previousTerm _ _ =>
      (appendEntriesRejectResponse?
        state message previousIndex previousTerm).isSome
  | .returnToFollower,
      .appendEntriesRequest _ _ _ _ =>
      decide (message.term = state.currentTerm message.dest) &&
        state.leadershipState message.dest == .candidate
  | .appendEntriesAlreadyDone,
      .appendEntriesRequest previousIndex previousTerm entries _ =>
      appendEntriesAcceptBase
          state message.dest message.term previousIndex previousTerm &&
        appendEntriesAlreadyDoneGuard
          state message.dest previousIndex entries
  | .appendEntriesNoConflict,
      .appendEntriesRequest previousIndex previousTerm entries _ =>
      appendEntriesAcceptBase
          state message.dest message.term previousIndex previousTerm &&
        appendEntriesNoConflictGuard
          state message.dest previousIndex entries
  | .appendEntriesConflictThenAlreadyDone,
      .appendEntriesRequest previousIndex previousTerm entries _ =>
      appendEntriesAcceptBase
          state message.dest message.term previousIndex previousTerm &&
        appendEntriesConflictGuard
          state message.dest previousIndex entries &&
        let rolled := conflictRollback state message.dest previousIndex
        appendEntriesAlreadyDoneGuard
          rolled message.dest previousIndex entries
  | .appendEntriesConflictThenNoConflict,
      .appendEntriesRequest previousIndex previousTerm entries _ =>
      appendEntriesAcceptBase
          state message.dest message.term previousIndex previousTerm &&
        appendEntriesConflictGuard
          state message.dest previousIndex entries &&
        let rolled := conflictRollback state message.dest previousIndex
        appendEntriesNoConflictGuard
          rolled message.dest previousIndex entries
  | .handleAppendEntriesResponseSuccess,
      .appendEntriesResponse success _ =>
      success &&
        decide (message.term = state.currentTerm message.dest) &&
        state.leadershipState message.dest == .leader
  | .handleAppendEntriesResponseFailure,
      .appendEntriesResponse success _ =>
      !success
  | .dropAppendEntriesResponseOutOfState,
      .appendEntriesResponse _ _ =>
      state.leadershipState message.dest != .leader
  | .dropAppendEntriesResponseStale,
      .appendEntriesResponse success _ =>
      success && decide (message.term < state.currentTerm message.dest)
  | _, _ => false

def actionEnabled (state : State) : Action -> Bool
  | .timeout node =>
      candidateEligible state node &&
        (state.leadershipState node == .follower ||
          state.leadershipState node == .candidate)
  | .requestVote source dest =>
      source != dest &&
        state.leadershipState source == .candidate &&
        isInServerSet state dest source
  | .appendEntries source dest =>
      let message := appendEntriesMessage state source dest
      let sendsEntries :=
        match message.body with
        | .appendEntriesRequest _ _ entries _ => !entries.isEmpty
        | _ => false
      source != dest &&
        state.leadershipState source == .leader &&
        (isInServerSet state dest source ||
          decide (dest ∈ state.retirementCompleted source)) &&
        (state.membershipState source != .retiredCommitted ||
          sendsEntries)
  | .becomeLeader node =>
      state.leadershipState node == .candidate &&
        allConfigurationsHaveQuorum
          (state.votesGranted node)
          (state.configurations node)
  | .clientRequest node =>
      state.leadershipState node == .leader &&
        state.membershipState node != .retiredCommitted
  | .signCommittableMessages node =>
      state.leadershipState node == .leader &&
        state.membershipState node != .retiredCommitted &&
        !(state.log node).isEmpty
  | .changeConfiguration node configuration =>
      let added := configuration \ maxConfiguration (state.configurations node)
      state.leadershipState node == .leader &&
        decide (configuration ≠ ∅) &&
        decide
          (configuration != maxConfiguration (state.configurations node)) &&
        decide
          (forall addedNode : Node,
            addedNode ∈ added ->
              state.hasJoined addedNode = false)
  | .advanceCommitIndex node =>
      state.leadershipState node == .leader &&
        decide
          (state.commitIndex node < highestCommittableIndex state node)
  | .receive dest source kind =>
      match headMessage? state dest source with
      | some message =>
          message.dest == dest &&
            message.source == source &&
            receiveBranchEnabled state message kind
      | none => false

/-- The guard relation shared by execution, replay, and proof. -/
def Enabled (state : State) (action : Action) : Prop :=
  actionEnabled state action = true

instance enabledDecidable (state : State) (action : Action) :
    Decidable (Enabled state action) :=
  by
    unfold Enabled
    infer_instance

def nextTimeout (state : State) (node : Node) : State :=
  {
    state with
    leadershipState :=
      updateNode state.leadershipState node .candidate
    currentTerm :=
      updateNode state.currentTerm node (state.currentTerm node + 1)
    votedFor := updateNode state.votedFor node (some node)
    votesGranted :=
      updateNode state.votesGranted node {node}
  }

def nextRequestVote
    (state : State)
    (source dest : Node) :
    State :=
  {
    state with
    messages := enqueue state.messages (requestVoteMessage state source dest)
  }

def nextAppendEntries
    (state : State)
    (source dest : Node) :
    State :=
  let message := appendEntriesMessage state source dest
  let sentCount :=
    match message.body with
    | .appendEntriesRequest _ _ entries _ => entries.length
    | _ => 0
  {
    state with
    messages := enqueue state.messages message
    sentIndex :=
      update₂ state.sentIndex source dest
        (state.sentIndex source dest + sentCount)
  }

def nextBecomeLeader (state : State) (node : Node) : State :=
  let nextLog := committable state node
  let nextLength := nextLog.length
  {
    state with
    leadershipState :=
      updateNode state.leadershipState node .leader
    log := updateNode state.log node nextLog
    sentIndex :=
      updateNode state.sentIndex node (NodeMap.const nextLength)
    matchIndex :=
      updateNode state.matchIndex node (NodeMap.const 0)
    configurations :=
      updateNode state.configurations node
        (configurationsToIndex (state.configurations node) nextLength)
    membershipState :=
      updateNode state.membershipState node
        (if state.membershipState node == .retirementOrdered then
          .active
        else
          state.membershipState node)
  }

def nextClientRequest (state : State) (node : Node) : State :=
  {
    state with
    log :=
      updateNode state.log node
        (state.log node ++
          [{ term := state.currentTerm node, content := .entry }])
  }

def nextSignCommittableMessages
    (state : State)
    (node : Node) :
    State :=
  {
    state with
    log :=
      updateNode state.log node
        (state.log node ++
          [{ term := state.currentTerm node, content := .signature }])
    membershipState :=
      updateNode state.membershipState node
        (if state.membershipState node == .retirementOrdered then
          .retirementSigned
        else
          state.membershipState node)
  }

def nextChangeConfiguration
    (state : State)
    (node : Node)
    (configuration : Configuration) :
    State :=
  let oldMaximum := maxConfiguration (state.configurations node)
  let added := configuration \ oldMaximum
  let nextLog :=
    state.log node ++
      [{
        term := state.currentTerm node
        content := .reconfiguration configuration
      }]
  let nextConfiguration :=
    { index := nextLog.length, nodes := configuration }
  {
    state with
    hasJoined :=
      NodeMap.ofFn fun candidate =>
        if candidate ∈ added then true else state.hasJoined candidate
    sentIndex :=
      updateNode state.sentIndex node <|
        NodeMap.ofFn fun candidate =>
          if candidate ∈ added then
            (state.log node).length
          else
            state.sentIndex node candidate
    log := updateNode state.log node nextLog
    configurations :=
      updateNode state.configurations node
        (state.configurations node ++ [nextConfiguration])
    membershipState :=
      updateNode state.membershipState node
        (if state.membershipState node == .active &&
            node ∉ configuration then
          .retirementOrdered
        else
          state.membershipState node)
  }

def nextAdvanceCommitIndex (state : State) (node : Node) : State :=
  let nextCommitIndex := highestCommittableIndex state node
  let nextMembership :=
    calcMembershipState (state.log node) nextCommitIndex node
  let nextConfigurations :=
    match nextConfigurationIndex? (state.configurations node) with
    | some nextIndex =>
        if nextIndex <= nextCommitIndex then
          configurationsFromIndex
            (state.configurations node)
            (lastConfigurationToIndex
              (state.configurations node)
              nextCommitIndex)
        else
          state.configurations node
    | none => state.configurations node
  {
    state with
    commitIndex :=
      updateNode state.commitIndex node nextCommitIndex
    membershipState :=
      updateNode state.membershipState node nextMembership
    leadershipState :=
      updateNode state.leadershipState node
        (if nextMembership == .retiredCommitted then
          .follower
        else
          state.leadershipState node)
    configurations :=
      updateNode state.configurations node nextConfigurations
    retirementCompleted :=
      updateNode state.retirementCompleted node
        (nextRetirementCompleted
          (state.retirementCompleted node)
          (state.configurations node)
          nextCommitIndex)
  }

def nextAppendEntriesAlreadyDone
    (state : State)
    (message : Message)
    (previousIndex : Nat)
    (entries : List Entry)
    (leaderCommitIndex : Nat) :
    State :=
  let dest := message.dest
  let requestEndIndex := previousIndex + entries.length
  let nextCommitIndex :=
    max
      (maxCommittableIndexAt
        (state.log dest)
        (min leaderCommitIndex requestEndIndex))
      (state.commitIndex dest)
  let nextConfigurationIndex :=
    lastConfigurationToIndex
      (state.configurations dest)
      nextCommitIndex
  let response : Message :=
    {
      term := state.currentTerm dest
      source := dest
      dest := message.source
      body := .appendEntriesResponse true requestEndIndex
    }
  {
    state with
    commitIndex :=
      updateNode state.commitIndex dest nextCommitIndex
    configurations :=
      updateNode state.configurations dest
        (configurationsFromIndex
          (state.configurations dest)
          nextConfigurationIndex)
    retirementCompleted :=
      updateNode state.retirementCompleted dest
        (nextRetirementCompleted
          (state.retirementCompleted dest)
          (state.configurations dest)
          nextCommitIndex)
    membershipState :=
      updateNode state.membershipState dest
        (calcMembershipState (state.log dest) nextCommitIndex dest)
    messages := reply state.messages response message
  }

def nextAppendEntriesNoConflict
    (state : State)
    (message : Message)
    (previousIndex : Nat)
    (entries : List Entry)
    (leaderCommitIndex : Nat) :
    State :=
  let dest := message.dest
  let nextLog := (state.log dest).take previousIndex ++ entries
  let requestEndIndex := previousIndex + entries.length
  let nextCommitIndex :=
    max
      (maxCommittableIndexAt
        nextLog
        (min leaderCommitIndex requestEndIndex))
      (state.commitIndex dest)
  let extendedConfigurations :=
    overrideConfigurations
      (state.configurations dest)
      (configurationsInEntries (previousIndex + 1) entries)
  let nextConfigurationIndex :=
    lastConfigurationToIndex extendedConfigurations nextCommitIndex
  let nextLeadershipState :=
    if state.leadershipState dest == .none &&
        extendedConfigurations.any
          (fun configuration => dest ∈ configuration.nodes) then
      .follower
    else
      state.leadershipState dest
  let response : Message :=
    {
      term := state.currentTerm dest
      source := dest
      dest := message.source
      body := .appendEntriesResponse true nextLog.length
    }
  {
    state with
    log := updateNode state.log dest nextLog
    commitIndex :=
      updateNode state.commitIndex dest nextCommitIndex
    configurations :=
      updateNode state.configurations dest
        (configurationsFromIndex
          extendedConfigurations
          nextConfigurationIndex)
    retirementCompleted :=
      updateNode state.retirementCompleted dest
        (nextRetirementCompleted
          (state.retirementCompleted dest)
          (state.configurations dest)
          nextCommitIndex)
    leadershipState :=
      updateNode state.leadershipState dest nextLeadershipState
    membershipState :=
      updateNode state.membershipState dest
        (calcMembershipState nextLog nextCommitIndex dest)
    messages := reply state.messages response message
  }

def nextReceive
    (state : State)
    (dest source : Node)
    (kind : ReceiveKind) :
    State :=
  match headMessage? state dest source with
  | none => state
  | some message =>
      match kind, message.body with
      | .dropIgnored, _
      | .dropRequestVoteResponseOutOfState, _
      | .dropRequestVoteResponseStale, _
      | .dropAppendEntriesResponseOutOfState, _
      | .dropAppendEntriesResponseStale, _ =>
          { state with messages := discard state.messages message }
      | .updateTerm, _ =>
          {
            state with
            currentTerm :=
              updateNode state.currentTerm dest message.term
            leadershipState :=
              updateNode state.leadershipState dest
                (match state.leadershipState dest with
                | .leader | .candidate | .none => .follower
                | .follower => .follower)
            isNewFollower :=
              updateNode state.isNewFollower dest true
            votedFor := updateNode state.votedFor dest none
          }
      | .handleRequestVoteRequest,
          .requestVoteRequest lastTerm lastIndex isPreVote =>
          let grant :=
            requestVoteGranted
              state dest source message.term lastTerm lastIndex
          let response : Message :=
            {
              term := state.currentTerm dest
              source := dest
              dest := source
              body := .requestVoteResponse grant isPreVote
            }
          {
            state with
            votedFor :=
              if grant then
                updateNode state.votedFor dest (some source)
              else
                state.votedFor
            messages := reply state.messages response message
          }
      | .handleRequestVoteResponse,
          .requestVoteResponse voteGranted _ =>
          {
            state with
            votesGranted :=
              if voteGranted then
                updateNode state.votesGranted dest
                  (insert source (state.votesGranted dest))
              else
                state.votesGranted
            messages := discard state.messages message
          }
      | .rejectAppendEntriesRequest,
          .appendEntriesRequest previousIndex previousTerm _ _ =>
          match appendEntriesRejectResponse?
              state message previousIndex previousTerm with
          | some response =>
              { state with messages := reply state.messages response message }
          | none => state
      | .returnToFollower, .appendEntriesRequest _ _ _ _ =>
          {
            state with
            leadershipState :=
              updateNode state.leadershipState dest .follower
            isNewFollower :=
              updateNode state.isNewFollower dest true
          }
      | .appendEntriesAlreadyDone,
          .appendEntriesRequest previousIndex _ entries leaderCommitIndex =>
          nextAppendEntriesAlreadyDone
            state message previousIndex entries leaderCommitIndex
      | .appendEntriesNoConflict,
          .appendEntriesRequest previousIndex _ entries leaderCommitIndex =>
          nextAppendEntriesNoConflict
            state message previousIndex entries leaderCommitIndex
      | .appendEntriesConflictThenAlreadyDone,
          .appendEntriesRequest previousIndex _ entries leaderCommitIndex =>
          nextAppendEntriesAlreadyDone
            (conflictRollback state dest previousIndex)
            message previousIndex entries leaderCommitIndex
      | .appendEntriesConflictThenNoConflict,
          .appendEntriesRequest previousIndex _ entries leaderCommitIndex =>
          nextAppendEntriesNoConflict
            (conflictRollback state dest previousIndex)
            message previousIndex entries leaderCommitIndex
      | .handleAppendEntriesResponseSuccess,
          .appendEntriesResponse _ lastLogIndex =>
          {
            state with
            matchIndex :=
              update₂ state.matchIndex dest source
                (max (state.matchIndex dest source) lastLogIndex)
            messages := discard state.messages message
          }
      | .handleAppendEntriesResponseFailure,
          .appendEntriesResponse _ lastLogIndex =>
          let possibleMatch :=
            findHighestPossibleMatch
              (state.log dest)
              lastLogIndex
              message.term
          let nextSentIndex :=
            max
              (min possibleMatch (state.sentIndex dest source))
              (state.matchIndex dest source)
          {
            state with
            sentIndex :=
              update₂ state.sentIndex dest source nextSentIndex
            messages := discard state.messages message
          }
      | _, _ => state

/-- The raw TLA update before representation-only function materialization. -/
def rawNext (state : State) : Action -> State
  | .timeout node => nextTimeout state node
  | .requestVote source dest => nextRequestVote state source dest
  | .appendEntries source dest => nextAppendEntries state source dest
  | .becomeLeader node => nextBecomeLeader state node
  | .clientRequest node => nextClientRequest state node
  | .signCommittableMessages node =>
      nextSignCommittableMessages state node
  | .changeConfiguration node configuration =>
      nextChangeConfiguration state node configuration
  | .advanceCommitIndex node => nextAdvanceCommitIndex state node
  | .receive dest source kind => nextReceive state dest source kind

/-- The sole state transformer shared by execution, replay, and proof. -/
def next (state : State) (action : Action) : State :=
  rawNext state action

/-- The selected `ccfraft.tla` transition system for a chosen initial leader. -/
def system (start : Node) : ExecutableTransitionSystem where
  State := State
  Action := Action
  initial := initialState start
  Enabled := Enabled
  enabledDecidable := enabledDecidable
  next := next

abbrev Reachable (start : Node) : State -> Prop :=
  (system start).Reachable

def isLogPrefix (left right : List Entry) : Prop :=
  left.IsPrefix right

/-- `LogInv` from `ccfraft.tla`: committed logs are pairwise prefix-comparable. -/
def LogInv (state : State) : Prop :=
  forall i j : Node,
    Or
      (isLogPrefix (committed state i) (committed state j))
      (isLogPrefix (committed state j) (committed state i))

/-- `MoreThanOneLeaderInv` from `ccfraft.tla`: one leader per term. -/
def MoreThanOneLeaderInv (state : State) : Prop :=
  forall i j : Node,
    state.currentTerm i = state.currentTerm j ->
      state.leadershipState i = .leader ->
        state.leadershipState j = .leader ->
          i = j

def votersForCandidateTerm
    (state : State)
    (candidate : Node) :
    Configuration :=
  Finset.univ.filter fun voter =>
      And
        (state.currentTerm voter = state.currentTerm candidate)
        (state.votedFor voter = some candidate)

/--
`CandidateTermNotInLogInv` from `ccfraft.tla`: a candidate with an election
quorum has no existing entry in its term.
-/
def CandidateTermNotInLogInv (state : State) : Prop :=
  forall candidate : Node,
    state.leadershipState candidate = .candidate ->
      (forall configuration,
        configuration ∈ state.configurations candidate ->
          isQuorum
            (votersForCandidateTerm state candidate)
            configuration.nodes = true) ->
        forall node : Node,
          forall entry,
            entry ∈ state.log node ->
              entry.term != state.currentTerm candidate

def electionTermFold (term : Nat) (entries : List Entry) : Nat :=
  entries.foldl
    (fun result entry =>
      if entry.term = term then max entry.term result else result)
    0

/--
`ElectionSafetyInv` from `ccfraft.tla`: the literal `FoldSeq` comparison for
the current leader term.
-/
def ElectionSafetyInv (state : State) : Prop :=
  forall leader : Node,
    state.leadershipState leader = .leader ->
      forall node : Node,
        leader != node ->
          electionTermFold
              (state.currentTerm leader)
              (state.log leader) >=
            electionTermFold
              (state.currentTerm leader)
              (state.log node)

/--
`LogMatchingInv` from `ccfraft.tla`: an equal `(index, term)` determines the
whole prefix through that index.
-/
def LogMatchingInv (state : State) : Prop :=
  forall i j : Node,
    i != j ->
      forall index : Nat,
        1 <= index ->
          index <= min (state.log i).length (state.log j).length ->
            (entryAt? (state.log i) index).map (·.term) =
                (entryAt? (state.log j) index).map (·.term) ->
              logPrefix (state.log i) index =
                logPrefix (state.log j) index

/--
`QuorumLogInv` from `ccfraft.tla`: every quorum of the current configuration
contains a copy of the local committed prefix.
-/
def QuorumLogInv (state : State) : Prop :=
  forall node : Node,
    state.configurations node != [] ->
      forall quorum : Configuration,
        isQuorum
            quorum
            (currentConfiguration (state.configurations node)) = true ->
          Exists fun member : Node =>
            And
              (member ∈ quorum)
              (isLogPrefix (committed state node) (state.log member))

/--
`LeaderCompletenessInv` from `ccfraft.tla`: a higher-term leader contains
every lower-term committed prefix.
-/
def LeaderCompletenessInv (state : State) : Prop :=
  forall leader : Node,
    state.leadershipState leader = .leader ->
      forall node : Node,
        leader != node ->
          state.currentTerm node < state.currentTerm leader ->
            isLogPrefix (committed state node) (state.log leader)

/-- `SignatureInv` from `ccfraft.tla`: every positive commit index names a signature. -/
def SignatureInv (state : State) : Prop :=
  forall node : Node,
    state.commitIndex node > 0 ->
      (entryAt? (state.log node) (state.commitIndex node)).map
          (·.content) =
        some .signature

/--
`MonoTermInv` from `ccfraft.tla`: a sender's current term is no smaller than
the term on any in-flight message it sent.
-/
def MonoTermInv (state : State) : Prop :=
  forall dest source : Node,
    forall message,
      message ∈ state.messages dest source ->
        message.term <= state.currentTerm message.source

def monoLogEntries : List Entry -> Prop
  | [] => True
  | [_] => True
  | first :: second :: rest =>
      And
        (Or
          (first.term = second.term)
          (And
            (first.term < second.term)
            (first.content = .signature)))
        (monoLogEntries (second :: rest))

/--
`MonoLogInv` from `ccfraft.tla`: log terms rise only after a signature, and
the last log term does not exceed the local term.
-/
def MonoLogInv (state : State) : Prop :=
  forall node : Node,
    state.log node != [] ->
      And
        (((state.log node).getLast?.map (·.term)).getD 0 <=
          state.currentTerm node)
        (monoLogEntries (state.log node))

def configurationsMatchLog (state : State) (node : Node) : Prop :=
  forall configuration,
    configuration ∈ state.configurations node ->
      logReconfigurationAt? (state.log node) configuration.index =
        some configuration.nodes

def noCommittedReconfigurationAfterCurrent
    (state : State)
    (node : Node) :
    Prop :=
  let currentIndex :=
    (state.configurations node).head?.map (·.index) |>.getD 0
  forall index : Nat,
    currentIndex < index ->
      index <= state.commitIndex node ->
        logReconfigurationAt? (state.log node) index = none

def uncommittedReconfigurationsAreActive
    (state : State)
    (node : Node) :
    Prop :=
  forall index : Nat,
    state.commitIndex node < index ->
      index <= (state.log node).length ->
        forall configuration,
          logReconfigurationAt? (state.log node) index =
              some configuration ->
            configurationAt? (state.configurations node) index =
              some configuration

/--
`LogConfigurationConsistentInv` from `ccfraft.tla`: active configuration
records agree with reconfiguration entries and the local commit boundary.
-/
def LogConfigurationConsistentInv (state : State) : Prop :=
  forall node : Node,
    Or
      (state.leadershipState node = .none)
      (Or
        (state.leadershipState node = .follower &&
          state.configurations node = [])
        (And
          (configurationsMatchLog state node)
          (And
            ((state.configurations node).length > 1 ->
              state.commitIndex node <
                (nextConfigurationIndex?
                  (state.configurations node)).getD 0)
            (And
              (noCommittedReconfigurationAfterCurrent state node)
              (uncommittedReconfigurationsAreActive state node)))))

def lastCommittedConfiguration?
    (state : State)
    (node : Node) :
    Option Configuration :=
  (indices (committed state node)).foldl
    (fun result index =>
      match logReconfigurationAt? (state.log node) index with
      | some configuration => some configuration
      | none => result)
    none

/--
`ReplicationInv` from `ccfraft.tla`: one maximal committed prefix has a
quorum copy in its last committed configuration.
-/
def ReplicationInv (state : State) : Prop :=
  Exists fun node : Node =>
    And
      (forall other : Node,
        state.commitIndex other <= state.commitIndex node)
      (Exists fun configuration : Configuration =>
        And
          (lastCommittedConfiguration? state node = some configuration)
          (Exists fun quorum : Configuration =>
            And
              (isQuorum quorum configuration = true)
              (forall member : Node,
                member ∈ quorum ->
                  isLogPrefix
                    (committed state node)
                    (state.log member))))

/--
`CommittedLogAppendOnlyProp` from `ccfraft.tla`: one transition only extends
each committed log.
-/
def CommittedLogAppendOnlyProp (before after : State) : Prop :=
  forall node : Node,
    isLogPrefix (committed before node) (committed after node)

/--
`MonotonicCommitIndexProp` from `ccfraft.tla`: one transition never lowers a
commit index.
-/
def MonotonicCommitIndexProp (before after : State) : Prop :=
  forall node : Node,
    before.commitIndex node <= after.commitIndex node

/--
`MonotonicTermProp` from `ccfraft.tla`: one transition never lowers a current
term.
-/
def MonotonicTermProp (before after : State) : Prop :=
  forall node : Node,
    before.currentTerm node <= after.currentTerm node

/--
`MonotonicMatchIndexProp` from `ccfraft.tla`: match indices do not decrease
except when `BecomeLeader` resets one row.
-/
def MonotonicMatchIndexProp
    (before : State)
    (action : Action)
    (after : State) :
    Prop :=
  match action with
  | .becomeLeader _ => True
  | _ =>
      forall i j : Node,
        before.matchIndex i j <= after.matchIndex i j

/--
`NeverCommitEntryPrevTermsProp` from `ccfraft.tla`: a leader advances commit
only to an entry in its current term.
-/
def NeverCommitEntryPrevTermsProp
    (before after : State) :
    Prop :=
  forall leader : Node,
    before.leadershipState leader = .leader ->
      before.commitIndex leader < after.commitIndex leader ->
        (entryAt? (before.log leader) (after.commitIndex leader)).map
            (·.term) =
          some (after.currentTerm leader)

/--
`MatchIndexBoundedByLogInv` from `ccfraft.tla`: same-term leader match indices
do not exceed the acknowledged node's log.
-/
def MatchIndexBoundedByLogInv (state : State) : Prop :=
  forall leader node : Node,
    state.leadershipState leader = .leader ->
      state.currentTerm leader = state.currentTerm node ->
        state.matchIndex leader node <= (state.log node).length

end Model

end CCFRaft
