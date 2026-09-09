-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import BoundedTrace
import Shared.SmtOrder

set_option autoImplicit false

/-!
# Full-template leader-write encoding

The encoder executes the reviewed model transition over the symbolic template.
Transaction identifiers may be unknown. Named derived values preserve causal
links in diagnostic cores; structural control fields come from the template.
-/

namespace CCFRaft.TraceEncoding

open TraceSmt BoundedTrace
open TransactionMapping

abbrev Value := TraceSmt.NatTerm

def boolValue {holes : Nat} (value : Bool) : Value holes :=
  .literal (if value then 1 else 0)

def markerSlot (base : Nat) (node : Node) : Nat :=
  base + node.val

def ALLOCATED_SLOT_BASE : Nat := 10
def JOINED_SLOT_BASE : Nat := 30
def SENT_INDEX_SLOT_BASE : Nat := 50

#guard 4 < ALLOCATED_SLOT_BASE &&
  ALLOCATED_SLOT_BASE + NODE_COUNT ≤ JOINED_SLOT_BASE &&
  JOINED_SLOT_BASE + NODE_COUNT ≤ SENT_INDEX_SLOT_BASE

structure Tracking (holes : Nat) where
  logLengths : Node -> Value holes
  retirementWriters : Node -> Option Nat
  allocated : Node -> Value holes
  joined : Node -> Value holes
  sentIndex : Node -> Node -> Value holes

def constantClause {holes : Nat} (label : String) (condition : Prop)
    [Decidable condition] : Clause holes :=
  { label, expression := .boolean (decide condition) }

def lessClause {holes : Nat}
    (label : String) (value : Value holes) (bound : Nat) : Clause holes :=
  { label, expression := .lessThan value (.literal bound) }

def atMostClause {holes : Nat}
    (label : String) (value : Value holes) (bound : Nat) : Clause holes :=
  { label, expression := .not (.lessThan (.literal bound) value) }

def fresh {holes : Nat}
    (transaction : Value holes) (prior : List (Value holes)) : Expr holes :=
  prior.foldr
    (fun previous rest => .and (.not (.equal transaction previous)) rest)
    (.boolean true)

def submittedTerms {holes : Nat}
    (state : Template holes) : List (Value holes) :=
  state.submittedTxIds.sort (· ≤ ·)

def entryBoundsClauses {holes : Nat}
    (bounds : Bounds) (entry : Entry Node (Value holes)) : List (Clause holes) :=
  constantClause "entry term domain" (entry.term < bounds.termCount) ::
    match entry.content with
    | .transaction transaction =>
        [lessClause "entry transaction domain" transaction bounds.transactionCount]
    | .signature | .reconfiguration _ | .retiredCommitted _ => []

def messageBoundsClauses {holes : Nat}
    (bounds : Bounds) : Message Node (Value holes) -> List (Clause holes)
  | .appendEntriesRequest request =>
      [constantClause "message term domain" (request.term < bounds.termCount),
       constantClause "previous log index domain"
         (request.prevLogIndex < bounds.indexCount),
       constantClause "previous log term domain"
         (request.prevLogTerm < bounds.termCount),
       constantClause "AppendEntries entry capacity"
         (request.entries.length ≤ bounds.logCapacity),
       constantClause "leader commit domain"
         (request.leaderCommit < bounds.indexCount)] ++
        request.entries.flatMap (entryBoundsClauses bounds)
  | .appendEntriesResponse response =>
      [constantClause "message term domain" (response.term < bounds.termCount),
       constantClause "last log index domain"
         (response.lastLogIndex < bounds.indexCount)]
  | .requestVoteRequest request =>
      [constantClause "message term domain" (request.term < bounds.termCount),
       constantClause "last committable term domain"
         (request.lastCommittableTerm < bounds.termCount),
       constantClause "last committable index domain"
         (request.lastCommittableIndex < bounds.indexCount)]
  | .requestVoteResponse response =>
      [constantClause "message term domain" (response.term < bounds.termCount)]
  | .requestPreVote request =>
      [constantClause "message term domain" (request.term < bounds.termCount),
       constantClause "last committable term domain"
         (request.lastCommittableTerm < bounds.termCount),
       constantClause "last committable index domain"
         (request.lastCommittableIndex < bounds.indexCount)]
  | .requestPreVoteResponse response =>
      [constantClause "message term domain" (response.term < bounds.termCount)]
  | .proposeVoteRequest request =>
      [constantClause "message term domain" (request.term < bounds.termCount)]

def optionalIndexClauses {holes : Nat}
    (bounds : Bounds) (writer : Option Nat) (slot : Nat) (label : String) :
    Option Nat -> List (Clause holes)
  | none => []
  | some index =>
      let value : Value holes :=
        match writer with
        | none => .literal index
        | some group => .named group slot label (.literal index)
      [lessClause s!"{label} domain" value bounds.indexCount]

def localBoundsClauses {holes : Nat}
    (bounds : Bounds)
    (tracking : Tracking holes)
    (node : Node)
    (state : NodeState Node (Value holes)) :
    List (Clause holes) :=
  [constantClause "current term domain" (state.currentTerm < bounds.termCount),
   atMostClause "log capacity" (tracking.logLengths node) bounds.logCapacity,
   constantClause "commit index domain" (state.commitIndex < bounds.indexCount)] ++
  state.log.flatMap (entryBoundsClauses bounds) ++
  ((List.finRange NODE_COUNT).flatMap fun peer =>
    [lessClause "sent index domain"
       (tracking.sentIndex node peer) bounds.indexCount,
     constantClause "match index domain"
       (state.matchIndex peer < bounds.indexCount)]) ++
  optionalIndexClauses bounds (tracking.retirementWriters node) 2
      "retirement index" state.retirementIndex ++
  optionalIndexClauses bounds (tracking.retirementWriters node) 3
      "retirement committable index" state.retirementCommittableIndex ++
  optionalIndexClauses bounds (tracking.retirementWriters node) 4
      "retired committed index" state.retiredCommittedIndex

def nodeBoundsClauses {holes : Nat}
    (bounds : Bounds)
    (state : Template holes)
    (tracking : Tracking holes)
    (node : Node) :
    List (Clause holes) :=
  match state.node? node with
  | none => []
  | some localState =>
      localBoundsClauses bounds tracking node localState

def queueBoundsClauses {holes : Nat}
    (bounds : Bounds) (state : Template holes) (node : Node) :
    List (Clause holes) :=
  constantClause "queue capacity"
      ((state.network node).length ≤ bounds.queueCapacity) ::
    (state.network node).flatMap (messageBoundsClauses bounds)

def stateBoundsClauses {holes : Nat}
    (bounds : Bounds)
    (state : Template holes)
    (tracking : Tracking holes) :
    List (Clause holes) :=
  (List.finRange NODE_COUNT).flatMap
      (nodeBoundsClauses bounds state tracking) ++
  (List.finRange NODE_COUNT).flatMap (queueBoundsClauses bounds state) ++
  (submittedTerms state).map fun transaction =>
    lessClause "submitted transaction domain" transaction bounds.transactionCount

def observationExpression {holes : Nat}
    (assignmentState : Template holes)
    (tracking : Tracking holes) :
    TraceInstructions.Observation holes -> Expr holes
  | .role node value =>
      .boolean (decide ((assignmentState.nodes node).role = value))
  | .currentTerm node value =>
      .boolean (decide ((assignmentState.nodes node).currentTerm = value))
  | .logLength node value =>
      .equal (tracking.logLengths node) (.literal value)
  | .commitIndex node value =>
      .boolean (decide ((assignmentState.nodes node).commitIndex = value))
  | .allocated node value =>
      .equal (tracking.allocated node) (boolValue value)
  | .joined node value =>
      .equal (tracking.joined node) (boolValue value)
  | .submitted transaction value =>
      if value then
        .not (fresh transaction (submittedTerms assignmentState))
      else
        fresh transaction (submittedTerms assignmentState)

def observationClauses {holes : Nat}
    (bounds : Bounds)
    (state : Template holes)
    (tracking : Tracking holes)
    (observation : TraceInstructions.Observation holes) :
    List (Clause holes) :=
  let observed : Clause holes :=
    { label := "observed value"
      expression := observationExpression state tracking observation }
  match observation with
  | .submitted transaction _ =>
      [lessClause "observed transaction domain"
        transaction bounds.transactionCount, observed]
  | _ => [observed]

def observationGroup {holes : Nat}
    (bounds : Bounds)
    (state : Template holes)
    (tracking : Tracking holes)
    (observation : TraceInstructions.Observation holes) :
    Group holes :=
  { label := "observation"
    clauses :=
      stateBoundsClauses bounds state tracking ++
        observationClauses bounds state tracking observation }

def clientRequestGroup {holes : Nat}
    (bounds : Bounds)
    (state : Template holes)
    (tracking : Tracking holes)
    (node : Node)
    (transaction : Value holes) :
    Group holes :=
  { label := "clientRequest"
    clauses :=
      stateBoundsClauses bounds state tracking ++
      [constantClause "structural clientRequest guard"
         (structuralClientRequestEnabled state node transaction),
       lessClause "transaction domain" transaction bounds.transactionCount,
       { label := "transaction freshness"
         expression := fresh transaction (submittedTerms state) }] }

def leaderWriteGroup {holes : Nat}
    (label : String)
    (bounds : Bounds)
    (state : Template holes)
    (tracking : Tracking holes)
    (enabled : Prop)
    [Decidable enabled] :
    Group holes :=
  { label
    clauses :=
      stateBoundsClauses bounds state tracking ++
        [constantClause s!"structural {label} guard" enabled] }

def initialTracking {holes : Nat} (state : Template holes) : Tracking holes where
  logLengths := fun node => .literal (state.nodes node).log.length
  retirementWriters := fun _ => none
  allocated := fun node => boolValue (decide (state.allocated node))
  joined := fun node => boolValue (decide (node ∈ state.hasJoined))
  sentIndex := fun node peer => .literal ((state.nodes node).sentIndex peer)

def nextLogLengths {holes : Nat}
    (position : Nat)
    (logLengths : Node -> Value holes)
    (node : Node) :
    Node -> Value holes :=
  Function.update logLengths node
    (.named position 1 "next log length"
      (.add (logLengths node) (.literal 1)))

def nextRetirementWriters
    (position : Nat)
    (retirementWriters : Node -> Option Nat)
    (node : Node) :
    Node -> Option Nat :=
  Function.update retirementWriters node (some position)

def nextWriteTracking {holes : Nat}
    (position : Nat) (tracking : Tracking holes) (node : Node) :
    Tracking holes :=
  { tracking with
    logLengths := nextLogLengths position tracking.logLengths node
    retirementWriters :=
      nextRetirementWriters position tracking.retirementWriters node }

def nextConfigurationTracking {holes : Nat}
    (position : Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (source : Node)
    (configuration : Finset Node) :
    Tracking holes :=
  let added :=
    configuration \ (latestConfiguration (state.nodes source)).nodes
  let allocated := fun node =>
    if state.allocated node then
      tracking.allocated node
    else if node = source ∨ node ∈ added then
      .named position (markerSlot ALLOCATED_SLOT_BASE node)
        s!"allocated node {node.val}" (.literal 1)
    else
      tracking.allocated node
  let joined := fun node =>
    if node ∈ state.hasJoined then
      tracking.joined node
    else if node ∈ added then
      .named position (markerSlot JOINED_SLOT_BASE node)
        s!"joined node {node.val}" (.literal 1)
    else
      tracking.joined node
  let sentIndex := fun node peer =>
    if node = source then
      if peer ∈ added then
        .named position (markerSlot SENT_INDEX_SLOT_BASE peer)
          s!"sent index {peer.val}" (tracking.logLengths source)
      else
        tracking.sentIndex node peer
    else
      tracking.sentIndex node peer
  { logLengths := nextLogLengths position tracking.logLengths source
    retirementWriters :=
      nextRetirementWriters position tracking.retirementWriters source
    allocated
    joined
    sentIndex }

def encodeFrom {holes : Nat}
    (bounds : Bounds)
    (position : Nat)
    (state : Template holes)
    (tracking : Tracking holes) :
    List (TraceInstructions.Instruction holes) -> Formula holes
  | [] =>
      [{ label := "final state bounds"
         clauses := stateBoundsClauses bounds state tracking }]
  | .observation observation :: rest =>
      observationGroup bounds state tracking observation ::
        encodeFrom bounds (position + 1) state tracking rest
  | .clientRequest node transaction :: rest =>
      let accepted :=
        .named position 0 "accepted transaction" transaction
      clientRequestGroup bounds state tracking node transaction ::
        encodeFrom bounds (position + 1)
          (next state (.clientRequest node accepted))
          (nextWriteTracking position tracking node)
          rest
  | .signCommittableMessages node :: rest =>
      leaderWriteGroup "signCommittableMessages" bounds state tracking
          (Enabled state (.signCommittableMessages node)) ::
        encodeFrom bounds (position + 1)
          (next state (.signCommittableMessages node))
          (nextWriteTracking position tracking node) rest
  | .changeConfiguration node configuration :: rest =>
      leaderWriteGroup "changeConfiguration" bounds state tracking
          (Enabled state (.changeConfiguration node configuration)) ::
        encodeFrom bounds (position + 1)
          (next state (.changeConfiguration node configuration))
          (nextConfigurationTracking position state tracking node configuration)
          rest
  | .appendRetiredCommitted node :: rest =>
      leaderWriteGroup "appendRetiredCommitted" bounds state tracking
          (Enabled state (.appendRetiredCommitted node)) ::
        encodeFrom bounds (position + 1)
          (next state (.appendRetiredCommitted node))
          (nextWriteTracking position tracking node) rest

def encode {holes : Nat}
    (bounds : Bounds)
    (entry : Template holes)
    (trace : List (TraceInstructions.Instruction holes)) :
    Formula holes :=
  { label := "unknown transaction domains"
    clauses := (List.finRange holes).map fun index =>
      lessClause s!"unknown {index.val} domain" (.unknown index)
        bounds.transactionCount } ::
  encodeFrom bounds 1 entry (initialTracking entry) trace

end CCFRaft.TraceEncoding
