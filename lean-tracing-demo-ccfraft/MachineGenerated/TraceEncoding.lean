-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import BoundedTrace
import Shared.SmtOrder
import MachineGenerated.GuardedAppendEntries

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
def QUEUE_LENGTH_SLOT_BASE : Nat := 70
def PATH_SLOT_STRIDE : Nat := 100

#guard 4 < ALLOCATED_SLOT_BASE &&
  ALLOCATED_SLOT_BASE + NODE_COUNT ≤ JOINED_SLOT_BASE &&
  JOINED_SLOT_BASE + NODE_COUNT ≤ SENT_INDEX_SLOT_BASE &&
  SENT_INDEX_SLOT_BASE + NODE_COUNT ≤ QUEUE_LENGTH_SLOT_BASE &&
  QUEUE_LENGTH_SLOT_BASE + NODE_COUNT ≤ PATH_SLOT_STRIDE

def pathSlot (pathId base : Nat) : Nat :=
  pathId * PATH_SLOT_STRIDE + base

structure Tracking (holes : Nat) where
  logLengths : Node -> Value holes
  retirementWriters : Node -> Option (Nat × Nat)
  allocated : Node -> Value holes
  joined : Node -> Value holes
  sentIndex : Node -> Node -> Value holes
  queueLengths : Node -> Value holes

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
    (bounds : Bounds)
    (writer : Option (Nat × Nat))
    (slot : Nat)
    (label : String) :
    Option Nat -> List (Clause holes)
  | none => []
  | some index =>
      let value : Value holes :=
        match writer with
        | none => .literal index
        | some (group, pathId) =>
            .named group (pathSlot pathId slot) label (.literal index)
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
    (bounds : Bounds)
    (state : Template holes)
    (tracking : Tracking holes)
    (node : Node) :
    List (Clause holes) :=
  atMostClause "queue capacity"
      (tracking.queueLengths node) bounds.queueCapacity ::
    (state.network node).flatMap (messageBoundsClauses bounds)

def stateBoundsClauses {holes : Nat}
    (bounds : Bounds)
    (state : Template holes)
    (tracking : Tracking holes) :
    List (Clause holes) :=
  (List.finRange NODE_COUNT).flatMap
      (nodeBoundsClauses bounds state tracking) ++
  (List.finRange NODE_COUNT).flatMap
      (queueBoundsClauses bounds state tracking) ++
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
  | .queueLength node value =>
      .equal (tracking.queueLengths node) (.literal value)
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
  queueLengths := fun node => .literal (state.network node).length

def nextLogLengths {holes : Nat}
    (position : Nat)
    (pathId : Nat)
    (logLengths : Node -> Value holes)
    (node : Node) :
    Node -> Value holes :=
  Function.update logLengths node
    (.named position (pathSlot pathId 1) "next log length"
      (.add (logLengths node) (.literal 1)))

def nextRetirementWriters
    (position : Nat)
    (pathId : Nat)
    (retirementWriters : Node -> Option (Nat × Nat))
    (node : Node) :
    Node -> Option (Nat × Nat) :=
  Function.update retirementWriters node (some (position, pathId))

def nextWriteTracking {holes : Nat}
    (position pathId : Nat) (tracking : Tracking holes) (node : Node) :
    Tracking holes :=
  { tracking with
    logLengths := nextLogLengths position pathId tracking.logLengths node
    retirementWriters :=
      nextRetirementWriters position pathId tracking.retirementWriters node }

def nextConfigurationTracking {holes : Nat}
    (position : Nat)
    (pathId : Nat)
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
      .named position
        (pathSlot pathId (markerSlot ALLOCATED_SLOT_BASE node))
        s!"allocated node {node.val}" (.literal 1)
    else
      tracking.allocated node
  let joined := fun node =>
    if node ∈ state.hasJoined then
      tracking.joined node
    else if node ∈ added then
      .named position
        (pathSlot pathId (markerSlot JOINED_SLOT_BASE node))
        s!"joined node {node.val}" (.literal 1)
    else
      tracking.joined node
  let sentIndex := fun node peer =>
    if node = source then
      if peer ∈ added then
        .named position
          (pathSlot pathId (markerSlot SENT_INDEX_SLOT_BASE peer))
          s!"sent index {peer.val}" (tracking.logLengths source)
      else
        tracking.sentIndex node peer
    else
      tracking.sentIndex node peer
  { logLengths := nextLogLengths position pathId tracking.logLengths source
    retirementWriters :=
      nextRetirementWriters position pathId tracking.retirementWriters source
    allocated
    joined
    sentIndex
    queueLengths := tracking.queueLengths }

def nextAppendEntriesTracking {holes : Nat}
    (position pathId : Nat)
    (tracking : Tracking holes)
    (source destination : Node)
    (batchEnd : Nat)
    (queueGrew : Bool) :
    Tracking holes :=
  let queueLengths :=
    Function.update tracking.queueLengths destination
      (if queueGrew then
        .named position
          (pathSlot pathId (markerSlot QUEUE_LENGTH_SLOT_BASE destination))
          s!"queue length {destination.val}"
          (.add (tracking.queueLengths destination) (.literal 1))
       else
        tracking.queueLengths destination)
  let sourceIndices :=
    Function.update (tracking.sentIndex source) destination
      (.named position
        (pathSlot pathId (markerSlot SENT_INDEX_SLOT_BASE destination))
        s!"sent index {destination.val}" (.literal batchEnd))
  { tracking with
    sentIndex := Function.update tracking.sentIndex source sourceIndices
    queueLengths }

structure Frame (holes : Nat) where
  state : Template holes
  tracking : Tracking holes
  pathId : Nat

def clientRequestFrame {holes : Nat}
    (position : Nat)
    (node : Node)
    (accepted : Value holes)
    (frame : Frame holes) :
    Frame holes :=
  { state := next frame.state (.clientRequest node accepted)
    tracking :=
      nextWriteTracking position frame.pathId frame.tracking node
    pathId := frame.pathId }

def signatureFrame {holes : Nat}
    (position : Nat)
    (node : Node)
    (frame : Frame holes) :
    Frame holes :=
  { state := next frame.state (.signCommittableMessages node)
    tracking :=
      nextWriteTracking position frame.pathId frame.tracking node
    pathId := frame.pathId }

def configurationFrame {holes : Nat}
    (position : Nat)
    (node : Node)
    (configuration : Finset Node)
    (frame : Frame holes) :
    Frame holes :=
  { state := next frame.state (.changeConfiguration node configuration)
    tracking :=
      nextConfigurationTracking position frame.pathId frame.state
        frame.tracking node configuration
    pathId := frame.pathId }

def retiredCommittedFrame {holes : Nat}
    (position : Nat)
    (node : Node)
    (frame : Frame holes) :
    Frame holes :=
  { state := next frame.state (.appendRetiredCommitted node)
    tracking :=
      nextWriteTracking position frame.pathId frame.tracking node
    pathId := frame.pathId }

def guardClauses {holes : Nat}
    (condition : Expr holes)
    (clauses : List (Clause holes)) :
    List (Clause holes) :=
  clauses.map fun clause =>
    { clause with expression := condition.implies clause.expression }

def guardedClauses {holes : Nat} {α : Type}
    (tree : Guarded holes α)
    (clauses : α -> List (Clause holes)) :
    List (Clause holes) :=
  match tree with
  | .pure value => clauses value
  | .branch condition thenTree elseTree =>
      guardClauses condition (guardedClauses thenTree clauses) ++
        guardClauses (.not condition) (guardedClauses elseTree clauses)

def guardedGroup {holes : Nat}
    (label : String)
    (frames : Guarded holes (Frame holes))
    (clauses : Frame holes -> List (Clause holes)) :
    Group holes :=
  { label, clauses := guardedClauses frames clauses }

def childPath (pathId : Nat) (right : Bool) : Nat :=
  pathId * 2 + if right then 2 else 1

def attachAppendFrame {holes : Nat}
    (position priorLength : Nat)
    (tracking : Tracking holes)
    (source destination : Node)
    (batchEnd : Nat)
    (pathId : Nat) :
    Guarded holes (Template holes) -> Guarded holes (Frame holes)
  | .pure successor =>
      let queueGrew :=
        decide (priorLength < (successor.network destination).length)
      .pure {
        state := successor
        tracking :=
          nextAppendEntriesTracking position pathId tracking
            source destination batchEnd queueGrew
        pathId
      }
  | .branch condition thenTree elseTree =>
      Guarded.branchSmart condition
        (attachAppendFrame position priorLength tracking source destination
          batchEnd (childPath pathId false) thenTree)
        (attachAppendFrame position priorLength tracking source destination
          batchEnd (childPath pathId true) elseTree)

def appendFrames {holes : Nat}
    (position : Nat)
    (frame : Frame holes)
    (source destination : Node)
    (batchEnd : Nat) :
    Guarded holes (Frame holes) :=
  let priorLength := (frame.state.network destination).length
  attachAppendFrame position priorLength frame.tracking source destination
    batchEnd frame.pathId
    (GuardedAppendEntries.step frame.state source destination batchEnd)

def encodeFrom {holes : Nat}
    (bounds : Bounds)
    (position : Nat)
    (frames : Guarded holes (Frame holes)) :
    List (TraceInstructions.Instruction holes) -> Formula holes
  | [] =>
      [{ label := "final state bounds"
         clauses := guardedClauses frames fun frame =>
           stateBoundsClauses bounds frame.state frame.tracking }]
  | .observation observation :: rest =>
      (guardedGroup "observation" frames fun frame =>
        stateBoundsClauses bounds frame.state frame.tracking ++
          observationClauses bounds frame.state frame.tracking observation) ::
        encodeFrom bounds (position + 1) frames rest
  | .clientRequest node transaction :: rest =>
      let accepted :=
        .named position 0 "accepted transaction" transaction
      (guardedGroup "clientRequest" frames fun frame =>
        (clientRequestGroup bounds frame.state frame.tracking
          node transaction).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map (clientRequestFrame position node accepted)) rest
  | .signCommittableMessages node :: rest =>
      (guardedGroup "signCommittableMessages" frames fun frame =>
        (leaderWriteGroup "signCommittableMessages" bounds
          frame.state frame.tracking
          (Enabled frame.state (.signCommittableMessages node))).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map (signatureFrame position node)) rest
  | .changeConfiguration node configuration :: rest =>
      (guardedGroup "changeConfiguration" frames fun frame =>
        (leaderWriteGroup "changeConfiguration" bounds
          frame.state frame.tracking
          (Enabled frame.state
            (.changeConfiguration node configuration))).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map
            (configurationFrame position node configuration)) rest
  | .appendRetiredCommitted node :: rest =>
      (guardedGroup "appendRetiredCommitted" frames fun frame =>
        (leaderWriteGroup "appendRetiredCommitted" bounds
          frame.state frame.tracking
          (Enabled frame.state (.appendRetiredCommitted node))).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map (retiredCommittedFrame position node)) rest
  | .appendEntries source destination batchEnd :: rest =>
      (guardedGroup "appendEntries" frames fun frame =>
        (leaderWriteGroup "appendEntries" bounds frame.state frame.tracking
          (Enabled frame.state
            (.appendEntries source destination batchEnd))).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.bind fun frame =>
            appendFrames position frame source destination batchEnd)
          rest

def encode {holes : Nat}
    (bounds : Bounds)
    (entry : Template holes)
    (trace : List (TraceInstructions.Instruction holes)) :
    Formula holes :=
  { label := "unknown transaction domains"
    clauses := (List.finRange holes).map fun index =>
      lessClause s!"unknown {index.val} domain" (.unknown index)
        bounds.transactionCount } ::
  encodeFrom bounds 1
    (.pure { state := entry, tracking := initialTracking entry, pathId := 0 })
    trace

end CCFRaft.TraceEncoding
