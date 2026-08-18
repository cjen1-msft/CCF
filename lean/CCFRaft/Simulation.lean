-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs

set_option autoImplicit false

/-!
# Bounded simulator adapter

The adapter does not define protocol semantics. It materializes choices as
ordinary model actions, then calls `ExecutableTransitionSystem.applyAction`.
-/

namespace CCFRaft.Simulation

/-- Number of transaction IDs available to the bounded simulator. -/
def TX_COUNT : Nat := 8
/-- Finite transaction-ID type used only by simulation and replay. -/
abbrev TxId := Fin TX_COUNT
/-- Concrete finite state explored by the simulator. -/
abbrev SimState := State TxId
/-- Concrete finite action type explored by the simulator. -/
abbrev SimAction := Action TxId

/-- Action families used for coverage telemetry. -/
inductive ActionFamily where
  | clientRequest
  | appendEntries
  | receive
  | advanceCommitIndex
  | timeout
  | requestVote
  | updateTerm
  | becomeLeader
  deriving DecidableEq, Repr

/-- Raw simulator choices that materialize directly as semantic actions. -/
inductive Choice where
  | clientRequest (node : Node) (txId : TxId)
  | appendEntries (source destination : Node) (batchEnd : Nat)
  | receive (source destination : Node)
  | advanceCommitIndex (node : Node)
  | timeout (node : Node)
  | requestVote (source destination : Node)
  | updateTerm (source destination : Node)
  | becomeLeader (node : Node)
  deriving DecidableEq, Repr

/-- Classify a simulator choice for coverage reporting. -/
def Choice.family : Choice -> ActionFamily
  | .clientRequest .. => .clientRequest
  | .appendEntries .. => .appendEntries
  | .receive .. => .receive
  | .advanceCommitIndex .. => .advanceCommitIndex
  | .timeout .. => .timeout
  | .requestVote .. => .requestVote
  | .updateTerm .. => .updateTerm
  | .becomeLeader .. => .becomeLeader

/-- Convert a simulator choice into the exact model action it denotes. -/
def materialize (_state : SimState) : Choice -> Option SimAction
  | .clientRequest node txId => some (.clientRequest node txId)
  | .appendEntries source destination batchEnd =>
      some (.appendEntries source destination batchEnd)
  | .receive source destination => some (.receive source destination)
  | .advanceCommitIndex node => some (.advanceCommitIndex node)
  | .timeout node => some (.timeout node)
  | .requestVote source destination =>
      some (.requestVote source destination)
  | .updateTerm source destination =>
      some (.updateTerm source destination)
  | .becomeLeader node => some (.becomeLeader node)

/-- Every enabled finite model action has a corresponding simulator choice. -/
theorem materializeComplete
    (state : SimState)
    (action : SimAction)
    (_enabled : Enabled state action) :
    Exists fun choice =>
      materialize state choice = some action := by
  cases action with
  | clientRequest node txId =>
      exact ⟨.clientRequest node txId, rfl⟩
  | appendEntries source destination batchEnd =>
      exact ⟨.appendEntries source destination batchEnd, rfl⟩
  | receive source destination =>
      exact ⟨.receive source destination, rfl⟩
  | advanceCommitIndex node =>
      exact ⟨.advanceCommitIndex node, rfl⟩
  | timeout node =>
      exact ⟨.timeout node, rfl⟩
  | requestVote source destination =>
      exact ⟨.requestVote source destination, rfl⟩
  | updateTerm source destination =>
      exact ⟨.updateTerm source destination, rfl⟩
  | becomeLeader node =>
      exact ⟨.becomeLeader node, rfl⟩

/-- Package materialization and its completeness proof for the generic engine. -/
def adapter :
    ExecutableTransitionSystem.SimulationAdapter
      (system (TxId := TxId)) where
  Choice
  materialize
  complete := materializeComplete

/-- Executable enumeration of all five nodes. -/
def allNodes : List Node :=
  List.ofFn fun node => node

/-- Executable enumeration of all bounded transaction IDs. -/
def allTxIds : List TxId :=
  List.ofFn fun txId => txId

/-- Every node occurs in the simulator's node enumeration. -/
@[simp]
theorem memAllNodes (node : Node) :
    node ∈ allNodes :=
  List.mem_ofFn.mpr ⟨node, rfl⟩

/-- Every bounded transaction ID occurs in its enumeration. -/
@[simp]
theorem memAllTxIds (txId : TxId) :
    txId ∈ allTxIds :=
  List.mem_ofFn.mpr ⟨txId, rfl⟩

/-- Executably check every category of the proof's supporting invariant. -/
def stateChecks (state : SimState) : Bool :=
  let nodeChecks :=
    allNodes.all fun node =>
      decide ((state.nodes node).commitIndex <=
        (state.nodes node).log.length) &&
      decide ((state.nodes node).log <+: (state.nodes INITIAL_LEADER).log) &&
      ((state.nodes node).log.all fun entry =>
        decide (entry.term = TERM_ONE)) &&
      decide (
        (state.nodes node).currentTerm = TERM_ONE \/
          (state.nodes node).currentTerm = 2) &&
      decide (
        (state.nodes node).role = .leader ->
          (state.nodes node).currentTerm = TERM_ONE ->
          node = INITIAL_LEADER) &&
      decide (
        (state.nodes node).role = .candidate ->
          (state.nodes node).currentTerm = 2 /\
          (state.nodes node).votedFor = some node /\
          node ∈ (state.nodes node).votesGranted) &&
      decide (
        (state.nodes node).role = .leader ->
          (state.nodes node).currentTerm = 2 ->
          hasElectionMajority state node) &&
      (allNodes.all fun voter =>
        if decide (voter ∈ (state.nodes node).votesGranted) then
          decide ((state.nodes node).currentTerm = 2) &&
          decide ((state.nodes voter).votedFor = some node) &&
          decide ((state.nodes voter).log <+: (state.nodes node).log)
        else
          true)
  let voterChecks :=
    allNodes.all fun voter =>
      match (state.nodes voter).votedFor with
      | none => true
      | some _ => decide ((state.nodes voter).currentTerm = 2)
  let leaderChecks :=
    decide ((state.nodes INITIAL_LEADER).log.map Entry.txId |>.Nodup) &&
      ((state.nodes INITIAL_LEADER).log.all fun entry =>
        decide (entry.txId ∈ state.submittedTxIds)) &&
      (allNodes.all fun node =>
        decide ((state.nodes INITIAL_LEADER).sentIndex node <=
          (state.nodes INITIAL_LEADER).log.length) &&
        decide ((state.nodes INITIAL_LEADER).matchIndex node <=
          (state.nodes INITIAL_LEADER).log.length) &&
        decide (
          (state.nodes INITIAL_LEADER).log.take
              ((state.nodes INITIAL_LEADER).matchIndex node) =
            (state.nodes node).log.take
              ((state.nodes INITIAL_LEADER).matchIndex node))) &&
      decide (
        (state.nodes INITIAL_LEADER).currentTerm = TERM_ONE ->
          (state.nodes INITIAL_LEADER).role = .leader) &&
      decide (
        (state.nodes INITIAL_LEADER).commitIndex = 0 \/
          hasMajorityAt state INITIAL_LEADER (state.nodes INITIAL_LEADER).commitIndex) &&
      decide (Not ((state.nodes INITIAL_LEADER).role = .candidate))
  let networkChecks :=
    allNodes.all fun destination =>
      (state.network destination).all fun message =>
        decide (message.destination = destination) &&
          match message with
          | .appendEntriesRequest request =>
              decide (RequestMatchesLeader state request)
          | .appendEntriesResponse response =>
              decide (ResponseMatchesLeader state response)
          | .requestVoteRequest request =>
              decide (RequestVoteRequestSafe state request)
          | .requestVoteResponse response =>
              decide (RequestVoteResponseSafe state response)
  nodeChecks && voterChecks && leaderChecks && networkChecks

/-- Executably check committed-log monotonicity on one explored edge. -/
def edgeChecks (before after : SimState) : Bool :=
  allNodes.all fun node =>
    decide (
      (before.nodes node).committedLog <+:
        (after.nodes node).committedLog)

/-- State of the deterministic pseudo-random number generator. -/
structure Generator where
  state : UInt64

/-- Produce the next pseudo-random word and generator state. -/
def Generator.next (generator : Generator) : UInt64 × Generator :=
  let value :=
    generator.state * 6364136223846793005 + 1442695040888963407
  (value, { state := value })

/-- Choose an index below a bound, returning zero for an empty range. -/
def Generator.choose
    (generator : Generator)
    (bound : Nat) :
    Nat × Generator :=
  let (value, nextGenerator) := generator.next
  if bound = 0 then
    (0, nextGenerator)
  else
    (value.toNat % bound, nextGenerator)

/-- Enumerate every bounded action shape that could be enabled in a state. -/
def candidateChoices (state : SimState) : List Choice :=
  (allNodes.flatMap fun node =>
    allTxIds.map fun txId => .clientRequest node txId) ++
  (allNodes.flatMap fun source =>
    allNodes.map fun destination =>
      .appendEntries
        source
        destination
        (min
          ((state.nodes source).sentIndex destination + 1)
          (state.nodes source).log.length)) ++
  (allNodes.flatMap fun source =>
    allNodes.map fun destination => .receive source destination) ++
  (allNodes.map fun node => .advanceCommitIndex node) ++
  (allNodes.map fun node => .timeout node) ++
  (allNodes.flatMap fun source =>
    allNodes.map fun destination => .requestVote source destination) ++
  (allNodes.flatMap fun source =>
    allNodes.map fun destination => .updateTerm source destination) ++
  (allNodes.map fun node => .becomeLeader node)

/-- Every enabled finite action appears in the simulator candidate list. -/
theorem candidateChoicesComplete
    (state : SimState)
    (action : SimAction)
    (enabled : Enabled state action) :
    Exists fun choice =>
      choice ∈ candidateChoices state /\
        materialize state choice = some action := by
  cases action with
  | clientRequest node txId =>
      refine ⟨.clientRequest node txId, ?_, rfl⟩
      simp [candidateChoices]
  | appendEntries source destination batchEnd =>
      refine ⟨.appendEntries source destination batchEnd, ?_, rfl⟩
      simp [candidateChoices, enabled.2.2.2]
  | receive source destination =>
      refine ⟨.receive source destination, ?_, rfl⟩
      simp [candidateChoices]
  | advanceCommitIndex node =>
      refine ⟨.advanceCommitIndex node, ?_, rfl⟩
      simp [candidateChoices]
  | timeout node =>
      refine ⟨.timeout node, ?_, rfl⟩
      simp [candidateChoices]
  | requestVote source destination =>
      refine ⟨.requestVote source destination, ?_, rfl⟩
      simp [candidateChoices]
  | updateTerm source destination =>
      refine ⟨.updateTerm source destination, ?_, rfl⟩
      simp [candidateChoices]
  | becomeLeader node =>
      refine ⟨.becomeLeader node, ?_, rfl⟩
      simp [candidateChoices]

/-- Retain exactly the candidate choices enabled by the authoritative guard. -/
def enabledChoices (state : SimState) : List Choice :=
  candidateChoices state |>.filter fun choice =>
    match materialize state choice with
    | none => false
    | some action => decide (Enabled state action)

/-- Randomly select one currently enabled choice from the complete list. -/
def propose
    (state : SimState)
    (generator : Generator) :
    Option Choice × Generator :=
  let candidates := enabledChoices state
  let (index, generator) := generator.choose candidates.length
  (candidates[index]?, generator)

/-- Counts proposals, accepted actions, rejections, traces, and explored depth. -/
structure Telemetry where
  proposedClient : Nat := 0
  proposedAppend : Nat := 0
  proposedReceive : Nat := 0
  proposedCommit : Nat := 0
  proposedTimeout : Nat := 0
  proposedVote : Nat := 0
  proposedUpdateTerm : Nat := 0
  proposedBecomeLeader : Nat := 0
  takenClient : Nat := 0
  takenAppend : Nat := 0
  takenReceive : Nat := 0
  takenCommit : Nat := 0
  takenTimeout : Nat := 0
  takenVote : Nat := 0
  takenUpdateTerm : Nat := 0
  takenBecomeLeader : Nat := 0
  rejected : Nat := 0
  traces : Nat := 0
  steps : Nat := 0
  maxDepth : Nat := 0
  deriving Repr

/-- Increment the proposal counter for one action family. -/
def Telemetry.proposed
    (telemetry : Telemetry)
    (family : ActionFamily) : Telemetry :=
  match family with
  | .clientRequest =>
      { telemetry with proposedClient := telemetry.proposedClient + 1 }
  | .appendEntries =>
      { telemetry with proposedAppend := telemetry.proposedAppend + 1 }
  | .receive =>
      { telemetry with proposedReceive := telemetry.proposedReceive + 1 }
  | .advanceCommitIndex =>
      { telemetry with proposedCommit := telemetry.proposedCommit + 1 }
  | .timeout =>
      { telemetry with proposedTimeout := telemetry.proposedTimeout + 1 }
  | .requestVote =>
      { telemetry with proposedVote := telemetry.proposedVote + 1 }
  | .updateTerm =>
      { telemetry with proposedUpdateTerm := telemetry.proposedUpdateTerm + 1 }
  | .becomeLeader =>
      { telemetry with
          proposedBecomeLeader := telemetry.proposedBecomeLeader + 1 }

/-- Increment the accepted-action counter for one action family. -/
def Telemetry.taken
    (telemetry : Telemetry)
    (family : ActionFamily) : Telemetry :=
  match family with
  | .clientRequest =>
      { telemetry with takenClient := telemetry.takenClient + 1 }
  | .appendEntries =>
      { telemetry with takenAppend := telemetry.takenAppend + 1 }
  | .receive =>
      { telemetry with takenReceive := telemetry.takenReceive + 1 }
  | .advanceCommitIndex =>
      { telemetry with takenCommit := telemetry.takenCommit + 1 }
  | .timeout =>
      { telemetry with takenTimeout := telemetry.takenTimeout + 1 }
  | .requestVote =>
      { telemetry with takenVote := telemetry.takenVote + 1 }
  | .updateTerm =>
      { telemetry with takenUpdateTerm := telemetry.takenUpdateTerm + 1 }
  | .becomeLeader =>
      { telemetry with
          takenBecomeLeader := telemetry.takenBecomeLeader + 1 }

/-- Serialize one semantic action as a stable replay line. -/
def renderAction : SimAction -> String
  | .clientRequest node txId =>
      s!"client,{node.val},{txId.val}"
  | .appendEntries source destination batchEnd =>
      s!"append,{source.val},{destination.val},{batchEnd}"
  | .receive source destination =>
      s!"receive,{source.val},{destination.val}"
  | .advanceCommitIndex node =>
      s!"commit,{node.val}"
  | .timeout node =>
      s!"timeout,{node.val}"
  | .requestVote source destination =>
      s!"vote,{source.val},{destination.val}"
  | .updateTerm source destination =>
      s!"term,{source.val},{destination.val}"
  | .becomeLeader node =>
      s!"leader,{node.val}"

/-- Parse a natural number only when it lies below a given bound. -/
def parseBounded
    (bound : Nat)
    (raw : String) :
    Option Nat := do
  let value <- raw.toNat?
  if value < bound then some value else none

/-- Parse a node identifier from replay text. -/
def nodeOfString (raw : String) : Option Node := do
  let value <- raw.toNat?
  if within : value < NODE_COUNT then
    some ⟨value, within⟩
  else
    none

/-- Parse a bounded transaction ID from replay text. -/
def txIdOfString (raw : String) : Option TxId := do
  let value <- raw.toNat?
  if within : value < TX_COUNT then
    some ⟨value, within⟩
  else
    none

/-- Parse one replay line into a semantic action. -/
def parseAction (line : String) : Option SimAction := do
  match line.splitOn "," with
  | ["client", node, txId] =>
      let node <- nodeOfString node
      let txId <- txIdOfString txId
      some (.clientRequest node txId)
  | ["append", source, destination, batchEnd] =>
      let source <- nodeOfString source
      let destination <- nodeOfString destination
      let batchEnd <- batchEnd.toNat?
      some (.appendEntries source destination batchEnd)
  | ["receive", source, destination] =>
      let source <- nodeOfString source
      let destination <- nodeOfString destination
      some (.receive source destination)
  | ["commit", node] =>
      let node <- nodeOfString node
      some (.advanceCommitIndex node)
  | ["timeout", node] =>
      let node <- nodeOfString node
      some (.timeout node)
  | ["vote", source, destination] =>
      let source <- nodeOfString source
      let destination <- nodeOfString destination
      some (.requestVote source destination)
  | ["term", source, destination] =>
      let source <- nodeOfString source
      let destination <- nodeOfString destination
      some (.updateTerm source destination)
  | ["leader", node] =>
      let node <- nodeOfString node
      some (.becomeLeader node)
  | _ => none

/-- Write semantic actions in execution order to a replayable trace. -/
def writeTrace (path : System.FilePath) (actions : List SimAction) : IO Unit :=
  IO.FS.writeFile path
    (String.intercalate "\n" (actions.reverse.map renderAction) ++ "\n")

/-- Reapply a trace while checking every state and edge invariant. -/
def replayActions
    (actions : List SimAction) :
    Except String SimState :=
  actions.foldlM (init := (initialState : SimState)) fun state action => do
    let some nextState :=
      (system (TxId := TxId)).applyAction state action
      | throw s!"disabled action: {renderAction action}"
    if !stateChecks nextState then
      throw s!"state invariant failed after: {renderAction action}"
    if !edgeChecks state nextState then
      throw s!"edge invariant failed after: {renderAction action}"
    pure nextState

/-- Parse and replay a trace file, reporting its final commit frontier. -/
def replayFile (path : System.FilePath) : IO UInt32 := do
  let content <- IO.FS.readFile path
  let lines := content.splitOn "\n" |>.filter (· != "")
  let mut actions := []
  for line in lines do
    let some action := parseAction line
      | IO.eprintln s!"invalid trace line: {line}"
        return 2
    actions := actions ++ [action]
  match replayActions actions with
  | .ok state =>
      IO.println s!"replayed {actions.length} actions; leader commit={(state.nodes INITIAL_LEADER).commitIndex}"
      return 0
  | .error message =>
      IO.eprintln message
      return 1

/-- Run random traces until the deadline, restarting at the depth limit. -/
partial def simulateLoop
    (deadlineMs : Nat)
    (maxDepth : Nat)
    (generator : Generator)
    (state : SimState)
    (depth : Nat)
    (trace : List SimAction)
    (telemetry : Telemetry) :
    IO (Telemetry × Generator) := do
  let now <- IO.monoMsNow
  if now >= deadlineMs then
    return (telemetry, generator)
  let state :=
    if depth >= maxDepth then
      (initialState : SimState)
    else
      state
  let depth := if depth >= maxDepth then 0 else depth
  let trace := if depth = 0 then [] else trace
  let telemetry :=
    if depth = 0 then
      { telemetry with traces := telemetry.traces + 1 }
    else telemetry
  let (choice?, generator) := propose state generator
  let some choice := choice?
    | simulateLoop
        deadlineMs maxDepth generator
        (initialState : SimState) 0 [] telemetry
  let telemetry := telemetry.proposed choice.family
  let some action := materialize state choice
    | simulateLoop deadlineMs maxDepth generator state depth trace
        { telemetry with rejected := telemetry.rejected + 1 }
  match (system (TxId := TxId)).applyAction state action with
  | none =>
      simulateLoop deadlineMs maxDepth generator state depth trace
        { telemetry with rejected := telemetry.rejected + 1 }
  | some nextState =>
      let trace := action :: trace
      if !stateChecks nextState || !edgeChecks state nextState then
        let path : System.FilePath := "ccf-raft-failure.trace"
        writeTrace path trace
        throw <| IO.userError s!"invariant failure; replay {path}"
      let nextDepth := depth + 1
      let telemetry :=
        { telemetry.taken choice.family with
          steps := telemetry.steps + 1
          maxDepth := max telemetry.maxDepth nextDepth }
      simulateLoop deadlineMs maxDepth generator nextState nextDepth trace telemetry

/-- Run timed simulation from a seed and print coverage telemetry. -/
def simulate
    (durationMs seed maxDepth : Nat) :
    IO UInt32 := do
  let start <- IO.monoMsNow
  let (telemetry, _) <-
    simulateLoop
      (start + durationMs)
      maxDepth
      { state := UInt64.ofNat seed }
      (initialState : SimState)
      0
      []
      {}
  IO.println s!"{repr telemetry}"
  return 0

end CCFRaft.Simulation
