-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Slice25Simulation
import CCFRaft.Slice3Model

set_option autoImplicit false

namespace CCFRaft.Slice3.Simulation

abbrev TxId := CCFRaft.Simulation.TxId
abbrev SimState := State TxId
abbrev SimAction := Action TxId
abbrev Choice := CCFRaft.Simulation.Choice
abbrev ActionFamily := CCFRaft.Simulation.ActionFamily
abbrev Generator := CCFRaft.Simulation.Generator
abbrev Telemetry := CCFRaft.Simulation.Telemetry

def materialize (state : SimState) (choice : Choice) : Option SimAction :=
  CCFRaft.Simulation.materialize state choice

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

def adapter :
    ExecutableTransitionSystem.SimulationAdapter
      (system (TxId := TxId)) where
  Choice
  materialize
  complete := materializeComplete

def allNodes := CCFRaft.Simulation.allNodes
def candidateChoices (state : SimState) : List Choice :=
  CCFRaft.Simulation.candidateChoices state

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
      simp [candidateChoices, CCFRaft.Simulation.candidateChoices]
  | appendEntries source destination batchEnd =>
      refine ⟨.appendEntries source destination batchEnd, ?_, rfl⟩
      simp [
        candidateChoices,
        CCFRaft.Simulation.candidateChoices,
        enabled.2.2
      ]
  | receive source destination =>
      refine ⟨.receive source destination, ?_, rfl⟩
      simp [candidateChoices, CCFRaft.Simulation.candidateChoices]
  | advanceCommitIndex node =>
      refine ⟨.advanceCommitIndex node, ?_, rfl⟩
      simp [candidateChoices, CCFRaft.Simulation.candidateChoices]
  | timeout node =>
      refine ⟨.timeout node, ?_, rfl⟩
      simp [candidateChoices, CCFRaft.Simulation.candidateChoices]
  | requestVote source destination =>
      refine ⟨.requestVote source destination, ?_, rfl⟩
      simp [candidateChoices, CCFRaft.Simulation.candidateChoices]
  | updateTerm source destination =>
      refine ⟨.updateTerm source destination, ?_, rfl⟩
      simp [candidateChoices, CCFRaft.Simulation.candidateChoices]
  | becomeLeader node =>
      refine ⟨.becomeLeader node, ?_, rfl⟩
      simp [candidateChoices, CCFRaft.Simulation.candidateChoices]

def stateChecks (state : SimState) : Bool :=
  (allNodes.all fun node =>
    decide (
      (state.nodes node).commitIndex <=
        (state.nodes node).log.length)) &&
  Slice25.Simulation.committedPrefixesCheck state &&
  Slice25.Simulation.logMatchingCheck state &&
  Slice25.Simulation.logTermChecks state &&
  Slice25.Simulation.electionSafetyCheck state

def edgeChecks := CCFRaft.Simulation.edgeChecks

def enabledChoices (state : SimState) : List Choice :=
  candidateChoices state |>.filter fun choice =>
    match materialize state choice with
    | none => false
    | some action => decide (Enabled state action)

def familyChoices
    (family : ActionFamily)
    (choices : List Choice) : List Choice :=
  choices.filter fun choice => decide (choice.family = family)

def preferredChoices (state : SimState) : List Choice :=
  let enabled := enabledChoices state
  let promotions := familyChoices .becomeLeader enabled
  let updates := familyChoices .updateTerm enabled
  let receives := familyChoices .receive enabled
  let votes := familyChoices .requestVote enabled
  let candidateTimeouts :=
    (familyChoices .timeout enabled).filter fun choice =>
      match choice with
      | .timeout node => (state.nodes node).role = .candidate
      | _ => false
  let commits := familyChoices .advanceCommitIndex enabled
  let appends := familyChoices .appendEntries enabled
  let progressingAppends :=
    appends.filter fun choice =>
      match choice with
      | .appendEntries source destination batchEnd =>
          decide (
            (state.nodes source).sentIndex destination < batchEnd)
      | _ => false
  let clients := familyChoices .clientRequest enabled
  let electionActive :=
    allNodes.any fun node => (state.nodes node).role = .candidate
  let aLeaderNeedsCurrentEntry :=
    allNodes.any fun node =>
      (state.nodes node).role = .leader /\
        !(state.nodes node).log.any fun entry =>
          entry.term = (state.nodes node).currentTerm
  if !promotions.isEmpty then promotions
  else if !updates.isEmpty then updates
  else if !receives.isEmpty then receives
  else if electionActive && !(votes ++ candidateTimeouts).isEmpty then
    votes ++ candidateTimeouts
  else if aLeaderNeedsCurrentEntry && !clients.isEmpty then clients
  else if !commits.isEmpty then commits
  else if !progressingAppends.isEmpty then progressingAppends
  else enabled

def propose
    (state : SimState)
    (generator : Generator) :
    Option Choice × Generator :=
  let candidates := preferredChoices state
  let (index, generator) := generator.choose candidates.length
  (candidates[index]?, generator)

def renderAction := CCFRaft.Simulation.renderAction
def parseAction := CCFRaft.Simulation.parseAction
def writeTrace := CCFRaft.Simulation.writeTrace

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
      IO.println
        s!"replayed {actions.length} slice-3 actions; max term={
          (allNodes.map fun node => (state.nodes node).currentTerm).foldl max 0}"
      return 0
  | .error message =>
      IO.eprintln message
      return 1

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
    else state
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
        let path : System.FilePath := "ccf-raft-3-failure.trace"
        writeTrace path trace
        throw <| IO.userError s!"slice-3 invariant failure; replay {path}"
      let nextDepth := depth + 1
      let telemetry :=
        { telemetry.taken choice.family with
          steps := telemetry.steps + 1
          maxDepth := max telemetry.maxDepth nextDepth }
      simulateLoop
        deadlineMs maxDepth generator nextState nextDepth trace telemetry

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

end CCFRaft.Slice3.Simulation
