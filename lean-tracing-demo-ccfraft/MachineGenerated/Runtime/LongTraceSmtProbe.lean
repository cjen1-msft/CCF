-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.Runtime.Simulation

set_option autoImplicit false

/-!
# Throwaway long real-trace replay probe

This executable replays a generated semantic suffix from a concrete checkpoint.
It uses the canonical transition system and does not claim checkpoint reachability.
-/

namespace CCFRaft.LongTraceSmtProbe

open CCFRaft.Simulation

structure ModelValues where
  n0Term : Nat
  n0Last : Nat
  n0Commit : Nat
  n1Term : Nat
  n1Last : Nat
  n1Commit : Nat
  sent01 : Nat
  match01 : Nat
  requestQueue : Nat
  responseQueue : Nat
  response0Term : Nat
  response0Success : Bool
  response0Index : Nat
  response0Source : Nat
  response0Destination : Nat
  response1Term : Nat
  response1Success : Bool
  response1Index : Nat
  response1Source : Nat
  response1Destination : Nat
  txId : Nat

structure Observation where
  event : Nat
  step : Nat
  node : Node
  role : Role
  term : Option Nat
  last : Option Nat
  commit : Option Nat
  sent : Option Nat
  matched : Option Nat

def lookupValue
    (entries : List (Prod String String))
    (key : String) :
    Except String String :=
  match entries.find? fun entry => entry.1 = key with
  | some entry => pure entry.2
  | none => throw s!"model values omit {key}"

def parseNatValue
    (entries : List (Prod String String))
    (key : String) :
    Except String Nat := do
  let raw <- lookupValue entries key
  match raw.toNat? with
  | some value => pure value
  | none => throw s!"model value {key} is not a natural number: {raw}"

def parseBoolValue
    (entries : List (Prod String String))
    (key : String) :
    Except String Bool := do
  match <- lookupValue entries key with
  | "true" => pure true
  | "false" => pure false
  | raw => throw s!"model value {key} is not Boolean: {raw}"

def parseModelValues (content : String) : Except String ModelValues := do
  let mut entries := []
  for line in content.splitOn "\n" do
    if !line.trimAscii.isEmpty then
      match line.splitOn "=" with
      | [key, value] => entries := entries ++ [(key, value)]
      | _ => throw s!"invalid model value line: {line}"
  pure {
    n0Term := <- parseNatValue entries "n0_term_s00"
    n0Last := <- parseNatValue entries "n0_last_s00"
    n0Commit := <- parseNatValue entries "n0_commit_s00"
    n1Term := <- parseNatValue entries "n1_term_s00"
    n1Last := <- parseNatValue entries "n1_last_s00"
    n1Commit := <- parseNatValue entries "n1_commit_s00"
    sent01 := <- parseNatValue entries "sent01_s00"
    match01 := <- parseNatValue entries "match01_s00"
    requestQueue := <- parseNatValue entries "request_queue_s00"
    responseQueue := <- parseNatValue entries "response_queue_s00"
    response0Term := <- parseNatValue entries "initial_response_0_term"
    response0Success := <- parseBoolValue entries "initial_response_0_success"
    response0Index := <- parseNatValue entries "initial_response_0_index"
    response0Source := <- parseNatValue entries "initial_response_0_source"
    response0Destination := <-
      parseNatValue entries "initial_response_0_destination"
    response1Term := <- parseNatValue entries "initial_response_1_term"
    response1Success := <- parseBoolValue entries "initial_response_1_success"
    response1Index := <- parseNatValue entries "initial_response_1_index"
    response1Source := <- parseNatValue entries "initial_response_1_source"
    response1Destination := <-
      parseNatValue entries "initial_response_1_destination"
    txId := <- parseNatValue entries "tx_id"
  }

def node0 : Node := Fin.mk 0 (by decide)
def node1 : Node := Fin.mk 1 (by decide)

def retainedLog : List (Entry Node TxId) :=
  [
    { term := 2, content := .reconfiguration {node0} },
    { term := 2, content := .signature },
    { term := 2, content := .reconfiguration {node0, node1} },
    { term := 2, content := .signature }
  ]

def modelNode
    (base : NodeState Node TxId)
    (role : Role)
    (term commit : Nat)
    (sent matched : Node -> Nat) :
    NodeState Node TxId :=
  { base with
    role
    currentTerm := term
    log := retainedLog
    commitIndex := commit
    sentIndex := sent
    matchIndex := matched }

def responseMessage
    (term : Nat)
    (success : Bool)
    (lastLogIndex : Nat)
    (source destination : Node) :
    Message Node TxId :=
  .appendEntriesResponse {
    term
    success
    lastLogIndex
    source
    destination
  }

def buildCheckpoint (values : ModelValues) : Except String SimState := do
  if values.n0Last != retainedLog.length then
    throw s!"model node 0 last index is {values.n0Last}, retained log length is {
      retainedLog.length}"
  if values.n1Last != retainedLog.length then
    throw s!"model node 1 last index is {values.n1Last}, retained log length is {
      retainedLog.length}"
  if values.requestQueue != 0 || values.responseQueue != 2 then
    throw s!"model queue counts are request={values.requestQueue}, response={
      values.responseQueue}; expected 0 and 2"
  if values.response0Source != 1 || values.response1Source != 1 ||
      values.response0Destination != 0 || values.response1Destination != 0 then
    throw "model response endpoints differ from node 1 to node 0"
  if values.txId >= TX_COUNT then
    throw s!"model transaction ID {values.txId} is outside Fin {TX_COUNT}"
  let initial : SimState := initialState
  let leader :=
    modelNode
      (initial.nodes node0)
      .leader
      values.n0Term
      values.n0Commit
      (fun peer => if peer = node1 then values.sent01 else 0)
      (fun peer => if peer = node1 then values.match01 else 0)
  let follower :=
    modelNode
      (initial.nodes node1)
      .follower
      values.n1Term
      values.n1Commit
      (fun _ => 0)
      (fun _ => 0)
  let response0 :=
    responseMessage
      values.response0Term
      values.response0Success
      values.response0Index
      node1
      node0
  let response1 :=
    responseMessage
      values.response1Term
      values.response1Success
      values.response1Index
      node1
      node0
  pure {
    initial with
    nodes :=
      updateNode (updateNode initial.nodes node0 leader) node1 follower
    network := updateQueue initial.network node0 [response0, response1]
    submittedTxIds := Finset.empty
    hasJoined := INITIAL_CONFIGURATION
  }

def parseActions (content : String) : Except String (List SimAction) := do
  let mut actions := []
  for line in content.splitOn "\n" do
    if !line.trimAscii.isEmpty then
      match parseAction line with
      | some action => actions := actions ++ [action]
      | none => throw s!"invalid semantic action: {line}"
  pure actions

def parseOptionalNat (raw : String) : Except String (Option Nat) :=
  if raw == "-" then
    pure none
  else
    match raw.toNat? with
    | some value => pure (some value)
    | none => throw s!"observation value is not a natural number: {raw}"

def parseRole : String -> Except String Role
  | "Leader" => pure .leader
  | "Follower" => pure .follower
  | "Candidate" => pure .candidate
  | "None" => pure .none
  | raw => throw s!"unsupported observation role: {raw}"

def parseObservation (line : String) : Except String Observation := do
  match line.splitOn "," with
  | [event, step, node, role, term, last, commit, sent, matched] =>
      let some event := event.toNat?
        | throw s!"invalid observation event: {event}"
      let some step := step.toNat?
        | throw s!"invalid observation step: {step}"
      let some nodeValue := node.toNat?
        | throw s!"invalid observation node: {node}"
      if inRange : nodeValue < NODE_COUNT then
        pure {
          event
          step
          node := Fin.mk nodeValue inRange
          role := <- parseRole role
          term := <- parseOptionalNat term
          last := <- parseOptionalNat last
          commit := <- parseOptionalNat commit
          sent := <- parseOptionalNat sent
          matched := <- parseOptionalNat matched
        }
      else
        throw s!"observation node {nodeValue} exceeds model world"
  | _ => throw s!"invalid observation line: {line}"

def parseObservations (content : String) : Except String (List Observation) := do
  let mut observations := []
  for line in content.splitOn "\n" do
    if !line.trimAscii.isEmpty then
      observations := observations ++ [<- parseObservation line]
  pure observations

def checkOptional
    (event : Nat)
    (label : String)
    (observed : Option Nat)
    (actual : Nat) :
    Except String Unit :=
  match observed with
  | none => pure ()
  | some expected =>
      if expected != actual then
        throw s!"event {event}: {label} is {actual}, observed {expected}"
      else
        pure ()

def checkObservation
    (state : SimState)
    (observation : Observation) :
    Except String Unit := do
  let nodeState := state.nodes observation.node
  if nodeState.role != observation.role then
    throw s!"event {observation.event}: canonical role differs from observation"
  checkOptional observation.event "term" observation.term nodeState.currentTerm
  checkOptional observation.event "last index" observation.last nodeState.log.length
  checkOptional observation.event "commit index" observation.commit
    nodeState.commitIndex
  if observation.node = node0 then
    checkOptional observation.event "sent index" observation.sent
      (nodeState.sentIndex node1)
    checkOptional observation.event "match index" observation.matched
      (nodeState.matchIndex node1)

def checkObservationsAt
    (state : SimState)
    (observations : List Observation)
    (step : Nat) :
    Except String Nat := do
  let selected := observations.filter fun observation => observation.step = step
  for observation in selected do
    checkObservation state observation
  pure selected.length

def clientTxId (actions : List SimAction) : Except String TxId :=
  match actions.filterMap fun action =>
      match action with
      | .clientRequest node txId => if node = node0 then some txId else none
      | _ => none
  with
  | [txId] => pure txId
  | transactions =>
      throw s!"expected one node 0 client action, found {transactions.length}"

def replay
    (state : SimState)
    (actions : List SimAction)
    (observations : List Observation)
    (step : Nat := 0)
    (checked : Nat := 0) :
    Except String (Prod SimState Nat) := do
  let checked := checked + (<- checkObservationsAt state observations step)
  match actions with
  | [] => pure (state, checked)
  | action :: remaining => do
      let some rawNext :=
        (system (TxId := TxId)).applyAction state action
        | throw s!"step {step + 1}: disabled canonical action {
            renderAction action}"
      let next := compactState rawNext
      if !stateChecks next then
        throw s!"step {step + 1}: stateChecks failed after {
          renderAction action}"
      if !edgeChecks state next then
        throw s!"step {step + 1}: edgeChecks failed after {
          renderAction action}"
      replay next remaining observations (step + 1) checked

def checkFinal
    (state : SimState)
    (txId : TxId) :
    Except String Unit := do
  let leader := state.nodes node0
  let follower := state.nodes node1
  if leader.currentTerm != 2 || follower.currentTerm != 2 then
    throw "final node terms are not both 2"
  if leader.log.length != 7 || leader.commitIndex != 7 then
    throw s!"final node 0 last/commit is {leader.log.length}/{leader.commitIndex}"
  if follower.log.length != 7 || follower.commitIndex != 7 then
    throw s!"final node 1 last/commit is {
      follower.log.length}/{follower.commitIndex}"
  if leader.sentIndex node1 != 7 || leader.matchIndex node1 != 7 then
    throw s!"final sent01/match01 is {
      leader.sentIndex node1}/{leader.matchIndex node1}"
  if !(state.network node0).isEmpty || !(state.network node1).isEmpty then
    throw s!"final relevant queue lengths are {
      (state.network node1).length}/{(state.network node0).length}"
  if !decide (Membership.mem state.submittedTxIds txId) ||
      state.submittedTxIds.card != 1 then
    throw "final submitted transaction set does not contain exactly the solver ID"

def main (args : List String) : IO UInt32 := do
  match args with
  | [tracePath, modelPath, observationsPath] =>
      let traceContent <- IO.FS.readFile tracePath
      let modelContent <- IO.FS.readFile modelPath
      let observationsContent <- IO.FS.readFile observationsPath
      match parseModelValues modelContent with
      | .error message =>
          IO.eprintln message
          return 1
      | .ok values =>
          match buildCheckpoint values with
          | .error message =>
              IO.eprintln message
              return 1
          | .ok checkpoint =>
              if !stateChecks checkpoint then
                IO.eprintln "stateChecks rejected the concrete segment checkpoint"
                return 1
              match parseActions traceContent with
              | .error message =>
                  IO.eprintln message
                  return 1
              | .ok actions =>
                  match parseObservations observationsContent with
                  | .error message =>
                    IO.eprintln message
                    return 1
                  | .ok observations =>
                    if actions.length != 26 then
                      IO.eprintln s!"semantic trace has {actions.length} actions, expected 26"
                      return 1
                    match clientTxId actions with
                    | .error message =>
                        IO.eprintln message
                        return 1
                    | .ok txId =>
                      if txId.val != values.txId then
                        IO.eprintln s!"trace transaction ID {txId.val} differs from model {
                          values.txId}"
                        return 1
                      match replay checkpoint actions observations with
                      | .error message =>
                        IO.eprintln message
                        return 1
                      | .ok (finalState, observationChecks) =>
                        match checkFinal finalState txId with
                        | .error message =>
                          IO.eprintln message
                          return 1
                        | .ok () =>
                          let summary :=
                            s!"canonical_replay=passed actions={actions.length} " ++
                              s!"state_checks={actions.length + 1} " ++
                              s!"edge_checks={actions.length} " ++
                              s!"observation_checks={observationChecks} " ++
                              s!"node0_last={
                                (finalState.nodes node0).log.length} " ++
                              s!"node0_commit={
                                (finalState.nodes node0).commitIndex} " ++
                              s!"node1_last={
                                (finalState.nodes node1).log.length} " ++
                              s!"node1_commit={
                                (finalState.nodes node1).commitIndex} " ++
                              s!"request_queue={
                                (finalState.network node1).length} " ++
                              s!"response_queue={
                                (finalState.network node0).length}"
                          IO.println summary
                          return 0
  | _ =>
      IO.eprintln
        "usage: lean --run CCFRaft/LongTraceSmtProbe.lean <trace> <model-values> <observations>"
      return 2

end CCFRaft.LongTraceSmtProbe

def main := CCFRaft.LongTraceSmtProbe.main
