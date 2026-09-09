-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import TraceMessageSummaryJson
import MachineGenerated.TraceMessageSummaryProofs

set_option autoImplicit false

namespace CCFRaft.TraceMessageSummary.Tests

open Lean

private def sender : Node := ⟨0, by decide⟩
private def receiver : Node := ⟨1, by decide⟩
private def unrelated : Node := ⟨2, by decide⟩

private def request (previousTerm transaction : Nat) : Message Node Nat :=
  .appendEntriesRequest
    { term := 2
      prevLogIndex := 0
      prevLogTerm := previousTerm
      entries := [{ term := 2, content := .transaction transaction }]
      leaderCommit := 0
      source := sender
      destination := receiver }

private def summary : Summary Node := ofMessage (request 0 4)

#guard ofMessage (request 9 8) = summary
#guard ofMessage (request 0 4) = ofMessage (request 0 8)

private def stateWith (messages : List (Message Node Nat)) : State Node Nat :=
  { initialState with network := fun node => if node = receiver then messages else [] }

private def otherSource : Message Node Nat :=
  .proposeVoteRequest { term := 2, source := unrelated, destination := receiver }

private def wrongFirst : Message Node Nat :=
  .proposeVoteRequest { term := 2, source := sender, destination := receiver }

#guard summary.matchesFirst (stateWith [otherSource, request 9 8])
#guard !(summary.matchesFirst (stateWith [wrongFirst, request 0 4]))
#guard !(summary.matchesFirst (stateWith []))
#guard !(summary.matchesFirst (initialState : State Node Nat))

private def wrongDestination : Message Node Nat :=
  .appendEntriesRequest
    { term := 2, prevLogIndex := 0, prevLogTerm := 0
      entries := [{ term := 2, content := .transaction 4 }]
      leaderCommit := 0, source := sender, destination := unrelated }

#guard !(summary.matchesFirst (stateWith [wrongDestination, request 0 4]))

private def summaryJson : Lean.Json :=
  Lean.Json.mkObj
    [("kind", .str "appendEntriesRequest"),
     ("source", toJson (0 : Nat)), ("destination", toJson (1 : Nat)),
     ("term", toJson (2 : Nat)), ("prevLogIndex", toJson (0 : Nat)),
     ("entriesLength", toJson (1 : Nat)), ("leaderCommit", toJson (0 : Nat))]

#guard (decode summaryJson).toOption = some summary
#guard (decode (Lean.Json.mkObj
  [("kind", .str "appendEntriesRequest"), ("source", toJson (0 : Nat))])).toOption.isNone
#guard (decode (Lean.Json.mkObj
  [("kind", .str "futureMessage"), ("source", toJson (0 : Nat))])).toOption.isNone

end CCFRaft.TraceMessageSummary.Tests

run_cmd do
  for theoremName in [
      ``CCFRaft.TraceMessageSummary.ofMessage_map,
      ``CCFRaft.TraceMessageSummary.matchesFirst_map] do
    for axiomName in ← Lean.collectAxioms theoremName do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{theoremName} depends on unapproved axiom {axiomName}"
