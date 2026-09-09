-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicMessageSummary

set_option autoImplicit false

namespace CCFRaft.SymbolicModel.MessageSummaryTests

open Symbolic TraceMessageSummary

private def source : Node := ⟨0, by decide⟩
private def destination : Node := ⟨1, by decide⟩
private def other : Node := ⟨2, by decide⟩
private def ρ : Assignment := fun _ => 0

private def request (previousTerm tx : Nat) : Message Node Nat :=
  .appendEntriesRequest
    { term := 2, prevLogIndex := 3, prevLogTerm := previousTerm
      entries := [{ term := 2, content := .transaction tx }]
      leaderCommit := 1, source, destination }

private def packets : List (Message Node Nat) :=
  [request 0 0,
   .appendEntriesResponse ⟨2, false, 3, source, destination⟩,
   .requestVoteRequest ⟨2, 1, 3, source, destination⟩,
   .requestVoteResponse ⟨2, true, source, destination⟩,
   .requestPreVote ⟨2, 1, 3, source, destination⟩,
   .requestPreVoteResponse ⟨2, false, source, destination⟩,
   .proposeVoteRequest ⟨2, source, destination⟩]

#guard packets.all fun message =>
  (messageMatchesSummary (messageCodec.literal message) (ofMessage message)).eval ρ

#guard packets.all fun message => packets.all fun expected =>
  (messageMatchesSummary (messageCodec.literal message) (ofMessage expected)).eval ρ ==
    decide (ofMessage message = ofMessage expected)

#guard (messageMatchesSummary
  (messageCodec.literal (request 9 8)) (ofMessage (request 0 0))).eval ρ

private def wrongFirst : Message Node Nat := .proposeVoteRequest ⟨2, source, destination⟩
private def unrelated : Message Node Nat := .proposeVoteRequest ⟨2, other, destination⟩
private def summary : Summary Node := ofMessage (request 0 0)

private def wrongRequests : List (Message Node Nat) :=
  let base : AppendEntriesRequest Node Nat :=
    { term := 2, prevLogIndex := 3, prevLogTerm := 0
      entries := [{ term := 2, content := .transaction 0 }]
      leaderCommit := 1, source, destination }
  [ .appendEntriesRequest { base with term := 3 },
    .appendEntriesRequest { base with prevLogIndex := 2 },
    .appendEntriesRequest { base with entries := [] },
    .appendEntriesRequest { base with leaderCommit := 0 },
    .appendEntriesRequest { base with source := other },
    .appendEntriesRequest { base with destination := other } ]

#guard wrongRequests.all fun message =>
  !((messageMatchesSummary (messageCodec.literal message) summary).eval ρ)

#guard (queueMatchesSummary 2 (queueCodec.literal [unrelated, request 9 8]) summary).eval ρ
#guard !(queueMatchesSummary 2 (queueCodec.literal [wrongFirst, request 0 0]) summary).eval ρ
#guard !(queueMatchesSummary 0 (queueCodec.literal []) summary).eval ρ

private def symbolicMessage : Expr messageCodec.ty :=
  let base := (messageCodec.literal (request 0 0)).leftD (defaultExpr appendRequestCodec.ty)
  .inl (.pair (.unknown 0) base.snd)

#guard (messageMatchesSummary symbolicMessage summary).eval (fun _ => 2)
#guard !((messageMatchesSummary symbolicMessage summary).eval (fun _ => 3))

private def entryBounds : BoundedState.Bounds := ⟨2, 3, 3, 1, 1⟩
private def lastNode : Node := ⟨14, by decide⟩
private def entrySummary : Summary Node :=
  .proposeVoteRequest ⟨1, lastNode, lastNode⟩

#guard (entryMatchesSummary entryBounds (freshEntry entryBounds) entrySummary).eval (fun _ => 1)
#guard !((entryMatchesSummary entryBounds (freshEntry entryBounds) entrySummary).eval (fun _ => 0))

end CCFRaft.SymbolicModel.MessageSummaryTests

run_cmd do
  for theoremName in [
      ``CCFRaft.SymbolicModel.messageMatchesSummary_correct,
      ``CCFRaft.SymbolicModel.queueMatchesSummary_correct,
      ``CCFRaft.SymbolicModel.entryMatchesSummary_correct] do
    for axiomName in ← Lean.collectAxioms theoremName do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{theoremName} depends on unapproved axiom {axiomName}"
