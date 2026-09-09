-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import SymbolicTraceObservationJson
import BoundedSymbolicTrace

set_option autoImplicit false

/-!
Input contract for the not-yet-live `ccfraft-symbolic-trace/v1` schema.
Decoding is not validation or a solver verdict. Execution still requires proved
symbolic Model steps and explicit transaction-unknown domain constraints.
-/

namespace CCFRaft.SymbolicTraceCertificate

open Lean TraceJson Symbolic

abbrev Action := BoundedSymbolicTrace.SymbolicAction
abbrev Instruction := BoundedSymbolicTrace.Instruction

structure Input where
  bounds : BoundedState.Bounds
  unknowns : Array String
  entry : Expr (SymbolicModel.stateCodec bounds.transactionCount).ty
  trace : List Instruction
  rawSteps : Array Json

def decodeBounds (json : Json) : Except String BoundedState.Bounds := do
  checkKeys json ["transaction_count", "term_count", "index_count", "log_capacity", "queue_capacity"]
  pure
    { transactionCount := ← field json "transaction_count" >>= Json.getNat?
      termCount := ← field json "term_count" >>= Json.getNat?
      indexCount := ← field json "index_count" >>= Json.getNat?
      logCapacity := ← field json "log_capacity" >>= Json.getNat?
      queueCapacity := ← field json "queue_capacity" >>= Json.getNat? }

def action (unknownStart : Nat) (unknowns : Array String) (json : Json) :
    Except String Action := do
  let kind <- field json "kind" >>= Json.getStr?
  unless kind == "action" do
    throw s!"expected action kind, got: {kind}"
  let name <- field json "action" >>= Json.getStr?
  let extraKeys := match name with
    | "clientRequest" => ["transaction"]
    | "changeConfiguration" => ["configuration"]
    | "appendEntries" => ["destination", "batchEnd"]
    | "receive" | "requestVote" | "requestPreVote" | "updateTerm" |
        "proposeVote" | "advanceCommitIndexAndProposeVote" => ["destination"]
    | _ => []
  checkKeys json (["kind", "action", "node", "provenance", "rule"] ++ extraKeys)
  let node <- field json "node" >>= nodeValue
  match name with
  | "clientRequest" => pure (.clientRequest node
      (← field json "transaction" >>= SymbolicTraceObservation.transactionValue unknownStart unknowns))
  | "changeConfiguration" =>
      pure (.changeConfiguration node (← field json "configuration" >>= nodeSet))
  | "appendRetiredCommitted" => pure (.appendRetiredCommitted node)
  | "signCommittableMessages" => pure (.signCommittableMessages node)
  | "appendEntries" => pure (.appendEntries node
      (← field json "destination" >>= nodeValue) (← field json "batchEnd" >>= Json.getNat?))
  | "receive" => pure (.receive node (← field json "destination" >>= nodeValue))
  | "advanceCommitIndex" => pure (.advanceCommitIndex node)
  | "timeout" => pure (.timeout node)
  | "becomePreVoteCandidate" => pure (.becomePreVoteCandidate node)
  | "becomeCandidate" => pure (.becomeCandidate node)
  | "requestVote" => pure (.requestVote node (← field json "destination" >>= nodeValue))
  | "requestPreVote" => pure (.requestPreVote node (← field json "destination" >>= nodeValue))
  | "checkQuorum" => pure (.checkQuorum node)
  | "updateTerm" => pure (.updateTerm node (← field json "destination" >>= nodeValue))
  | "becomeLeader" => pure (.becomeLeader node)
  | "proposeVote" => pure (.proposeVote node (← field json "destination" >>= nodeValue))
  | "advanceCommitIndexAndProposeVote" =>
      pure (.advanceCommitIndexAndProposeVote node (← field json "destination" >>= nodeValue))
  | other => throw s!"unsupported symbolic action: {other}"

def instruction (unknownStart : Nat) (unknowns : Array String) (json : Json) :
    Except String Instruction := do
  match ← field json "kind" >>= Json.getStr? with
  | "action" => pure (.action (← action unknownStart unknowns json))
  | "observation" => pure (.observation (← SymbolicTraceObservation.decode unknownStart unknowns json))
  | other => throw s!"unsupported symbolic instruction kind: {other}"

def decode (json : Json) : Except String Input := do
  checkKeys json ["schema_version", "bounds", "unknowns", "entry", "steps"]
  unless (← field json "schema_version" >>= Json.getStr?) == "ccfraft-symbolic-trace/v1" do
    throw "unsupported symbolic certificate schema_version"
  unless (← field json "entry" >>= Json.getStr?) == "symbolic" do
    throw "symbolic certificate requires entry: symbolic; supply entry facts as initial observations"
  let bounds <- field json "bounds" >>= decodeBounds
  let unknowns <- field json "unknowns" >>= unknownNames
  let rawSteps <- field json "steps" >>= Json.getArr?
  let trace <- rawSteps.toList.mapM (instruction (SymbolicModel.entryWidth bounds) unknowns)
  pure { bounds, unknowns, entry := SymbolicModel.freshEntry bounds, trace, rawSteps }

end CCFRaft.SymbolicTraceCertificate
