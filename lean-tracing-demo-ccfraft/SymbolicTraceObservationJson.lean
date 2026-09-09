-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import SymbolicTraceObservation
import TraceStateObservationJson
import TraceMessageSummaryJson

set_option autoImplicit false

namespace CCFRaft.SymbolicTraceObservation

open Lean TraceJson Symbolic

/-- `unknownStart` follows the structural entry inputs; names may alias in value. -/
def transactionValue (unknownStart : Nat) (unknowns : Array String) (json : Json) :
    Except String (Expr .nat) := do
  match json with
  | .num _ => pure (.nat (← json.getNat?))
  | .obj _ =>
      checkKeys json ["unknown"]
      let name <- field json "unknown" >>= Json.getStr?
      match (List.finRange unknowns.size).find? (fun index => unknowns[index] == name) with
      | some index => pure (.unknown (unknownStart + index.val))
      | none => throw s!"undeclared transaction unknown: {name}"
  | _ => throw "transaction must be a natural number or an unknown reference"

def decode (unknownStart : Nat) (unknowns : Array String) (json : Json) :
    Except String Observation := do
  let kind <- field json "kind" >>= Json.getStr?
  unless kind == "observation" do
    throw s!"expected observation kind, got: {kind}"
  let variableName <- field json "variable" >>= Json.getStr?
  match variableName with
  | "preVoteStatus" | "membershipState" | "retirementIndex" |
      "retirementCommittableIndex" | "retiredCommittedIndex" | "retirementCompleted" =>
      pure (.state (← TraceStateObservation.decode json))
  | "submitted" =>
      checkKeys json ["kind", "variable", "transaction", "value", "provenance", "rule"]
      pure (.submitted
        (← field json "transaction" >>= transactionValue unknownStart unknowns)
        (← field json "value" >>= Json.getBool?))
  | "firstMessageFrom" =>
      checkKeys json ["kind", "variable", "node", "value", "provenance", "rule"]
      let node <- field json "node" >>= nodeValue
      let summary <- field json "value" >>= TraceMessageSummary.decode
      unless node == summary.destination do
        throw "firstMessageFrom node must equal the summary destination"
      pure (.message summary)
  | _ =>
      checkKeys json ["kind", "variable", "node", "value", "provenance", "rule"]
      let node <- field json "node" >>= nodeValue
      let value <- field json "value"
      match variableName with
      | "role" => pure (.role node (← roleValue value))
      | "currentTerm" => pure (.currentTerm node (← value.getNat?))
      | "logLength" => pure (.logLength node (← value.getNat?))
      | "queueLength" => pure (.queueLength node (← value.getNat?))
      | "commitIndex" => pure (.commitIndex node (← value.getNat?))
      | "allocated" => pure (.allocated node (← value.getBool?))
      | "joined" => pure (.joined node (← value.getBool?))
      | other => throw s!"unsupported symbolic observation: {other}"

end CCFRaft.SymbolicTraceObservation
