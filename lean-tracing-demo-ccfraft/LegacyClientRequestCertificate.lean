-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import TraceInstructions
import TraceJson

set_option autoImplicit false

namespace CCFRaft.LegacyClientRequestCertificate

open Lean TraceInstructions TraceJson

def instruction (unknowns : Array String) (json : Json) :
    Except String (Instruction unknowns.size) := do
  match ← field json "kind" >>= Json.getStr? with
  | "action" =>
      checkKeys json ["kind", "action", "node", "transaction", "provenance", "rule"]
      let action <- field json "action" >>= Json.getStr?
      unless action == "clientRequest" do
        throw s!"unsupported action in checked client-request slice: {action}"
      pure (.clientRequest
        (← field json "node" >>= nodeValue)
        (← field json "transaction" >>= transactionValue unknowns))
  | "observation" =>
      let variableName <- field json "variable" >>= Json.getStr?
      let value <- field json "value"
      if variableName == "submitted" then
        checkKeys json ["kind", "variable", "transaction", "value", "provenance", "rule"]
        pure (.observation (.submitted
          (← field json "transaction" >>= transactionValue unknowns)
          (← value.getBool?)))
      else
        checkKeys json ["kind", "variable", "node", "value", "provenance", "rule"]
        let node <- field json "node" >>= nodeValue
        let observation <- match variableName with
          | "role" => pure (.role node (← roleValue value))
          | "currentTerm" => pure (.currentTerm node (← value.getNat?))
          | "logLength" => pure (.logLength node (← value.getNat?))
          | "queueLength" => pure (.queueLength node (← value.getNat?))
          | "commitIndex" => pure (.commitIndex node (← value.getNat?))
          | "allocated" => pure (.allocated node (← value.getBool?))
          | "joined" => pure (.joined node (← value.getBool?))
          | _ => throw s!"unsupported observation in checked client-request slice: {variableName}"
        pure (.observation observation)
  | other => throw s!"unsupported instruction kind: {other}"

structure Input where
  unknowns : Array String
  bounds : Bounds
  trace : List (Instruction unknowns.size)
  rawSteps : Array Json

def decode (json : Json) : Except String Input := do
  checkKeys json ["schema_version", "entry", "bounds", "unknowns", "steps"]
  unless (← field json "schema_version" >>= Json.getStr?) == "ccfraft-client-request/v1" do
    throw "unsupported certificate schema_version"
  unless (← field json "entry" >>= Json.getStr?) == "bootstrap" do
    throw "checked client-request slice requires entry: bootstrap; mid-trace entry is unsupported"
  let boundsJson <- field json "bounds"
  checkKeys boundsJson ["transaction_count", "log_capacity"]
  let bounds : Bounds :=
    { transactionCount := ← field boundsJson "transaction_count" >>= Json.getNat?
      logCapacity := ← field boundsJson "log_capacity" >>= Json.getNat? }
  let unknowns <- field json "unknowns" >>= unknownNames
  let rawSteps <- field json "steps" >>= Json.getArr?
  let trace <- rawSteps.toList.mapM (instruction unknowns)
  pure { unknowns, bounds, trace, rawSteps }

end CCFRaft.LegacyClientRequestCertificate
