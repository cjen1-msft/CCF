-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import BoundedTrace
import LegacyClientRequestCertificate
import TraceStateJson

set_option autoImplicit false

namespace CCFRaft.TraceCertificate

open Lean TraceJson

structure Input where
  schemaVersion : String
  acceptedActions : List String
  unknowns : Array String
  bounds : BoundedState.Bounds
  entry : BoundedTrace.Template unknowns.size
  entryProfile : String
  trace : List (TraceInstructions.Instruction unknowns.size)
  rawSteps : Array Json

def instruction (unknowns : Array String) (json : Json) :
    Except String (TraceInstructions.Instruction unknowns.size) := do
  if (← field json "kind" >>= Json.getStr?) != "action" then
    LegacyClientRequestCertificate.instruction unknowns json
  else
    let action <- field json "action" >>= Json.getStr?
    match action with
    | "clientRequest" => LegacyClientRequestCertificate.instruction unknowns json
    | "changeConfiguration" =>
        checkKeys json ["kind", "action", "node", "configuration", "provenance", "rule"]
        pure (.changeConfiguration
          (← field json "node" >>= nodeValue)
          (← field json "configuration" >>= nodeSet))
    | "signCommittableMessages" =>
        checkKeys json ["kind", "action", "node", "provenance", "rule"]
        pure (.signCommittableMessages (← field json "node" >>= nodeValue))
    | "appendRetiredCommitted" =>
        checkKeys json ["kind", "action", "node", "provenance", "rule"]
        pure (.appendRetiredCommitted (← field json "node" >>= nodeValue))
    | "appendEntries" =>
        checkKeys json ["kind", "action", "node", "destination", "batchEnd", "provenance", "rule"]
        pure (.appendEntries
          (← field json "node" >>= nodeValue)
          (← field json "destination" >>= nodeValue)
          (← field json "batchEnd" >>= Json.getNat?))
    | other => throw s!"unsupported action in checked trace: {other}"

def decode (json : Json) : Except String Input := do
  checkKeys json ["schema_version", "entry", "bounds", "unknowns", "steps"]
  let version <- field json "schema_version" >>= Json.getStr?
  if version == "ccfraft-client-request/v1" then
    let legacy <- LegacyClientRequestCertificate.decode json
    -- Bootstrap client requests preserve term one, zero peer/commit indices, and empty queues.
    pure
      { schemaVersion := version
        acceptedActions := ["clientRequest"]
        unknowns := legacy.unknowns
        bounds :=
          { transactionCount := legacy.bounds.transactionCount
            termCount := 2
            indexCount := 1
            logCapacity := legacy.bounds.logCapacity
            queueCapacity := 0 }
        entry := initialState
        entryProfile := "bootstrap"
        trace := legacy.trace
        rawSteps := legacy.rawSteps }
  else
    let general := version == "ccfraft-trace/v1"
    unless general || version == "ccfraft-client-request/v2" do
      throw "unsupported certificate schema_version"
    let boundsJson <- field json "bounds"
    checkKeys boundsJson
      ["transaction_count", "term_count", "index_count", "log_capacity", "queue_capacity"]
    let bounds : BoundedState.Bounds :=
      { transactionCount := ← field boundsJson "transaction_count" >>= Json.getNat?
        termCount := ← field boundsJson "term_count" >>= Json.getNat?
        indexCount := ← field boundsJson "index_count" >>= Json.getNat?
        logCapacity := ← field boundsJson "log_capacity" >>= Json.getNat?
        queueCapacity := ← field boundsJson "queue_capacity" >>= Json.getNat? }
    let unknowns <- field json "unknowns" >>= unknownNames
    let (entry, entryProfile) <- match ← field json "entry" with
      | .str "bootstrap" => pure (initialState, "bootstrap")
      | .obj fields =>
          pure (← TraceStateJson.decode unknowns (.obj fields), "template")
      | _ => throw "entry must be bootstrap or an explicit full-state template"
    let rawSteps <- field json "steps" >>= Json.getArr?
    let decodeInstruction := if general then instruction unknowns
      else LegacyClientRequestCertificate.instruction unknowns
    let trace <- rawSteps.toList.mapM decodeInstruction
    pure
      { schemaVersion := version
        acceptedActions := if general then TraceInstructions.supportedActions else ["clientRequest"]
        unknowns, bounds, entry, entryProfile, trace, rawSteps }

end CCFRaft.TraceCertificate
