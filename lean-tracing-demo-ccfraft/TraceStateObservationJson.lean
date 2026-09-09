-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import TraceStateObservation
import TraceStateJson

set_option autoImplicit false

namespace CCFRaft.TraceStateObservation

open Lean TraceJson

def decode (json : Json) : Except String (Observation Node) := do
  let kind <- field json "kind" >>= Json.getStr?
  unless kind == "observation" do
    throw s!"expected observation kind, got: {kind}"
  let variableName <- field json "variable" >>= Json.getStr?
  let value <- field json "value"
  if variableName == "retirementCompleted" then
    checkKeys json ["kind", "variable", "observer", "retired", "value", "provenance", "rule"]
    pure (.retirementCompleted
      (← field json "observer" >>= nodeValue)
      (← field json "retired" >>= nodeValue)
      (← value.getBool?))
  else
    checkKeys json ["kind", "variable", "node", "value", "provenance", "rule"]
    let node <- field json "node" >>= nodeValue
    match variableName with
    | "preVoteStatus" => pure (.preVoteStatus node (← TraceStateJson.preVoteValue value))
    | "membershipState" =>
        pure (.membershipState node (← TraceStateJson.membershipValue value))
    | "retirementIndex" =>
        pure (.retirementIndex node (← TraceStateJson.optional Json.getNat? value))
    | "retirementCommittableIndex" =>
        pure (.retirementCommittableIndex node (← TraceStateJson.optional Json.getNat? value))
    | "retiredCommittedIndex" =>
        pure (.retiredCommittedIndex node (← TraceStateJson.optional Json.getNat? value))
    | other => throw s!"unsupported state observation: {other}"

end CCFRaft.TraceStateObservation
