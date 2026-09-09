-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model
import Shared.Smt
import Lean

set_option autoImplicit false

namespace CCFRaft.TraceJson

open Lean

def checkKeys (json : Json) (allowed : List String) : Except String Unit := do
  let object <- json.getObj?
  for key in object.keys do
    unless allowed.contains key do
      throw s!"unsupported field: {key}"

def field (json : Json) (name : String) : Except String Json :=
  json.getObjVal? name

def nodeValue (json : Json) : Except String Node := do
  let value <- match json with
    | .str text =>
        match text.toNat? with
        | some value => pure value
        | none => throw "node must be a natural number"
    | _ => json.getNat?
  if bounded : value < NODE_COUNT then
    pure ⟨value, bounded⟩
  else
    throw s!"node {value} is outside Fin {NODE_COUNT}"

def nodeSet (json : Json) : Except String (Finset Node) := do
  pure (← (← json.getArr?).toList.mapM nodeValue).toFinset

def transactionValue (unknowns : Array String) (json : Json) :
    Except String (TraceSmt.NatTerm unknowns.size) := do
  match json with
  | .num _ => pure (.literal (← json.getNat?))
  | .obj _ =>
      checkKeys json ["unknown"]
      let name <- field json "unknown" >>= Json.getStr?
      match (List.finRange unknowns.size).find? (fun index => unknowns[index] == name) with
      | some index => pure (.unknown index)
      | none => throw s!"undeclared transaction unknown: {name}"
  | _ => throw "transaction must be a natural number or an unknown reference"

def unknownNames (json : Json) : Except String (Array String) := do
  let unknowns <- (← json.getArr?).mapM Json.getStr?
  unless unknowns.all (fun name => !name.isEmpty) do
    throw "unknown names must be nonempty"
  unless unknowns.toList.Nodup do
    throw "unknown names must be unique"
  pure unknowns

def roleValue (json : Json) : Except String Role := do
  match ← json.getStr? with
  | "none" => pure .none
  | "follower" => pure .follower
  | "preVoteCandidate" => pure .preVoteCandidate
  | "candidate" => pure .candidate
  | "leader" => pure .leader
  | other => throw s!"unsupported role: {other}"

end CCFRaft.TraceJson
