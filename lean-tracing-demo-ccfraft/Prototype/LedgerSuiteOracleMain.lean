-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeParameterizedFrame
import Sparse.NativeArrayLogWrite

set_option autoImplicit false

namespace CCFRaft.LedgerSuiteOracle

open Lean NativeEncode NativeArrayCheckQuorum

abbrev Value := Entry (Fin 2) Nat

def get {α : Type} (values : Std.HashMap String α) (name : String) : Except String α :=
  match values[name]? with
  | some value => pure value
  | none => throw s!"unknown reference {name}"

def text (value : Json) (key : String) : Except String String := do
  (← field value key).getStr?

def decodeEntry (value : Json) : Except String Value := do
  let term <- natural (← field value "term")
  let kind <- text value "kind"
  let data <- natural (← field value "value")
  let content <- match kind with
    | "transaction" => pure (EntryContent.transaction data)
    | "signature" =>
      if data == 0 then pure .signature else throw "signature value must be zero"
    | "configuration" | "retirement" =>
      if data < 4 then
        let members := Finset.univ.filter fun node : Fin 2 => data.testBit node.val
        pure (if kind == "configuration" then .reconfiguration members else .retiredCommitted members)
      else throw "member bitmask outside two-node domain"
    | _ => throw "unknown entry constructor"
  return { term, content }

def encodeEntry (entry : Value) : Json :=
  let mask := fun members : Finset (Fin 2) => members.sum fun node => 2 ^ node.val
  let (kind, value) := match entry.content with
    | .transaction value => ("transaction", value)
    | .signature => ("signature", 0)
    | .reconfiguration members => ("configuration", mask members)
    | .retiredCommitted members => ("retirement", mask members)
  Json.mkObj [("term", toJson entry.term), ("kind", toJson kind), ("value", toJson value)]

def run (stream : Json) : Except String Json := do
  let mut entries : Std.HashMap String Value := {}
  for (name, value) in (← (← field stream "entries").getObj?).toList do
    entries := entries.insert name (← decodeEntry value)
  let mut states : Std.HashMap String (Log (Fin 2) Nat) := {}
  for (name, refs) in (← (← field stream "initial_states").getObj?).toList do
    let values <- (← refs.getArr?).toList.mapM fun ref => do get entries (← ref.getStr?)
    states := states.insert name (Log.ofList values)
  let mut booleans : Std.HashMap String Bool := {}
  for event in ← (← field stream "events").getArr? do
    match ← text event "kind" with
    | "append" =>
      let before <- get states (← text event "before")
      let values <- match event.getObjVal? "entries" with
        | .ok refs => (← refs.getArr?).toList.mapM fun ref => do get entries (← ref.getStr?)
        | .error _ => pure [← get entries (← text event "entry")]
      states := states.insert (← text event "after") (NativeArrayLogWrite.append before (Log.ofList values))
    | "rollback" =>
      let before <- get states (← text event "before")
      states := states.insert (← text event "after")
        (NativeArrayLogWrite.take before (← natural (← field event "target")))
    | "equality" =>
      let left <- get states (← text event "left")
      let right <- get states (← text event "right")
      booleans := booleans.insert (← text event "result") (left.decode == right.decode)
    | _ => throw "unknown ledger operation"
  return Json.mkObj [
    ("states", Json.mkObj (states.toList.map fun (name, log) => (name, toJson (log.decode.map encodeEntry)))),
    ("booleans", Json.mkObj (booleans.toList.map fun (name, value) => (name, toJson value)))]

end CCFRaft.LedgerSuiteOracle

def main : IO UInt32 := do
  let input <- (← IO.getStdin).readToEnd
  let result := do
    let values <- (← Lean.Json.parse input).getArr?
    return Lean.toJson (← values.mapM CCFRaft.LedgerSuiteOracle.run)
  match result with
  | .ok output => IO.println output.compress; return 0
  | .error error => (← IO.getStderr).putStrLn error; return 2
