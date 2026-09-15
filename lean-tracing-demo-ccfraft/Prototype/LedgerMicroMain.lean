-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeParameterizedFrame

set_option autoImplicit false

namespace CCFRaft.LedgerMicro

open Lean NativeEncode NativeSmt

abbrev Width : PNat := ⟨2, by decide⟩
abbrev Ledger := Expr (.array .int (entryTy Width))

def entry (index : Nat) : Expr (entryTy Width) :=
  entryTerm ({ term := index + 1, content := .transaction (index + 11) } : Entry (Fin Width) Nat)

def appendCase (count initialLength : Nat) (variant observation : String) (negative : Bool) :
    EncodeM Width (Array Group × Json) := do
  let baseId <- fresh
  let mut ledger : Ledger := .free _ baseId
  let mut cells : Array (Expr (entryTy Width)) := #[]
  let mut groups : Array Group := #[]
  let mut transitions := 0
  for index in List.range initialLength do
    if variant == "cells" || variant == "ssa" then
      let id <- define (entry index)
      cells := cells.push (.free _ id)
    else
      assertion (.equal (.select ledger (.integer index)) (entry index))
  let start <- get
  groups := groups.push { instruction := none, start := 0, stop := start.assertions.size }
  for step in List.range count do
    let before <- get
    let oldLength := initialLength + step
    let value := entry oldLength
    if variant == "native" then
      let payloadId <- fresh
      let payload : Ledger := .free _ payloadId
      assertion (.equal (.select payload (.integer 0)) value)
      let outputId <- fresh
      let output : Ledger := .free _ outputId
      assertion (logSpliceTerm Width (.integer oldLength) ledger (.integer 1) payload
        (.integer oldLength) output)
      ledger := output
      transitions := transitions + 2
    else if variant == "store" then
      let outputId <- define (.store ledger (.integer oldLength) value)
      ledger := .free _ outputId
      transitions := transitions + 1
    else if variant == "cells" then
      let mut output := #[]
      for cell in cells do
        let id <- define cell
        output := output.push (.free _ id)
        transitions := transitions + 1
      let id <- define value
      cells := output.push (.free _ id)
      transitions := transitions + 1
    else if variant == "ssa" then
      let id <- define value
      cells := cells.push (.free _ id)
      transitions := transitions + 1
    else throw "unknown append representation"
    if observation == "each" then
      let actual <- if variant == "cells" || variant == "ssa" then
        match cells[oldLength]? with
        | some cell => pure cell
        | none => throw "missing append cell"
        else pure (.select ledger (.integer oldLength))
      assertion (.equal actual value)
    let after <- get
    groups := groups.push { instruction := some step, start := before.assertions.size, stop := after.assertions.size }
  let before <- get
  let finalLength := initialLength + count
  let positions := if observation == "last" then [finalLength - 1] else List.range finalLength
  for index in positions do
    let actual <- if variant == "cells" || variant == "ssa" then
      match cells[index]? with
      | some cell => pure cell
      | none => throw "missing observed cell"
      else pure (.select ledger (.integer index))
    let expected := if negative && index == positions.head! then entry (index + finalLength + 1) else entry index
    assertion (.equal actual expected)
  let after <- get
  groups := groups.push { instruction := some count, start := before.assertions.size, stop := after.assertions.size }
  return (groups, Json.mkObj [
    ("operation", toJson "append"), ("variant", toJson variant), ("count", toJson count),
    ("initial_length", toJson initialLength), ("final_length", toJson finalLength),
    ("observation", toJson observation), ("expected", toJson (if negative then "unsat" else "sat")),
    ("transition_constraints", toJson transitions)])

def rollbackCase (count requestedLength : Nat) (variant observation : String) (negative : Bool) :
    EncodeM Width (Array Group × Json) := do
  let initialLength := if requestedLength == 0 then count + 1 else requestedLength
  unless count < initialLength do throw "rollback series must retain a nonempty prefix"
  unless variant == "native" || variant == "relation" do throw "unknown rollback representation"
  let baseId <- fresh
  let mut ledger : Ledger := .free _ baseId
  let lengthId <- define (.integer initialLength)
  let mut length : Expr .int := .free _ lengthId
  for index in List.range initialLength do
    assertion (.equal (.select ledger (.integer index)) (entry index))
  let state <- get
  let mut groups := #[{ instruction := none, start := 0, stop := state.assertions.size : Group }]
  for step in List.range count do
    let before <- get
    let target := initialLength - step - 1
    let old := { nodeRowSnapshot (width := Width) before.toColumns (0 : Fin Width) with
      logLength := length, logEntries := ledger }
    -- This is the ledger projection of the existing leader rollback helper.
    let next := becomeLeaderRowTerms old (.integer target)
    let newLengthId <- define next.logLength
    if variant == "relation" then
      let payloadId <- fresh
      let outputId <- fresh
      let output : Ledger := .free _ outputId
      assertion (logSpliceTerm Width length ledger (.integer 0) (.free _ payloadId)
        (.integer target) output)
      ledger := output
    else
      ledger := next.logEntries
    length := .free _ newLengthId
    if observation == "each" then assertion (.equal length (.integer target))
    let after <- get
    groups := groups.push { instruction := some step, start := before.assertions.size, stop := after.assertions.size }
  let before <- get
  let finalLength := initialLength - count
  assertion (.equal length (.integer (if negative then finalLength + 1 else finalLength)))
  let positions := if observation == "last" then [finalLength - 1] else List.range finalLength
  for index in positions do
    assertion (.equal (.select ledger (.integer index)) (entry index))
  let after <- get
  groups := groups.push { instruction := some count, start := before.assertions.size, stop := after.assertions.size }
  return (groups, Json.mkObj [
    ("operation", toJson "rollback"), ("variant", toJson variant), ("count", toJson count),
    ("initial_length", toJson initialLength), ("final_length", toJson finalLength),
    ("observation", toJson observation), ("expected", toJson (if negative then "unsat" else "sat")),
    ("transition_constraints", toJson (count * if variant == "relation" then 2 else 1))])

def equalityCase (count requestedLength : Nat) (variant observation : String) (negative : Bool) :
    EncodeM Width (Array Group × Json) := do
  let size := if requestedLength == 0 then count else requestedLength
  unless variant == "native" || variant == "ground" || variant == "cells" ||
      variant == "canonical" || variant == "ssa" ||
      variant == "typed-normalized" || variant == "typed-direct" do
    throw "unknown equality representation"
  let scalar := variant == "cells" || variant == "canonical" || variant == "ssa"
  let typed := variant == "typed-normalized" || variant == "typed-direct"
  let direct := variant == "typed-direct"
  let compare := fun (left right : Expr (entryTy Width)) =>
    if direct then .equal left right else logRangeEntryEqual false left right
  let valid := fun (entries : Ledger) =>
    boundedForall (.integer size)
      (entryDomain (.select (entries.weaken .int) (.bound .here)))
  let baseId <- fresh
  let mut ledger : Ledger := .free _ baseId
  let mut cells : Array (Expr (entryTy Width)) := #[]
  for index in List.range size do
    if scalar then
      let id <- define (entry index)
      cells := cells.push (.free _ id)
    else assertion (.equal (.select ledger (.integer index)) (entry index))
  if typed then assertion (valid ledger)
  let before <- get
  let mut groups := #[{ instruction := none, start := 0, stop := before.assertions.size : Group }]
  for step in List.range count do
    let start <- get
    if variant == "cells" then
      let mut next := #[]
      for old in cells do
        let id <- fresh
        let cell : Expr (entryTy Width) := .free _ id
        assertion (logRangeEntryEqual false old cell)
        next := next.push cell
      cells := next
    else if variant == "canonical" then
      let mut next := #[]
      for old in cells do
        let id <- define old
        next := next.push (.free _ id)
      cells := next
    else if variant == "ssa" then
      -- Equality allows reusing the same Model entry representatives.
      assertion (.boolean true)
    else
      let nextId <- fresh
      let next : Ledger := .free _ nextId
      if variant == "native" || variant == "typed-normalized" then
        assertion (logRangeEqualTerm Width false ledger next (.integer 0) (.integer 0) (.integer size))
      else if direct then
        assertion (boundedForall (.integer size)
          (.equal (.select (ledger.weaken .int) (.bound .here))
            (.select (next.weaken .int) (.bound .here))))
      else
        assertion (all ((List.range size).map fun index =>
          logRangeEntryEqual false (.select ledger (.integer index)) (.select next (.integer index))))
      ledger := next
      if typed then assertion (valid ledger)
    if observation == "each" then
      let actual <- if scalar then
        match cells[0]? with
        | some cell => pure cell
        | none => throw "empty equality ledger"
        else pure (.select ledger (.integer 0))
      assertion (compare actual (entry 0))
    let after <- get
    groups := groups.push { instruction := some step, start := start.assertions.size, stop := after.assertions.size }
  let start <- get
  let positions := if observation == "last" then [size - 1] else List.range size
  for index in positions do
    let actual <- if scalar then
      match cells[index]? with
      | some cell => pure cell
      | none => throw "missing equality cell"
      else pure (.select ledger (.integer index))
    let expected := if negative && index == positions.head! then entry (index + size + 1) else entry index
    assertion (compare actual expected)
  let after <- get
  groups := groups.push { instruction := some count, start := start.assertions.size, stop := after.assertions.size }
  return (groups, Json.mkObj [
    ("operation", toJson "equality"), ("variant", toJson variant), ("count", toJson count),
    ("initial_length", toJson size), ("final_length", toJson size),
    ("observation", toJson observation), ("expected", toJson (if negative then "unsat" else "sat")),
    ("semantic_cell_equalities", toJson (count * size)),
    ("emitted_scalar_cell_equalities", toJson (if variant == "cells" || variant == "canonical" then count * size else 0)),
    ("quantified_range_equalities", toJson (if variant == "native" || typed then count else 0)),
    ("live_entry_type_predicates", toJson (if typed then count + 1 else 0)),
    ("state_links", toJson count)])

def generate (request : Json) : Except String Json := do
  fields request ["operation", "variant", "count", "initialLength", "observation", "negative"]
  let operation <- (← field request "operation").getStr?
  let variant <- (← field request "variant").getStr?
  let count <- natural (← field request "count")
  let initialLength <- natural (← field request "initialLength")
  let observation <- (← field request "observation").getStr?
  let negative <- (← field request "negative").getBool?
  unless count > 0 && count <= 4096 && initialLength <= 4096 do throw "microbenchmark size outside limits"
  unless observation == "final" || observation == "each" || observation == "last" do throw "unknown observation mode"
  let initial := initialEncoding Width {(0 : Fin Width)}
  let action <- match operation with
    | "append" => pure (appendCase count initialLength variant observation negative)
    | "rollback" => pure (rollbackCase count initialLength variant observation negative)
    | "equality" => pure (equalityCase count initialLength variant observation negative)
    | _ => throw "unsupported operation"
  let ((groups, metadata), final) <- action.run initial
  let details := compiledDetails request { assertions := final.assertions, groups }
  return Json.mkObj [("metadata", metadata), ("encoding", details)]

end CCFRaft.LedgerMicro

def main : IO UInt32 := do
  let text <- (← IO.getStdin).readToEnd
  let result := do
    let input <- Lean.Json.parse text
    let requests <- input.getArr?
    return Lean.toJson (← requests.mapM CCFRaft.LedgerMicro.generate)
  match result with
  | .ok output => IO.println output.compress; return 0
  | .error error => (← IO.getStderr).putStrLn error; return 2
