-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeParameterizedFrame

set_option autoImplicit false

namespace CCFRaft.LedgerMicroLaws

open Lean NativeEncode NativeSmt

def checks : EncodeM (⟨2, by decide⟩) (Array (String × Expr .bool)) := do
  let width : PNat := ⟨2, by decide⟩
  let leftId <- fresh
  let rightId <- fresh
  let left : Expr (.array .int (entryTy width)) := .free _ leftId
  let right : Expr (.array .int (entryTy width)) := .free _ rightId
  let valueId <- fresh
  let value : Expr (entryTy width) := .free _ valueId
  let otherId <- fresh
  let other : Expr (entryTy width) := .free _ otherId
  let mut output := #[]
  for size in ([0, 1, 4] : List Nat) do
    let quantified := logRangeEqualTerm width false left right (.integer 0) (.integer 0) (.integer size)
    let finite := all ((List.range size).map fun index =>
      logRangeEntryEqual false (.select left (.integer index)) (.select right (.integer index)))
    output := output.push (s!"equality-grounding-{size}", .not (.equal quantified finite))
    let validLeft := boundedForall (.integer size)
      (entryDomain (.select (left.weaken .int) (.bound .here)))
    let validRight := boundedForall (.integer size)
      (entryDomain (.select (right.weaken .int) (.bound .here)))
    let direct := boundedForall (.integer size)
      (.equal (.select (left.weaken .int) (.bound .here))
        (.select (right.weaken .int) (.bound .here)))
    output := output.push (s!"typed-range-equality-{size}",
      all [validLeft, validRight, .not (.equal quantified direct)])
    let stored : Expr (.array .int (entryTy width)) := .store left (.integer size) value
    let payloadId <- fresh
    let payload : Expr (.array .int (entryTy width)) := .free _ payloadId
    let relation := logSpliceTerm width (.integer size) left (.integer 1) payload (.integer size) stored
    output := output.push (s!"append-store-{size}",
      .and (.equal (.select payload (.integer 0)) value) (.not relation))
    let emptySplice := logSpliceTerm width (.integer (size + 2)) left
      (.integer 0) right (.integer size) left
    output := output.push (s!"rollback-retain-array-{size}", .not emptySplice)
  output := output.push ("normalization-idempotent",
    .not (.equal (normalizedEntryTerm (normalizedEntryTerm value)) (normalizedEntryTerm value)))
  output := output.push ("canonical-representative",
    .not (logRangeEntryEqual false value (normalizedEntryTerm value)))
  output := output.push ("typed-entry-equality",
    all [entryDomain value, entryDomain other,
      .not (.equal (logRangeEntryEqual false value other) (.equal value other))])
  output := output.push ("negative-term-excluded",
    entryDomain (width := width) (.pair (.integer (-1)) (.inr (.inl (.integer 0)))))
  output := output.push ("negative-transaction-excluded",
    entryDomain (width := width) (.pair (.integer 0) (.inr (.inl (.integer (-1))))))
  output := output.push ("zero-entry-allowed",
    .not (entryDomain (width := width) (.pair (.integer 0) (.inr (.inl (.integer 0))))))
  output := output.push ("typed-domain-feasible", all [
    entryDomain value, entryDomain other,
    boundedForall (.integer 4) (entryDomain (.select (left.weaken .int) (.bound .here))),
    boundedForall (.integer 4) (entryDomain (.select (right.weaken .int) (.bound .here)))])
  return output

end CCFRaft.LedgerMicroLaws

def main : IO UInt32 := do
  let result : Except String Lean.Json := do
    let width : PNat := ⟨2, by decide⟩
    let initial := CCFRaft.NativeEncode.initialEncoding width {(0 : Fin width)}
    let (cases, ready) <- CCFRaft.LedgerMicroLaws.checks.run initial
    let mut outputs := #[]
    for (name, formula) in cases do
      let (_, final) <- (CCFRaft.NativeEncode.assertion formula).run ready
      let details := CCFRaft.NativeEncode.compiledDetails Lean.Json.null {
        assertions := final.assertions,
        groups := #[{ instruction := none, start := 0, stop := final.assertions.size }] }
      outputs := outputs.push (Lean.Json.mkObj [
        ("name", Lean.toJson name),
        ("expected", Lean.toJson (if name == "typed-domain-feasible" then "sat" else "unsat")),
        ("script", ← CCFRaft.NativeEncode.field details "script")])
    return Lean.toJson outputs
  match result with
  | .ok output => IO.println output.compress; return 0
  | .error error => (← IO.getStderr).putStrLn error; return 2
