module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import MidTrace.GenLower

public import MidTrace.GenLower

@[expose] public section

namespace Consensus.MidTrace.Tests

open Gen
open Smt (Tm)

/-- Compare lowered results, not just the satisfiability of the emitted assertions. -/
private def check (build : GM (Array Tm)) (expected : Array Tm) (initial : LState := {})
    : IO LState := do
  let (terms, ir) := build.run {}
  let act := terms.mapM fun t => do Smt.norm (← lowerS {} t)
  let ((actual, ls), enc) := ((act.run ir).run initial).run {}
  if let some (_, reason) := enc.unsupported then throw (IO.userError reason)
  unless actual == expected do
    throw (IO.userError s!"got {repr actual}, expected {repr expected}")
  return ls

private def gaps : IO Unit := do
  let build := do
    let terms ← declareArr (.arr .int) (some 2) (some 2) (gapUniform := true)
    let flags ← declareArr (.arr .bool) (some 0) (some 1)
    let rows ← declareArr (.arr (.arr .int)) (some 0) (some 20)
    let ok ← foldAll (.int 1) (.int 99) fun k => do eqK (← select terms k) 2
    let total ← scan .int (.int 0) fun k acc => do addT acc (← select terms k)
    let indices ← foldSum (.int 1) (.int 99) (fun _ => pure (.bool true)) pure
    return #[
      ok,
      ← select total (.int 99),
      ← select flags (.int 1),
      ← select (← select rows (.int 1)) (.int 0),
      ← select (← select rows (.int 0)) (.int 1),
      indices
    ]
  let ls ←
    check build #[.bool true, .int 198, .bool false, .int 0, .int 0, .int 4950]
      { explicit := #[(0, 0)], fill := .literal }
  unless ls.probed > 0 do
    throw (IO.userError "expected a summarized gap")

private def overwrites : IO Unit := do
  let build := do
    let base ← zeroArr (.arr .int)
    let i ← declare false (some 0) (some 99)
    let writes ← store (← store base i (.int 1)) i (.int 2)
    let count (a : Tm) :=
      foldSum (.int 1) (.int 50) (fun _ => pure (.bool true)) (select a)
    let sumThrough (a : Tm) := scan .int (.int 0) fun k acc => do addT acc (← select a k)
    let a ← store base (.int 5) (.int 3)
    let b ← store a (.int 40) (.int 7)
    return #[
      ← select writes i,
      ← select writes (← addK i 1),
      ← count a,
      ← count b,
      ← select (← sumThrough a) (.int 50),
      ← select (← sumThrough b) (.int 50)
    ]
  let expected := #[.int 2, .int 0, .int 3, .int 10, .int 3, .int 10]
  discard <| check build expected { reuse := false }
  let ls ← check build expected
  unless ls.reusedPoints > 0 && ls.seededScans > 0 do
    throw (IO.userError "expected incremental fold and scan reuse")

#eval gaps
#eval overwrites

#eval
  show IO Unit from do
    let ((choice, observation), ir) :=
      (do
        let choice ← declare false (some 0) (some 32) (selector := true)
        let state ← declare false (some 0) (some 4)
        return (choice, ← eqK state 2)).run
        {}
    let action := do
      discard <| lowerS {} observation
      lowerS {} choice
    let ((selected, _), enc) := ((action.run ir).run {}).run {}
    let .ref id := selected | throw (IO.userError "expected a symbolic choice")
    unless enc.selectors.size == 1 && enc.selectors.contains id do
      throw (IO.userError "only the explicit branch choice should be probed")

#eval
  show IO Unit from do
    let (term, ir) :=
      (do
        let rows ← declareArr (.arr (.arr .int)) (some 2) (some 20)
        select (← select rows (.int 0)) (.int 1)).run
        {}
    let (_, enc) := runLM ir (discard <| lowerS {} term) { explicit := #[(0, 0)] } {}
    unless enc.unsupported.any
            (·.2.endsWith "zero gap fill outside array bounds [2, 20]") do
      throw (IO.userError "expected out-of-bounds literal fill to be rejected")

-- A failed speculative read must not memoize its placeholder for a later real read.
#eval
  show IO Unit from do
    let (term, ir) :=
      (do
        select (← declareArr (.arr .int)) (← declare false)
        : GM Tm).run
        {}
    let action : LM Unit := do
      discard <| attempt (lowerS {} term)
      discard <| lowerS {} term
    let (_, enc) := runLM ir action {} {}
    unless enc.unsupported.isSome do
      throw (IO.userError "failed probe masked unsupported read")

-- An unbounded term may equal any literal, however large.
#eval
  show IO Unit from do
    let big : Int := 2 ^ 64 - 1
    let act : Smt.M (Tm × Tm) := do
      let x ← Smt.declare false (some 0)
      let eq ← Smt.eqK (← Smt.addK x 1) (big + 1)
      Smt.require eq "large"
      return (eq, ← Smt.norm x)
    let ((eq, x), enc) := act.run {}
    unless eq != .bool false && enc.falsified.isNone && x == .int big do
      throw (IO.userError "large literal folded as out of bounds")

end Consensus.MidTrace.Tests
