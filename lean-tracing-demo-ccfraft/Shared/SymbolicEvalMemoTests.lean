-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicEvalMemo
import Lean

set_option autoImplicit false

namespace Symbolic.Expr.EvalMemoTests

def tower : Nat → Expr .nat
  | 0 => .unknown 0
  | depth + 1 => let previous := tower depth; .add previous previous

theorem tower_eval (depth : Nat) (assignment : Assignment) :
    (tower depth).eval assignment = 2 ^ depth * assignment 0 := by
  induction depth with
  | zero => simp [tower, eval]
  | succ depth ih =>
    simp only [tower, eval, ih, pow_succ]
    ring

theorem tower_evalMemo (depth : Nat) (assignment : Assignment) :
    (tower depth).evalMemo assignment = 2 ^ depth * assignment 0 := by
  rw [evalMemo_correct, tower_eval]

private structure Case where
  label : String
  sort : Ty
  expression : Expr sort
  expected : Assignment → sort.Value

private def list : Expr (.seq .nat) := .ofList [.unknown 0, .nat 5]
private def pair : Expr (.pair .nat .bool) := .pair (.unknown 0) (.bool true)
private def left : Expr (.sum .nat .bool) := .inl (.unknown 0)
private def right : Expr (.sum .nat .bool) := .inr (.bool true)

private def cases : List Case :=
  [ ⟨"nat", .nat, .nat 9, fun _ => 9⟩,
    ⟨"bool", .bool, .bool true, fun _ => true⟩,
    ⟨"unit", .unit, .unit, fun _ => ()⟩,
    ⟨"unknown", .nat, .unknown 0, fun ρ => ρ 0⟩,
    ⟨"named", .nat, .named 4 8 (.add (.unknown 0) (.nat 1)), fun ρ => ρ 0 + 1⟩,
    ⟨"add", .nat, .add (.unknown 0) (.unknown 1), fun ρ => ρ 0 + ρ 1⟩,
    ⟨"sub", .nat, .sub (.unknown 0) (.nat 5), fun ρ => ρ 0 - 5⟩,
    ⟨"lt", .bool, .lt (.unknown 0) (.nat 5), fun ρ => decide (ρ 0 < 5)⟩,
    ⟨"eq", .bool, .eq (.unknown 0) (.unknown 1), fun ρ => decide (ρ 0 = ρ 1)⟩,
    ⟨"not", .bool, .not (.lt (.unknown 0) (.nat 5)), fun ρ => !(decide (ρ 0 < 5))⟩,
    ⟨"and", .bool, .and (.lt (.unknown 0) (.nat 5)) (.bool true), fun ρ => decide (ρ 0 < 5)⟩,
    ⟨"ite", .nat, .ite (.eq (.unknown 0) (.nat 0)) (.unknown 1) (.nat 7),
      fun ρ => if ρ 0 = 0 then ρ 1 else 7⟩,
    ⟨"pair", .pair .nat .bool, pair, fun ρ => (ρ 0, true)⟩,
    ⟨"fst", .nat, .fst (.named 0 0 pair), fun ρ => ρ 0⟩,
    ⟨"snd", .bool, .snd (.named 0 0 pair), fun _ => true⟩,
    ⟨"inl", .sum .nat .bool, left, fun ρ => .inl (ρ 0)⟩,
    ⟨"inr", .sum .nat .bool, right, fun _ => .inr true⟩,
    ⟨"isLeft", .bool, .isLeft (.named 0 0 left), fun _ => true⟩,
    ⟨"leftD", .nat, .leftD (.named 0 0 left) (.nat 8), fun ρ => ρ 0⟩,
    ⟨"rightD", .bool, .rightD (.named 0 0 right) (.bool false), fun _ => true⟩,
    ⟨"nil", .seq .nat, .nil, fun _ => []⟩,
    ⟨"cons", .seq .nat, .cons (.unknown 0) (.cons (.nat 5) .nil), fun ρ => [ρ 0, 5]⟩,
    ⟨"append", .seq .nat, .append list list, fun ρ => [ρ 0, 5, ρ 0, 5]⟩,
    ⟨"length", .nat, .length list, fun _ => 2⟩,
    ⟨"take", .seq .nat, .take (.unknown 0) list, fun ρ => [ρ 0, 5].take (ρ 0)⟩,
    ⟨"drop", .seq .nat, .drop (.unknown 0) list, fun ρ => [ρ 0, 5].drop (ρ 0)⟩,
    ⟨"get?", .sum .unit .nat, .get? list (.unknown 0),
      fun ρ => match [ρ 0, 5][ρ 0]? with | none => .inl () | some value => .inr value⟩,
    ⟨"set", .seq .nat, .set list (.unknown 0) (.nat 9), fun ρ => [ρ 0, 5].set (ρ 0) 9⟩,
    ⟨"contains", .bool, .contains list (.unknown 1), fun ρ => decide (ρ 1 ∈ [ρ 0, 5])⟩,
    ⟨"sub clamps", .nat, .sub (.nat 2) (.nat 9), fun _ => 0⟩,
    ⟨"last element", .sum .unit .nat, .get? list (.nat 1), fun _ => .inr 5⟩,
    ⟨"past end get", .sum .unit .nat, .get? list (.nat 2), fun _ => .inl ()⟩,
    ⟨"past end set", .seq .nat, .set list (.nat 2) (.nat 9), fun ρ => [ρ 0, 5]⟩,
    ⟨"empty get", .sum .unit .nat, .get? (.nil : Expr (.seq .nat)) (.nat 0), fun _ => .inl ()⟩,
    ⟨"empty set", .seq .nat, .set .nil (.nat 0) (.nat 9), fun _ => []⟩,
    ⟨"generic right tag", .bool, .isLeft (.named 0 0 right), fun _ => false⟩,
    ⟨"generic left fallback", .nat, .leftD (.named 0 0 right) (.nat 8), fun _ => 8⟩,
    ⟨"generic right fallback", .bool, .rightD (.named 0 0 left) (.bool false), fun _ => false⟩,
    ⟨"pair equality", .bool, .eq pair (.pair (.unknown 1) (.bool true)),
      fun ρ => decide (ρ 0 = ρ 1)⟩,
    ⟨"sum inequality", .bool, .eq left right, fun _ => false⟩,
    ⟨"sequence equality", .bool, .eq list (.ofList [.unknown 1, .nat 5]),
      fun ρ => decide (ρ 0 = ρ 1)⟩,
    ⟨"typed contains", .bool, .contains (.ofList [left, right]) (.inl (.unknown 1)),
      fun ρ => decide (ρ 1 = ρ 0)⟩,
    ⟨"same name different definitions", .nat,
      .add (.named 0 0 (.unknown 0)) (.named 0 0 (.unknown 1)), fun ρ => ρ 0 + ρ 1⟩,
    ⟨"same name different types", .pair .nat .bool,
      .pair (.named 0 0 (.unknown 0)) (.named 0 0 (.bool false)), fun ρ => (ρ 0, false)⟩ ]

private def checkCase (assignment : Assignment) (sample : Case) : IO Unit := do
  let actual := sample.expression.evalMemo assignment
  unless decide (actual = sample.expected assignment) do
    throw (IO.userError s!"{sample.label}: incorrect memoized value")
  unless decide (actual = sample.expression.eval assignment) do
    throw (IO.userError s!"{sample.label}: differs from Expr.eval")

private def checkVisited {s : Ty} (label : String) (expression : Expr s)
    (expected : s.Value) (visited : Nat) : IO Unit := do
  let (value, state) := (evalMemoM (fun _ => 3) expression).run {}
  unless decide (value = expected) && state.size == visited do
    throw (IO.userError s!"{label}: discarded expression was evaluated or value changed")

private def shortCircuitCases : IO Unit := do
  let dead := tower 512
  let deadBool := Expr.eq dead (.nat 0)
  checkVisited "and skips false branch" (.and (.bool false) deadBool) false 2
  checkVisited "ite skips right branch" (.ite (.bool true) (.nat 7) dead) 7 3
  checkVisited "ite skips left branch" (.ite (.bool false) dead (.nat 7)) 7 3
  checkVisited "fst discards second field" (.fst (.pair (.nat 7) dead)) 7 2
  checkVisited "snd discards first field" (.snd (.pair dead (.nat 7))) 7 2
  checkVisited "left tag discards payload" (.isLeft (Expr.inl (b := .nat) dead)) true 1
  checkVisited "right tag discards payload" (.isLeft (Expr.inr (a := .nat) dead)) false 1
  checkVisited "left discards fallback" (.leftD (Expr.inl (b := .nat) (.nat 7)) dead) 7 2
  checkVisited "left discards wrong payload" (.leftD (Expr.inr (a := .nat) dead) (.nat 7)) 7 2
  checkVisited "right discards fallback" (.rightD (Expr.inr (a := .nat) (.nat 7)) dead) 7 2
  checkVisited "right discards wrong payload" (.rightD (Expr.inl (b := .nat) dead) (.nat 7)) 7 2

private def collisionCases : IO Unit := do
  let naturals : Expr (.seq .nat) := .nil
  let booleans : Expr (.seq .bool) := .nil
  unless naturals.memoKey == booleans.memoKey do
    throw (IO.userError "typed collision fixture no longer collides")
  let typed : StateM (EvaluationState (fun i => i)) (List Nat × List Bool) := do
    let ns ← evalMemoM (fun i => i) naturals
    let bs ← evalMemoM (fun i => i) booleans
    return (ns, bs)
  let (values, cache) := typed.run {}
  unless values == ([], []) && cache.size == 2 && cache.entries.size == 1 do
    throw (IO.userError "hash collision confused different expression types")
  let hidden (index : Nat) :=
    (List.range 8).foldl (fun value _ => Expr.not value) (.eq (.unknown index) (.nat 0))
  let first := hidden 0
  let second := hidden 1
  unless first.memoKey == second.memoKey do
    throw (IO.userError "same-type collision fixture no longer collides")
  let untyped : StateM (EvaluationState (fun i => i)) (Bool × Bool) := do
    let a ← evalMemoM (fun i => i) first
    let b ← evalMemoM (fun i => i) second
    return (a, b)
  unless (untyped.run {}).1 == (true, false) do
    throw (IO.userError "hash collision confused distinct same-typed expressions")

def run : IO Unit := do
  for assignment in [(fun _ => 0), (fun i => i + 1), (fun _ => 7)] do
    for sample in cases do
      checkCase assignment sample
  shortCircuitCases
  collisionCases
  let graph := tower 64
  for base in [0, 1, 3, 7] do
    let assignment : Assignment := fun _ => base
    let start ← IO.monoMsNow
    let (actual, cache) := (evalMemoM assignment graph).run {}
    unless actual == 2 ^ 64 * base && cache.size == 65 do
      throw (IO.userError "depth-64 DAG was not evaluated once per unique node")
    let program : StateM (EvaluationState assignment) (Nat × Bool) := do
      let again ← evalMemoM assignment (.named 2 9 graph)
      let checked ← evalMemoM assignment (.eq graph (.nat actual))
      return (again, checked)
    let (reused, _) := program.run cache
    unless reused == (actual, true) do
      throw (IO.userError "reusing a typed assignment-local cache changed evaluation")
    let firstWrapper := Expr.named 5 13 graph
    let (_, warmed) := (evalMemoM assignment firstWrapper).run cache
    let slotCell ← IO.mkRef 13
    let slot ← slotCell.get
    let secondWrapper := Expr.named 5 slot graph
    let (wrapped, finalCache) := (evalMemoM assignment secondWrapper).run warmed
    unless wrapped == actual && finalCache.size == warmed.size do
      throw (IO.userError "equal wrappers around a shared DAG missed the typed cache")
    let indexCell ← IO.mkRef 0
    let index ← indexCell.get
    let rebuilt := (List.range 64).foldl (fun value _ => Expr.add value value) (.unknown index)
    let (independent, independentCache) := (evalMemoM assignment rebuilt).run cache
    unless independent == actual && independentCache.size == cache.size do
      throw (IO.userError "independently allocated equal DAG missed the typed cache")
    let (overlap, overlapCache) := (evalMemoM assignment (.add graph rebuilt)).run independentCache
    unless overlap == 2 * actual && overlapCache.size == cache.size + 1 do
      throw (IO.userError "overlapping equal DAGs were evaluated redundantly")
    IO.println s!"depth 64, assignment {base}: {actual}, {(← IO.monoMsNow) - start} ms"
  IO.println s!"Memoized evaluation: {cases.length * 3} constructor cases, 11 short-circuit cases, 2 forced collisions, and 4 DAG assignments passed"

run_cmd do
  let info ← Lean.getConstInfo ``Symbolic.Expr
  let .inductInfo definition := info | throwError "Expr is not an inductive type"
  let covered := cases.take definition.ctors.length |>.map (·.label)
  for constructorName in definition.ctors do
    unless covered.contains constructorName.getString! do
      throwError "Missing evaluator constructor case: {constructorName}"
  for name in [``evalMemo_correct, ``evalMemoM_correct, ``tower_evalMemo] do
    for axiomName in ← Lean.collectAxioms name do
      unless axiomName == ``propext || axiomName == ``Classical.choice || axiomName == ``Quot.sound do
        throwError "{name} depends on unapproved axiom {axiomName}"

end Symbolic.Expr.EvalMemoTests
