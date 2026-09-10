-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SmtTests
import Shared.SmtOrder

set_option autoImplicit false

namespace TraceSmt.DagTests

private def same {holes : Nat} (a b : NatTerm holes) : Bool :=
  @decide (a = b) (NatTerm.sharedDecEq a b)

private def dag : Nat -> NatTerm 2
  | 0 => .unknown 0
  | count + 1 => let child := dag count; .add child child

private def separateDag (count : Nat) : NatTerm 2 :=
  (List.range count).foldl (fun child _ => .add child child) (.unknown 0)

#guard same (dag 64) (separateDag 64)
#guard !same (.add (dag 64) (.literal 0)) (.add (separateDag 64) (.literal 1))
#guard !same (.named 0 0 "first" (dag 64)) (.named 0 0 "second" (separateDag 64))

private def hidden (value : Nat) : NatTerm 2 :=
  .add (.add (.add (.literal value) (.unknown 0)) (.unknown 0)) (.unknown 0)

#guard (hidden 0).memoKey == (hidden 1).memoKey
#guard !same (hidden 0) (hidden 1)
#guard NatTerm.lookup (hidden 1) [(hidden 0, 7), (hidden 1, 9)] == some 9

-- Two histories feed one acceptance predicate, then both successor histories.
-- There are five new arithmetic nodes per step and only two actual producers.
private def crossStep (previous : NatTerm 2 × NatTerm 2) : NatTerm 2 × NatTerm 2 :=
  let (left, right) := previous
  let accepted := NatTerm.iteEqual left right (.literal 1) (.literal 0)
  let nextLeft := NatTerm.iteEqual accepted (.literal 1) (.add left (.literal 1)) left
  let nextRight := NatTerm.iteEqual accepted (.literal 1) (.max right nextLeft) right
  (nextLeft, nextRight)

private def crossed (count : Nat) : NatTerm 2 × NatTerm 2 :=
  (List.range count).foldl (fun previous _ => crossStep previous)
    (.named 0 0 "left entry" (.unknown 0), .named 0 1 "right entry" (.unknown 1))

private def concreteStep (previous : Nat × Nat) : Nat × Nat :=
  let (left, right) := previous
  let nextLeft := if left = right then left + 1 else left
  (nextLeft, if left = right then Nat.max right nextLeft else right)

private def prepared {holes : Nat} (expression : Expr holes) : Except String Prepared :=
  Formula.prepare
    [{ label := "entry", clauses := [] },
     { label := "unchanged action", clauses := [] },
     { label := "observation", clauses := [{ label := "condition", expression }] }]

private def checked {α : Type} : Except String α -> IO α
  | .ok value => pure value
  | .error message => throw (IO.userError message)

private def expect (solver text status : String) : IO String := do
  let result ← IO.Process.output { cmd := solver, args := #["--lang=smt2"] } (some text)
  unless result.exitCode == 0 &&
      (result.stdout.splitOn "\n").head? == some status do
    throw (IO.userError s!"expected {status}, exit={result.exitCode}\n{result.stdout}\n{result.stderr}")
  pure result.stdout

private def rejected {holes : Nat} (formula : Formula holes) : Bool :=
  match formula.prepare with
  | .ok _ => false
  | .error _ => true

-- A subtree first cached in a later context must retain its latest owner when
-- reached inside an earlier producer's definition.
#guard rejected ([
  { label := "early", clauses := [] },
  { label := "later", clauses := [] },
  { label := "observation", clauses := [
    { label := "prime cache", expression := .equal (.named 1 0 "later" (.literal 2)) (.literal 2) },
    { label := "bad owner", expression := .equal
        (.named 0 0 "early" (.named 1 0 "later" (.literal 2))) (.literal 2) }] }] : Formula 0)

#guard rejected ([
  { label := "entry", clauses := [] },
  { label := "conflict", clauses := [
    { label := "first", expression := .equal (.named 0 0 "value" (hidden 0)) (.literal 0) },
    { label := "second", expression := .equal (.named 0 0 "value" (hidden 1)) (.literal 0) }] }] : Formula 2)

-- All five clamp positions remain reachable even when the predicate is false.
#guard (List.finRange 5).all fun position =>
  let inputs := fun index : Fin 5 =>
    if index = position then
      NatTerm.named 0 0 "clashing" (.add (.literal 1) (.literal 1))
    else .literal 0
  let term := NatTerm.clampIfEqual (inputs 0) (inputs 1) (inputs 2) (inputs 3) (inputs 4)
  rejected ([
    { label := "entry", clauses := [
      { label := "cache", expression := .equal (.named 0 0 "clashing" (.literal 2)) (.literal 2) },
      { label := "different syntax", expression := .equal term (.literal 0) }] }] : Formula 0)

private def heterogeneous : List (NatTerm 2) :=
  [.literal 0, .unknown 0, .unknown 1, .add (.unknown 0) (.literal 1),
   .sub (.unknown 0) (.literal 1), .min (.unknown 0) (.literal 1),
   .max (.unknown 0) (.literal 1),
   .iteEqual (.unknown 0) (.unknown 1) (.literal 0) (.literal 1),
   .clampIfEqual (.unknown 0) (.unknown 1) (.literal 0) (.literal 1) (.literal 2),
   .named 0 0 "first" (.unknown 0), .named 0 1 "first" (.unknown 0),
   .named 1 0 "first" (.unknown 0), .named 0 0 "second" (.unknown 0)]

#guard heterogeneous.all fun a => heterogeneous.all fun b => same a b == decide (a = b)

def run (solver : String) : IO Unit := do
  let common : NatTerm 2 := .add (.unknown 0) (.unknown 1)
  let variants : List (NatTerm 2) :=
    [.literal 0, .unknown 0, .add common common, .sub common (.unknown 0),
     .sub (.sub common (.literal 1)) (.literal 1),
     .min common (.unknown 0), .max common (.unknown 1),
     .iteEqual (.unknown 0) (.unknown 1) common (.literal 3),
     .clampIfEqual (.unknown 0) (.unknown 1) common (.unknown 1) (.unknown 0),
     .named 0 0 "computed entry" (.add common common)]
  for term in variants do
    for (a, b) in [(0, 0), (0, 3), (4, 1)] do
      let expected := term.eval (fun index => if index.val = 0 then a else b)
      let values : Expr 2 := .and (.equal (.unknown 0) (.literal a)) (.equal (.unknown 1) (.literal b))
      let result : Expr 2 := .and (.equal term (.literal expected))
        (.equal (.add term term) (.literal (expected + expected)))
      let _ ← expect solver (← checked (prepared (.and values result))).toSmt "sat"
      let _ ← expect solver (← checked (prepared (.and values (.not result)))).toSmt "unsat"
  for depth in [3, 4, 12, 16, 32] do
    let (left, right) := crossed depth
    let text := (Expr.equal left right).toSmt
    let bindingKeys := (Expr.equal left right).bindings.map fun binding => (binding.group, binding.slot)
    unless bindingKeys == [(0, 0), (0, 1)] &&
        (text.splitOn "(let ((dag_").length == 5 * depth + 1 do
      throw (IO.userError s!"crosslinked graph traversal or emission duplicated nodes at {depth}")
    -- Each fixed-size operator contributes at most five decimal DAG references.
    unless text.utf8ByteSize <= 5 * depth * (120 + 5 * (toString (5 * depth)).length) + 128 do
      throw (IO.userError s!"crosslinked output exceeded its node/identifier-size bound at {depth}")
    for (a, b) in [(0, 0), (2, 2), (1, 4), (4, 1)] do
      let expected := (List.range depth).foldl (fun pair _ => concreteStep pair) (a, b)
      let values : Expr 2 := .and (.equal (.unknown 0) (.literal a)) (.equal (.unknown 1) (.literal b))
      let result : Expr 2 := .and (.equal left (.literal expected.1)) (.equal right (.literal expected.2))
      let good ← checked (prepared (.and values result))
      let bad ← checked (prepared (.and values (.not result)))
      unless good.groups.map (fun group => group.clauses.length) == [2, 0, 1] do
        throw (IO.userError "DAG emission invented an unchanged-action writer")
      let _ ← expect solver good.toSmt "sat"
      let _ ← expect solver bad.toSmt "unsat"
    IO.println s!"crosslinked depth={depth} bindings={bindingKeys.length} arithmetic_nodes={5 * depth} bytes={text.utf8ByteSize}"
  -- Separately allocated equal histories are interned; hash collisions are not.
  let repeated := Expr.equal (dag 32) (separateDag 32)
  let _ ← expect solver (← checked (prepared (.not repeated))).toSmt "unsat"
  let _ ← expect solver (← checked (prepared (.equal (hidden 0) (hidden 1)))).toSmt "unsat"
  let source : NatTerm 0 := .named 0 0 "source" (.literal 2)
  let common := NatTerm.sub source (.literal 1)
  let predicate := NatTerm.named 1 0 "predicate" (.literal 0)
  let selected := NatTerm.iteEqual predicate (.literal 0) (.add common common) common
  let query ← checked (Formula.prepare
    [{ label := "source", clauses := [] },
     { label := "predicate", clauses := [] },
     { label := "unchanged", clauses := [] },
     { label := "observation", clauses := [{ label := "wrong", expression := .equal selected common }] }])
  let core ← expect solver
    ("(set-option :produce-unsat-cores true)\n" ++ query.toSmt ++ "(get-unsat-core)\n") "unsat"
  unless [0, 1, 3].all (fun index => (core.splitOn s!"group_{index}").length == 2) &&
      (core.splitOn "group_2").length == 1 do
    throw (IO.userError s!"DAG sharing changed producer/noop core ownership: {core}")
  for index in [0, 1, 3] do
    let reduced := { query with groups := query.groups.zipIdx.filterMap fun (group, i) =>
      if i = index then none else some group }
    let _ ← expect solver reduced.toSmt "sat"
  IO.println "legacy DAG semantics, exact cache hits, owner validation, and noop cores passed"

end TraceSmt.DagTests

run_cmd do
  for name in [``TraceSmt.NatTerm.sharedDecEq, ``TraceSmt.NatTerm.sharedDecEq_correct,
      ``TraceSmt.NatTerm.lookup_sound, ``TraceSmt.NatTerm.bindings,
      ``TraceSmt.NatTerm.toSmt, ``TraceSmt.Formula.prepare] do
    for axiomName in ← Lean.collectAxioms name do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{name} depends on unapproved axiom {axiomName}"

def main (args : List String) : IO Unit :=
  match args with
  | [solver] => TraceSmt.DagTests.run solver
  | _ => throw (IO.userError "usage: SmtDagTests.lean /path/to/cvc5")
