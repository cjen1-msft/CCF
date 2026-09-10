-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SmtTests
import Shared.SmtOrder

set_option autoImplicit false

namespace TraceSmt.ClampTests

-- Matches the concrete receiver's persisted conditional fixture without
-- importing its model-specific Scalar adapter.
private def nackStep (index : Nat) (old : NatTerm 0) : NatTerm 0 :=
  (Expr.equal (.named (index + 1) 0 "packet success" (.literal 0)) (.literal 0)).clamp
    old (.named 0 1 "match index" (.literal 1))
    (.named (index + 1) 1 "possible match" (.literal 3))

private def repeatedNackClamp : Nat -> NatTerm 0
  | 0 => .named 0 0 "initial sent index" (.literal 2)
  | count + 1 => nackStep count (repeatedNackClamp count)

private def oldNackStep (index : Nat) (old : NatTerm 0) : NatTerm 0 :=
  (Expr.equal (.named (index + 1) 0 "packet success" (.literal 0)) (.literal 0)).ite
    (.max (.min old (.named (index + 1) 1 "possible match" (.literal 3)))
      (.named 0 1 "match index" (.literal 1))) old

private def oldRepeatedNackClamp : Nat -> NatTerm 0
  | 0 => .named 0 0 "initial sent index" (.literal 2)
  | count + 1 => oldNackStep count (oldRepeatedNackClamp count)

private theorem repeatedNackClamp_eval (count : Nat) :
    (repeatedNackClamp count).eval Fin.elim0 = 2 := by
  induction count with
  | zero => rfl
  | succ count ih => simp [repeatedNackClamp, nackStep, Expr.clamp_eval, Expr.Holds, NatTerm.eval, ih]

#guard (oldRepeatedNackClamp 12).bindings.length == 16381
#guard (oldRepeatedNackClamp 15).bindings.length == 131069
#guard [0, 1, 12, 15, 32, 64].all fun count =>
  (repeatedNackClamp count).bindings.length == 3 * count + 1 &&
    (repeatedNackClamp count).eval Fin.elim0 == 2

private def clampOf {holes : Nat} (operand : Fin 5 -> NatTerm holes) : NatTerm holes :=
  .clampIfEqual (operand 0) (operand 1) (operand 2) (operand 3) (operand 4)

private def referenceOf {holes : Nat} (operand : Fin 5 -> NatTerm holes) : NatTerm holes :=
  .iteEqual (operand 0) (operand 1) (.max (.min (operand 2) (operand 4)) (operand 3))
    (operand 2)

private def termAt (index : Fin 5) (value : NatTerm 0) : NatTerm 0 :=
  clampOf (fun position => if position = index then value else .literal 0)

#guard (List.finRange 5).all fun index =>
  let named := NatTerm.named 0 0 "operand" (.literal 1)
  let term := termAt index named
  term.bindings.length == 1 &&
    (term.toSmt.splitOn "state_0_0").length == 2 &&
    TraceSmt.Tests.rejected
      [{ label := "conflict", clauses :=
          [{ label := "same key, different value",
             expression := .equal term (.named 0 0 "operand" (.literal 0)) }] }] &&
    TraceSmt.Tests.rejected
      [{ label := "conflict", clauses :=
          [{ label := "same key, different label",
             expression := .equal term (.named 0 0 "different" (.literal 1)) }] }] &&
    TraceSmt.Tests.rejected
      [{ label := "absent", clauses :=
          [TraceSmt.Tests.equality (termAt index (.named 1 0 "future" (.literal 1)))] }] &&
    TraceSmt.Tests.rejected
      [{ label := "early", clauses :=
          [TraceSmt.Tests.equality (termAt index (.named 1 0 "future" (.literal 1)))] },
       { label := "future", clauses := [] }]

private def samples : List (NatTerm 0) :=
  clampOf (fun _ => .literal 0) ::
    (List.finRange 5).map (fun index => termAt index (.literal 1))

#guard samples.all fun left => samples.all fun right =>
  (decide (left.syntaxKey = right.syntaxKey) == decide (left = right)) &&
    (compare left right == .eq) == decide (left = right)

#guard ([0, 1, 2, 3] : List Nat).all fun old =>
  [0, 1, 2, 3].all fun lower =>
    [0, 1, 2, 3].all fun upper =>
      [0, 1].all fun right =>
        let term : NatTerm 0 :=
          .clampIfEqual (.literal 0) (.literal right) (.literal old) (.literal lower) (.literal upper)
        term.eval Fin.elim0 == (if right = 0 then Nat.max (Nat.min old upper) lower else old)

private def checked {α : Type} : Except String α -> IO α
  | .ok value => pure value
  | .error message => throw (IO.userError message)

private def expect (solver text status : String) : IO String := do
  let result ← IO.Process.output { cmd := solver, args := #["--lang=smt2"] } (some text)
  unless result.exitCode == 0 &&
      (result.stdout.splitOn "\n").head? == some status do
    throw (IO.userError s!"expected {status}, exit={result.exitCode}\n{result.stdout}\n{result.stderr}")
  pure result.stdout

private def expectEquivalent {holes : Nat} (solver : String)
    (left right : NatTerm holes) : IO Unit := do
  let query ← checked (Formula.prepare
    [{ label := "equivalence", clauses :=
        [{ label := "different", expression := .not (.equal left right) }] }])
  let _ ← expect solver query.toSmt "unsat"

private def nackFormula (count expected : Nat) : Formula 0 :=
  (List.range (count + 1)).map (fun index =>
    { label := s!"producer {index}", clauses := [] }) ++
    [{ label := "observation", clauses :=
        [{ label := "sent index", expression := .equal (repeatedNackClamp count) (.literal expected) }] }]

def run (solver : String) : IO Unit := do
  let inputs : Fin 5 -> NatTerm 5 := NatTerm.unknown
  expectEquivalent solver (clampOf inputs) (referenceOf inputs)
  -- Each of the five operand positions may itself contain a clamp using the
  -- same local SMT names. Simultaneous let bindings must preserve its scope.
  for index in List.finRange 5 do
    let nested := fun position => if position = index then clampOf inputs else inputs position
    expectEquivalent solver (clampOf nested) (referenceOf nested)
  let conditions : List (Expr 5) :=
    [.boolean false, .boolean true, .equal (.unknown 0) (.unknown 1),
     .lessThan (.unknown 0) (.unknown 1),
     .not (.equal (.unknown 0) (.unknown 1)),
     .and (.lessThan (.unknown 0) (.unknown 1))
       (.not (.equal (.unknown 0) (.literal 0)))]
  for condition in conditions do
    expectEquivalent solver (condition.clamp (.unknown 2) (.unknown 3) (.unknown 4))
      (condition.ite (.max (.min (.unknown 2) (.unknown 4)) (.unknown 3)) (.unknown 2))
  for count in [12, 15, 32, 64] do
    let term := repeatedNackClamp count
    let text := term.toSmt
    let query ← checked ((nackFormula count 2).prepare)
    unless term.bindings.length == 3 * count + 1 &&
        (text.splitOn "state_0_0").length == 2 &&
        (text.splitOn "(let ((clamp_left ").length == count + 1 &&
        query.groups.map (fun group => group.clauses.length) ==
          (2 :: List.replicate count 2) ++ [1] do
      throw (IO.userError "conditional clamp duplicated old state or added/lost producer definitions")
    -- Compare with the sum of independently rendered steps, accounting exactly
    -- for growing decimal group identifiers rather than imposing a byte cap.
    let expectedBytes := (repeatedNackClamp 0).toSmt.utf8ByteSize +
      ((List.range count).map fun index => (nackStep index (.literal 0)).toSmt.utf8ByteSize - 1).sum
    let expectedKeyLength := (repeatedNackClamp 0).syntaxKey.length +
      ((List.range count).map fun index =>
        (nackStep index (.literal 0)).syntaxKey.length - (.literal 0 : NatTerm 0).syntaxKey.length).sum
    unless text.utf8ByteSize == expectedBytes && term.syntaxKey.length == expectedKeyLength do
      throw (IO.userError "conditional clamp rendering or structural key exceeded exact additive growth")
    let _ ← expect solver query.toSmt "sat"
    let wrong ← checked ((nackFormula count 1).prepare)
    let _ ← expect solver wrong.toSmt "unsat"
    IO.println s!"conditional depth={count} value={term.eval Fin.elim0} bindings={term.bindings.length} bytes={text.utf8ByteSize}"
  let old : NatTerm 0 := .named 0 0 "old" (.literal 2)
  let condition : Expr 0 := .equal (.named 1 0 "predicate" (.literal 0)) (.literal 0)
  let query ← checked (Formula.prepare
    [{ label := "entry", clauses := [] },
     { label := "predicate producer", clauses := [] },
     { label := "observation", clauses :=
         [{ label := "unchanged", expression := .equal (condition.clamp old (.literal 3) (.literal 5)) old }] }])
  let core ← expect solver
    ("(set-option :produce-unsat-cores true)\n" ++ query.toSmt ++ "(get-unsat-core)\n") "unsat"
  unless [0, 1, 2].all (fun index => (core.splitOn s!"group_{index}").length == 2) do
    throw (IO.userError s!"conditional core lost a producer: {core}")
  for index in [0, 1, 2] do
    let reduced := { query with groups := query.groups.zipIdx.filterMap fun (group, i) =>
      if i = index then none else some group }
    let _ ← expect solver reduced.toSmt "sat"
  IO.println "conditional clamp semantics, all operands, predicate ownership, and exact NACK growth passed"

end TraceSmt.ClampTests

run_cmd do
  for name in [``TraceSmt.NatTerm.clampIfEqual_eval, ``TraceSmt.Expr.clamp_eval,
      ``TraceSmt.NatTerm.syntaxKey_injective,
      ``TraceSmt.ClampTests.repeatedNackClamp_eval] do
    for axiomName in ← Lean.collectAxioms name do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{name} depends on unapproved axiom {axiomName}"

def main (args : List String) : IO Unit :=
  match args with
  | [solver] => TraceSmt.ClampTests.run solver
  | _ => throw (IO.userError "usage: SmtClampTests.lean /path/to/cvc5")
