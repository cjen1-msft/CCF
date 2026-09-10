-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SmtTests
import Shared.SmtOrder

set_option autoImplicit false

namespace TraceSmt.MinMaxTests

private def stored (slot : Fin 3) : NatTerm 3 :=
  .named 0 slot.val "entry value" (.unknown slot)

private def repeatedClamp : Nat -> NatTerm 3
  | 0 => stored 0
  | count + 1 => .max (.min (stored 1) (repeatedClamp count)) (stored 2)

private def occurrences (text needle : String) : Nat :=
  (text.splitOn needle).length - 1

private def linearGrowth (depth : Nat) : Bool :=
  let term := repeatedClamp depth
  let text := term.toSmt
  let base := (repeatedClamp 0).toSmt.utf8ByteSize
  let step := (repeatedClamp 1).toSmt.utf8ByteSize - base
  let keyBase := (repeatedClamp 0).syntaxKey.length
  let keyStep := (repeatedClamp 1).syntaxKey.length - keyBase
  term.bindings.length == (if depth = 0 then 1 else 3) &&
    text.utf8ByteSize == base + depth * step &&
    term.syntaxKey.length == keyBase + depth * keyStep &&
    occurrences text "state_0_0" == 1 &&
    occurrences text "state_0_1" == depth &&
    occurrences text "state_0_2" == depth

#guard [0, 1, 12, 15, 32, 64].all linearGrowth

private def samples : List (NatTerm 3) :=
  [.literal 0, .unknown 0, .add (.unknown 0) (.unknown 1),
   .sub (.unknown 0) (.unknown 1),
   .iteEqual (.unknown 0) (.unknown 1) (.literal 2) (.literal 3),
   stored 0, .min (.unknown 0) (.unknown 1), .min (.unknown 1) (.unknown 0),
   .min (.unknown 0) (.unknown 2), .max (.unknown 0) (.unknown 1),
   .max (.unknown 1) (.unknown 0), .max (.unknown 0) (.unknown 2)]

#guard samples.all fun left => samples.all fun right =>
  (decide (left.syntaxKey = right.syntaxKey) == decide (left = right)) &&
    (compare left right == .eq) == decide (left = right)

private def referenceMin (left right : NatTerm 3) : NatTerm 3 :=
  (Expr.lessThan left right).ite left right

private def referenceMax (left right : NatTerm 3) : NatTerm 3 :=
  (Expr.lessThan left right).ite right left

private def prepared (expression : Expr 3) : Except String Prepared :=
  Formula.prepare
    [{ label := "entry", clauses := [] },
     { label := "observation", clauses := [{ label := "condition", expression }] }]

private def expect (solver text status : String) : IO String := do
  let result ← IO.Process.output { cmd := solver, args := #["--lang=smt2"] } (some text)
  unless result.exitCode == 0 &&
      (result.stdout.splitOn "\n").head? == some status do
    throw (IO.userError s!"expected {status}, exit={result.exitCode}\n{result.stdout}\n{result.stderr}")
  pure result.stdout

private def checked {α : Type} : Except String α -> IO α
  | .ok value => pure value
  | .error message => throw (IO.userError message)

def run (solver : String) : IO Unit := do
  let a : NatTerm 3 := .unknown 0
  let b : NatTerm 3 := .unknown 1
  let c : NatTerm 3 := .unknown 2
  -- Nested uses of the same let names must not capture surrounding operands.
  for (actual, expected) in [
      (a.min b, referenceMin a b),
      (a.max b, referenceMax a b),
      ((a.min b).max c, referenceMax (referenceMin a b) c),
      ((a.min b).min (b.min c), referenceMin (referenceMin a b) (referenceMin b c)),
      ((a.max b).max (b.max c), referenceMax (referenceMax a b) (referenceMax b c)),
      ((a.sub b).min (c.add a), referenceMin (a.sub b) (c.add a)),
      (a.min (.iteEqual b c a c), referenceMin a (.iteEqual b c a c))] do
    let query ← checked (prepared (.not (.equal actual expected)))
    let _ ← expect solver query.toSmt "unsat"
  for depth in [12, 15, 32, 64] do
    unless linearGrowth depth do
      throw (IO.userError s!"nonlinear min/max traversal or rendering at depth {depth}")
    let term := repeatedClamp depth
    let query ← checked (prepared (.equal term (.max (.min b a) c)))
    unless query.declarations.length == 12 &&
        query.groups.map (fun group => group.clauses.length) == [3, 1] do
      throw (IO.userError "repeated clamp added writers or lost entry definitions")
    let _ ← expect solver query.toSmt "sat"
    let contradiction ← checked (prepared (.not (.equal term (.max (.min b a) c))))
    let _ ← expect solver contradiction.toSmt "unsat"
    IO.println s!"min/max depth={depth} bindings={term.bindings.length} bytes={term.toSmt.utf8ByteSize}"
  let named : NatTerm 0 :=
    .max (.min (.named 0 0 "upper" (.literal 2))
      (.named 0 1 "old" (.literal 5))) (.named 0 2 "lower" (.literal 7))
  let query ← checked (Formula.prepare
    [{ label := "entry", clauses := [] },
     { label := "observation", clauses :=
         [{ label := "wrong value", expression := .equal named (.literal 5) }] }])
  let core ← expect solver
    ("(set-option :produce-unsat-cores true)\n" ++ query.toSmt ++ "(get-unsat-core)\n")
    "unsat"
  unless (core.splitOn "group_0").length == 2 && (core.splitOn "group_1").length == 2 do
    throw (IO.userError s!"min/max core lost the entry definitions or observation: {core}")
  let withoutEntry := { query with groups := query.groups.drop 1 }
  let _ ← expect solver withoutEntry.toSmt "sat"
  let withoutObservation := { query with groups := query.groups.take 1 }
  let _ ← expect solver withoutObservation.toSmt "sat"
  IO.println "min/max arbitrary-operand semantics, lexical scopes, naming, and linear growth passed"

end TraceSmt.MinMaxTests

run_cmd do
  for name in [``TraceSmt.NatTerm.min_eval, ``TraceSmt.NatTerm.max_eval,
      ``TraceSmt.NatTerm.syntaxKey_injective] do
    for axiomName in ← Lean.collectAxioms name do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{name} depends on unapproved axiom {axiomName}"

def main (args : List String) : IO Unit :=
  match args with
  | [solver] => TraceSmt.MinMaxTests.run solver
  | _ => throw (IO.userError "usage: SmtMinMaxTests.lean /path/to/cvc5")
