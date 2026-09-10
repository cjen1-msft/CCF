-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicNaming
import Shared.SymbolicSmt

set_option autoImplicit false

namespace Symbolic.NamingTests

private def entry : Expr (.pair .nat .nat) :=
  .named 0 0 (.pair (.unknown 0) (.unknown 1))

private def predicate : Expr .bool := .eq (.unknown 2) (.nat 0)

private def groups (before after : Expr .bool) : List (List (Expr .bool)) :=
  [[], [before], [], [after]]

private def checked {α : Type} (result : Except String α) : IO α :=
  match result with
  | .ok value => pure value
  | .error error => throw (IO.userError error)

private def expect (solver label text expected : String) : IO String := do
  let result ← IO.Process.output { cmd := solver, args := #["--lang=smt2"] } (some text)
  unless result.exitCode == 0 &&
      (result.stdout.splitOn "\n").head? == some expected do
    throw (IO.userError s!"{label}: expected {expected}, got {result.stdout}\n{result.stderr}")
  return result.stdout

private def withoutGroup (text : String) (group : Nat) : String :=
  String.intercalate "\n" <| (text.splitOn "\n").filter fun line =>
    !((line.splitOn s!":named group_{group})").length > 1)

private def checkCausality (solver label : String)
    (formulas : List (List (Expr .bool))) (writerNeeded : Bool) : IO Unit := do
  let text ← checked (scriptGroups formulas)
  discard <| expect solver label text "unsat"
  discard <| expect solver (label ++ " without writer")
    (withoutGroup text 2) (if writerNeeded then "sat" else "unsat")
  for group in [1, 3] do
    discard <| expect solver s!"{label} without observation {group}"
      (withoutGroup text group) "sat"
  IO.println s!"{label}: exact observation/writer dependencies passed"

private def optionalEntry : Expr (.sum .unit (.pair .nat .nat)) :=
  .named 0 0 (.ite predicate (.inl .unit) (.inr (.pair (.unknown 0) (.unknown 1))))

def run (solver : String) : IO Unit := do
  let after := nameChanged 2 entry (.pair entry.fst (.add entry.snd (.nat 1)))
  unless @decide _ (after.fst.normalizeMemo.sharedDecEq entry.fst) do
    throw (IO.userError "untouched first field was not preserved")
  checkCausality solver "untouched field"
    (groups (.eq entry.fst (.nat 0)) (.eq after.fst (.nat 1))) false
  checkCausality solver "changed field"
    (groups (.eq entry.snd (.nat 0)) (.eq after.snd (.nat 2))) true
  let copied := nameChanged 2 entry (.pair entry.snd entry.snd)
  checkCausality solver "copy from different field"
    (groups (.eq entry.snd (.nat 0)) (.eq copied.fst (.nat 1))) true
  let conditional := nameChanged 2 entry
    (.pair (.ite predicate entry.fst (.add entry.fst (.nat 1))) entry.snd)
  checkCausality solver "unchanged conditional branch"
    (groups (.and predicate (.eq entry.fst (.nat 0)))
      (.eq conditional.fst (.nat 1))) false
  checkCausality solver "changed conditional branch"
    (groups (.and predicate.not (.eq entry.fst (.nat 0)))
      (.eq conditional.fst (.nat 2))) true
  let redundant := nameChanged 2 entry
    (.pair (.ite predicate entry.fst entry.fst) (.add entry.snd (.nat 1)))
  checkCausality solver "both branches unchanged"
    (groups (.eq entry.fst (.nat 0)) (.eq redundant.fst (.nat 1))) false
  let payload := optionalEntry.rightD (defaultExpr (.pair .nat .nat))
  let optionalAfter := nameChanged 2 optionalEntry
    (.ite optionalEntry.isLeft optionalEntry
      (.inr (.pair payload.fst (.add payload.snd (.nat 1)))))
  let afterPayload := optionalAfter.rightD (defaultExpr (.pair .nat .nat))
  checkCausality solver "nested optional unchanged field"
    (groups (.and optionalEntry.isLeft.not (.eq payload.fst (.nat 0)))
      (.eq afterPayload.fst (.nat 1))) false
  checkCausality solver "nested optional unchanged field to default"
    (groups (.and optionalEntry.isLeft.not (.eq payload.fst (.nat 1)))
      (.eq afterPayload.fst (.nat 0))) false
  checkCausality solver "nested optional unchanged constructor"
    (groups optionalEntry.isLeft.not optionalAfter.isLeft) false
  checkCausality solver "nested optional changed field"
    (groups (.and optionalEntry.isLeft.not (.eq payload.snd (.nat 0)))
      (.eq afterPayload.snd (.nat 2))) true
  let toggled := nameChanged 2 optionalEntry
    (.ite optionalEntry.isLeft (.inr payload) (.inl .unit))
  checkCausality solver "changed optional constructor"
    (groups optionalEntry.isLeft toggled.isLeft) true
  let same := nameChanged 2 entry entry
  unless @decide _ (same.sharedDecEq entry) do
    throw (IO.userError "identical state was not reused")
  let sequence : Expr (.pair (.seq .nat) .nat) :=
    .named 0 0 (.pair (.ofList [.unknown 0]) (.unknown 1))
  let sequenceAfter := nameChanged 2 sequence
    (.pair sequence.fst (.add sequence.snd (.nat 1)))
  checkCausality solver "unchanged sequence"
    (groups (.eq sequence.fst (.ofList [.nat 0]))
      (.eq sequenceAfter.fst (.ofList [.nat 1]))) false
  let appended := nameChanged 2 sequence
    (.pair (.append sequence.fst (.ofList [.nat 1])) sequence.snd)
  checkCausality solver "changed sequence"
    (groups (.eq sequence.fst (.ofList [.nat 0]))
      (.eq appended.fst (.ofList [.nat 1, .nat 1]))) true
  let inactiveValue := Expr.named 2 0 (.add entry.fst (.nat 1))
  checkCausality solver "inactive branch definition remains total"
    (groups (.and predicate (.eq entry.fst (.nat 0)))
      (.and (.eq conditional.fst entry.fst) (.eq inactiveValue (.nat 2)))) true
  let collision := nameChanged 2 entry (.pair (.nat 7) (.nat 8))
  discard <| checked (prepareGroups [[], [], [], [.eq collision collision]])
  match prepareGroups [[], [], [],
      [.eq collision collision, .eq (.named 2 0 (.nat 99)) (.nat 99)]] with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError "conflicting leaf name accepted")
  match prepareGroups [[.eq collision collision], [], [], []] with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError "future leaf owner accepted")
  IO.println "structural naming and ownership regressions passed"

end Symbolic.NamingTests

run_cmd do
  for axiomName in ← Lean.collectAxioms ``Symbolic.nameChanged_correct do
    unless axiomName == ``propext || axiomName == ``Classical.choice ||
        axiomName == ``Quot.sound do
      throwError "nameChanged_correct depends on unapproved axiom {axiomName}"

def main (args : List String) : IO Unit :=
  match args with
  | [solver] => Symbolic.NamingTests.run solver
  | _ => throw (IO.userError "usage: SymbolicNamingTests.lean /path/to/cvc5")
