-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicSmt
import Shared.BoundedContainer
import MachineGenerated.SymbolicEntry

set_option autoImplicit false

namespace Symbolic.NamedTests

private def scalar : Expr .nat := .named 0 0 (.add (.unknown 0) (.nat 1))
private def product : Expr (.pair .nat (.seq .nat)) :=
  .named 0 1 (.pair scalar (.ofList [.nat 4, .nat 5]))
private def sequence : Expr (.seq .nat) := .named 1 0 (.drop (.nat 1) product.snd)

#guard scalar.eval (fun _ => 8) == 9
#guard product.eval (fun _ => 8) == (9, [4, 5])
#guard sequence.eval (fun _ => 8) == [5]
#guard scalar.normalize == .named 0 0 (.add (.unknown 0) (.nat 1))
#guard (Expr.named 0 0 (.add (.nat 2) (.nat 3))).normalize ==
  .named 0 0 (.add (.nat 2) (.nat 3))
#guard product.fst.normalize == .fst product.normalize
#guard sequence.length.normalize == .length sequence.normalize
#guard ((Expr.named 0 2 (.inl (.nat 3)) : Expr (.sum .nat .bool)).isLeft).normalize ==
  .isLeft (.named 0 2 (.inl (.nat 3)) : Expr (.sum .nat .bool))

private def causal : List (List (Expr .bool)) :=
  [[], [], [.eq sequence.length (.nat 2)]]

private def rejected (groups : List (List (Expr .bool))) : Bool :=
  match prepareGroups groups with
  | .error _ => true
  | .ok _ => false

#guard !rejected causal
#guard match prepareGroups causal with
  | .error _ => false
  | .ok (groups, printed) =>
      groups.map List.length == [2, 1, 1] &&
        printed.stateDeclarations.size == 3 &&
        (groups[0]!).all (fun line => line.startsWith "(= state_0_") &&
        (groups[1]!).all (fun line => line.startsWith "(= state_1_") &&
        printed.definitions.all (fun line => !(line.startsWith "(assert"))
-- Duplicate occurrences produce one defining equality.
#guard match prepareGroups [[.eq scalar (.nat 1), .lt scalar (.nat 2)]] with
  | .error _ => false
  | .ok (groups, printed) => groups.map List.length == [3] &&
      printed.stateDeclarations.size == 1

#guard rejected [[.eq (.named 0 0 (.nat 1)) (.named 0 0 (.nat 2))]]
#guard rejected [[.eq (.named 0 0 (.nat 1)) (.nat 1),
  .named 0 0 (.bool true)]]
-- Conflicts are syntactic, not equality after normalization or evaluation.
#guard rejected [[.eq (.named 0 0 (.add (.nat 0) (.nat 1))) (.named 0 0 (.nat 1))]]
#guard rejected [[.eq (.named 1 0 (.nat 1)) (.nat 1)], []]
#guard rejected [[.eq (.named 2 0 (.nat 1)) (.nat 1)], []]
-- A definition cannot refer to a future owner, even when discovered later.
#guard rejected [[], [], [.eq (.named 0 0 (.named 1 0 (.nat 1))) (.nat 1)]]
#guard rejected [[.eq (.named 0 0 (.named 0 0 (.nat 1))) (.nat 1)]]
-- Dead syntax must not hide invalid ownership or conflicting definitions.
#guard rejected [[.and (.bool false) (.named 1 0 (.bool true))]]
#guard rejected [[.eq (.named 0 0 (.nat 1)) (.nat 1),
  .ite (.bool true) (.bool true) (.eq (.named 0 0 (.nat 2)) (.nat 2))]]
#guard !rejected [[.eq (.named 0 0 (.nat 1)) (.nat 1),
  .eq (.named 0 1 (.nat 2)) (.nat 2)]]
#guard !rejected [[], [.eq (.named 0 0 (.nat 1)) (.named 1 0 (.nat 1))]]

private def sum : Expr (.sum .nat .bool) := .named 0 2 (.inr (.bool true))
private def typed : List (List (Expr .bool)) :=
  [[], [.eq product.fst (.nat 1), .eq product.snd.length (.nat 2),
    sum.isLeft.not, .eq (sum.rightD (.bool false)) (.bool true),
    .named 0 3 (.bool true), .eq (.named 0 4 Expr.unit) Expr.unit]]

private def total : List (List (Expr .bool)) :=
  let value := Expr.named 0 0 (.bool false)
  [[.ite (.bool false) value (.bool true)], [value]]

private def scan (capacity : Nat) : Expr .bool :=
  let queue := Expr.named 0 0 <|
    Expr.take (.unknown 0) (.ofList ((List.range capacity).map fun i => .unknown (i + 1)))
  (Container.takeFirst (fun value => .eq value (.nat 7)) capacity queue).isLeft

private def bounds : CCFRaft.BoundedState.Bounds := ⟨0, 0, 0, 0, 0⟩
private def wholeState :=
  Expr.named 0 0 (CCFRaft.SymbolicModel.freshEntry bounds)
private def absent : Expr .bool :=
  (tableGet wholeState.fst (⟨14, by decide⟩ : CCFRaft.Node)).isLeft

#guard absent.eval (fun _ => 0)
#guard !absent.eval (fun _ => 1)
#guard match wholeState.normalize with
  | .named 0 0 _ => true
  | _ => false

example {s : Ty} (assignment : Assignment) (group slot : Nat) (value : Expr s) :
    (Expr.named group slot value).normalize.eval assignment = value.eval assignment := by
  rw [Expr.normalize_correct, eval_named]

private def expect (solver text expected : String) : IO String := do
  let result ← IO.Process.output { cmd := solver, args := #["--lang=smt2"] } (some text)
  unless result.exitCode == 0 do
    throw (IO.userError s!"solver failed: {result.stderr}\n{result.stdout}")
  unless (result.stdout.splitOn "\n").head? == some expected do
    throw (IO.userError s!"expected {expected}, got: {result.stdout}")
  return result.stdout

private def checked {α : Type} (result : Except String α) : IO α :=
  match result with
  | .ok value => pure value
  | .error message => throw (IO.userError message)

def run (solver : String) : IO Unit := do
  let text ← checked (scriptGroups causal)
  let core ← expect solver (text ++ "(get-unsat-core)\n") "unsat"
  let tokens := (core.replace "(" " " |>.replace ")" " " |>.replace "\n" " ").splitOn " "
  unless tokens.contains "group_0" && tokens.contains "group_1" &&
      tokens.contains "group_2" do
    throw (IO.userError s!"causal core lost an owner: {core}")
  -- Remove assertions from the prepared script, not the expression tree.
  -- The latter would rediscover and reinsert the producer definitions.
  for index in [0, 1, 2] do
    let reduced := String.intercalate "\n" <|
      (text.splitOn "\n").filter fun line =>
        !((line.splitOn s!":named group_{index})").length > 1)
    discard <| expect solver reduced "sat"
  discard <| expect solver (← checked (scriptGroups typed)) "sat"
  discard <| expect solver (← checked (scriptGroups total)) "unsat"
  discard <| expect solver
    (← checked (scriptGroups [[], [absent]])) "sat"
  discard <| expect solver
    (← checked (scriptGroups [[], [absent, absent.not]])) "unsat"
  -- Root serialization retains its original name-free behavior.
  discard <| expect solver
    (← checked (script [.eq (.sub (.nat 1) (.nat 2)) (.nat 0)])) "sat"
  for capacity in [16, 32] do
    let text ← checked (scriptGroups [[], [scan capacity]])
    if text.utf8ByteSize > 200000 then
      throw (IO.userError s!"named scan capacity {capacity} produced {text.utf8ByteSize} bytes")
    discard <| expect solver text "sat"
    IO.println s!"named scan capacity={capacity} bytes={text.utf8ByteSize}"
  IO.println "typed names, whole-state names, and causal-core regressions passed"

end Symbolic.NamedTests

run_cmd do
  for theoremName in [``Symbolic.eval_named, ``Symbolic.Expr.normalize_correct] do
    for axiomName in ← Lean.collectAxioms theoremName do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{theoremName} depends on unapproved axiom {axiomName}"

def main (args : List String) : IO Unit :=
  match args with
  | [solver] => Symbolic.NamedTests.run solver
  | _ => throw (IO.userError "usage: SymbolicNamedTests.lean /path/to/cvc5")
