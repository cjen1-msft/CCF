-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.Guarded

set_option autoImplicit false

namespace TraceSmt.GuardedTests

def unknown0 : NatTerm 2 := .unknown ⟨0, by decide⟩
def unknown1 : NatTerm 2 := .unknown ⟨1, by decide⟩

def sameAssignment : Fin 2 -> Nat
  | ⟨0, _⟩ => 7
  | ⟨1, _⟩ => 7

def distinctAssignment : Fin 2 -> Nat
  | ⟨0, _⟩ => 7
  | ⟨1, _⟩ => 9

def equalityBranch : Guarded 2 String :=
  .branch
    (.equal unknown0 unknown1)
    (.pure "same")
    (.pure "different")

#guard equalityBranch.eval sameAssignment == "same"
#guard equalityBranch.eval distinctAssignment == "different"

#guard
  (Guarded.branchSmart (.boolean true) (.pure 1) (.pure 2) :
    Guarded 2 Nat).eval sameAssignment == 1
#guard
  (Guarded.branchSmart (.boolean false) (.pure 1) (.pure 2) :
    Guarded 2 Nat).eval sameAssignment == 2

def mappedBranch : Guarded 2 Nat :=
  equalityBranch.map String.length

#guard mappedBranch.eval sameAssignment == 4
#guard mappedBranch.eval distinctAssignment == 9

def boundBranch : Guarded 2 Nat :=
  equalityBranch.bind fun result =>
    if result == "same" then .pure 1 else .pure 2

#guard boundBranch.eval sameAssignment == 1
#guard boundBranch.eval distinctAssignment == 2

def selectedLeafIsSame : Expr 2 :=
  equalityBranch.test fun value => .boolean (value == "same")

#guard decide (selectedLeafIsSame.Holds sameAssignment)
#guard !decide (selectedLeafIsSame.Holds distinctAssignment)

def termEqual (left right : NatTerm 2) : Expr 2 :=
  .equal left right

def symbolicQueue : List (NatTerm 2) := [unknown0]

#guard
  ((Guarded.enqueueNoDup termEqual unknown1 symbolicQueue).eval sameAssignment).map
    (NatTerm.eval sameAssignment) == [7]

#guard
  ((Guarded.enqueueNoDup termEqual unknown1 symbolicQueue).eval
    distinctAssignment).map (NatTerm.eval distinctAssignment) == [7, 9]

example (assignment : Fin 2 -> Nat) :
    ((Guarded.enqueueNoDup termEqual unknown1 symbolicQueue).eval assignment).map
        (NatTerm.eval assignment) =
      if unknown1.eval assignment ∈
          symbolicQueue.map (NatTerm.eval assignment) then
        symbolicQueue.map (NatTerm.eval assignment)
      else
        symbolicQueue.map (NatTerm.eval assignment) ++
          [unknown1.eval assignment] := by
  apply Guarded.eval_enqueueNoDup_map
  intro left right
  rfl

end TraceSmt.GuardedTests
