-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.ControlTraceConfigurations

set_option autoImplicit false

namespace CCFRaft.ReceiveTraceConfigurations

open TraceSmt ControlTraceConfigurations

theorem configurationsFrom_append {Tx : Type} (left right : List (Entry Node Tx)) (start : Nat) :
    configurationsInLogFrom start (left ++ right) =
      configurationsInLogFrom start left ++ configurationsInLogFrom (start + left.length) right := by
  induction left generalizing start with
  | nil => simp [configurationsInLogFrom]
  | cons entry rest ih =>
      cases content : entry.content <;>
        simp [configurationsInLogFrom, content, ih, Nat.add_assoc, Nat.add_comm, Nat.add_left_comm]

theorem allConfigurations_append {Tx : Type} (left right : List (Entry Node Tx)) :
    allConfigurations (left ++ right) =
      allConfigurations left ++ configurationsInLogFrom (left.length + 1) right := by
  simp [allConfigurations, configurationsInLog, configurationsFrom_append, Nat.add_comm]

def copied {holes : Nat} (configurations : List (Configuration Node))
    (positions : Nat -> NatTerm holes) (lower upper : NatTerm holes)
    (group : Nat) (slot : Nat -> Nat) : List (Snapshot holes) :=
  configurations.map fun configuration =>
    { configuration
      position := positions configuration.index
      present := .named group (slot configuration.index) "received configuration present"
        ((Expr.and (.lessThan lower (positions configuration.index))
          (.not (.lessThan upper (positions configuration.index)))).ite (.literal 1) (.literal 0)) }

theorem copied_correct {holes : Nat} (assignment : Fin holes -> Nat) (configurations : List (Configuration Node))
    (positions : Nat -> NatTerm holes) (lower upper : NatTerm holes) (group : Nat) (slot : Nat -> Nat)
    (positionsCorrect : ∀ index, (positions index).eval assignment = index)
    (inside : ∀ configuration ∈ configurations,
      lower.eval assignment < configuration.index ∧ configuration.index ≤ upper.eval assignment) :
    Correct assignment configurations (copied configurations positions lower upper group slot) := by
  have present (configuration : Configuration Node) (member : configuration ∈ configurations) :
      (((Expr.and (.lessThan lower (positions configuration.index))
        (.not (.lessThan upper (positions configuration.index)))).ite (.literal 1) (.literal 0))).eval assignment = 1 := by
    simp [Expr.ite_eval, Expr.Holds, positionsCorrect, (inside configuration member).1,
      (inside configuration member).2, NatTerm.eval]
  constructor
  · simp [copied, positionsCorrect]
  · intro snapshot member
    simp only [copied, List.mem_map] at member
    obtain ⟨configuration, member, rfl⟩ := member
    exact Or.inr (present configuration member)
  · simp only [selected, copied, List.filter_map]
    have filtered :
        configurations.filter (fun configuration =>
          ((NatTerm.named group (slot configuration.index) "received configuration present"
            ((Expr.and (.lessThan lower (positions configuration.index))
              (.not (.lessThan upper (positions configuration.index)))).ite (.literal 1) (.literal 0))).eval assignment == 1)) =
          configurations := by
      apply List.filter_eq_self.mpr
      intro configuration member
      simp [NatTerm.eval, present configuration member]
    simp [filtered, Function.comp_def]

theorem append_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (left right : List (Configuration Node)) (old added : List (Snapshot holes))
    (oldCorrect : Correct assignment left old) (addedCorrect : Correct assignment right added) :
    Correct assignment (left ++ right) (old ++ added) := by
  constructor
  · intro snapshot member
    rcases List.mem_append.mp member with member | member
    · exact oldCorrect.positions snapshot member
    · exact addedCorrect.positions snapshot member
  · intro snapshot member
    rcases List.mem_append.mp member with member | member
    · exact oldCorrect.presence snapshot member
    · exact addedCorrect.presence snapshot member
  · simpa [selected, List.filter_append, List.map_append] using
      congrArg₂ List.append oldCorrect.selected addedCorrect.selected

end CCFRaft.ReceiveTraceConfigurations
