-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Mathlib

set_option autoImplicit false

namespace CCFRaft.NativeArrayNatSet

structure Array where
  limit : Nat
  cells : Nat -> Bool

def Array.Valid (array : Array) : Prop :=
  forall index, array.limit <= index -> array.cells index = false

def Array.decode (array : Array) : Finset Nat :=
  (Finset.range array.limit).filter fun index => array.cells index

def Array.ofFinset (values : Finset Nat) : Array :=
  { limit := values.sup Nat.succ, cells := fun index => decide (index ∈ values) }

theorem member_correct (array : Array) (valid : array.Valid) (index : Nat) :
    index ∈ array.decode <-> array.cells index = true := by
  simp only [Array.decode, Finset.mem_filter, Finset.mem_range]
  constructor
  · exact And.right
  · intro present
    refine ⟨?_, present⟩
    by_contra outside
    have absent := valid index (by omega)
    simp [absent] at present

theorem of_finset_valid (values : Finset Nat) : (Array.ofFinset values).Valid := by
  intro index outside
  simp only [Array.ofFinset] at outside ⊢
  apply decide_eq_false
  intro member
  have bound : Nat.succ index <= values.sup Nat.succ := Finset.le_sup member
  omega

theorem of_finset_correct (values : Finset Nat) : (Array.ofFinset values).decode = values := by
  ext index
  rw [member_correct _ (of_finset_valid values)]
  simp [Array.ofFinset]

theorem exists_iff (predicate : Finset Nat -> Prop) :
    (exists array : Array, array.Valid /\ predicate array.decode) <->
      exists values : Finset Nat, predicate values := by
  constructor
  · rintro ⟨array, _, holds⟩
    exact ⟨array.decode, holds⟩
  · rintro ⟨values, holds⟩
    exact ⟨Array.ofFinset values, of_finset_valid values, by simpa [of_finset_correct] using holds⟩

end CCFRaft.NativeArrayNatSet

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayNatSet).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
