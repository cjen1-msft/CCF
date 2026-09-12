-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEncodeProofs
import Sparse.NativeArrayNatSet

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def natSetDomain (cells limit : Nat) : Expr .bool :=
  .and (.le (.integer 0) (.free .int limit))
    (.forall_ .int (implies
      (.or (lt (.bound .here) (.integer 0)) (.le (.free .int limit) (.bound .here)))
      (.not (.select (.free (.array .int .bool) cells) (.bound .here)))))

def NatSetDomain (assignment : Assignment) (cells limit : Nat) : Prop :=
  0 <= assignment .int limit /\
    forall index : Int, index < 0 \/ assignment .int limit <= index ->
      assignment (.array .int .bool) cells index = false

theorem nat_set_domain_correct (assignment : Assignment) (cells limit : Nat) :
    (natSetDomain cells limit).eval assignment Locals.empty = true <->
      NatSetDomain assignment cells limit := by
  simp only [natSetDomain, NatSetDomain, Term.eval, Bool.and_eq_true, decide_eq_true_eq]
  apply and_congr_right
  intro _
  apply forall_congr'
  intro index
  rw [implies_eval]
  simp [lt, Term.eval, Locals.cons]

def natSetArray (assignment : Assignment) (cells limit : Nat)
    (_domain : NatSetDomain assignment cells limit) : NativeArrayNatSet.Array :=
  { limit := (assignment .int limit).toNat
    cells := fun index => assignment (.array .int .bool) cells index }

theorem nat_set_array_valid (assignment : Assignment) (cells limit : Nat)
    (domain : NatSetDomain assignment cells limit) :
    (natSetArray assignment cells limit domain).Valid := by
  intro index outside
  exact domain.2 index (Or.inr (by
    change (assignment .int limit).toNat <= index at outside
    simpa only [Int.toNat_of_nonneg domain.1] using Int.ofNat_le.mpr outside))

theorem nat_set_member_correct (assignment : Assignment) (cells limit : Nat)
    (domain : NatSetDomain assignment cells limit) (index : Nat) :
    index ∈ (natSetArray assignment cells limit domain).decode <->
      assignment (.array .int .bool) cells index = true :=
  NativeArrayNatSet.member_correct _ (nat_set_array_valid assignment cells limit domain) index

theorem nat_set_observation_correct (assignment : Assignment) (cells limit : Nat)
    (domain : NatSetDomain assignment cells limit) (index : Nat) (expected : Bool) :
    (Term.equal (.select (.free (.array .int .bool) cells) (.integer index))
      (.boolean expected)).eval assignment Locals.empty = true <->
      decide (index ∈ (natSetArray assignment cells limit domain).decode) = expected := by
  simp only [Term.eval, decide_eq_true_eq]
  have membership := nat_set_member_correct assignment cells limit domain index
  have value : decide (index ∈ (natSetArray assignment cells limit domain).decode) =
      assignment (.array .int .bool) cells index := by
    apply Bool.eq_iff_iff.mpr
    simpa using membership
  rw [value]

def natSetAssignment (seed : Assignment) (cells limit : Nat) (values : Finset Nat) : Assignment :=
  let assignment := seed.set (.array .int .bool) cells
    (fun index => decide (0 <= index /\ index.toNat ∈ values))
  assignment.set .int limit (NativeArrayNatSet.Array.ofFinset values).limit

theorem nat_set_assignment_agrees_below (seed : Assignment) (cells limit boundary : Nat)
    (values : Finset Nat) (cellsFresh : boundary <= cells) (limitFresh : boundary <= limit) :
    seed.AgreesBelow boundary (natSetAssignment seed cells limit values) := by
  let filled := seed.set (.array .int .bool) cells
    (fun index => decide (0 <= index /\ index.toNat ∈ values))
  have first : seed.AgreesBelow boundary filled :=
    seed.agrees_below_set boundary _ cells _ cellsFresh
  exact first.trans
    (filled.agrees_below_set boundary .int limit (NativeArrayNatSet.Array.ofFinset values).limit limitFresh)

theorem nat_set_assignment_domain (seed : Assignment) (cells limit : Nat) (values : Finset Nat) :
    NatSetDomain (natSetAssignment seed cells limit values) cells limit := by
  constructor
  · simp [natSetAssignment, Assignment.set]
  · intro index outside
    have outside' : index < 0 \/ ((values.sup Nat.succ : Nat) : Int) <= index := by
      simpa [natSetAssignment, Assignment.set, NativeArrayNatSet.Array.ofFinset] using outside
    have absent : Not (0 <= index /\ index.toNat ∈ values) := by
      rintro ⟨nonnegative, member⟩
      have bound : index.toNat + 1 <= values.sup Nat.succ := Finset.le_sup member
      have same := Int.toNat_of_nonneg nonnegative
      rcases outside' with negative | beyond <;> omega
    simpa [natSetAssignment, Assignment.set] using absent

theorem nat_set_assignment_decode (seed : Assignment) (cells limit : Nat) (values : Finset Nat) :
    (natSetArray (natSetAssignment seed cells limit values) cells limit
      (nat_set_assignment_domain seed cells limit values)).decode = values := by
  ext index
  rw [nat_set_member_correct]
  simp [natSetAssignment, Assignment.set]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
