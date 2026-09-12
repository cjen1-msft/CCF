-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEncodeProofs
import Sparse.NativeArrayNatSet

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def natSetMember {context : List Ty} (cells limit : Nat) (index : Term context .int) : Term context .bool :=
  all [.le (.integer 0) index, lt index (.free .int limit),
    .equal (.select (.free (.array .int (.bits 1)) cells) index) (.bits 1)]

def natSetDomain (limit : Nat) : Expr .bool :=
  .le (.integer 0) (.free .int limit)

def NatSetDomain (assignment : Assignment) (limit : Nat) : Prop :=
  0 <= assignment .int limit

theorem nat_set_domain_correct (assignment : Assignment) (limit : Nat) :
    (natSetDomain limit).eval assignment Locals.empty = true <->
      NatSetDomain assignment limit := by
  simp [natSetDomain, NatSetDomain, Term.eval]

def natSetArray (assignment : Assignment) (cells limit : Nat)
    (_domain : NatSetDomain assignment limit) : NativeArrayNatSet.Array :=
  { limit := (assignment .int limit).toNat
    cells := fun index => decide (index < (assignment .int limit).toNat /\
      assignment (.array .int (.bits 1)) cells index = 1) }

theorem nat_set_array_valid (assignment : Assignment) (cells limit : Nat)
    (domain : NatSetDomain assignment limit) :
    (natSetArray assignment cells limit domain).Valid := by
  intro index outside
  change (assignment .int limit).toNat <= index at outside
  simp only [natSetArray, Nat.not_lt.mpr outside, false_and, decide_false]

theorem nat_set_member_correct (assignment : Assignment) (cells limit : Nat)
    (domain : NatSetDomain assignment limit) (index : Nat) :
    index ∈ (natSetArray assignment cells limit domain).decode <->
      (index : Int) < assignment .int limit /\ assignment (.array .int (.bits 1)) cells index = 1 := by
  have cast : (index < (assignment .int limit).toNat) <-> (index : Int) < assignment .int limit := by
    rw [<- Int.ofNat_lt, Int.toNat_of_nonneg domain]
  simpa only [natSetArray, decide_eq_true_eq, cast] using
    NativeArrayNatSet.member_correct _ (nat_set_array_valid assignment cells limit domain) index

theorem nat_set_observation_correct (assignment : Assignment) (cells limit : Nat)
    (domain : NatSetDomain assignment limit) (index : Nat) (expected : Bool) :
    (Term.equal (natSetMember cells limit (.integer index))
      (.boolean expected)).eval assignment Locals.empty = true <->
      decide (index ∈ (natSetArray assignment cells limit domain).decode) = expected := by
  have membership := nat_set_member_correct assignment cells limit domain index
  cases expected <;> simp [natSetMember, all, lt, Term.eval, membership]
  simp only [or_iff_not_imp_left, not_le]

def natSetAssignment (seed : Assignment) (cells limit : Nat) (values : Finset Nat) : Assignment :=
  let assignment := seed.set (.array .int (.bits 1)) cells
    (fun index => if 0 <= index /\ index.toNat ∈ values then 1 else 0)
  assignment.set .int limit (NativeArrayNatSet.Array.ofFinset values).limit

theorem nat_set_assignment_agrees_below (seed : Assignment) (cells limit boundary : Nat)
    (values : Finset Nat) (cellsFresh : boundary <= cells) (limitFresh : boundary <= limit) :
    seed.AgreesBelow boundary (natSetAssignment seed cells limit values) := by
  let filled := seed.set (.array .int (.bits 1)) cells
    (fun index => if 0 <= index /\ index.toNat ∈ values then 1 else 0)
  have first : seed.AgreesBelow boundary filled :=
    seed.agrees_below_set boundary _ cells _ cellsFresh
  exact first.trans
    (filled.agrees_below_set boundary .int limit (NativeArrayNatSet.Array.ofFinset values).limit limitFresh)

theorem nat_set_assignment_domain (seed : Assignment) (cells limit : Nat) (values : Finset Nat) :
    NatSetDomain (natSetAssignment seed cells limit values) limit := by
  simp [NatSetDomain, natSetAssignment, Assignment.set]

theorem nat_set_assignment_member (seed : Assignment) (cells limit : Nat) (values : Finset Nat) (index : Nat) :
    ((index : Int) < (natSetAssignment seed cells limit values) .int limit /\
      (natSetAssignment seed cells limit values) (.array .int (.bits 1)) cells index = 1) <->
      index ∈ values := by
  simp [natSetAssignment, Assignment.set, NativeArrayNatSet.Array.ofFinset]
  intro member
  exact ⟨index, member, le_refl _⟩

theorem nat_set_assignment_decode (seed : Assignment) (cells limit : Nat) (values : Finset Nat) :
    (natSetArray (natSetAssignment seed cells limit values) cells limit
      (nat_set_assignment_domain seed cells limit values)).decode = values := by
  ext index
  rw [nat_set_member_correct]
  exact nat_set_assignment_member seed cells limit values index

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
