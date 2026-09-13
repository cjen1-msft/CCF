-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNatSetInsert

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

private theorem nat_set_bound_member_correct {context : List Ty}
    (assignment : Assignment) (locals : Locals context)
    (cells limit : Nat) (index : Nat) :
    (natSetMember cells limit (.bound .here)).eval assignment
        (locals.cons (index : Int)) = true <->
      (index : Int) < assignment .int limit /\
        assignment (.array .int (.bits 1)) cells index = 1 := by
  simp [natSetMember, all, lt, Term.eval, Locals.cons]

theorem nat_set_insert_constraints_rep_correct {context : List Ty}
    (assignment : Assignment) (locals : Locals context)
    (oldCells oldLimit newCells newLimit : Nat)
    (value : Term context .int) (valueNat : Nat)
    (oldSet : Finset Nat)
    (oldRep : forall index : Nat,
      ((index : Int) < assignment .int oldLimit /\
        assignment (.array .int (.bits 1)) oldCells index = 1) <->
        index ∈ oldSet)
    (sameValue : value.eval assignment locals = (valueNat : Int)) :
    (natSetInsertConstraints oldCells oldLimit newCells newLimit value).eval
        assignment locals = true <->
      NatSetDomain assignment newLimit /\
        forall index : Nat,
          ((index : Int) < assignment .int newLimit /\
            assignment (.array .int (.bits 1)) newCells index = 1) <->
            index ∈ insert valueNat oldSet := by
  simp only [natSetInsertConstraints, Term.eval, Bool.and_eq_true,
    decide_eq_true_eq]
  constructor
  · rintro ⟨newDomain, accepted⟩
    refine ⟨newDomain, fun index => ?_⟩
    rw [Finset.mem_insert]
    have point := accepted (index : Int)
    constructor
    · intro newMember
      have newTrue :=
        (nat_set_bound_member_correct assignment locals newCells newLimit
          index).mpr newMember
      rw [point] at newTrue
      simp only [Bool.or_eq_true] at newTrue
      rcases newTrue with oldTrue | equalTrue
      · exact Or.inr
          (oldRep index |>.mp
            ((nat_set_bound_member_correct assignment locals oldCells oldLimit
              index).mp oldTrue))
      · have equalInt :
            (index : Int) = (valueNat : Int) := by
          have equalValue :
              locals.cons (index : Int) .int .here =
                (value.weaken .int).eval assignment
                  (locals.cons (index : Int)) := by
            by_contra different
            simp [different] at equalTrue
          simpa only [Locals.cons, Term.weaken_eval, sameValue] using equalValue
        exact Or.inl (Int.ofNat_inj.mp equalInt)
    · intro inserted
      rcases inserted with equal | oldMember
      · have equalInt : (index : Int) = (valueNat : Int) :=
          congrArg (fun value : Nat => (value : Int)) equal
        have equalValue :
            locals.cons (index : Int) .int .here =
              (value.weaken .int).eval assignment
                (locals.cons (index : Int)) := by
          simpa only [Locals.cons, Term.weaken_eval, sameValue] using equalInt
        apply
          (nat_set_bound_member_correct assignment locals newCells newLimit
            index).mp
        rw [point]
        simp only [Bool.or_eq_true]
        exact Or.inr (by simp [equalValue])
      · have oldTrue :=
          (nat_set_bound_member_correct assignment locals oldCells oldLimit
            index).mpr ((oldRep index).mpr oldMember)
        apply
          (nat_set_bound_member_correct assignment locals newCells newLimit
            index).mp
        rw [point]
        simp only [Bool.or_eq_true]
        exact Or.inl oldTrue
  · rintro ⟨newDomain, newRep⟩
    refine ⟨newDomain, ?_⟩
    intro index
    by_cases nonnegative : 0 <= index
    · let natural := index.toNat
      have sameIndex : (natural : Int) = index :=
        Int.toNat_of_nonneg nonnegative
      have point :
          ((natural : Int) < assignment .int newLimit /\
            assignment (.array .int (.bits 1)) newCells natural = 1) <->
              natural ∈ insert valueNat oldSet :=
        newRep natural
      rw [<- sameIndex]
      apply Bool.eq_iff_iff.mpr
      constructor
      · intro newTrue
        have newMember :=
          (nat_set_bound_member_correct assignment locals newCells newLimit
            natural).mp newTrue
        rw [point, Finset.mem_insert] at newMember
        rcases newMember with equal | oldMember
        · simp only [Bool.or_eq_true]
          apply Or.inr
          have equalInt := congrArg (fun value : Nat => (value : Int)) equal
          have equalValue :
              locals.cons (natural : Int) .int .here =
                (value.weaken .int).eval assignment
                  (locals.cons (natural : Int)) := by
            simpa only [Locals.cons, Term.weaken_eval, sameValue] using equalInt
          simp [equalValue]
        · simp only [Bool.or_eq_true]
          exact Or.inl
            ((nat_set_bound_member_correct assignment locals oldCells oldLimit
              natural).mpr ((oldRep natural).mpr oldMember))
      · intro rhsTrue
        apply
          (nat_set_bound_member_correct assignment locals newCells newLimit
            natural).mpr
        apply point.mpr
        rw [Finset.mem_insert]
        simp only [Bool.or_eq_true] at rhsTrue
        rcases rhsTrue with oldTrue | equalTrue
        · exact Or.inr
            (oldRep natural |>.mp
              ((nat_set_bound_member_correct assignment locals oldCells oldLimit
                natural).mp oldTrue))
        · have equalInt :
              (natural : Int) = (valueNat : Int) := by
            have equalValue :
                locals.cons (natural : Int) .int .here =
                  (value.weaken .int).eval assignment
                    (locals.cons (natural : Int)) := by
              by_contra different
              simp [different] at equalTrue
            simpa only [Locals.cons, Term.weaken_eval, sameValue] using equalValue
          exact Or.inl (Int.ofNat_inj.mp equalInt)
    · have different : index ≠ (valueNat : Int) := by
        intro same
        subst index
        exact nonnegative (Int.natCast_nonneg valueNat)
      have valueAt :
          (value.weaken .int).eval assignment (locals.cons index) =
            (valueNat : Int) := by
        simpa only [Term.weaken_eval] using sameValue
      simp [natSetMember, all, lt, Term.eval, Locals.cons, nonnegative,
        valueAt, different]

theorem nat_set_insert_constraints_correct {context : List Ty}
    (assignment : Assignment) (locals : Locals context)
    (oldCells oldLimit newCells newLimit : Nat)
    (value : Term context .int) (valueNat : Nat)
    (oldDomain : NatSetDomain assignment oldLimit)
    (sameValue : value.eval assignment locals = (valueNat : Int)) :
    (natSetInsertConstraints oldCells oldLimit newCells newLimit value).eval
        assignment locals = true <->
      exists newDomain : NatSetDomain assignment newLimit,
        (natSetArray assignment newCells newLimit newDomain).decode =
          insert valueNat
            (natSetArray assignment oldCells oldLimit oldDomain).decode := by
  let oldSet := (natSetArray assignment oldCells oldLimit oldDomain).decode
  have oldRep : forall index : Nat,
      ((index : Int) < assignment .int oldLimit /\
        assignment (.array .int (.bits 1)) oldCells index = 1) <->
        index ∈ oldSet := fun index =>
    (nat_set_member_correct assignment oldCells oldLimit oldDomain index).symm
  rw [nat_set_insert_constraints_rep_correct assignment locals oldCells oldLimit
    newCells newLimit value valueNat oldSet oldRep sameValue]
  constructor
  · rintro ⟨newDomain, newRep⟩
    refine ⟨newDomain, Finset.ext fun index => ?_⟩
    rw [nat_set_member_correct]
    exact newRep index
  · rintro ⟨newDomain, sameDecode⟩
    refine ⟨newDomain, fun index => ?_⟩
    rw [<- nat_set_member_correct assignment newCells newLimit newDomain index,
      sameDecode]

theorem nat_set_insert_rep_assignment {context : List Ty}
    (assignment : Assignment) (locals : Locals context)
    (oldCells oldLimit newCells newLimit boundary : Nat)
    (value : Term context .int) (valueNat : Nat)
    (oldSet : Finset Nat)
    (oldRep : forall index : Nat,
      ((index : Int) < assignment .int oldLimit /\
        assignment (.array .int (.bits 1)) oldCells index = 1) <->
        index ∈ oldSet)
    (oldCellsBounded : oldCells < boundary)
    (oldLimitBounded : oldLimit < boundary)
    (valueBounded :
      value.symbols.all (fun symbol => symbol.2 < boundary) = true)
    (newCellsFresh : boundary <= newCells)
    (newLimitFresh : boundary <= newLimit)
    (sameValue : value.eval assignment locals = (valueNat : Int)) :
    exists extended : Assignment,
      assignment.AgreesBelow boundary extended /\
      (natSetInsertConstraints oldCells oldLimit newCells newLimit value).eval
        extended locals = true /\
      NatSetDomain extended newLimit /\
      forall index : Nat,
        ((index : Int) < extended .int newLimit /\
          extended (.array .int (.bits 1)) newCells index = 1) <->
          index ∈ insert valueNat oldSet := by
  let values := insert valueNat oldSet
  let extended := natSetAssignment assignment newCells newLimit values
  have agreement : assignment.AgreesBelow boundary extended :=
    nat_set_assignment_agrees_below assignment newCells newLimit boundary values
      newCellsFresh newLimitFresh
  have sameOldLimit :
      assignment .int oldLimit = extended .int oldLimit :=
    agreement .int oldLimit oldLimitBounded
  have sameOldCells :
      assignment (.array .int (.bits 1)) oldCells =
        extended (.array .int (.bits 1)) oldCells :=
    agreement (.array .int (.bits 1)) oldCells oldCellsBounded
  have extendedOldRep : forall index : Nat,
      ((index : Int) < extended .int oldLimit /\
        extended (.array .int (.bits 1)) oldCells index = 1) <->
        index ∈ oldSet := by
    intro index
    rw [<- sameOldLimit, <- congrFun sameOldCells (index : Int)]
    exact oldRep index
  have boundedValue :
      forall symbol, symbol ∈ value.symbols -> symbol.2 < boundary := by
    intro symbol member
    simpa using List.all_eq_true.mp valueBounded symbol member
  have extendedValue :
      value.eval extended locals = (valueNat : Int) :=
    (value.eval_agrees_below assignment extended locals boundary boundedValue
      agreement).symm.trans sameValue
  have newDomain := nat_set_assignment_domain assignment newCells newLimit values
  have newRep : forall index : Nat,
      ((index : Int) < extended .int newLimit /\
        extended (.array .int (.bits 1)) newCells index = 1) <->
        index ∈ insert valueNat oldSet := by
    intro index
    exact nat_set_assignment_member assignment newCells newLimit values index
  have accepted :=
    (nat_set_insert_constraints_rep_correct extended locals oldCells oldLimit
      newCells newLimit value valueNat oldSet extendedOldRep extendedValue).mpr
      ⟨newDomain, newRep⟩
  exact ⟨extended, agreement, accepted, newDomain, newRep⟩

theorem nat_set_insert_assignment {context : List Ty}
    (assignment : Assignment) (locals : Locals context)
    (oldCells oldLimit newCells newLimit boundary : Nat)
    (value : Term context .int) (valueNat : Nat)
    (oldCellsBounded : oldCells < boundary)
    (oldLimitBounded : oldLimit < boundary)
    (valueBounded :
      value.symbols.all (fun symbol => symbol.2 < boundary) = true)
    (newCellsFresh : boundary <= newCells)
    (newLimitFresh : boundary <= newLimit)
    (oldDomain : NatSetDomain assignment oldLimit)
    (sameValue : value.eval assignment locals = (valueNat : Int)) :
    exists extended : Assignment,
      assignment.AgreesBelow boundary extended /\
      (natSetInsertConstraints oldCells oldLimit newCells newLimit value).eval
        extended locals = true /\
      exists newDomain : NatSetDomain extended newLimit,
        (natSetArray extended newCells newLimit newDomain).decode =
          insert valueNat
            (natSetArray assignment oldCells oldLimit oldDomain).decode := by
  let oldSet := (natSetArray assignment oldCells oldLimit oldDomain).decode
  have oldRep : forall index : Nat,
      ((index : Int) < assignment .int oldLimit /\
        assignment (.array .int (.bits 1)) oldCells index = 1) <->
        index ∈ oldSet := fun index =>
    (nat_set_member_correct assignment oldCells oldLimit oldDomain index).symm
  obtain ⟨extended, agreement, accepted, newDomain, newRep⟩ :=
    nat_set_insert_rep_assignment assignment locals oldCells oldLimit newCells
      newLimit boundary value valueNat oldSet oldRep oldCellsBounded
      oldLimitBounded valueBounded newCellsFresh newLimitFresh sameValue
  refine ⟨extended, agreement, accepted, newDomain, Finset.ext fun index => ?_⟩
  rw [nat_set_member_correct]
  exact newRep index

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
