-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAssignmentEncoding
import Sparse.NativeMaxMatchEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem max_match_assignment {width : PNat} [Bootstrap (Fin width)]
    (before : Encoding width) (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (length cap : Expr .int) (eligible : Term [.int] .bool)
    (lengthNat capNat best : Nat) (eligibleModel : Nat -> Prop)
    (lengthBounded :
      length.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (capBounded :
      cap.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (eligibleBounded :
      eligible.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (sameLength :
      length.eval assignment Locals.empty = (lengthNat : Int))
    (sameCap : cap.eval assignment Locals.empty = (capNat : Int))
    (sameEligible : forall position, position < min capNat lengthNat ->
      (eligible.eval assignment (Locals.empty.cons (position : Int)) = true <->
        eligibleModel position))
    (summary :
      Sparse.LogMatchSummary.StorageSummary lengthNat capNat best eligibleModel) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
      Holds before.assertions.toList extended /\
      (.free .int before.next : Expr .int).eval extended Locals.empty =
        (best : Int) /\
      (maxMatchTerm length cap (.free .int before.next) eligible).eval
          extended Locals.empty = true := by
  let extended := assignment.set .int before.next (best : Int)
  have agreement : assignment.AgreesBelow before.next extended :=
    assignment.agrees_below_set before.next .int before.next (best : Int)
      (le_refl _)
  have boundedLength :
      forall symbol, symbol ∈ length.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp lengthBounded symbol member
  have boundedCap :
      forall symbol, symbol ∈ cap.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp capBounded symbol member
  have boundedEligible :
      forall symbol, symbol ∈ eligible.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp eligibleBounded symbol member
  have extendedLength :
      length.eval extended Locals.empty = (lengthNat : Int) :=
    (length.eval_agrees_below assignment extended Locals.empty before.next
      boundedLength agreement).symm.trans sameLength
  have extendedCap :
      cap.eval extended Locals.empty = (capNat : Int) :=
    (cap.eval_agrees_below assignment extended Locals.empty before.next
      boundedCap agreement).symm.trans sameCap
  have extendedEligible : forall position, position < min capNat lengthNat ->
      (eligible.eval extended (Locals.empty.cons (position : Int)) = true <->
        eligibleModel position) := by
    intro position live
    have sameEval :=
      eligible.eval_agrees_below assignment extended
        (Locals.empty.cons (position : Int)) before.next boundedEligible agreement
    rw [<- sameEval]
    exact sameEligible position live
  have sameSelected :
      (.free .int before.next : Expr .int).eval extended Locals.empty =
        (best : Int) := by
    simp [extended, Assignment.set, Term.eval]
  have accepted :
      (maxMatchTerm length cap (.free .int before.next) eligible).eval
          extended Locals.empty = true :=
    (max_match_term_correct extended Locals.empty length cap
      (.free .int before.next) eligible lengthNat capNat best eligibleModel
      extendedLength extendedCap sameSelected extendedEligible).mpr summary
  exact ⟨extended, agreement,
    before.holds_agrees_below assignment extended holds agreement,
    sameSelected, accepted⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
