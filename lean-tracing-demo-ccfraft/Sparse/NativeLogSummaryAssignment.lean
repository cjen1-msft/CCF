-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAssignmentEncoding
import Sparse.NativeLogSummaryEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem current_configuration_index_assignment {width : PNat}
    [Bootstrap (Fin width)] (before : Encoding width)
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (length : Expr .int) (entries : Expr (.array .int (entryTy width)))
    (commit : Expr .int) (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (commitNat : Nat)
    (lengthBounded :
      length.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (entriesBounded :
      entries.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (commitBounded :
      commit.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (sameLength : length.eval assignment Locals.empty = (log.length : Int))
    (sameCommit : commit.eval assignment Locals.empty = (commitNat : Int))
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment Locals.empty (position : Int)) =
        log.entries position) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
        Holds before.assertions.toList extended /\
        (currentConfigurationIndexTerm width length entries commit
          (.free .int before.next)).eval extended Locals.empty = true := by
  let current := (currentConfigurationAt log.decode commitNat).index
  let extended := assignment.set .int before.next (current : Int)
  have agreement : assignment.AgreesBelow before.next extended :=
    assignment.agrees_below_set before.next .int before.next (current : Int)
      (le_refl _)
  have boundedLength :
      forall symbol, symbol ∈ length.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp lengthBounded symbol member
  have boundedEntries :
      forall symbol, symbol ∈ entries.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp entriesBounded symbol member
  have boundedCommit :
      forall symbol, symbol ∈ commit.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp commitBounded symbol member
  have extendedLength :
      length.eval extended Locals.empty = (log.length : Int) :=
    (length.eval_agrees_below assignment extended Locals.empty before.next
      boundedLength agreement).symm.trans sameLength
  have extendedCommit :
      commit.eval extended Locals.empty = (commitNat : Int) :=
    (commit.eval_agrees_below assignment extended Locals.empty before.next
      boundedCommit agreement).symm.trans sameCommit
  have extendedEntries : forall position, position < log.length ->
      modelEntry (entries.eval extended Locals.empty (position : Int)) =
        log.entries position := by
    intro position live
    have sameArray :=
      entries.eval_agrees_below assignment extended Locals.empty before.next
        boundedEntries agreement
    rw [<- sameArray]
    exact sameEntries position live
  have sameSelected :
      (Term.free .int before.next).eval extended Locals.empty = (current : Int) := by
    simp only [Term.eval]
    simp [extended, Assignment.set]
  refine ⟨extended, agreement,
    before.holds_agrees_below assignment extended holds agreement, ?_⟩
  apply (current_configuration_index_term_correct extended Locals.empty length entries
    commit (.free .int before.next) log commitNat current extendedLength extendedCommit
    sameSelected extendedEntries).mpr
  rfl

theorem bounded_signature_assignment {width : PNat} [Bootstrap (Fin width)]
    (before : Encoding width) (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (length : Expr .int) (entries : Expr (.array .int (entryTy width)))
    (cap : Expr .int) (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (capNat : Nat)
    (lengthBounded :
      length.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (entriesBounded :
      entries.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (capBounded :
      cap.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (sameLength : length.eval assignment Locals.empty = (log.length : Int))
    (sameCap : cap.eval assignment Locals.empty = (capNat : Int))
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment Locals.empty (position : Int)) =
        log.entries position) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
        Holds before.assertions.toList extended /\
        (boundedSignatureTerm width length entries cap
          (.free .int before.next)).eval extended Locals.empty = true := by
  let best := maxCommittableIndexUpTo log.decode capNat
  let extended := assignment.set .int before.next (best : Int)
  have agreement : assignment.AgreesBelow before.next extended :=
    assignment.agrees_below_set before.next .int before.next (best : Int)
      (le_refl _)
  have boundedLength :
      forall symbol, symbol ∈ length.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp lengthBounded symbol member
  have boundedEntries :
      forall symbol, symbol ∈ entries.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp entriesBounded symbol member
  have boundedCap :
      forall symbol, symbol ∈ cap.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp capBounded symbol member
  have extendedLength :
      length.eval extended Locals.empty = (log.length : Int) :=
    (length.eval_agrees_below assignment extended Locals.empty before.next
      boundedLength agreement).symm.trans sameLength
  have extendedCap : cap.eval extended Locals.empty = (capNat : Int) :=
    (cap.eval_agrees_below assignment extended Locals.empty before.next
      boundedCap agreement).symm.trans sameCap
  have extendedEntries : forall position, position < log.length ->
      modelEntry (entries.eval extended Locals.empty (position : Int)) =
        log.entries position := by
    intro position live
    have sameArray :=
      entries.eval_agrees_below assignment extended Locals.empty before.next
        boundedEntries agreement
    rw [<- sameArray]
    exact sameEntries position live
  have sameSelected :
      (Term.free .int before.next).eval extended Locals.empty = (best : Int) := by
    simp only [Term.eval]
    simp [extended, Assignment.set]
  refine ⟨extended, agreement,
    before.holds_agrees_below assignment extended holds agreement, ?_⟩
  apply (bounded_signature_term_correct extended Locals.empty length entries cap
    (.free .int before.next) log capNat best extendedLength extendedCap sameSelected
    extendedEntries).mpr
  rfl

theorem nack_match_assignment {width : PNat} [Bootstrap (Fin width)]
    (before : Encoding width) (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (length : Expr .int) (entries : Expr (.array .int (entryTy width)))
    (previous threshold : Expr .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (previousNat thresholdNat : Nat)
    (lengthBounded :
      length.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (entriesBounded :
      entries.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (previousBounded :
      previous.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (thresholdBounded :
      threshold.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (sameLength : length.eval assignment Locals.empty = (log.length : Int))
    (samePrevious : previous.eval assignment Locals.empty = (previousNat : Int))
    (sameThreshold : threshold.eval assignment Locals.empty = (thresholdNat : Int))
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment Locals.empty (position : Int)) =
        log.entries position) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
        Holds before.assertions.toList extended /\
        (nackMatchTerm width length entries previous threshold
          (.free .int before.next)).eval extended Locals.empty = true := by
  let best := findHighestPossibleMatch log.decode previousNat thresholdNat
  let extended := assignment.set .int before.next (best : Int)
  have agreement : assignment.AgreesBelow before.next extended :=
    assignment.agrees_below_set before.next .int before.next (best : Int)
      (le_refl _)
  have boundedLength :
      forall symbol, symbol ∈ length.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp lengthBounded symbol member
  have boundedEntries :
      forall symbol, symbol ∈ entries.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp entriesBounded symbol member
  have boundedPrevious :
      forall symbol, symbol ∈ previous.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp previousBounded symbol member
  have boundedThreshold :
      forall symbol, symbol ∈ threshold.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp thresholdBounded symbol member
  have extendedLength :
      length.eval extended Locals.empty = (log.length : Int) :=
    (length.eval_agrees_below assignment extended Locals.empty before.next
      boundedLength agreement).symm.trans sameLength
  have extendedPrevious :
      previous.eval extended Locals.empty = (previousNat : Int) :=
    (previous.eval_agrees_below assignment extended Locals.empty before.next
      boundedPrevious agreement).symm.trans samePrevious
  have extendedThreshold :
      threshold.eval extended Locals.empty = (thresholdNat : Int) :=
    (threshold.eval_agrees_below assignment extended Locals.empty before.next
      boundedThreshold agreement).symm.trans sameThreshold
  have extendedEntries : forall position, position < log.length ->
      modelEntry (entries.eval extended Locals.empty (position : Int)) =
        log.entries position := by
    intro position live
    have sameArray :=
      entries.eval_agrees_below assignment extended Locals.empty before.next
        boundedEntries agreement
    rw [<- sameArray]
    exact sameEntries position live
  have sameSelected :
      (Term.free .int before.next).eval extended Locals.empty = (best : Int) := by
    simp only [Term.eval]
    simp [extended, Assignment.set]
  refine ⟨extended, agreement,
    before.holds_agrees_below assignment extended holds agreement, ?_⟩
  apply (nack_match_term_correct extended Locals.empty length entries previous threshold
    (.free .int before.next) log previousNat thresholdNat best extendedLength
    extendedPrevious extendedThreshold sameSelected extendedEntries).mpr
  rfl

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
