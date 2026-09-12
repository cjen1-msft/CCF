-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAssignmentEncoding
import Sparse.NativeLogSpliceEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem log_splice_assignment {width : PNat}
    (before : Encoding width) (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (oldLength : Expr .int)
    (oldEntries : Expr (.array .int (entryTy width)))
    (payloadLength : Expr .int)
    (payloadEntries : Expr (.array .int (entryTy width)))
    (previous : Expr .int)
    (oldLengthValue payloadLengthValue previousIndex : Nat)
    (tail : Int -> (entryTy width).denote)
    (oldLengthBounded :
      oldLength.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (oldEntriesBounded :
      oldEntries.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (payloadLengthBounded :
      payloadLength.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (payloadEntriesBounded :
      payloadEntries.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (previousBounded :
      previous.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (sameOldLength :
      oldLength.eval assignment Locals.empty = (oldLengthValue : Int))
    (samePayloadLength :
      payloadLength.eval assignment Locals.empty = (payloadLengthValue : Int))
    (samePrevious : previous.eval assignment Locals.empty = (previousIndex : Int)) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
        Holds before.assertions.toList extended /\
        extended (.array .int (entryTy width)) before.next =
          spliceRawOutput
            (oldEntries.eval assignment Locals.empty)
            (payloadEntries.eval assignment Locals.empty)
            tail oldLengthValue payloadLengthValue previousIndex /\
        (logSpliceTerm width oldLength oldEntries payloadLength payloadEntries previous
          (.free (.array .int (entryTy width)) before.next)).eval
            extended Locals.empty = true := by
  let output :=
    spliceRawOutput
      (oldEntries.eval assignment Locals.empty)
      (payloadEntries.eval assignment Locals.empty)
      tail oldLengthValue payloadLengthValue previousIndex
  let extended :=
    assignment.set (.array .int (entryTy width)) before.next output
  have agreement : assignment.AgreesBelow before.next extended :=
    assignment.agrees_below_set before.next (.array .int (entryTy width))
      before.next output (le_refl _)
  have boundedOldLength :
      forall symbol, symbol ∈ oldLength.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp oldLengthBounded symbol member
  have boundedOldEntries :
      forall symbol, symbol ∈ oldEntries.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp oldEntriesBounded symbol member
  have boundedPayloadLength :
      forall symbol, symbol ∈ payloadLength.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp payloadLengthBounded symbol member
  have boundedPayloadEntries :
      forall symbol, symbol ∈ payloadEntries.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp payloadEntriesBounded symbol member
  have boundedPrevious :
      forall symbol, symbol ∈ previous.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp previousBounded symbol member
  have extendedOldLength :
      oldLength.eval extended Locals.empty = (oldLengthValue : Int) :=
    (oldLength.eval_agrees_below assignment extended Locals.empty before.next
      boundedOldLength agreement).symm.trans sameOldLength
  have extendedPayloadLength :
      payloadLength.eval extended Locals.empty = (payloadLengthValue : Int) :=
    (payloadLength.eval_agrees_below assignment extended Locals.empty before.next
      boundedPayloadLength agreement).symm.trans samePayloadLength
  have extendedPrevious :
      previous.eval extended Locals.empty = (previousIndex : Int) :=
    (previous.eval_agrees_below assignment extended Locals.empty before.next
      boundedPrevious agreement).symm.trans samePrevious
  have extendedOldEntries :
      oldEntries.eval extended Locals.empty =
        oldEntries.eval assignment Locals.empty :=
    (oldEntries.eval_agrees_below assignment extended Locals.empty before.next
      boundedOldEntries agreement).symm
  have extendedPayloadEntries :
      payloadEntries.eval extended Locals.empty =
        payloadEntries.eval assignment Locals.empty :=
    (payloadEntries.eval_agrees_below assignment extended Locals.empty before.next
      boundedPayloadEntries agreement).symm
  have assigned :
      extended (.array .int (entryTy width)) before.next =
        spliceRawOutput
          (oldEntries.eval assignment Locals.empty)
          (payloadEntries.eval assignment Locals.empty)
          tail oldLengthValue payloadLengthValue previousIndex := by
    simp [extended, output, Assignment.set]
  have sameOutput :
      (Term.free (.array .int (entryTy width)) before.next).eval
          extended Locals.empty =
        spliceRawOutput
          (oldEntries.eval extended Locals.empty)
          (payloadEntries.eval extended Locals.empty)
          tail oldLengthValue payloadLengthValue previousIndex := by
    simp only [Term.eval]
    rw [assigned, extendedOldEntries, extendedPayloadEntries]
  refine ⟨extended, agreement,
    before.holds_agrees_below assignment extended holds agreement, assigned, ?_⟩
  exact log_splice_term_complete extended Locals.empty oldLength oldEntries
    payloadLength payloadEntries previous
    (.free (.array .int (entryTy width)) before.next)
    oldLengthValue payloadLengthValue previousIndex tail extendedOldLength
    extendedPayloadLength extendedPrevious sameOutput

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
