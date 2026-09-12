-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAssignmentEncoding
import Sparse.NativeRetirementRefreshEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem retirement_refresh_canonical_choices {width : PNat} [Bootstrap (Fin width)]
    (node : Fin width) (log : NativeArrayCheckQuorum.Log (Fin width) Nat) :
    exists firstChoice retirementChoice signatureChoice retiredChoice : Option Nat,
      NativeArrayFirstMatch.FirstMatch (NativeArrayRetirementIndex.virtualLog log)
          (NativeArrayRetirementIndex.includes node) firstChoice /\
        retirementIndexInLog node log.decode = retirementChoice /\
        RetirementSignatureScan log retirementChoice signatureChoice /\
        NativeArrayFirstMatch.FirstMatch log
          (fun _ entry => Sparse.RetirementScan.namesRetiredNode node entry)
          retiredChoice := by
  let firstChoice :=
    ((allConfigurations log.decode).find?
      (fun configuration => decide (node ∈ configuration.nodes))).map Configuration.index
  have firstCorrect :
      NativeArrayFirstMatch.FirstMatch (NativeArrayRetirementIndex.virtualLog log)
        (NativeArrayRetirementIndex.includes node) firstChoice :=
    (NativeArrayRetirementIndex.first_inclusion_correct log node firstChoice).mpr rfl
  let retiredChoice :=
    (log.decode.zipIdx.find? fun indexed =>
      Sparse.RetirementScan.namesRetiredNode node indexed.1).map Prod.snd
  have retiredCorrect :
      NativeArrayFirstMatch.FirstMatch log
        (fun _ entry => Sparse.RetirementScan.namesRetiredNode node entry)
        retiredChoice :=
    (NativeArrayFirstMatch.first_match_correct log
      (fun _ entry => Sparse.RetirementScan.namesRetiredNode node entry)
      retiredChoice).mpr rfl
  cases retirementCorrect : retirementIndexInLog node log.decode with
  | none =>
    exact ⟨firstChoice, none, none, retiredChoice, firstCorrect, rfl, rfl,
      retiredCorrect⟩
  | some retirementIndex =>
    let signatureChoice :=
      (log.decode.zipIdx.find? fun indexed =>
        decide (retirementIndex < 1 + indexed.2 /\
          indexed.1.content = .signature)).map Prod.snd
    have signatureCorrect :
        NativeArrayFirstMatch.FirstMatch log
          (fun position entry =>
            decide (retirementIndex < 1 + position /\ entry.content = .signature))
          signatureChoice :=
      (NativeArrayFirstMatch.first_match_correct log
        (fun position entry =>
          decide (retirementIndex < 1 + position /\ entry.content = .signature))
        signatureChoice).mpr rfl
    exact ⟨firstChoice, some retirementIndex, signatureChoice, retiredChoice,
      firstCorrect, rfl, by
        simpa [RetirementSignatureScan] using signatureCorrect,
      retiredCorrect⟩

theorem retirement_refresh_assignment {width : PNat} [Bootstrap (Fin width)]
    (before : Encoding width) (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (bootstrap : BitVec width) (length : Expr .int)
    (entries : Expr (.array .int (entryTy width))) (node : Fin width)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (lengthBounded :
      length.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (entriesBounded :
      entries.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (sameLength : length.eval assignment Locals.empty = (log.length : Int))
    (sameEntries : forall index, index < log.length ->
      modelEntry (entries.eval assignment Locals.empty (index : Int)) =
        log.entries index) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
        Holds before.assertions.toList extended /\
        (retirementRefreshConstraints width bootstrap length entries node
          (.free .int before.next)
          (.free .int (before.next + 1))
          (.free .int (before.next + 2))
          (.free .int (before.next + 3))).eval extended Locals.empty = true := by
  obtain ⟨firstChoice, retirementChoice, signatureChoice, retiredChoice,
    firstCorrect, retirementCorrect, signatureCorrect, retiredCorrect⟩ :=
    retirement_refresh_canonical_choices node log
  let withFirst :=
    assignment.set .int before.next (firstMatchValue firstChoice)
  let withRetirement :=
    withFirst.set .int (before.next + 1) (firstMatchValue retirementChoice)
  let withSignature :=
    withRetirement.set .int (before.next + 2) (firstMatchValue signatureChoice)
  let extended :=
    withSignature.set .int (before.next + 3) (firstMatchValue retiredChoice)
  have firstAgreement : assignment.AgreesBelow before.next withFirst :=
    assignment.agrees_below_set before.next .int before.next
      (firstMatchValue firstChoice) (le_refl _)
  have retirementAgreement : withFirst.AgreesBelow (before.next + 1) withRetirement :=
    withFirst.agrees_below_set (before.next + 1) .int (before.next + 1)
      (firstMatchValue retirementChoice) (le_refl _)
  have signatureAgreement :
      withRetirement.AgreesBelow (before.next + 2) withSignature :=
    withRetirement.agrees_below_set (before.next + 2) .int (before.next + 2)
      (firstMatchValue signatureChoice) (le_refl _)
  have retiredAgreement :
      withSignature.AgreesBelow (before.next + 3) extended :=
    withSignature.agrees_below_set (before.next + 3) .int (before.next + 3)
      (firstMatchValue retiredChoice) (le_refl _)
  have agreement : assignment.AgreesBelow before.next extended :=
    firstAgreement.trans
      ((retirementAgreement.restrict (by omega)).trans
        ((signatureAgreement.restrict (by omega)).trans
          (retiredAgreement.restrict (by omega))))
  have extendedHolds :=
    before.holds_agrees_below assignment extended holds agreement
  have boundedLength :
      forall symbol, symbol ∈ length.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp lengthBounded symbol member
  have boundedEntries :
      forall symbol, symbol ∈ entries.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp entriesBounded symbol member
  have extendedLength :
      length.eval extended Locals.empty = (log.length : Int) :=
    (length.eval_agrees_below assignment extended Locals.empty before.next
      boundedLength agreement).symm.trans sameLength
  have extendedEntries : forall index, index < log.length ->
      modelEntry (entries.eval extended Locals.empty (index : Int)) =
        log.entries index := by
    intro index live
    have sameArray :=
      entries.eval_agrees_below assignment extended Locals.empty before.next
        boundedEntries agreement
    rw [<- sameArray]
    exact sameEntries index live
  have sameFirst :
      (Term.free .int before.next).eval extended Locals.empty =
        firstMatchValue firstChoice := by
    simp only [Term.eval]
    rw [<- retiredAgreement .int before.next (by omega),
      <- signatureAgreement .int before.next (by omega),
      <- retirementAgreement .int before.next (by omega)]
    simp [withFirst, Assignment.set]
  have sameRetirement :
      (Term.free .int (before.next + 1)).eval extended Locals.empty =
        firstMatchValue retirementChoice := by
    simp only [Term.eval]
    rw [<- retiredAgreement .int (before.next + 1) (by omega),
      <- signatureAgreement .int (before.next + 1) (by omega)]
    simp [withRetirement, Assignment.set]
  have sameSignature :
      (Term.free .int (before.next + 2)).eval extended Locals.empty =
        firstMatchValue signatureChoice := by
    simp only [Term.eval]
    rw [<- retiredAgreement .int (before.next + 2) (by omega)]
    simp [withSignature, Assignment.set]
  have sameRetired :
      (Term.free .int (before.next + 3)).eval extended Locals.empty =
        firstMatchValue retiredChoice := by
    simp only [Term.eval]
    simp [extended, Assignment.set]
  refine ⟨extended, agreement, extendedHolds, ?_⟩
  apply (retirement_refresh_constraints_correct extended Locals.empty bootstrap
    length entries node
    (.free .int before.next)
    (.free .int (before.next + 1))
    (.free .int (before.next + 2))
    (.free .int (before.next + 3))
    log firstChoice retirementChoice signatureChoice retiredChoice
    extendedLength sameBootstrap sameFirst sameRetirement sameSignature sameRetired
    extendedEntries).mpr
  exact ⟨firstCorrect, retirementCorrect, signatureCorrect, retiredCorrect⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
