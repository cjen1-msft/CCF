-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeFirstMatchWitness
import Sparse.NativeRetirementIndexSound
import Sparse.NativeRetirementRefreshConstraints

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def RetirementSignatureScan {N T : Type} [DecidableEq N] [DecidableEq T]
    (log : NativeArrayCheckQuorum.Log N T)
    (retirement signature : Option Nat) : Prop :=
  match retirement with
  | none => signature = none
  | some retirementIndex =>
    NativeArrayFirstMatch.FirstMatch log
      (fun position entry =>
        decide (retirementIndex < 1 + position /\ entry.content = .signature))
      signature

theorem retirement_refresh_constraints_correct {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width) (length : Term context .int)
    (entries : Term context (.array .int (entryTy width))) (node : Fin width)
    (first retirement signature retired : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (firstChoice retirementChoice signatureChoice retiredChoice : Option Nat)
    (sameLength : length.eval assignment locals = (log.length : Int))
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameFirst : first.eval assignment locals = firstMatchValue firstChoice)
    (sameRetirement : retirement.eval assignment locals = firstMatchValue retirementChoice)
    (sameSignature : signature.eval assignment locals = firstMatchValue signatureChoice)
    (sameRetired : retired.eval assignment locals = firstMatchValue retiredChoice)
    (sameEntries : forall index, index < log.length ->
      modelEntry (entries.eval assignment locals (index : Int)) = log.entries index) :
    (retirementRefreshConstraints width bootstrap length entries node
      first retirement signature retired).eval assignment locals = true <->
      NativeArrayFirstMatch.FirstMatch (NativeArrayRetirementIndex.virtualLog log)
          (NativeArrayRetirementIndex.includes node) firstChoice /\
        retirementIndexInLog node log.decode = retirementChoice /\
        RetirementSignatureScan log retirementChoice signatureChoice /\
        NativeArrayFirstMatch.FirstMatch log
          (fun _ entry => Sparse.RetirementScan.namesRetiredNode node entry)
          retiredChoice := by
  have indexIff := retirement_index_term_correct assignment locals bootstrap length entries node
    first retirement log firstChoice retirementChoice sameLength sameFirst
    sameRetirement sameBootstrap sameEntries
  have retiredIff :
      (retiredRecordTerm width length entries node retired).eval assignment locals = true <->
        NativeArrayFirstMatch.FirstMatch log
          (fun _ entry => Sparse.RetirementScan.namesRetiredNode node entry)
          retiredChoice :=
    (retired_record_term_correct assignment locals length entries node retired log
      retiredChoice sameLength sameRetired sameEntries).trans
        (NativeArrayRetirement.retired_index_scan_correct log node retiredChoice).symm
  have signatureIff :
      (Term.ite (.equal retirement (.integer (-1))) (.equal signature (.integer (-1)))
        (signatureAfterRetirementTerm width length entries retirement signature)).eval
          assignment locals = true <->
        RetirementSignatureScan log retirementChoice signatureChoice := by
    cases retirementChoice with
    | none =>
      simp only [firstMatchValue] at sameRetirement
      cases signatureChoice <;>
        simp [RetirementSignatureScan, Term.eval, sameRetirement, sameSignature,
          firstMatchValue]
    | some retirementIndex =>
      simp only [firstMatchValue] at sameRetirement
      simp only [Term.eval, sameRetirement,
        show ¬(retirementIndex : Int) = -1 by omega, decide_false,
        Bool.false_eq_true, if_false]
      have correct := (signature_after_retirement_term_correct assignment locals length entries
        retirement signature log retirementIndex signatureChoice sameLength sameSignature
        sameRetirement sameEntries).trans
          (NativeArrayRetirement.signature_scan_correct
            log retirementIndex signatureChoice).symm
      simpa [RetirementSignatureScan] using correct
  simp only [retirementRefreshConstraints, all, List.foldr_cons, List.foldr_nil,
    Term.eval, Bool.and_eq_true, and_true]
  constructor
  · rintro ⟨indexAccepted, signatureAccepted, retiredAccepted⟩
    have indexCorrect := indexIff.mp indexAccepted
    exact ⟨indexCorrect.1, indexCorrect.2, signatureIff.mp signatureAccepted,
      retiredIff.mp retiredAccepted⟩
  · rintro ⟨firstCorrect, retirementCorrect, signatureCorrect, retiredCorrect⟩
    exact ⟨indexIff.mpr ⟨firstCorrect, retirementCorrect⟩,
      signatureIff.mpr signatureCorrect, retiredIff.mpr retiredCorrect⟩

theorem retirement_refresh_constraints_complete {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width) (length : Term context .int)
    (entries : Term context (.array .int (entryTy width))) (node : Fin width)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (firstChoice retirementChoice signatureChoice retiredChoice : Option Nat)
    (sameLength : length.eval assignment locals = (log.length : Int))
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameEntries : forall index, index < log.length ->
      modelEntry (entries.eval assignment locals (index : Int)) = log.entries index)
    (firstCorrect : NativeArrayFirstMatch.FirstMatch
      (NativeArrayRetirementIndex.virtualLog log)
      (NativeArrayRetirementIndex.includes node) firstChoice)
    (retirementCorrect : retirementIndexInLog node log.decode = retirementChoice)
    (signatureCorrect : RetirementSignatureScan log retirementChoice signatureChoice)
    (retiredCorrect : NativeArrayFirstMatch.FirstMatch log
      (fun _ entry => Sparse.RetirementScan.namesRetiredNode node entry) retiredChoice) :
    (retirementRefreshConstraints width bootstrap length entries node
      (.integer (firstMatchValue firstChoice))
      (.integer (firstMatchValue retirementChoice))
      (.integer (firstMatchValue signatureChoice))
      (.integer (firstMatchValue retiredChoice))).eval assignment locals = true := by
  apply (retirement_refresh_constraints_correct assignment locals bootstrap length entries
    node _ _ _ _ log firstChoice retirementChoice signatureChoice retiredChoice
    sameLength sameBootstrap (by simp [Term.eval]) (by simp [Term.eval])
    (by simp [Term.eval]) (by simp [Term.eval]) sameEntries).mpr
  exact ⟨firstCorrect, retirementCorrect, signatureCorrect, retiredCorrect⟩

theorem retirement_refresh_constraints_sound {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width) (length : Term context .int)
    (entries : Term context (.array .int (entryTy width))) (node : Fin width)
    (first retirement signature retired : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (sameLength : length.eval assignment locals = (log.length : Int))
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameEntries : forall index, index < log.length ->
      modelEntry (entries.eval assignment locals (index : Int)) = log.entries index)
    (accepted : (retirementRefreshConstraints width bootstrap length entries node
      first retirement signature retired).eval assignment locals = true) :
    exists firstChoice retirementChoice signatureChoice retiredChoice : Option Nat,
      first.eval assignment locals = firstMatchValue firstChoice /\
        retirement.eval assignment locals = firstMatchValue retirementChoice /\
        signature.eval assignment locals = firstMatchValue signatureChoice /\
        retired.eval assignment locals = firstMatchValue retiredChoice /\
        NativeArrayFirstMatch.FirstMatch (NativeArrayRetirementIndex.virtualLog log)
          (NativeArrayRetirementIndex.includes node) firstChoice /\
        retirementIndexInLog node log.decode = retirementChoice /\
        RetirementSignatureScan log retirementChoice signatureChoice /\
        NativeArrayFirstMatch.FirstMatch log
          (fun _ entry => Sparse.RetirementScan.namesRetiredNode node entry)
          retiredChoice := by
  have clauses := accepted
  simp only [retirementRefreshConstraints, all, List.foldr_cons, List.foldr_nil,
    Term.eval, Bool.and_eq_true, and_true] at clauses
  obtain ⟨firstChoice, retirementChoice, sameFirst, sameRetirement,
      firstCorrect, retirementCorrect⟩ :=
    retirement_index_term_sound assignment locals bootstrap length entries node
      first retirement log sameLength sameBootstrap sameEntries clauses.1
  rw [retiredRecordTerm] at clauses
  obtain ⟨retiredChoice, sameRetired, retiredCorrect⟩ :=
    first_match_term_sound assignment locals length retired
      (retiredRecordPredicate entries node) log
      (fun _ entry => Sparse.RetirementScan.namesRetiredNode node entry)
      clauses.2.2 sameLength
      (fun index live => by
        rw [retired_record_predicate_eval, sameEntries index live])
  cases retirementChoice with
  | none =>
    simp only [firstMatchValue] at sameRetirement
    have sameSignature : signature.eval assignment locals = firstMatchValue none := by
      simp only [firstMatchValue]
      simpa [sameRetirement] using clauses.2.1
    exact ⟨firstChoice, none, none, retiredChoice, sameFirst, sameRetirement,
      sameSignature, sameRetired, firstCorrect, retirementCorrect, rfl, retiredCorrect⟩
  | some retirementIndex =>
    simp only [firstMatchValue] at sameRetirement
    have signatureAccepted :
        (firstMatchTerm length signature
          (signatureAfterRetirementPredicate entries retirement)).eval
            assignment locals = true := by
      simpa [signatureAfterRetirementTerm, sameRetirement] using clauses.2.1
    obtain ⟨signatureChoice, sameSignature, signatureCorrect⟩ :=
      first_match_term_sound assignment locals length signature
        (signatureAfterRetirementPredicate entries retirement) log
        (fun position entry =>
          decide (retirementIndex < 1 + position /\ entry.content = .signature))
        signatureAccepted sameLength
        (fun index live => by
          rw [signature_after_retirement_predicate_eval assignment locals entries
            retirement index retirementIndex sameRetirement, sameEntries index live])
    exact ⟨firstChoice, some retirementIndex, signatureChoice, retiredChoice,
      sameFirst, sameRetirement, sameSignature, sameRetired, firstCorrect,
      retirementCorrect, by simpa [RetirementSignatureScan] using signatureCorrect,
      retiredCorrect⟩

theorem retirement_refresh_constraints_output_sound
    {context : List Ty} {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width) (length : Term context .int)
    (entries : Term context (.array .int (entryTy width))) (node : Fin width)
    (commit first retirement signature retired : Term context .int)
    (row : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (sameLength : length.eval assignment locals = (row.log.length : Int))
    (sameCommit : commit.eval assignment locals = (row.commit : Int))
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameEntries : forall index, index < row.log.length ->
      modelEntry (entries.eval assignment locals (index : Int)) = row.log.entries index)
    (accepted : (retirementRefreshConstraints width bootstrap length entries node
      first retirement signature retired).eval assignment locals = true) :
    let terms := retirementRefreshTerms commit retirement signature retired
    let refreshed := refreshRetirementState node row.toModel
    terms.retirementIndex.eval assignment locals =
        optionalValue Nat.cast refreshed.retirementIndex /\
      terms.retirementCommittableIndex.eval assignment locals =
        optionalValue Nat.cast refreshed.retirementCommittableIndex /\
      terms.retiredCommittedIndex.eval assignment locals =
        optionalValue Nat.cast refreshed.retiredCommittedIndex /\
      terms.membershipState.eval assignment locals =
        membershipCode refreshed.membershipState := by
  obtain ⟨firstChoice, retirementChoice, signatureChoice, retiredChoice,
      sameFirst, sameRetirement, sameSignature, sameRetired, firstCorrect,
      retirementCorrect, signatureCorrect, retiredCorrect⟩ :=
    retirement_refresh_constraints_sound assignment locals bootstrap length entries node
      first retirement signature retired row.log sameLength sameBootstrap sameEntries accepted
  let refreshedNative := NativeArrayRetirement.refresh row retirementChoice
    (signatureChoice.map (1 + ·)) (retiredChoice.map (1 + ·))
  have modelCorrect :
      refreshedNative.toModel = refreshRetirementState node row.toModel := by
    cases retirementChoice with
    | none =>
      exact NativeArrayRetirement.refresh_from_scans_correct row node none
        signatureChoice retiredChoice retirementCorrect
        (by simpa [RetirementSignatureScan] using signatureCorrect) retiredCorrect
    | some retirementIndex =>
      exact NativeArrayRetirement.refresh_from_scans_correct row node (some retirementIndex)
        signatureChoice retiredChoice retirementCorrect
        (by simpa [RetirementSignatureScan] using signatureCorrect) retiredCorrect
  have termsCorrect :=
    retirement_refresh_terms_eval assignment locals commit retirement signature retired
      row retirementChoice signatureChoice retiredChoice sameCommit sameRetirement
      sameSignature sameRetired
  have sameRetirementField :
      refreshedNative.retirementIndex =
        (refreshRetirementState node row.toModel).retirementIndex := by
    simpa [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.retirementIndex modelCorrect
  have sameCommittableField :
      refreshedNative.retirementCommittableIndex =
        (refreshRetirementState node row.toModel).retirementCommittableIndex := by
    simpa [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.retirementCommittableIndex modelCorrect
  have sameCommittedField :
      refreshedNative.retiredCommittedIndex =
        (refreshRetirementState node row.toModel).retiredCommittedIndex := by
    simpa [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.retiredCommittedIndex modelCorrect
  have sameMembershipField :
      refreshedNative.membershipState =
        (refreshRetirementState node row.toModel).membershipState := by
    simpa [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.membershipState modelCorrect
  dsimp only at termsCorrect ⊢
  exact ⟨termsCorrect.1.trans (congrArg (optionalValue Nat.cast) sameRetirementField),
    termsCorrect.2.1.trans (congrArg (optionalValue Nat.cast) sameCommittableField),
    termsCorrect.2.2.1.trans (congrArg (optionalValue Nat.cast) sameCommittedField),
    termsCorrect.2.2.2.trans (congrArg membershipCode sameMembershipField)⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
