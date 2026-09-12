-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveFinalRowTerms
import Sparse.NativeNodeRowWritesEncoding
import Sparse.NativeRetirementRefreshEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem append_receive_final_row_terms_rep {width : PNat}
    (assignment : Assignment) (candidate : NodeRowTerms width)
    (nativeCandidate : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (candidateRep : candidate.Rep assignment nativeCandidate)
    (stepDown : Expr .bool) (step : Bool)
    (retirement signature retired : Expr .int)
    (retirementChoice signatureChoice retiredChoice : Option Nat)
    (sameStep : stepDown.eval assignment Locals.empty = step)
    (refreshCorrect : step = false ->
      let terms := retirementRefreshTerms candidate.commit retirement signature retired
      let refreshed := NativeArrayRetirement.refresh nativeCandidate retirementChoice
        (signatureChoice.map (1 + ·)) (retiredChoice.map (1 + ·))
      terms.retirementIndex.eval assignment Locals.empty =
          optionalValue Nat.cast refreshed.retirementIndex /\
        terms.retirementCommittableIndex.eval assignment Locals.empty =
          optionalValue Nat.cast refreshed.retirementCommittableIndex /\
        terms.retiredCommittedIndex.eval assignment Locals.empty =
          optionalValue Nat.cast refreshed.retiredCommittedIndex /\
        terms.membershipState.eval assignment Locals.empty =
          membershipCode refreshed.membershipState) :
    (appendReceiveFinalRowTerms candidate stepDown retirement signature retired).Rep assignment
      (if step then
        { nativeCandidate with role := .follower, isNewFollower := true }
      else
        NativeArrayRetirement.refresh nativeCandidate retirementChoice
          (signatureChoice.map (1 + ·)) (retiredChoice.map (1 + ·))) := by
  have refreshed := refreshCorrect
  constructor
  · cases step <;>
      simp [appendReceiveFinalRowTerms, Term.eval, sameStep, NativeArrayRetirement.refresh,
        candidateRep.role]
  · cases step <;>
      simp [appendReceiveFinalRowTerms, Term.eval, sameStep, NativeArrayRetirement.refresh,
        candidateRep.newFollower]
  · cases step <;>
      simp [appendReceiveFinalRowTerms, NativeArrayRetirement.refresh, candidateRep.logLength]
  · cases step <;>
      simp [appendReceiveFinalRowTerms, NativeArrayRetirement.refresh, candidateRep.commit]
  · cases step <;>
      simp [appendReceiveFinalRowTerms, NativeArrayRetirement.refresh, candidateRep.currentTerm]
  · intro index live
    cases step <;>
      simpa [NativeArrayRetirement.refresh] using candidateRep.logEntries index live
  · cases step with
    | false =>
      simpa [appendReceiveFinalRowTerms, Term.eval, sameStep, NativeArrayRetirement.refresh] using
        (refreshed rfl).1
    | true =>
      simpa [appendReceiveFinalRowTerms, Term.eval, sameStep] using candidateRep.retirementIndex
  · cases step with
    | false =>
      simpa [appendReceiveFinalRowTerms, Term.eval, sameStep, NativeArrayRetirement.refresh] using
        (refreshed rfl).2.1
    | true =>
      simpa [appendReceiveFinalRowTerms, Term.eval, sameStep] using
        candidateRep.retirementCommittableIndex
  · cases step with
    | false =>
      simpa [appendReceiveFinalRowTerms, Term.eval, sameStep, NativeArrayRetirement.refresh] using
        (refreshed rfl).2.2.1
    | true =>
      simpa [appendReceiveFinalRowTerms, Term.eval, sameStep] using
        candidateRep.retiredCommittedIndex
  · cases step <;>
      simp [appendReceiveFinalRowTerms, NativeArrayRetirement.refresh, candidateRep.votedFor]
  · cases step <;>
      simp [appendReceiveFinalRowTerms, NativeArrayRetirement.refresh, candidateRep.votesGranted]
  · cases step <;>
      simp [appendReceiveFinalRowTerms, NativeArrayRetirement.refresh, candidateRep.preVotesGranted]
  · cases step with
    | false =>
      simpa [appendReceiveFinalRowTerms, Term.eval, sameStep, NativeArrayRetirement.refresh] using
        (refreshed rfl).2.2.2
    | true =>
      simpa [appendReceiveFinalRowTerms, Term.eval, sameStep] using candidateRep.membershipState
  · intro peer
    cases step <;>
      simp [appendReceiveFinalRowTerms, NativeArrayRetirement.refresh, candidateRep.sentIndex]
  · intro peer
    cases step <;>
      simp [appendReceiveFinalRowTerms, NativeArrayRetirement.refresh, candidateRep.matchIndex]

theorem append_receive_final_row_terms_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (bootstrap : BitVec width)
    (candidate : NodeRowTerms width)
    (nativeCandidate : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (candidateRep : candidate.Rep assignment nativeCandidate)
    (destination : Fin width) (stepDown : Expr .bool) (step : Bool)
    (first retirement signature retired : Expr .int)
    (sameStep : stepDown.eval assignment Locals.empty = step)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (accepted :
      (implies (.not stepDown)
        (retirementRefreshConstraints width bootstrap candidate.logLength
          candidate.logEntries destination first retirement signature retired)).eval
            assignment Locals.empty = true) :
    exists output : NativeArrayCheckQuorum.Local (Fin width) Nat,
      (appendReceiveFinalRowTerms candidate stepDown retirement signature retired).Rep
        assignment output /\
      (step = true ->
        output = { nativeCandidate with role := .follower, isNewFollower := true }) /\
      (step = false ->
        output.toModel = refreshRetirementState destination nativeCandidate.toModel) /\
      output.log = nativeCandidate.log /\
      output.commit = nativeCandidate.commit := by
  by_cases stepping : step = true
  · have stepValue : step = true := stepping
    let output : NativeArrayCheckQuorum.Local (Fin width) Nat :=
      { nativeCandidate with role := .follower, isNewFollower := true }
    refine ⟨output, ?_, fun _ => rfl, ?_, rfl, rfl⟩
    · simpa [output, stepValue] using
        append_receive_final_row_terms_rep assignment candidate nativeCandidate candidateRep
          stepDown step retirement signature retired none none none sameStep
          (by intro impossible; simp [stepValue] at impossible)
    · intro notStepping
      simp [stepValue] at notStepping
  · have stepValue : step = false := Bool.eq_false_of_not_eq_true stepping
    have refreshAccepted :
        (retirementRefreshConstraints width bootstrap candidate.logLength
          candidate.logEntries destination first retirement signature retired).eval
            assignment Locals.empty = true := by
      simpa [implies, Term.eval, sameStep, stepValue] using accepted
    obtain ⟨firstChoice, retirementChoice, signatureChoice, retiredChoice,
        sameFirst, sameRetirement, sameSignature, sameRetired, firstCorrect,
        retirementCorrect, signatureCorrect, retiredCorrect⟩ :=
      retirement_refresh_constraints_sound assignment Locals.empty bootstrap
        candidate.logLength candidate.logEntries destination first retirement signature retired
        nativeCandidate.log candidateRep.logLength sameBootstrap candidateRep.logEntries
        refreshAccepted
    let output := NativeArrayRetirement.refresh nativeCandidate retirementChoice
      (signatureChoice.map (1 + ·)) (retiredChoice.map (1 + ·))
    have refreshedTerms :=
      retirement_refresh_terms_eval assignment Locals.empty candidate.commit retirement signature
        retired nativeCandidate retirementChoice signatureChoice retiredChoice candidateRep.commit
        sameRetirement sameSignature sameRetired
    have outputModel :
        output.toModel = refreshRetirementState destination nativeCandidate.toModel := by
      cases retirementChoice with
      | none =>
        exact NativeArrayRetirement.refresh_from_scans_correct nativeCandidate destination
          none signatureChoice retiredChoice retirementCorrect
          (by simpa [RetirementSignatureScan] using signatureCorrect) retiredCorrect
      | some retirementIndex =>
        exact NativeArrayRetirement.refresh_from_scans_correct nativeCandidate destination
          (some retirementIndex) signatureChoice retiredChoice retirementCorrect
          (by simpa [RetirementSignatureScan] using signatureCorrect) retiredCorrect
    refine ⟨output, ?_, ?_, fun _ => outputModel, rfl, rfl⟩
    · simpa [output, stepValue] using
        append_receive_final_row_terms_rep assignment candidate nativeCandidate candidateRep
          stepDown step retirement signature retired retirementChoice signatureChoice
          retiredChoice sameStep (fun _ => refreshedTerms)
    · intro impossible
      simp [stepValue] at impossible

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
