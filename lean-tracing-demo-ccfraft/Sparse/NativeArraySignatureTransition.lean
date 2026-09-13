-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArraySignature

set_option autoImplicit false

namespace CCFRaft.NativeArraySignature

open NativeArrayCheckQuorum NativeArrayLeaderLogWrite

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

inductive Sign (frame : NativeArrayVote.Frame N T) (source : N) :
    NativeArrayVote.Frame N T -> Prop where
  | sign (retirement signature retired : Option Nat) (completed : Finset N)
      (retirementCorrect :
        retirementIndexInLog source
          (appendRow (get frame.nodes source) .signature).log.decode = retirement)
      (signatureCorrect :
        retirement.bind
          (retirementCommittableIndexInLog
            (appendRow (get frame.nodes source) .signature).log.decode) = signature)
      (retiredCorrect :
        retiredCommittedIndexInLog source
          (appendRow (get frame.nodes source) .signature).log.decode = retired)
      (completedCorrect :
        retirementCompletedNodes
            (refreshRow (get frame.nodes source) .signature
              retirement signature retired).log.decode
            (refreshRow (get frame.nodes source) .signature
              retirement signature retired).commit =
          completed)
      (allowed :
        enabled frame source
          (refreshRow (get frame.nodes source) .signature
            retirement signature retired)) :
      Sign frame source
        (NativeArraySignature.sign frame source
          (refreshRow (get frame.nodes source) .signature
            retirement signature retired)
          completed)

theorem Sign.model_correct
    (frame after : NativeArrayVote.Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N) (step : Sign frame source after) :
    CCFRaft.Enabled state (.signCommittableMessages source) /\
      after.Rep (CCFRaft.next state (.signCommittableMessages source)) := by
  cases step with
  | sign retirement signature retired completed retirementCorrect signatureCorrect
      retiredCorrect completedCorrect allowed =>
    let row := get frame.nodes source
    let output := refreshRow row .signature retirement signature retired
    have same : state.nodes source = row.toModel :=
      (get_rep frame.nodes state rep.nodes source).symm
    have rowCorrect :
        output.toModel =
          refreshRetirementState source
            { (state.nodes source) with
              log := (state.nodes source).log ++
                [{ term := (state.nodes source).currentTerm, content := .signature }] } := by
      rw [same]
      exact refresh_row_correct row source .signature retirement signature retired
        retirementCorrect signatureCorrect retiredCorrect
    exact
      ⟨(enabled_correct frame state rep source output rowCorrect).mp allowed,
        sign_output_rep frame state rep source output completed rowCorrect completedCorrect⟩

theorem Sign.exists_of_enabled
    (frame : NativeArrayVote.Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N)
    (allowed : CCFRaft.Enabled state (.signCommittableMessages source)) :
    exists after, Sign frame source after := by
  let row := get frame.nodes source
  let appended := appendRow row .signature
  let retirement := retirementIndexInLog source appended.log.decode
  let signature := retirement.bind (retirementCommittableIndexInLog appended.log.decode)
  let retired := retiredCommittedIndexInLog source appended.log.decode
  let output := refreshRow row .signature retirement signature retired
  let completed := retirementCompletedNodes output.log.decode output.commit
  have same : state.nodes source = row.toModel :=
    (get_rep frame.nodes state rep.nodes source).symm
  have rowCorrect :
      output.toModel =
        refreshRetirementState source
          { (state.nodes source) with
            log := (state.nodes source).log ++
              [{ term := (state.nodes source).currentTerm, content := .signature }] } := by
    rw [same]
    exact refresh_row_correct row source .signature retirement signature retired rfl rfl rfl
  have nativeAllowed : enabled frame source output :=
    (enabled_correct frame state rep source output rowCorrect).mpr allowed
  exact
    ⟨NativeArraySignature.sign frame source output completed,
      .sign retirement signature retired completed rfl rfl rfl rfl nativeAllowed⟩

end CCFRaft.NativeArraySignature

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArraySignature).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
