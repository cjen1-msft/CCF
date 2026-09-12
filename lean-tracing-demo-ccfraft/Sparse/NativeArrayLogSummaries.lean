-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayAppendReceive

set_option autoImplicit false

namespace CCFRaft.NativeArrayLogSummaries

open NativeArrayCheckQuorum NativeArrayVote NativeArrayLogWrite

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

omit [Bootstrap N] in
theorem signature_storage_summary_iff (log : Log N T) (cap best : Nat) :
    Sparse.LogMatchSummary.StorageSummary log.length cap best
      (fun position => (log.entries position).content = .signature) <->
        SignatureIndex (take log cap) best := by
  simp only [Sparse.LogMatchSummary.StorageSummary, SignatureIndex]
  constructor
  · rintro ⟨bound, selected, exclusion⟩
    refine ⟨by simpa [take] using bound, ?_, ?_⟩
    · by_cases zero : best = 0
      · exact Or.inl zero
      · apply Or.inr
        refine ⟨by omega, by simpa [take] using bound, ?_⟩
        simpa [take] using selected (by omega)
    · intro candidate after within signature
      rcases signature with ⟨positive, _, content⟩
      apply exclusion (candidate - 1) (by omega) (by simp [take] at within ⊢; omega)
      simpa [take] using content
  · rintro ⟨bound, selected, exclusion⟩
    refine ⟨by simpa [take] using bound, ?_, ?_⟩
    · intro positive
      rcases selected with zero | signature
      · omega
      · simpa [take] using signature.2.2
    · intro position after within content
      apply exclusion (position + 1) (by omega) (by simpa [take] using within)
      exact ⟨by omega, by simp [take]; omega, by simpa [take] using content⟩

theorem signature_storage_summary_model_iff (log : Log N T) (cap best : Nat) :
    Sparse.LogMatchSummary.StorageSummary log.length cap best
      (fun position => (log.entries position).content = .signature) <->
        maxCommittableIndexUpTo log.decode cap = best :=
  (signature_storage_summary_iff log cap best).trans
    (NativeArrayAppendReceive.bounded_signature_correct log cap best)

omit [DecidableEq N] [DecidableEq T] [Bootstrap N] in
theorem current_storage_summary_iff (log : Log N T) (commit current : Nat) :
    Sparse.LogMatchSummary.StorageSummary log.length commit current
      (fun position => exists nodes, (log.entries position).content = .reconfiguration nodes) <->
        CurrentIndex log commit current := by
  simp only [Sparse.LogMatchSummary.StorageSummary, CurrentIndex]
  constructor
  · rintro ⟨bound, selected, exclusion⟩
    refine ⟨bound, ?_, ?_⟩
    · by_cases zero : current = 0
      · exact Or.inl zero
      · right
        obtain ⟨nodes, content⟩ := selected (by omega)
        exact ⟨nodes, by
          exact ⟨by omega, by omega, content⟩⟩
    · intro candidate nodes after within reconfiguration
      rcases reconfiguration with ⟨positive, _, content⟩
      apply exclusion (candidate - 1) (by omega) (by omega)
      exact ⟨nodes, content⟩
  · rintro ⟨bound, selected, exclusion⟩
    refine ⟨bound, ?_, ?_⟩
    · intro positive
      rcases selected with zero | ⟨nodes, reconfiguration⟩
      · omega
      · exact ⟨nodes, reconfiguration.2.2⟩
    · rintro position after within ⟨nodes, content⟩
      apply exclusion (position + 1) nodes (by omega) (by omega)
      exact ⟨by omega, by omega, by simpa using content⟩

theorem current_storage_summary_model_iff (log : Log N T) (commit current : Nat) :
    Sparse.LogMatchSummary.StorageSummary log.length commit current
      (fun position => exists nodes, (log.entries position).content = .reconfiguration nodes) <->
        (currentConfigurationAt log.decode commit).index = current :=
  (current_storage_summary_iff log commit current).trans
    (current_index_correct log commit current)

end CCFRaft.NativeArrayLogSummaries

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayLogSummaries).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
