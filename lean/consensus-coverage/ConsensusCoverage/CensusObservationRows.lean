module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusGhost
public import ConsensusCoverage.CensusObserved
import all ConsensusCoverage.CensusGhost
import all ConsensusCoverage.CensusObserved
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersIndex
import all ConsensusCoverage.GuardedDomain

namespace ConsensusCoverage.CensusObservationRows

open Consensus Consensus.Model Consensus.Model.Node ReadersAtoms ExplorerGhost CensusGhost

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 16384
set_option maxHeartbeats 0

private abbrev input (x : XView) (g h : Ghost) : CensusGhost.Input :=
  ⟨slice g, slice h, ExplorerGhost.elections h x.base.before x.base.after⟩

private abbrev physical (x : XView) (g h : Ghost) : XView :=
  {x with base.past := [], committedBefore := g.committed, committedAfter := h.committed}

/-- Observation lists need not agree in order or multiplicity; only the
actual seen triples tracked by the finite ghost must agree with history. -/
public def Factored (b : Classes.StepBranch) : Prop :=
  ∀ (cfg : FullProfile.Configuration) (x : XView) (g h : Ghost),
    CensusObserved.Tracks g (x.base.before :: x.base.past) →
    CensusObserved.Tracks h (x.base.after :: x.base.before :: x.base.past) →
    @Exec.readView (input x g h) ⟨cfg⟩ (physical x g h) b = @ReadersCompiler.readView ⟨cfg⟩ x b

private noncomputable def truth (p : Prop) : Bool := @decide p (Classical.propDecidable _)

private theorem any_as_exists (xs : List α) (p : α → Bool) :
    xs.any p = truth (∃ a, a ∈ xs ∧ p a = true) := by
  apply Bool.eq_iff_iff.mpr
  simp only [truth, List.any_eq_true, decide_eq_true_eq]

local macro "observed_proof " finite:ident raw:ident : tactic => `(tactic|
  (intro cfg x g h pre post
   change some (@$finite (input x g h) ⟨cfg⟩ (physical x g h)) = some (@$raw ⟨cfg⟩ x)
   congr 1
   unfold $finite:ident $raw:ident
   simp only [Exec.reach_237, ReadersCompiler.R.reach_237, Exec.reach_39, ReadersCompiler.R.reach_39,
     Exec.reach_395, ReadersCompiler.R.reach_395, Exec.reach_26, ReadersCompiler.R.reach_26,
     Exec.reach_25, ReadersCompiler.R.reach_25, ReadersIndex.sameSent, ReadersIndex.patchedMatch,
     ReadersIndex.sameMatch, XView.sent, physical, input, obs, slice, any_as_exists,
     List.mem_attach, true_and, Subtype.exists, exists_prop, List.mem_eraseDups, List.mem_flatMap,
     List.mem_map, CensusObserved.observation_mem pre, CensusObserved.observation_mem post]))

set_option linter.unusedSimpArgs false in
private def certificates : List { b : Classes.StepBranch // Factored b } :=
  [⟨.inv_step_term_mono_now_inl, by
    observed_proof Exec.step_inv_step_term_mono_now_inl ReadersCompiler.R.step_inv_step_term_mono_now_inl⟩,
   ⟨.inv_step_term_mono_seen_inl, by
    observed_proof Exec.step_inv_step_term_mono_seen_inl ReadersCompiler.R.step_inv_step_term_mono_seen_inl⟩,
   ⟨.inv_step_term_mono_seen_inr, by
    observed_proof Exec.step_inv_step_term_mono_seen_inr ReadersCompiler.R.step_inv_step_term_mono_seen_inr⟩,
   ⟨.persist_now_after_inl, by
    observed_proof Exec.step_persist_now_after_inl ReadersCompiler.R.step_persist_now_after_inl⟩,
   ⟨.persist_persist_inl, by
    observed_proof Exec.step_persist_persist_inl ReadersCompiler.R.step_persist_persist_inl⟩,
   ⟨.persist_pre_kind_accept, by
    observed_proof Exec.step_persist_pre_kind_accept ReadersCompiler.R.step_persist_pre_kind_accept⟩,
   ⟨.persist_pre_kind_ack, by
    observed_proof Exec.step_persist_pre_kind_ack ReadersCompiler.R.step_persist_pre_kind_ack⟩,
   ⟨.persist_pre_kind_append, by
    observed_proof Exec.step_persist_pre_kind_append ReadersCompiler.R.step_persist_pre_kind_append⟩,
   ⟨.persist_pre_kind_elect, by
    observed_proof Exec.step_persist_pre_kind_elect ReadersCompiler.R.step_persist_pre_kind_elect⟩,
   ⟨.persist_pre_kind_same, by
    observed_proof Exec.step_persist_pre_kind_same ReadersCompiler.R.step_persist_pre_kind_same⟩,
   ⟨.persist_seen_after_inl, by
    observed_proof Exec.step_persist_seen_after_inl ReadersCompiler.R.step_persist_seen_after_inl⟩,
   ⟨.persist_seen_after_inr, by
    observed_proof Exec.step_persist_seen_after_inr ReadersCompiler.R.step_persist_seen_after_inr⟩,
   ⟨.rv_stable_now_after_inl, by
    observed_proof Exec.step_rv_stable_now_after_inl ReadersCompiler.R.step_rv_stable_now_after_inl⟩,
   ⟨.rv_stable_now_after_inr, by
    observed_proof Exec.step_rv_stable_now_after_inr ReadersCompiler.R.step_rv_stable_now_after_inr⟩]

public def columns : List Classes.StepBranch := certificates.map Subtype.val

public theorem count : columns.Nodup ∧ columns.length = 14 := by decide +kernel

public theorem correct {b : Classes.StepBranch} (mem : b ∈ columns) : Factored b := by
  obtain ⟨⟨_, proof⟩, _, rfl⟩ := List.mem_map.mp mem
  exact proof

end ConsensusCoverage.CensusObservationRows
