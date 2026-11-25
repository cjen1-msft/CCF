module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusGhost
public import ConsensusCoverage.CensusObserved
import all ConsensusCoverage.CensusGhost
import all ConsensusCoverage.CensusObserved
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersAtoms
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

local macro "observed_proof " finite:ident raw:ident : tactic => `(tactic|
  (intro cfg x g h pre post
   change some (@$finite (input x g h) ⟨cfg⟩ (physical x g h)) = some (@$raw ⟨cfg⟩ x)
   congr 1
   unfold $finite:ident $raw:ident
   simp only [physical, input, obs, slice, CensusObserved.observation_mem pre, CensusObserved.observation_mem post]
   all_goals
     repeat' first | apply congrArg (List.any _); funext a | split
     all_goals
       apply Bool.eq_iff_iff.mpr
       simp only [List.any_eq_true, List.mem_attach, true_and, Subtype.exists, exists_prop,
         CensusObserved.observation_mem pre, CensusObserved.observation_mem post]))

set_option linter.unusedSimpArgs false in
private def certificates : List { b : Classes.StepBranch // Factored b } :=
  [⟨.inv_step_term_mono_now_inl, by
    observed_proof Exec.step_inv_step_term_mono_now_inl ReadersCompiler.R.step_inv_step_term_mono_now_inl⟩,
   ⟨.inv_step_term_mono_seen_inl, by
    observed_proof Exec.step_inv_step_term_mono_seen_inl ReadersCompiler.R.step_inv_step_term_mono_seen_inl⟩,
   ⟨.inv_step_term_mono_seen_inr, by
    observed_proof Exec.step_inv_step_term_mono_seen_inr ReadersCompiler.R.step_inv_step_term_mono_seen_inr⟩]

public def columns : List Classes.StepBranch := certificates.map Subtype.val

public theorem correct {b : Classes.StepBranch} (mem : b ∈ columns) : Factored b := by
  obtain ⟨⟨_, proof⟩, _, rfl⟩ := List.mem_map.mp mem
  exact proof

end ConsensusCoverage.CensusObservationRows
