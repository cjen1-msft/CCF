module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusGrantHistory
public import ConsensusCoverage.CensusGhost
import all ConsensusCoverage.CensusGhost
import all ConsensusCoverage.CensusObservationRows
import all ConsensusCoverage.CensusGrantHistory
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain

namespace ConsensusCoverage.CensusGrantRows

open Consensus Consensus.Model ReadersAtoms ExplorerGhost CensusGhost

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 16384
set_option maxHeartbeats 0

public def columns : List Classes.StepBranch := [.candidate_candidate_inr, .campaign_backed_pre_split_inr]

/-- These campaign cases read only pre-step grants and observations. Nothing
about the post-step ghost, commit certificates, or list order is assumed. -/
private theorem correct {b : Classes.StepBranch} (mem : b ∈ columns) (cfg : FullProfile.Configuration)
    (x : XView) (g h : Ghost) (seen : CensusObserved.Tracks g (x.base.before :: x.base.past))
    (granted : CensusGrants.GrantHistory g (x.base.before :: x.base.past)) :
    @Exec.readView (CensusObservationRows.input x g h) ⟨cfg⟩ (CensusObservationRows.physical x g h) b =
      @ReadersCompiler.readView ⟨cfg⟩ x b := by
  unfold CensusGrants.GrantHistory at granted
  simp only [columns, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl
  all_goals
    first
    | change some (@Exec.step_candidate_candidate_inr _ ⟨cfg⟩ _) =
        some (@ReadersCompiler.R.step_candidate_candidate_inr ⟨cfg⟩ x)
    | change some (@Exec.step_campaign_backed_pre_split_inr _ ⟨cfg⟩ _) =
        some (@ReadersCompiler.R.step_campaign_backed_pre_split_inr ⟨cfg⟩ x)
    congr 1
    set_option linter.unusedSimpArgs false in
      simp only [Exec.step_candidate_candidate_inr, ReadersCompiler.R.step_candidate_candidate_inr,
        Exec.step_campaign_backed_pre_split_inr, ReadersCompiler.R.step_campaign_backed_pre_split_inr,
        Exec.reach_269, ReadersCompiler.R.reach_269, Exec.reach_12, ReadersCompiler.R.reach_12,
        CensusObservationRows.physical, CensusObservationRows.input, grants, obs, slice, granted,
        CensusObservationRows.any_as_exists, List.mem_attach, true_and, Subtype.exists, exists_prop,
        List.mem_eraseDups, List.mem_flatMap, CensusObserved.observation_mem seen]

public theorem action_read {b : Classes.StepBranch} (mem : b ∈ columns) (cfg : FullProfile.Configuration)
    (s t : Model.State) (act : Model.Action) (past : List Model.State) (g h : Ghost)
    (seen : CensusObserved.Tracks g (s :: past)) (granted : CensusGrants.GrantHistory g (s :: past)) :
    ((CensusGhost.answers cfg g h s t act).bind (· b)) =
      ((ofXAction cfg s t past act).bind fun x => @ReadersCompiler.readView ⟨cfg⟩ x b) := by
  cases a : CCF.MultiNodeTransitionSystem.nodeState s (GuardedDomain.actionActor act) <;>
    cases z : CCF.MultiNodeTransitionSystem.nodeState t (GuardedDomain.actionActor act) <;>
    simp only [CensusGhost.answers, ofXAction, GuardedDomain.ofAction, a, z,
      Option.bind_eq_bind, Option.bind_none, Option.bind_some, pure]
  exact correct mem cfg (packX (GuardedDomain.pack _ s t past _ _ _) (eventOf act)) g h seen granted

end ConsensusCoverage.CensusGrantRows
