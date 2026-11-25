module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusCommitHistory
public import ConsensusCoverage.CensusGhost
import all ConsensusCoverage.CensusGhost
import all ConsensusCoverage.CensusObservationRows
import all ConsensusCoverage.CensusCommitHistory
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
meta import ConsensusCoverage.CensusReach

namespace ConsensusCoverage.CensusPriorRows

open Consensus Consensus.Model Consensus.Model.Node ReadersAtoms ExplorerGhost CensusGhost

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 16384
set_option maxHeartbeats 0

census_reach finiteCampaignOrigin := reach% CensusGhost.Exec.step_campaign_backed_pre_split_inl[0]
census_reach rawCampaignOrigin := reach% ReadersCompiler.R.step_campaign_backed_pre_split_inl[0]
census_reach finiteCandidateOrigin := reach% CensusGhost.Exec.step_candidate_candidate_inl[0]
census_reach rawCandidateOrigin := reach% ReadersCompiler.R.step_candidate_candidate_inl[0]

public def columns : List Classes.StepBranch := [.candidate_candidate_inl, .campaign_backed_pre_split_inl]

private abbrev stripped (x : XView) (before after : List (Nat × List Entry)) : XView :=
  {x with base.past := [], committedBefore := before, committedAfter := after}

/-- These two historical readers require only pre-step commit-pair membership.
The post-step certificate list and all other ghost fields are arbitrary. -/
public theorem correct {b : Classes.StepBranch} (mem : b ∈ columns) (cfg : FullProfile.Configuration)
    (input : CensusGhost.Input) (x : XView) (before after : List (Nat × List Entry))
    (old : ∀ key, key ∈ before ↔ key ∈ x.committedBefore) :
    @Exec.readView input ⟨cfg⟩ (stripped x before after) b = @ReadersCompiler.readView ⟨cfg⟩ x b := by
  simp only [columns, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl
  all_goals
    first
    | change some (@Exec.step_candidate_candidate_inl input ⟨cfg⟩ _) =
        some (@ReadersCompiler.R.step_candidate_candidate_inl ⟨cfg⟩ x)
    | change some (@Exec.step_campaign_backed_pre_split_inl input ⟨cfg⟩ _) =
        some (@ReadersCompiler.R.step_campaign_backed_pre_split_inl ⟨cfg⟩ x)
    congr 1
    set_option linter.unusedSimpArgs false in
      simp only [Exec.step_candidate_candidate_inl, ReadersCompiler.R.step_candidate_candidate_inl,
        Exec.step_campaign_backed_pre_split_inl, ReadersCompiler.R.step_campaign_backed_pre_split_inl,
        finiteCampaignOrigin, rawCampaignOrigin, finiteCandidateOrigin, rawCandidateOrigin,
        stripped, CensusObservationRows.any_as_exists, List.mem_attach, true_and, Subtype.exists,
        exists_prop, List.mem_eraseDups, List.mem_flatMap, List.mem_map, old]

/-- Connect the setwise premise to start/read preservation for real ghosts
and transport the result through the actual node-lookup dispatcher. -/
public theorem action_read {b : Classes.StepBranch} (mem : b ∈ columns) (cfg : FullProfile.Configuration)
    (s t : Model.State) (act : Model.Action) (past : List Model.State) (g h : Ghost)
    (old : CensusCommitHistory.CommitHistory (cfg.min?.getD 0) g (s :: past)) :
    ((CensusGhost.answers cfg g h s t act).bind (· b)) =
      ((ofXAction cfg s t past act).bind fun x => @ReadersCompiler.readView ⟨cfg⟩ x b) := by
  cases a : CCF.MultiNodeTransitionSystem.nodeState s (GuardedDomain.actionActor act) <;>
    cases z : CCF.MultiNodeTransitionSystem.nodeState t (GuardedDomain.actionActor act) <;>
    simp only [CensusGhost.answers, ofXAction, GuardedDomain.ofAction, a, z,
      Option.bind_eq_bind, Option.bind_none, Option.bind_some, pure]
  apply correct mem cfg _ (packX (GuardedDomain.pack _ s t past _ _ _) (eventOf act)) _ _ old

end ConsensusCoverage.CensusPriorRows
