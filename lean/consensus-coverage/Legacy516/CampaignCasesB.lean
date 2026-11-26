module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.CampaignCasesB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile ReadersAtoms SolvedWitnesses DeepSchedulesB

set_option maxRecDepth 8192
set_option maxHeartbeats 500000

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t} {x : XView}
  (ok : x.Matches c) (changed : x.base.changed = true)
include ok changed

private theorem entry : (reach% step_canStartElection_engaged_can_inl[6,1,0]) f t c
    x.base.actor x.base.pre x.event :=
  ⟨t, c.tr, ReceiveCasesB.changedSummary ok changed, (X.tr_actor_eq ok).symm,
    (X.tr_pre_eq ok).symm, (X.tr_event_eq ok).symm⟩

private theorem proposed (n : NodeID)
    (ev : x.event = .receive n (.proposeRequestVoteRequest x.base.pre.currentTerm))
    (can : canStartElection x.base.pre x.base.actor) :
    (reach% step_canStartElection_engaged_can_inl[6]) f t c x.base.pre x.base.actor := by
  iterate 5 right
  refine ⟨n, ⟨x.event, entry ok changed, _, ev, ev, rfl⟩,
    fun h => Bool.noConfusion h.1, can, freshCandidate x.base.actor x.base.pre, [], Or.inl ⟨rfl, ?_⟩⟩
  intro e he
  contradiction

private theorem follower (n : NodeID)
    (ev : x.event = .receive n (.proposeRequestVoteRequest x.base.pre.currentTerm))
    (can : canStartElection x.base.pre x.base.actor) (role : x.base.pre.role = .follower) :
    step_canStartElection_engaged_can_inl f t c := by
  iterate 6 right
  left
  exact ⟨_, _, proposed ok changed n ev can, role, can⟩

private theorem preCandidate (n : NodeID)
    (ev : x.event = .receive n (.proposeRequestVoteRequest x.base.pre.currentTerm))
    (can : canStartElection x.base.pre x.base.actor) (role : x.base.pre.role = .preVoteCandidate) :
    step_canStartElection_engaged_can_inr_inl f t c := by
  iterate 6 right
  left
  exact ⟨_, _, proposed ok changed n ev can, Or.inl role, role, can⟩

private theorem candidate (ev : x.event = .internal (.timeout .election))
    (can : canStartElection x.base.pre x.base.actor) (role : x.base.pre.role = .candidate)
    (minority : ¬hasQuorum x.base.pre.activeConfigurations {x.base.actor}) :
    step_canStartElection_engaged_can_inr_inr f t c := by
  iterate 6 right
  left
  refine ⟨x.base.pre, x.base.actor, ?_, Or.inr role, role, can⟩
  iterate 3 right
  left
  refine ⟨⟨x.event, entry ok changed, _, ev, ev, rfl⟩, can, can, can, minority,
    [], fun _ h => False.elim (List.not_mem_nil h), Or.inl ⟨fun h => Role.noConfusion h, ?_⟩⟩
  exact fun h => Role.noConfusion h.1

end

private abbrev Certificate := {b : Classes.StepBranch // ∃ s : Step, label s (.step b) = true}

local macro "campaign_at " b:term:arg r:term:arg i:num cert:ident args:term:arg* : term => `(by
  refine ⟨$b, ?_⟩
  let a := ReceiveCasesB.asSample $r $i (by decide +kernel) (by decide +kernel)
  letI : Config.InitialConfiguration := ⟨a.s.cfg⟩
  let c := a.s.context
  refine ⟨a.s, (label_true a.s (.step $b)).mpr ((sig_iff c $b).mpr ?_)⟩
  apply $cert (x := a.x) (c := c) a.ok (by decide +kernel) $args*
  all_goals decide +kernel)

private def certificates : List Certificate := [
  campaign_at .canStartElection_engaged_can_inl campaign 3 follower 0,
  campaign_at .canStartElection_engaged_can_inr_inl higherPreReply 8 preCandidate 0,
  campaign_at .canStartElection_engaged_can_inr_inr retryCandidate 4 candidate]

public def witnessed : List Classes.StepBranch := certificates.map Subtype.val

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true := by
  obtain ⟨cert, _, rfl⟩ := List.mem_map.mp mem
  exact cert.property

end ConsensusCoverage.CampaignCasesB
