module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepCampaignCases

open Consensus Consensus.Proofs Consensus.Model Consensus.Model.Node Safety
open ActionProfile ReadersAtoms GuardedDomain SolvedWitnesses

set_option maxRecDepth 8192

inductive CampaignCase where
  | newTerm | sameTerm | newVote | oldVotes | retained | received

def CampaignCase.column : CampaignCase → Classes.StepBranch
  | .newTerm => .campaign_three_campaign_inl
  | .sameTerm => .campaign_three_campaign_inr
  | .newVote => .campaign_votes_campaign_inl
  | .oldVotes => .campaign_votes_campaign_inr
  | .retained => .campaign_votes_more_inl
  | .received => .campaign_votes_more_inr

private def newTerm : CampaignCase → Bool
  | .newTerm | .newVote => true
  | _ => false

private def voterTest (x : XView) (voter : NodeID) : CampaignCase → Bool
  | .retained => decide (voter ∈ x.base.pre.votesGranted)
  | .received => decide (x.event = .receive voter (.requestVoteResponse ⟨x.base.pre.currentTerm, true⟩))
  | _ => true

def check (s : Step) (k : CampaignCase) (voter : NodeID) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x =>
    decide (x.base.changed = true ∧ x.base.post.role = .candidate ∧ voter ∈ x.base.post.votesGranted ∧
      (if newTerm k then decide (x.base.pre.currentTerm < x.base.post.currentTerm) else
        decide (x.base.pre.currentTerm = x.base.post.currentTerm)) = true ∧ voterTest x voter k = true)

theorem correct (s : Step) (k : CampaignCase) (voter : NodeID) (yes : check s k voter = true) :
    label s (.step k.column) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x, made, ok⟩ := ofXAction_matches s
  simp only [check, made, Option.any_some, decide_eq_true_eq] at yes
  obtain ⟨changed, role, member, termGuard, voteGuard⟩ := yes
  rw [← View.post_eq ok.1] at role member termGuard
  rw [← View.pre_eq ok.1] at termGuard
  have fresh : ¬Now s.frame c.actor c.post := fun h =>
    Bool.noConfusion (changed.symm.trans ((View.old_post ok.1).mp h))
  have now := c.post_now
  have campaign := Summary.candidate c.sum role
  obtain ⟨floor, termCase⟩ := c.campaign_three campaign
  have facts := campaign
  obtain ⟨cand, clog, commit, alternatives⟩ := facts
  have first : (reach% SolvedWitnesses.step_campaign_three_campaign_inl[0]) s.frame s.after c c c.post :=
    ⟨⟨now, role, fun p => fresh p.1, rfl⟩, now, role, now, role, clog, commit, alternatives,
      now, role, campaign, rfl, rfl⟩
  have second : (reach% SolvedWitnesses.step_campaign_votes_campaign_inl[0]) s.frame s.after c c c.post :=
    ⟨⟨now, role, fun p => fresh p.1, rfl⟩, now, role, now, role, clog, commit, alternatives,
      floor, termCase, voter, member, now, role, campaign, rfl, rfl⟩
  refine (label_true s _).mpr ((SolvedWitnesses.sig_iff c _).mpr ?_)
  cases k <;> simp [newTerm] at termGuard
  all_goals
    first
    | have newer : c.pre.currentTerm < c.post.currentTerm := termGuard
      obtain ⟨engaged, next, vote, self⟩ :=
        alternatives.resolve_right (fun p => (Nat.ne_of_lt newer) p.2.1.symm)
    | have same : c.pre.currentTerm = c.post.currentTerm := termGuard
      obtain ⟨prior, equal, vote, more⟩ :=
        alternatives.resolve_left (fun p => by have eq := p.2.1; omega)
    first | refine Or.inl ⟨c.post, first, ?_⟩ | refine Or.inl ⟨c.post, second, ?_⟩
    repeat' first | assumption | rfl | apply And.intro
  · have before : voter ∈ c.pre.votesGranted := by
      rw [show c.pre = x.base.pre from View.pre_eq ok.1]
      exact of_decide_eq_true voteGuard
    exact ⟨voter, member, before, campaign, rfl, rfl⟩
  · let r : RequestVoteResponse := ⟨c.pre.currentTerm, true⟩
    have event : c.event = .receive voter (.requestVoteResponse r) := by
      dsimp only [r]
      rw [show c.event = x.event from X.event_eq ok, show c.pre = x.base.pre from View.pre_eq ok.1]
      exact of_decide_eq_true voteGuard
    exact ⟨voter, member, ⟨r, event, rfl, rfl⟩, r, ⟨event, rfl, rfl⟩,
      event, ⟨rfl, rfl⟩, rfl, rfl, campaign, rfl, rfl⟩

end ConsensusCoverage.DeepCampaignCases
