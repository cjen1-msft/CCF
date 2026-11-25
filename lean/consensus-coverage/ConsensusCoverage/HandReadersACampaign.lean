module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.ReadersShapes
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersA.CampaignRows

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety ActionProfile SolvedWitnesses
set_option maxRecDepth 8192
set_option maxHeartbeats 500000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

def column (vote fresh : Bool) : Classes.StepBranch :=
  if vote then (if fresh then .campaign_votes_campaign_inl else .campaign_votes_campaign_inr)
  else (if fresh then .campaign_three_campaign_inl else .campaign_three_campaign_inr)

def reader (vote fresh : Bool) : Reader := fun cfg before act after past =>
  (GuardedDomain.ofAction cfg before after past act).any fun v =>
    decide (decide (v.pre.currentTerm < v.post.currentTerm) = fresh ∧
      ((v.changed = true ∧ v.post.role = .candidate ∧ (vote = true → v.post.votesGranted.Nonempty)) ∨
        (v.post.role = .primary ∧ ¬(v.pre.role = .primary ∧ v.post.currentTerm = v.pre.currentTerm))))

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Here (v : Bool) := ¬Now f c.actor c.post ∧ c.post.role = .candidate ∧
  (v = true → c.post.votesGranted.Nonempty)

private abbrev Site (v : Bool) (cand : NodeState) :=
  c.post.currentTerm = cand.currentTerm ∧ (Here c v ∨ Wins c.actor c.pre c.event c.post)

-- The normalizer retains successive projections of each conjunction.
-- Search only its right spine: no disjunct can be chosen by this tactic.
local macro "along " h:term : tactic => `(tactic| {
  have spine := $h
  repeat' first | exact spine | exact spine.1 | obtain ⟨_,spine⟩ := spine })

private theorem local_three {cand} (src : (reach% step_campaign_three_campaign_inl[0]) f t c c cand) :
    Site c false cand := by
  have same : cand = c.post := by along src
  subst cand
  have role := src.2.2.1
  exact ⟨rfl,.inl ⟨fun h => src.1.2.2.1 ⟨h,role⟩,role,by simp⟩⟩

private theorem local_votes {cand} (src : (reach% step_campaign_votes_campaign_inl[0]) f t c c cand) :
    Site c true cand := by
  have root := src.1
  have role := src.2.2.1
  obtain ⟨_,_,_,_,_,_,_,_,_,_,voter,mem,_,_,_,_,rfl⟩ := src
  exact ⟨rfl,.inl ⟨fun h => root.2.2.1 ⟨h,role⟩,role,fun _ => ⟨voter,mem⟩⟩⟩

local macro "win_site " c:ident src:ident : tactic => `(tactic| {
  have won : Wins ($c).actor ($c).pre ($c).event ($c).post := by along $src
  exact ⟨($src).2.1.2.2.2.1,.inr won⟩ })

private theorem necessary (vote fresh : Bool) (h : sig c (column vote fresh)) :
    decide (c.pre.currentTerm < c.post.currentTerm) = fresh ∧
      (Here c vote ∨ Wins c.actor c.pre c.event c.post) := by
  cases vote <;> cases fresh
  all_goals
    rcases h with h | h | h | h | h | h | h | h | h | h
    all_goals
      obtain ⟨cand,src,tail⟩ := h
      refine (fun (site : Site c _ cand) => And.intro ?_ site.2) ?_
      · rw [site.1]
        first
        | rw [decide_eq_true_eq]
          have incr : cand.currentTerm = c.pre.currentTerm + 1 := by along tail
          omega
        | rw [decide_eq_false_iff_not]
          have same : cand.currentTerm = c.pre.currentTerm := by along tail
          omega
      ·
        first
        | exact local_three c src
        | exact local_votes c src
        | win_site c src
        | rcases src with src | src <;> win_site c src

omit [Config.InitialConfiguration] in
private theorem voter_of_quorum {cfgs : List Node.Configuration} {voters : CCF.Finset NodeID}
    (q : hasQuorum cfgs voters) : voters.Nonempty := by
  obtain ⟨cfg,mem⟩ := List.exists_mem_of_ne_nil _ q.1
  have maj := of_decide_eq_true (List.all_eq_true.mp q.2 cfg mem)
  change cfg.nodes.card < (voters ∩ cfg.nodes).val.length * 2 at maj
  obtain ⟨v,hv⟩ := List.exists_mem_of_ne_nil (voters ∩ cfg.nodes).val
    (fun empty => by rw [empty] at maj; simp at maj)
  exact ⟨v,CCF.Finset.inter_subset_left hv⟩

private abbrev Three (cand : NodeState) :=
  (reach% step_campaign_three_campaign_inl[0]) f t c c cand ∨
    (reach% step_campaign_three_campaign_inl[1]) f t c c cand

private abbrev Votes (cand : NodeState) :=
  (reach% step_campaign_votes_campaign_inl[0]) f t c c cand ∨
    (reach% step_campaign_votes_campaign_inl[1]) f t c c cand

private theorem supply (v : Bool) (site : Here c v ∨ Wins c.actor c.pre c.event c.post) :
    ∃ cand, Campaign c.actor c.pre c.event cand ∧ c.post.currentTerm = cand.currentTerm ∧
      c.post.votedFor = cand.votedFor ∧ (if v then Votes c cand else Three c cand) := by
  have now := c.post_now
  rcases site with ⟨changed,role,member⟩ | win
  · have campaign := Summary.candidate c.sum role
    refine ⟨c.post,campaign,rfl,rfl,?_⟩
    have ⟨_,log,commit,alt⟩ := campaign
    have ⟨floor,terms⟩ := c.campaign_three campaign
    have rt : (reach% step_campaign_three_campaign_inl[0,0]) f t c c c.actor c.post :=
      ⟨now,role,fun p => changed p.1,rfl⟩
    cases v
    · exact .inl ⟨rt,now,role,now,role,log,commit,alt,now,role,campaign,rfl,rfl⟩
    · obtain ⟨voter,mem⟩ := member rfl
      exact .inl ⟨rt,now,role,now,role,log,commit,alt,floor,terms,voter,mem,now,role,campaign,rfl,rfl⟩
  · obtain ⟨primary,fresh⟩ := (ReadersShapes.wins_recorded c).mp win
    have rt : (reach% step_campaign_three_campaign_inl[1,0]) f t c c := by
      refine ⟨⟨now,primary,?_,rfl⟩,now,primary,now,win,now,primary,rfl⟩
      rintro ⟨h,_⟩
      have eq := c.now_pre h
      exact fresh ⟨eq ▸ primary,congrArg NodeState.currentTerm eq⟩
    obtain ⟨cand,facts⟩ := Wins.facts win
    have ⟨campaign,q,log,term,voted,matched,role,le⟩ := facts
    have ⟨candRole,candLog,candCommit,alt⟩ := campaign
    have ⟨floor,terms⟩ := c.campaign_three campaign
    obtain ⟨w,member⟩ := voter_of_quorum q
    refine ⟨cand,campaign,term,voted,?_⟩
    cases v <;> apply Or.inr
    all_goals
      repeat' first | assumption | rfl | apply And.intro | exact ⟨w,member,win,rfl⟩

private theorem sufficient (vote fresh : Bool) (guard : decide (c.pre.currentTerm < c.post.currentTerm) = fresh)
    (site : Here c vote ∨ Wins c.actor c.pre c.event c.post) : sig c (column vote fresh) := by
  obtain ⟨cand,campaign,term,voted,src⟩ := supply c vote site
  have ⟨role,log,commit,alts⟩ := campaign
  rw [term] at guard
  cases vote <;> cases fresh
  all_goals
    first
    | rw [decide_eq_true_eq] at guard
      obtain ⟨engaged,incr,self,votes⟩ := alts.resolve_right (fun same => (Nat.ne_of_lt guard) same.2.1.symm)
    | rw [decide_eq_false_iff_not] at guard
      obtain ⟨old,same,voteEq,votes⟩ := alts.resolve_left (fun new => by have inc := new.2.1; omega)
    rcases src with localSite | winSite
    · refine Or.inl ⟨cand,localSite,?_⟩
      repeat' first | assumption | apply And.intro
    · refine Or.inr (Or.inl ⟨cand,winSite,?_⟩)
      repeat' first | assumption | apply And.intro
end

def exactReader (vote fresh : Bool) : Exact (column vote fresh) where
  eval := reader vote fresh
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    obtain ⟨v,made,ok⟩ := GuardedDomain.ofAction_matches s
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,reader,made,Option.any_some,decide_eq_true_eq]
    rw [show sig s.context (column vote fresh) ↔ _ from
      ⟨necessary s.context vote fresh,fun h => sufficient s.context vote fresh h.1 h.2⟩]
    simp only [Here,ReadersShapes.wins_recorded,GuardedDomain.View.old_post ok,Bool.not_eq_false]
    rw [GuardedDomain.View.pre_eq ok,GuardedDomain.View.post_eq ok]

end ConsensusCoverage.HandReadersA.CampaignRows
