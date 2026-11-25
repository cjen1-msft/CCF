module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersACampaign
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersShapes
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersA.Voter

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety ActionProfile SolvedWitnesses
set_option maxRecDepth 8192
set_option maxHeartbeats 500000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

def column (old : Bool) : Classes.StepBranch :=
  if old then .campaign_votes_more_inl else .campaign_votes_more_inr

def choices (old : Bool) (pre : NodeState) (ev : Event) : List NodeID :=
  if old then pre.votesGranted.val else
    match ev with
    | .receive n (.requestVoteResponse q) => if q.voteGranted && q.term == pre.currentTerm then [n] else []
    | _ => []

def reader (old : Bool) : Reader := fun cfg before act after past =>
  (GuardedDomain.ofAction cfg before after past act).any fun v =>
    let vs := choices old v.pre (ReadersAtoms.eventOf act)
    decide (v.post.currentTerm = v.pre.currentTerm ∧
      ((v.changed = true ∧ v.post.role = .candidate ∧ vs.any (fun n => decide (n ∈ v.post.votesGranted))) ∨
        (v.post.role = .primary ∧ ¬(v.pre.role = .primary ∧ v.post.currentTerm = v.pre.currentTerm) ∧ vs ≠ [])))

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private abbrev Responds (n : NodeID) :=
  ∃ q, c.event = .receive n (.requestVoteResponse q) ∧ q.term = c.pre.currentTerm ∧ q.voteGranted = true

private def Eligible (old : Bool) (n : NodeID) := if old then n ∈ c.pre.votesGranted else Responds c n

private theorem mem_choices (old n) : n ∈ choices old c.pre c.event ↔ Eligible c old n := by
  cases old
  case true => rfl
  case false =>
    unfold Eligible Responds choices
    cases c.event with
    | internal => simp
    | receive sender m =>
      cases m <;> simp
      grind

private abbrev Data (old : Bool) := c.post.currentTerm = c.pre.currentTerm ∧
  ((¬Now f c.actor c.post ∧ c.post.role = .candidate ∧
      ∃ n ∈ c.post.votesGranted, Eligible c old n) ∨
    (Wins c.actor c.pre c.event c.post ∧ ∃ n, Eligible c old n))

private abbrev Local (cand : NodeState) := (reach% step_campaign_votes_more_inl[0]) f t c c cand
private abbrev Winning (cand : NodeState) := (reach% step_campaign_votes_more_inl[1]) f t c c cand

local macro "along " h:term : tactic => `(tactic| {
  have spine := $h
  repeat' first | exact spine | exact spine.1 | obtain ⟨_,spine⟩ := spine })

private theorem local_site {cand} (src : Local c cand) :
    cand = c.post ∧ ¬Now f c.actor c.post ∧ c.post.role = .candidate := by
  have role := src.2.2.1
  exact ⟨by along src,fun h => src.1.2.2.1 ⟨h,role⟩,role⟩

private theorem close_case (old) {cand : NodeState}
    (site : (cand = c.post ∧ ¬Now f c.actor c.post ∧ c.post.role = .candidate) ∨
      Wins c.actor c.pre c.event c.post) (same : cand.currentTerm = c.pre.currentTerm)
    (choice : ∃ n ∈ cand.votesGranted, Eligible c old n ∧ c.post.currentTerm = cand.currentTerm) :
    Data c old := by
  obtain ⟨n,member,yes,term⟩ := choice
  refine ⟨term.trans same,?_⟩
  rcases site with ⟨rfl,new,role⟩ | won
  · exact .inl ⟨new,role,n,member,yes⟩
  · exact .inr ⟨won,n,yes⟩

private theorem necessary (old) (h : sig c (column old)) : Data c old := by
  cases old
  all_goals
    rcases h with h | h | h | h | h | h | h | h | h | h
    all_goals
      obtain ⟨cand,src,tail⟩ := h
      have same : cand.currentTerm = c.pre.currentTerm := by along tail
      refine close_case c _ (cand := cand) ?_ same ?_
      · first
        | exact .inl (local_site c src)
        | apply Or.inr
          first | solve | along src | rcases src with src | src <;> along src
      ·
        first
        | have last : ∃ n ∈ cand.votesGranted, n ∈ c.pre.votesGranted ∧
              Campaign c.actor c.pre c.event cand ∧ c.post.currentTerm = cand.currentTerm ∧
                c.post.votedFor = cand.votedFor := by along tail
          obtain ⟨n,mem,pre,_,term,_⟩ := last
          exact ⟨n,mem,pre,term⟩
        | have last : ∃ n ∈ cand.votesGranted, Responds c n ∧ ∃ q : RequestVoteResponse,
              (c.event = .receive n (.requestVoteResponse q) ∧ q.term = c.pre.currentTerm ∧ q.voteGranted = true) ∧
                c.event = .receive n (.requestVoteResponse q) ∧ (q.term = c.pre.currentTerm ∧ q.voteGranted = true) ∧
                  q.term = c.pre.currentTerm ∧ q.voteGranted = true ∧ Campaign c.actor c.pre c.event cand ∧
                    c.post.currentTerm = cand.currentTerm ∧ c.post.votedFor = cand.votedFor := by along tail
          obtain ⟨n,mem,yes,_,_,_,_,_,_,_,term,_⟩ := last
          exact ⟨n,mem,yes,term⟩

private theorem supply (old) (h : Data c old) :
    ∃ cand, (Local c cand ∨ Winning c cand) ∧ Campaign c.actor c.pre c.event cand ∧
      c.post.currentTerm = cand.currentTerm ∧ c.post.votedFor = cand.votedFor ∧
        ∃ n ∈ cand.votesGranted, Eligible c old n := by
  obtain ⟨stable,candidate | ⟨win,n,eligible⟩⟩ := h
  · obtain ⟨changed,role,n,mem,yes⟩ := candidate
    have now := c.post_now
    have camp := Summary.candidate c.sum role
    have ⟨_,log,commit,alt⟩ := camp
    have ⟨floor,term⟩ := c.campaign_three camp
    exact ⟨c.post,.inl ⟨⟨now,role,fun p => changed p.1,rfl⟩,now,role,now,role,log,commit,alt,floor,term,
      n,mem,now,role,camp,rfl,rfl⟩,camp,rfl,rfl,n,mem,yes⟩
  · obtain ⟨cand,camp,term,vote,localSite | src⟩ := CampaignRows.supply c true (Or.inr win)
    case inl =>
      obtain ⟨_,_,role⟩ := local_site c localSite
      cases role.symm.trans ((ReadersShapes.wins_recorded c).mp win).1
    let expanded := {cand with votesGranted := insert n cand.votesGranted}
    have ⟨candRole,clog,cidx,alt⟩ := camp
    have ⟨prior,cterm,kept,more⟩ := alt.resolve_left (fun new => by have inc := new.2.1; omega)
    have add : n ∈ c.pre.votesGranted ∨ Responds c n := by cases old <;> first | exact .inl eligible | exact .inr eligible
    have campaign : Campaign c.actor c.pre c.event expanded := by
      refine ⟨candRole,clog,cidx,.inr ⟨prior,cterm,kept,?_⟩⟩
      intro v m
      rcases Finset.mem_insert.mp m with rfl | prev
      · exact add
      · exact more v prev
    have facts := src.2.1
    have ⟨_,q,log,term',voted,matched,role,le⟩ := facts
    have enlarged : hasQuorum (activeConfigurations c.pre.log c.pre.commitIndex) expanded.votesGranted :=
      ReadersShapes.quorum_mono (fun _ m => Finset.mem_insert.mpr (.inr m)) q
    have ⟨fr,fl,fc,fa⟩ := campaign
    have ⟨floor,termCase⟩ := c.campaign_three campaign
    have member : n ∈ expanded.votesGranted := Finset.mem_insert.mpr (.inl rfl)
    refine ⟨expanded,.inr ?_,campaign,term,vote,n,member,eligible⟩
    refine ⟨src.1,?_⟩
    repeat' first | assumption | rfl | apply And.intro | exact ⟨n,member,win,rfl⟩

private theorem sufficient (old) (h : Data c old) : sig c (column old) := by
  obtain ⟨cand,src,camp,term,vote,n,mem,yes⟩ := supply c old h
  have ⟨role,log,idx,alt⟩ := camp
  have eq := h.1
  obtain ⟨prior,stable,kept,more⟩ := alt.resolve_left (fun fresh => by have inc := fresh.2.1; omega)
  cases old
  all_goals
    rcases src with loc | won
    all_goals
      first | refine Or.inl ⟨cand,loc,?_⟩ | refine Or.inr (Or.inl ⟨cand,won,?_⟩)
      repeat' first | assumption | apply And.intro
      first
      | exact ⟨n,mem,yes,camp,term,vote⟩
      | obtain ⟨q,ev,tm,grant⟩ := yes
        exact ⟨n,mem,⟨q,ev,tm,grant⟩,q,⟨ev,tm,grant⟩,ev,⟨tm,grant⟩,tm,grant,camp,term,vote⟩
end

def exactReader (old : Bool) : Exact (column old) where
  eval := reader old
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    obtain ⟨v,made,ok⟩ := GuardedDomain.ofAction_matches s
    change v.Matches c at ok
    have ev : ReadersAtoms.eventOf s.act = c.event := by
      rw [← (s.context_eq c).mpr rfl]
      change ReadersAtoms.eventOf (ActionContext.encode _ c.tr.event) = c.tr.event
      cases c.tr.event <;> rfl
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,reader,made,Option.any_some,decide_eq_true_eq]
    rw [show sig c (column old) ↔ Data c old from ⟨necessary c old,sufficient c old⟩]
    simp only [Data,ReadersShapes.wins_recorded,GuardedDomain.View.old_post ok,Bool.not_eq_false]
    rw [←GuardedDomain.View.pre_eq ok,←GuardedDomain.View.post_eq ok,ev]
    simp only [List.any_eq_true,decide_eq_true_eq,← ReadersAtoms.exists_mem_iff,mem_choices c]
    grind

end ConsensusCoverage.HandReadersA.Voter
