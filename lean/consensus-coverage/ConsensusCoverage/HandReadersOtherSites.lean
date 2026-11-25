module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.AckAdvance
import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersOther.Advance

open Consensus Model Model.Node Proofs Safety Ledger ActionProfile SolvedWitnesses HandReadersA

set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

def source : Reader := fun cfg before act after past =>
  let e := Readers.read cfg before act after past
  [Classes.StepBranch.commit_backed_kind_append,.commit_backed_kind_ack,.commit_backed_kind_elect].any fun b =>
    (Readers.read? e b).getD false

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev Source := step_commit_backed_kind_append f t c ∨ step_commit_backed_kind_ack f t c ∨
  step_commit_backed_kind_elect f t c

abbrev Site (m : NodeState) :=
  (reach% step_advance_backed_advance_inl[0]) f t c c m ∨
  (reach% step_advance_backed_advance_inl[1]) f t c c m ∨
  (reach% step_advance_backed_advance_inl[2]) f t c c m ∨
  (reach% step_advance_backed_advance_inl[3]) f t c c m

structure Ready (m : NodeState) : Prop where
  site : Site c m
  advance : Safety.Advance c.actor m c.post
  index : m.commitIndex = c.pre.commitIndex
  backed : Backed f c.post.log m.commitIndex c.post.currentTerm
  led : Led (f.advance t) c.actor c.post.currentTerm
  primary : m.role = .primary
  acks : ∀ v, v ≠ c.actor → 0 < m.matchIndex v → ∃ st, Seen (f.advance t) v st ∧
    st.currentTerm = c.post.currentTerm ∧ c.post.log.take (m.matchIndex v) <+: st.log

private abbrev Root :=
  (reach% step_commit_backed_kind_ack[0]) f t c c c.actor c.post ∨
  (reach% step_commit_backed_kind_ack[1]) f t c c c.actor c.post

theorem of_site {m} (h : Site c m) : Source c ∧ m.commitIndex = c.pre.commitIndex := by
  rcases h with h | h | h | h
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    first
    | obtain ⟨root,now,now',xs,sent,leader,terms,adv,eq,rest⟩ := h
      have mEq : m = {c.pre with log := c.pre.log ++ xs,sentIndex := sent} := by
        repeat' first | exact rest | obtain ⟨_,rest⟩ := rest
      refine ⟨.inl ?_,mEq ▸ rfl⟩
      first | left; exact ⟨root,now,now',xs,sent,leader,terms,adv,eq,now,fun b => ⟨⟨_,b⟩,fun _ _ => b⟩⟩
            | right; exact ⟨root,now,now',xs,sent,leader,terms,adv,eq,now,fun b => ⟨⟨_,b⟩,fun _ _ => b⟩⟩
    | obtain ⟨root,now,now',src,r,ev,leader,pos,term,adv,eq,rest⟩ := h
      have mEq : m = AckAdvance.middle c.pre src r := by
        repeat' first | exact rest | obtain ⟨_,rest⟩ := rest
      refine ⟨.inr (.inl ?_),mEq ▸ rfl⟩
      first | left; exact ⟨root,now,now',src,r,ev,leader,pos,term,adv,eq,now,fun b => ⟨⟨_,b⟩,fun _ _ => b⟩⟩
            | right; exact ⟨root,now,now',src,r,ev,leader,pos,term,adv,eq,now,fun b => ⟨⟨_,b⟩,fun _ _ => b⟩⟩
    | obtain ⟨root,now,now',wins,eq,z,_,camp,rest⟩ := h
      have mEq : m = primaryState z := by
        repeat' first | exact rest | obtain ⟨_,rest⟩ := rest
      refine ⟨.inr (.inr ?_),mEq ▸ camp.2.2.1⟩
      first | left; exact ⟨root,now,now',wins,eq,now,fun b => ⟨⟨_,b⟩,fun _ _ => b⟩⟩
            | right; exact ⟨root,now,now',wins,eq,now,fun b => ⟨⟨_,b⟩,fun _ _ => b⟩⟩

private theorem appendReady (root : Root c) {xs : List Entry} {sent : NodeID → Nat}
    (leader : c.pre.role = .primary) (terms : ∀ e ∈ xs, e.term = c.pre.currentTerm)
    (adv : Safety.Advance c.actor {c.pre with log := c.pre.log ++ xs,sentIndex := sent} c.post) :
    ∃ m, Ready c m := by
  let m := {c.pre with log := c.pre.log ++ xs,sentIndex := sent}
  have log : c.post.log = c.pre.log ++ xs := adv.log
  have term : c.post.currentTerm = c.pre.currentTerm := adv.term
  refine ⟨m,?_,adv,rfl,c.pre_backed (by rw [log]; exact List.take_append_of_le_length c.frontier_pre)
    (by simp [leader]) (c.pre_led leader),term ▸ (c.pre_led leader).mono t,leader,?_⟩
  · rcases root with root | root
    all_goals
      first
      | left; left; exact ⟨root,c.post_now,c.post_now,xs,sent,leader,terms,adv,rfl,c.post_now,log,term,rfl,rfl⟩
      | right; left; left; exact ⟨root,c.post_now,c.post_now,xs,sent,leader,terms,adv,rfl,c.post_now,log,term,rfl,rfl⟩
  · intro v other pos
    obtain ⟨st,seen,stamp,bound,sub⟩ := c.match_pre leader other pos
    refine ⟨st,seen,stamp.trans term.symm,?_⟩
    rw [log,List.take_append_of_le_length bound]; exact sub

private theorem ackReady (root : Root c) {src r} (ev : c.event = .receive src (.appendEntriesResponse r))
    (leader : c.pre.role = .primary) (pos : r.success = true) (term : r.term = c.pre.currentTerm)
    (adv : Safety.Advance c.actor (AckAdvance.middle c.pre src r) c.post) : ∃ m, Ready c m := by
  have log : c.post.log = c.pre.log := adv.log
  have stamp : c.post.currentTerm = c.pre.currentTerm := adv.term
  refine ⟨_,?_,adv,rfl,c.pre_backed (by rw [log]) (by simp [leader]) (c.pre_led leader),
    stamp ▸ (c.pre_led leader).mono t,leader,AckAdvance.ack_premises c ev leader pos term adv⟩
  rcases root with root | root
  all_goals
    first
    | left; right; right; left; exact ⟨root,c.post_now,c.post_now,src,r,ev,leader,pos,term,adv,rfl,c.post_now,log,stamp,rfl,rfl⟩
    | right; left; right; right; left; exact ⟨root,c.post_now,c.post_now,src,r,ev,leader,pos,term,adv,rfl,c.post_now,log,stamp,rfl,rfl⟩

private theorem electReady (root : Root c) (wins : Wins c.actor c.pre c.event c.post) :
    ∃ m, Ready c m := by
  obtain ⟨z,camp,q,adv⟩ := wins
  have wins : Wins c.actor c.pre c.event c.post := ⟨z,camp,q,adv⟩
  have elect := c.wins_elect wins
  have winning := (c.electStep elect).2.2.2.2.2.2.1
  have bound : c.pre.commitIndex ≤ maxCommittableIndex c.pre.log := by
    rcases Nat.eq_zero_or_pos c.pre.commitIndex with zero | pos
    · rw [zero]; exact Nat.zero_le _
    · exact signatureIndex_le_maxCommittableIndex ((c.inv.frontier _ _ c.pre_now).2 pos)
  have agree : c.post.log.take c.pre.commitIndex = c.pre.log.take c.pre.commitIndex := by
    rw [take_eq_of_prefix winning (by rw [List.length_take]; exact Nat.le_min.mpr ⟨bound,c.frontier_pre⟩),
      List.take_take,Nat.min_eq_left bound]
  refine ⟨primaryState z,?_,adv,camp.2.2.1,?_,.inr ⟨_,_,.inr ⟨f.current,rfl,elect⟩⟩,rfl,
    fun _ _ h => (Nat.lt_irrefl _ h).elim⟩
  · rcases root with root | root
    case' inl => right; right; left; left
    case' inr => right; right; right; left
    all_goals exact ⟨root,c.post_now,c.post_now,wins,rfl,z,⟨camp,q,adv⟩,camp,⟨q,adv⟩,
        camp.1,camp.2,camp.2.1,camp.2.2,camp.2.2.1,camp.2.2.2,q,adv,c.post_now,elect,winning,bound,agree,rfl,rfl⟩
  · change Backed _ _ z.commitIndex _
    rw [camp.2.2.1]
    exact ((c.elect_backed elect).weaken (Nat.sub_le _ _)).transfer agree

theorem ready (h : Source c) : ∃ m, Ready c m := by
  rcases h with (h | h) | (h | h) | (h | h)
  all_goals
    first
    | obtain ⟨r,_,_,_,_,l,ts,a,_⟩ := h; exact appendReady c (by first | exact .inl r | exact .inr r) l ts a
    | obtain ⟨r,_,_,_,_,ev,l,p,ts,a,_⟩ := h; exact ackReady c (by first | exact .inl r | exact .inr r) ev l p ts a
    | obtain ⟨r,_,_,w,_⟩ := h; exact electReady c (by first | exact .inl r | exact .inr r) w
end

theorem source_iff (s : Step) : letI : Config.InitialConfiguration := ⟨s.cfg⟩
    source s.cfg s.before s.act s.after s.past = true ↔ Source s.context := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  simp only [source,List.any_cons,List.any_nil,Bool.or_false,Bool.or_eq_true,
    Readers.read?_at s (b := .commit_backed_kind_append) (by decide +kernel),
    Readers.read?_at s (b := .commit_backed_kind_ack) (by decide +kernel),
    Readers.read?_at s (b := .commit_backed_kind_elect) (by decide +kernel),
    Option.getD_some,label_true,holds,sig_iff]
  rfl

end ConsensusCoverage.HandReadersOther.Advance
