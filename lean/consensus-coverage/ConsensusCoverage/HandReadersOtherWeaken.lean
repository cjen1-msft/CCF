module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersOtherShorten
import all ConsensusCoverage.HandReadersOtherSites
import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.Readers
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersOther.Weaken

open Consensus Model Model.Node Proofs Safety Ledger ActionProfile HandReadersA SolvedWitnesses
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

def gate (newTerm : Bool) : Reader := fun cfg before act after past =>
  let e := Readers.read cfg before act after past
  let yes := fun b => (Readers.read? e b).getD false
  if newTerm then yes .commit_backed_kind_elect || yes .keep_backed_led_after_inr else
    yes .commit_backed_kind_append || yes .commit_backed_kind_ack || yes .keep_backed_led_after_inl

def reader (zero : Bool) : Reader := fun cfg before act after past =>
  [false,true].any fun newTerm =>
    actorRead (fun _ pre _ post => Shorten.test zero (CommitKeys.keys (cfg.min?.getD 0) (before :: past))
      pre.commitIndex (if newTerm then post.currentTerm - 1 else pre.currentTerm)) cfg before act after past &&
    gate newTerm cfg before act after past

local macro "place " h:term : tactic => `(tactic| {
  repeat' first | exact $h | exact Or.inl $h | apply Or.inr
  done })
local macro "along " h:term : tactic => `(tactic| {
  have tail := $h
  repeat' first | exact tail | exact tail.1 | obtain ⟨_,tail⟩ := tail })

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev Gate (newTerm : Bool) := if newTerm then
  step_commit_backed_kind_elect f t c ∨ step_keep_backed_led_after_inr f t c else
  (step_commit_backed_kind_append f t c ∨ step_commit_backed_kind_ack f t c) ∨ step_keep_backed_led_after_inl f t c
abbrev Term (newTerm : Bool) := if newTerm then c.post.currentTerm - 1 else c.pre.currentTerm

abbrev Site (l : List Entry) (i k k' : Nat) :=
  (reach% step_weaken_backed_inl[0]) f t c l i k k' ∨ (reach% step_weaken_backed_inl[1]) f t c l i k k' ∨
  (reach% step_weaken_backed_inl[2]) f t c l i k k' ∨ (reach% step_weaken_backed_inl[3]) f t c l i k k'

private abbrev Early := (reach% step_weaken_backed_inl[2,1]) f t c c ∨ (reach% step_weaken_backed_inl[3,1]) f t c c

private theorem early_only (h : Early c) : Gate c false := by
  rcases h with h | h
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals first
    | obtain ⟨rt,x,y,es,sent,leader,terms,adv,eq,_⟩ := h
      refine .inl (.inl ?_)
      place ⟨rt,x,y,es,sent,leader,terms,adv,eq,x,fun b => ⟨⟨_,b⟩,fun _ _ => b⟩⟩
    | obtain ⟨rt,x,y,n,r,ev,leader,pos,term,adv,eq,_⟩ := h
      refine .inl (.inr ?_)
      place ⟨rt,x,y,n,r,ev,leader,pos,term,adv,eq,x,fun b => ⟨⟨_,b⟩,fun _ _ => b⟩⟩
    | obtain ⟨rt,led,_,_,_,agree,idx,post,_⟩ := h
      right; place ⟨rt,led,agree,idx,post⟩

theorem decode {l i k k'} (h : Site c l i k k') :
    l = c.pre.log ∧ i = c.pre.commitIndex ∧ k' = c.post.currentTerm ∧
      ∃ newTerm, Gate c newTerm ∧ k = Term c newTerm := by
  rcases h with h | h | h | h
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    refine ⟨by along h,by along h,by along h,?_⟩
    first
    | obtain ⟨rt,x,y,w,eq,rest⟩ := h
      refine ⟨true,.inl ?_,by along rest⟩
      place ⟨rt,x,y,w,eq,x,fun b => ⟨⟨_,b⟩,fun _ _ => b⟩⟩
    | obtain ⟨rt,ex,one,e,_,agree,idx,led,_,rest⟩ := h
      refine ⟨true,.inr ?_,by along rest⟩
      place ⟨rt,ex,c.pre.log,one,c.pre.commitIndex,e,agree,idx,led⟩
    | exact ⟨false,early_only c (by first | exact .inl h.1 | exact .inr h.1),by along h⟩

abbrev Agree := c.post.log.take c.pre.commitIndex = c.pre.log.take c.pre.commitIndex

private theorem early_of (h : Gate c false) : Early c ∧ Agree c ∧ ¬c.pre.role = .candidate ∧
    Led f c.actor c.pre.currentTerm := by
  rcases h with ((h | h) | (h | h)) | (h | h)
  all_goals first
    | obtain ⟨rt,x,y,es,sent,l,terms,a,eq,_⟩ := h
      have log : c.post.log = c.pre.log ++ es := a.log
      refine ⟨?_,by unfold Agree; rw [log]; exact List.take_append_of_le_length c.frontier_pre,by simp [l],c.pre_led l⟩
      first | left; left; exact ⟨rt,x,y,es,sent,l,terms,a,eq,x,log,a.term,rfl⟩
            | right; left; exact ⟨rt,x,y,es,sent,l,terms,a,eq,x,log,a.term,rfl⟩
    | obtain ⟨rt,x,y,n,r,ev,l,pos,tm,a,eq,_⟩ := h
      have log : c.post.log = c.pre.log := a.log
      refine ⟨?_,by unfold Agree; rw [log],by simp [l],c.pre_led l⟩
      first | left; place ⟨rt,x,y,n,r,ev,l,pos,tm,a,eq,x,log,a.term,rfl⟩
            | right; place ⟨rt,x,y,n,r,ev,l,pos,tm,a,eq,x,log,a.term,rfl⟩
    | obtain ⟨rt,led,agree,idx,post⟩ := h
      have same := (c.inv.led_cur _ _ _ c.pre_now led).resolve_left (Nat.not_lt_of_ge c.term_le)
      refine ⟨?_,agree,same.2,same.1 ▸ led⟩
      first | left; place ⟨rt,led,same,same.1,same.2,agree,idx,post,rfl⟩
            | right; place ⟨rt,led,same,same.1,same.2,agree,idx,post,rfl⟩

theorem encode (newTerm : Bool) (g : Gate c newTerm) :
    Site c c.pre.log c.pre.commitIndex (Term c newTerm) c.post.currentTerm ∧
      Backed f c.pre.log c.pre.commitIndex (Term c newTerm) ∧ Agree c ∧ Term c newTerm ≤ c.post.currentTerm := by
  cases newTerm
  case false =>
    obtain ⟨h | h,agree,nc,led⟩ := early_of c g
    all_goals
      refine ⟨?_,(c.inv.commit_backed _ _ c.pre_now).2 nc led,agree,c.term_le⟩
      place (Or.inr ⟨h,agree,nc,led,rfl,rfl,rfl,rfl⟩)
  case true =>
    rcases g with (h | h) | (h | h)
    all_goals first
      | obtain ⟨rt,x,y,w,eq,_⟩ := h
        have elect := c.wins_elect w
        have win := (c.electStep elect).2.2.2.2.2.2.1
        have bound : c.pre.commitIndex ≤ maxCommittableIndex c.pre.log := by
          rcases Nat.eq_zero_or_pos c.pre.commitIndex with zero | pos
          · rw [zero]; exact Nat.zero_le _
          · exact signatureIndex_le_maxCommittableIndex ((c.inv.frontier _ _ c.pre_now).2 pos)
        have agree : Agree c := by
          unfold Agree
          rw [take_eq_of_prefix win (by rw [List.length_take]; exact Nat.le_min.mpr ⟨bound,c.frontier_pre⟩),
            List.take_take,Nat.min_eq_left bound]
        refine ⟨?_,c.elect_backed elect,agree,Nat.sub_le ..⟩
        obtain ⟨z,camp,q,a⟩ := w
        place (Or.inl ⟨rt,x,y,⟨z,camp,q,a⟩,eq,z,⟨camp,q,a⟩,camp,⟨q,a⟩,camp.1,camp.2,camp.2.1,
          camp.2.2,camp.2.2.1,camp.2.2.2,q,a,x,elect,win,bound,agree,rfl,rfl,rfl,rfl⟩)
      | obtain ⟨rt,ex,l,one,i,e,agree,idx,led⟩ := h
        obtain ⟨_,rfl,rfl,term,_,role,sub,floor⟩ := c.electStep e
        have b := c.elect_backed e
        refine ⟨?_,b,agree,Nat.sub_le ..⟩
        place (Or.inl ⟨rt,ex,one,e,⟨term,role,sub,floor⟩,agree,idx,led,b,rfl,rfl,rfl,rfl⟩)

private def column (zero : Bool) : Classes.StepBranch := if zero then .weaken_backed_inl else .weaken_backed_inr

private theorem iff_guard (zero : Bool) : sig c (column zero) ↔
    ∃ q, Gate c q ∧ Shorten.Guard zero f c.pre.commitIndex (Term c q) := by
  constructor
  · cases zero <;> rintro (h | h | h | h)
    all_goals first
      | obtain ⟨l,i,k,k',co,positive,rest⟩ := h
        have b : Backed f l i k := by along rest
        obtain ⟨rfl,rfl,_,q,src,rfl⟩ := decode c (by place co)
        exact ⟨q,src,(Shorten.guard_iff b).mpr positive⟩
      | obtain ⟨l,k,k',co,_,_⟩ := h
        obtain ⟨_,i,_,q,src,rfl⟩ := decode c (by place co)
        exact ⟨q,src,i.symm⟩
  · rintro ⟨q,src,g⟩
    obtain ⟨co,b,_,le⟩ := encode c q src
    cases zero
    case true =>
      change c.pre.commitIndex = 0 at g
      rw [g] at co b
      rcases co with h | h | h | h
      all_goals place ⟨_,_,_,h,b,le⟩
    case false =>
      obtain ⟨e,p,m,i,sub⟩ := (Shorten.guard_iff b).mp g
      have pack := And.intro m (And.intro i sub)
      rcases co with h | h | h | h
      all_goals place ⟨_,_,_,_,h,⟨e,p,pack⟩,e,⟨p,pack⟩,p,pack,m,pack.2,i,sub,b,le⟩
end

theorem gate_iff (s : Step) (q : Bool) : letI : Config.InitialConfiguration := ⟨s.cfg⟩
    gate q s.cfg s.before s.act s.after s.past = true ↔ Gate s.context q := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  cases q <;> simp only [gate,Gate,ite_false,ite_true,Bool.false_eq_true,Bool.or_eq_true,
    Readers.read?_at s (b := .commit_backed_kind_append) (by decide +kernel),
    Readers.read?_at s (b := .commit_backed_kind_ack) (by decide +kernel),
    Readers.read?_at s (b := .commit_backed_kind_elect) (by decide +kernel),
    Readers.read?_at s (b := .keep_backed_led_after_inl) (by decide +kernel),
    Readers.read?_at s (b := .keep_backed_led_after_inr) (by decide +kernel),
    Option.getD_some,label_true,holds,sig_iff] <;> rfl

def exactReader (zero : Bool) : Exact (column zero) where
  eval := reader zero
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    have keys (k l) : (k,l) ∈ CommitKeys.keys (s.cfg.min?.getD 0) (s.before :: s.past) ↔ Committed s.frame k l :=
      CommitKeys.step_mem s k l
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,iff_guard]
    simp only [reader,List.any_eq_true,Bool.and_eq_true,actorRead_at,gate_iff,Shorten.test_iff keys,
      Term,List.mem_cons,List.not_mem_nil,or_false]
    constructor
    · rintro ⟨q,src,g⟩; exact ⟨q,by cases q <;> simp,g,src⟩
    · rintro ⟨q,_,g,src⟩; exact ⟨q,src,g⟩

end ConsensusCoverage.HandReadersOther.Weaken
