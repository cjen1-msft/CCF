module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersOtherFoldDirect
import all ConsensusCoverage.HandReadersOtherPromotion
import all ConsensusCoverage.HandReadersOtherAdvance
import all ConsensusCoverage.HandReadersOtherSites
import all ConsensusCoverage.HandReadersAObserve
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersOther.Fold

open Consensus Model Model.Node Proofs Safety ActionProfile HandReadersA SolvedWitnesses

set_option maxRecDepth 8192

private def localNil : Event → Bool
  | .internal (.append _) | .internal (.timeout .election) => true
  | _ => false

private def erased (self : NodeID) (pre : NodeState) (ev : Event) : Bool :=
  localNil ev || (ack self pre ev).isSome || (Promotion.candidate self pre ev).isSome

def nilReader : Reader := fun cfg before act after past =>
  Promotion.gated erased cfg before act after past || Advance.reader .growth cfg before act after past

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Local := (reach% step_foldl_select_max_values_nil[4,0,0,0]) f t c
private abbrev Remote := (reach% step_foldl_select_max_values_nil[4,0,0,1]) f t c

private theorem local_iff : Local c ↔ ¬Now f c.actor c.post ∧ localNil c.event := by
  constructor
  · rintro (⟨_,⟨n,st,e,a,o,site,ev,run,fr,ran⟩,xs,rfl⟩ | ⟨_,⟨n,st,e,a,o,site,ev,run,fr,ran⟩,rfl⟩)
    all_goals
      obtain ⟨fresh,_,_,eq⟩ := (Promotion.input_iff c).mp ⟨e,a,o,site,ev,run,fr,ran⟩
      exact ⟨fresh,by rw [eq]; rfl⟩
  · rintro ⟨fresh,h⟩
    cases ev : c.event with
    | receive => simp [ev,localNil] at h
    | internal i =>
      obtain ⟨e,a,o,site,eq,run,fr,ran⟩ := (Promotion.input_iff c (st := c.pre) (self := c.actor)).mpr ⟨fresh,rfl,rfl,ev⟩
      have co : (reach% step_foldl_select_max_values_nil[4,0,0,0,0]) f t c i := ⟨_,_,e,a,o,site,eq,run,fr,ran⟩
      cases i <;> simp only [ev,localNil] at h <;> try contradiction
      · exact .inl ⟨_,co,_,rfl⟩
      · rename_i k; cases k <;> try contradiction
        exact .inr ⟨_,co,rfl⟩

private theorem remote_only (h : Remote c) : ¬Now f c.actor c.post ∧ erased c.actor c.pre c.event := by
  rcases h with h | h | h | h
  · obtain ⟨self,st,n,m,co,pass,r,msg,pass',role,pos,term,fr,seen⟩ := h
    have call : RightCall c (AckAdvance.middle (observeTerm st m) n r) self :=
      .inl ⟨st,n,m,co,pass,r,msg,pass',role,pos,term,fr,seen,rfl⟩
    obtain ⟨fresh,rfl,rfl,ev⟩ := (Observe.receive_iff c).mp co
    subst m
    have peer := Classical.byContradiction fun no => pass' ⟨rfl,no⟩
    have prim : (observeTerm c.pre (.appendEntriesResponse r)).role = .primary := by simpa using role
    exact ⟨fresh,by rw [ev]; simp [erased,ack,peer,prim,pos,term]⟩
  · obtain ⟨self,st,n,m,co,pass,r,msg,pass',g,fr,seen⟩ := h
    have call : Promotion.Cast c self (Promotion.ballot (observeTerm st m) n) :=
      .inl (.inl ⟨st,n,m,co,pass,r,msg,pass',g,fr,seen,rfl⟩)
    obtain ⟨fresh,rfl,eq⟩ := Promotion.cast_only c call
    exact ⟨fresh,by simp [erased,eq]⟩
  · obtain ⟨self,st,n,m,co,pass,r,msg,pass',g,q,fr,seen⟩ := h
    have call : Promotion.Cast c self (freshCandidate self (Promotion.preBallot (observeTerm st m) n)) :=
      .inl (.inr ⟨_,.inl ⟨st,n,m,co,pass,r,msg,pass',g,q,fr,seen,rfl⟩,seen,rfl⟩)
    obtain ⟨fresh,rfl,eq⟩ := Promotion.cast_only c call
    exact ⟨fresh,by simp [erased,eq]⟩
  · obtain ⟨self,st,n,m,co,pass,msg,pass',g,fr,seen⟩ := h
    have call : Promotion.Cast c self (freshCandidate self (observeTerm st m)) :=
      .inl (.inr ⟨_,.inr ⟨st,n,m,co,pass,msg,pass',g,fr,seen,rfl⟩,seen,rfl⟩)
    obtain ⟨fresh,rfl,eq⟩ := Promotion.cast_only c call
    exact ⟨fresh,by simp [erased,eq]⟩

private theorem erased_of (fresh : ¬Now f c.actor c.post) (yes : erased c.actor c.pre c.event) :
    Local c ∨ Remote c := by
  simp only [erased,Bool.or_eq_true,Option.isSome_iff_exists] at yes
  rcases yes with (lo | ⟨m,eq⟩) | ⟨z,eq⟩
  · exact .inl ((local_iff c).mpr ⟨fresh,lo⟩)
  · obtain ⟨rc,_⟩ := to_ack c fresh eq
    cases ev : c.event with
    | internal => simp [ev,ack] at eq
    | receive n msg =>
      cases msg <;> simp only [ev,ack] at eq <;> try contradiction
      split at eq <;> try contradiction
      rename_i g
      have fr := c.inv.frontier _ _ c.pre_now
      exact .inr (.inl ⟨_,_,_,_,(Observe.receive_iff c).mpr ⟨fresh,rfl,rfl,ev⟩,fun no => no.2 g.1,_,
        rfl,fun no => no.2 g.1,by simp [g.2.1],g.2.2.1,g.2.2.2,fr,
        fr.of_log (Concrete.observeTerm_log ..) (Concrete.observeTerm_commitIndex ..)⟩)
  · obtain ⟨(call | ⟨_,(call | call),_,_⟩) | call,_⟩ := Promotion.cast_of c fresh eq
    · obtain ⟨st,n,m,co,pass,r,msg,pass',g,fr,seen,_⟩ := call
      exact .inr (.inr (.inl ⟨_,st,n,m,co,pass,r,msg,pass',g,fr,seen⟩))
    · obtain ⟨st,n,m,co,pass,r,msg,pass',g,q,fr,seen,_⟩ := call
      exact .inr (.inr (.inr (.inl ⟨_,st,n,m,co,pass,r,msg,pass',g,q,fr,seen⟩)))
    · obtain ⟨st,n,m,co,pass,msg,pass',g,fr,seen,_⟩ := call
      exact .inr (.inr (.inr (.inr ⟨_,st,n,m,co,pass,msg,pass',g,fr,seen⟩)))
    · obtain ⟨_,⟨_,⟨_,co,rfl,_⟩,_⟩,_⟩ := call
      obtain ⟨_,_,_,ev⟩ := (Promotion.input_iff c).mp co
      exact .inl ((local_iff c).mpr ⟨fresh,by rw [ev]; rfl⟩)

private theorem unpack (h : step_foldl_select_max_values_nil f t c) :
    (¬Now f c.actor c.post ∧ erased c.actor c.pre c.event) ∨
    (c.pre.commitIndex < c.post.commitIndex ∧ Advance.Source c) := by
  rcases h with h | h | h | h | h | h
  case inr.inr.inr.inr.inl =>
    rcases h with a | b | a | b | a
    all_goals first | exact .inl (remote_only c b)
                    | obtain ⟨fresh,lo⟩ := (local_iff c).mp a; exact .inl ⟨fresh,by simp [erased,lo]⟩
  case inr.inr.inr.inr.inr => exact .inl (remote_only c h)
  all_goals
    obtain ⟨m,site,fields,_⟩ := h
    have co : Advance.Site c m := by repeat' first | exact site | exact Or.inl site | apply Or.inr
    obtain ⟨src,eq⟩ := Advance.of_site c co
    exact .inr ⟨eq ▸ fields.2.2.2.2.2.2.1,src⟩

private theorem nil_of_growth (growth : step_advance_backed_advance_inr f t c) :
    step_foldl_select_max_values_nil f t c := by
  rcases growth with h | h | h | h
  all_goals
    obtain ⟨m,site,h,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,a,b,l,r,acks⟩ := h
    have hi : m.commitIndex < highestCommittableIndex m c.actor := h.2.2.2.2.2.2.2.1 ▸ h.2.2.2.2.2.2.1
    repeat' first
      | apply Or.inl; refine ⟨m,site,h,?_⟩
      | apply Or.inr
    obtain ⟨_,_,_,_,_,_,_,_,_⟩ := h
    repeat' first | assumption | apply And.intro
end

def nilExact : Exact .foldl_select_max_values_nil where
  eval := nilReader
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    have grew := Bool.eq_iff_iff.mp ((Advance.exactReader .growth).eq_label s)
    change label s (.step .advance_backed_advance_inr) = true ↔ Advance.reader .growth .. = true at grew
    rw [label_true,holds,sig_iff] at grew
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,nilReader,Bool.or_eq_true,Promotion.gated_iff]
    constructor
    · intro h
      rcases unpack c h with h | ⟨inc,src⟩
      · exact .inl h
      · right; rw [Advance.reader,Bool.and_eq_true,actorRead_at,Advance.source_iff]
        exact ⟨decide_eq_true inc,src⟩
    · rintro (⟨fresh,yes⟩ | inc)
      · rcases erased_of c fresh yes with h | h
        · exact .inr (.inr (.inr (.inr (.inl (.inl h)))))
        · exact .inr (.inr (.inr (.inr (.inr h))))
      · exact nil_of_growth c (grew.mpr inc)

end ConsensusCoverage.HandReadersOther.Fold
