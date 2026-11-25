module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersOtherFoldDirect
import all ConsensusCoverage.HandReadersOtherAdvance
import all ConsensusCoverage.HandReadersOtherSites
import all ConsensusCoverage.HandReadersOtherPromotion
import all ConsensusCoverage.MaximumCasesB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersOther.Fold

open Consensus Model Model.Node Proofs Safety ActionProfile HandReadersA SolvedWitnesses

set_option maxRecDepth 8192
set_option maxHeartbeats 1600000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

inductive Kind where | cons | kept | selected | smaller | larger | rejected | found

def column : Kind → Classes.StepBranch
  | .cons => .foldl_select_max_values_cons
  | .kept => .foldl_select_max_ih_inl
  | .selected => .foldl_select_max_chosen_pos
  | .smaller => .foldl_select_max_le_total_inl
  | .larger => .foldl_select_max_le_total_inr
  | .rejected => .foldl_select_max_chosen_neg
  | .found => .foldl_select_max_ih_inr

local macro "place " h:term : tactic => `(tactic| {
  repeat' first | exact $h | exact Or.inl $h | apply Or.inr
  done })

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Entry (p : Nat → Prop) (d : DecidablePred p) :=
  (reach% step_foldl_select_max_values_cons[0]) f t c p d ∨
  (reach% step_foldl_select_max_values_cons[1]) f t c p d ∨
  (reach% step_foldl_select_max_values_cons[2]) f t c p d ∨
  (reach% step_foldl_select_max_values_cons[3]) f t c p d ∨
  (reach% step_foldl_select_max_values_cons[4]) f t c p d ∨
  (reach% step_foldl_select_max_values_cons[5]) f t c p d

private abbrev Live := (¬Now f c.actor c.post ∧ direct c.actor c.pre c.event) ∨
  (c.pre.commitIndex < c.post.commitIndex ∧ Advance.Source c)

private theorem necessary {p d} (e : Entry c p d) : Live c := by
  rcases e with e | e | e | e | e | e
  all_goals
    obtain ⟨_,_,⟨m,n,site,_⟩,_⟩ := e
    first
    | exact .inl (direct_only c (by exact .inl site))
    | exact .inl (direct_only c (by exact .inr site))
    | have h : Advance.Site c m := by place site.1
      have ⟨src,eq⟩ := Advance.of_site c h
      exact .inr ⟨eq ▸ site.2.1.2.2.2.2.2.2.1,src⟩

private theorem directPool (fresh : ¬Now f c.actor c.post) (yes : direct c.actor c.pre c.event) :
    ∃ p d, Entry c p d ∧ (∃ i, p i) ∧ ¬p 0 := by
  obtain ⟨m,n,site,gt⟩ := direct_of c fresh yes
  have spec := highestCommittableIndex_spec m n gt
  let p := fun (i : Nat) => m.commitIndex < i ∧ isSignatureAt m.log i = true ∧
    termAt m.log i = m.currentTerm ∧ hasQuorum (m.activeConfigurations.filter (fun cfg => cfg.index ≤ i))
      (m.activeMembers.filter (fun v => v = n ∨ m.matchIndex v ≥ i))
  let d : DecidablePred p := fun _ => inferInstanceAs (Decidable (_ ∧ _ ∧ _ ∧ _))
  rcases site with site | site
  all_goals
    refine ⟨p,d,?_,?_⟩
    · place ⟨_,_,⟨m,n,site,Nat.zero_lt_of_lt gt,rfl,HEq.rfl,rfl⟩,Nat.zero_lt_of_lt gt,HEq.rfl⟩
    · exact ⟨⟨_,gt,spec.2.1,spec.2.2.1,spec.2.2.2⟩,fun zero => Nat.not_lt_zero _ zero.1⟩

private theorem fromPool (k : Kind) {p d} (e : Entry c p d) (good : ∃ i, p i) (bad : ¬p 0) :
    sig c (column k) := by
  obtain ⟨i,yes⟩ := good
  letI : DecidablePred p := d
  cases k <;> rcases e with e | e | e | e | e | e
  all_goals
    repeat' first | (apply Or.inl; refine ⟨p,d,e,?_⟩) | refine ⟨p,d,e,?_⟩ | apply Or.inr
    first
    | exact ⟨[],fun _ => Or.inl rfl⟩
    | exact ⟨i,[],fun _ => Or.inl rfl,i,rfl,yes,Nat.le_refl _⟩
    | exact ⟨i,[],fun _ => Or.inl rfl,i,rfl,yes⟩
    | exact ⟨0,[],fun _ => Or.inl rfl,i,rfl,bad⟩
    | exact ⟨i,[],fun _ => Or.inl rfl,i,rfl⟩
    | exact ⟨i,[],fun _ => Or.inl rfl,i,by simpa only [List.foldl_nil,ite_eq_left yes,Nat.max_self]⟩

private theorem of_sig (k : Kind) (h : sig c (column k)) : Live c := by
  cases k <;> rcases h with h | h | h | h | h | h
  all_goals
    obtain ⟨_,_,e,_⟩ := h
    apply necessary c
    place e
end

def exactReader (k : Kind) : Exact (column k) where
  eval := reader
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    have grows := Bool.eq_iff_iff.mp ((Advance.exactReader .growth).eq_label s)
    change label s (.step .advance_backed_advance_inr) = true ↔ Advance.reader .growth .. = true at grows
    rw [label_true,holds,sig_iff] at grows
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,reader,Bool.or_eq_true,Promotion.gated_iff]
    constructor
    · intro h
      rcases of_sig c k h with yes | ⟨inc,src⟩
      · exact .inl yes
      · right; rw [Advance.reader,Bool.and_eq_true,actorRead_at,Advance.source_iff]
        exact ⟨decide_eq_true inc,src⟩
    · rintro (⟨fresh,yes⟩ | growth)
      · obtain ⟨_,_,e,g,b⟩ := directPool c fresh yes
        exact fromPool c k e g b
      · rcases MaximumCasesB.pools (grows.mpr growth) with p | p | p | p
        all_goals obtain ⟨_,_,e,g,b⟩ := p; exact fromPool c k (by place e) g b

end ConsensusCoverage.HandReadersOther.Fold
