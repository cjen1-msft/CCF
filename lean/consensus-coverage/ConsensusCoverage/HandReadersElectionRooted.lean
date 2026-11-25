module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionCounted
import all ConsensusCoverage.HandReadersElectionOverlap
import all ConsensusCoverage.HandReadersElectionPairs
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.RootedRows

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger
open ActionProfile SolvedWitnesses HandReadersA Overlap
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

inductive Kind where | zero | positive | within | first
def column : Kind → Classes.StepBranch
  | .zero => .rooted_overlap_eq_zero_or_pos_inl
  | .positive => .rooted_overlap_eq_zero_or_pos_inr
  | .within => .rooted_overlap_bound_inl
  | .first => .rooted_overlap_bound_inr

def test : Kind → Test
  | .zero => fun _ _ b d => max b d == 0
  | .positive => fun _ _ _ d => decide (0 < d)
  | .within => fun _ _ b d => decide (0 < max b d)
  | .first => fun l r b d => (activeConfigurations l b).any fun u =>
      decide (u.index = 1 ∧ u ∈ activeConfigurations r d)

def reader (kind : Kind) : Reader := fun cfg before act after past =>
  Overlap.reader (test kind) cfg before act after past ||
    match kind with
    | .positive => Pairs.reader (Pairs.test .uncovered) cfg before act after past
    | _ => false

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Result (kind : Kind) := Evidence c (test kind) ∨
  (kind = .positive ∧ Pairs.Evidence c (Pairs.test .uncovered))

omit [Config.InitialConfiguration] in
private theorem active_pos {l : List Entry} {b : Nat} {u : Configuration}
    (mem : u ∈ activeConfigurations l b) : 0 < u.index :=
  Counted.positive_index (List.mem_of_mem_drop mem)

local macro "along " h:term : tactic => `(tactic| {
  have spine := $h
  repeat' first | exact spine | exact spine.1
                | change _ ∧ _ at spine; obtain ⟨_,spine⟩ := spine })

local macro "atPivot " ctx:term:arg l:term:arg r:term:arg b:term:arg d:term:arg j:term:arg h:term : term =>
  `(Overlap.pivot_of_site $ctx (l := $l) (r := $r) (b := $b) (d := $d) (j := $j) (by
    repeat' first | exact $h | exact Or.inl $h | apply Or.inr))

set_option maxHeartbeats 1200000 in
theorem necessary (kind : Kind) (h : sig c (column kind)) : Result c kind := by
  cases kind
  case zero =>
    repeat' (change _ ∨ _ at h; rcases h with h | h)
    all_goals
      obtain ⟨l,r,b,d,site,_,bl,dl,_⟩ := h
      have piv := atPivot c l r b d 0 site
      exact .inl ⟨l,r,b,d,piv.imp And.left And.left,beq_iff_eq.mpr (by omega)⟩
  case positive =>
    repeat' (change _ ∨ _ at h; rcases h with h | h)
    all_goals
      obtain ⟨l,r,b,d,j,site,pos,_⟩ := h
      have piv := atPivot c l r b d j site
      obtain ⟨⟨k,i,pair,gap,eq⟩,_⟩ | ⟨camp,fixed⟩ := piv
      · exact .inr ⟨rfl,l,k,b,i,r,d,pair,by simpa only [Pairs.test,Bool.and_eq_true,beq_iff_eq,decide_eq_true_eq] using And.intro eq gap⟩
      · exact .inl ⟨l,r,b,d,.inr camp,decide_eq_true (p := 0 < d) (fixed ▸ pos)⟩
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
      obtain ⟨l,r,b,d,j,site,u,_,left,_,right,_,bound,rest⟩ := h
      have piv := atPivot c l r b d j site
      refine .inl ⟨l,r,b,d,piv.imp And.left And.left,?_⟩
      first
      | exact decide_eq_true (Nat.lt_of_lt_of_le (active_pos left) bound)
      | have head : (r.take (max j 1)).take 1 = [Config.GENESIS] := by along rest
        obtain ⟨v,mem,one⟩ := Counted.genesis head
        have le := bound v mem
        have pos := active_pos left
        exact List.any_eq_true.mpr ⟨u,left,decide_eq_true ⟨by omega,right⟩⟩

local macro "useSite " sites:term:arg " finish " answer:term : tactic => `(tactic| {
  rcases $sites:term with site | site | site
  all_goals first
    | left; first | exact ⟨_,_,_,_,site,$answer⟩ | exact ⟨_,_,_,_,_,site,$answer⟩
    | iterate 3 right
      left; first | exact ⟨_,_,_,_,site,$answer⟩ | exact ⟨_,_,_,_,_,site,$answer⟩
    | iterate 5 right
      left; first | exact ⟨_,_,_,_,site,$answer⟩ | exact ⟨_,_,_,_,_,site,$answer⟩ })

private theorem positive {l r b d j} (s : Seed c l r b d j) (pos : 0 < j) : sig c (column .positive) := by
  have head : (r.take (max j 1)).take 1 = [Config.GENESIS] := by
    rw [List.take_take,Nat.min_eq_left (Nat.le_max_right ..),s.right.head s.rightNE]
  useSite s.site finish ⟨pos,s.same,s.leftLe,s.rightLe,head,s.left,s.right,s.leftNE,s.rightNE,
    s.left.head s.leftNE,s.right.head s.rightNE⟩

private theorem sufficient (kind : Kind) (h : Result c kind) : sig c (column kind) := by
  obtain ⟨l,r,b,d,enabled,check⟩ | ⟨rfl,l,k,b,i,r,d,pair,passed⟩ := h
  · obtain ⟨s⟩ := Overlap.sufficient c enabled
    let j := max b d
    have lh := s.left.head s.leftNE
    have rh := s.right.head s.rightNE
    have head : (r.take (max j 1)).take 1 = [Config.GENESIS] := by
      rw [List.take_take,Nat.min_eq_left (Nat.le_max_right ..),rh]
    have both : l.take (max j 1) = r.take (max j 1) := by
      rcases Nat.eq_zero_or_pos j with zero | pos
      · simp only [zero,Nat.zero_max,lh,rh]
      · simpa only [Nat.max_eq_left pos] using s.same
    cases kind
    case zero =>
      have z : max b d = 0 := beq_iff_eq.mp check
      generalize z' : max b d = z0 at s
      obtain rfl := z'.symm.trans z
      useSite s.site finish ⟨s.same,s.leftLe,s.rightLe,by simpa only [j,z] using head,s.left,s.right,s.leftNE,s.rightNE,lh,rh⟩
    case positive => exact positive c s (Nat.lt_of_lt_of_le (of_decide_eq_true check) (Nat.le_max_right ..))
    case within =>
      have jp : 0 < j := of_decide_eq_true check
      obtain ⟨u,left,right,le⟩ := rooted_overlap Config.GENESIS_configured s.left s.right s.leftNE s.rightNE
        s.same s.leftLe s.rightLe
      change u.index ≤ max j 1 at le
      have within : u.index ≤ j := by simpa only [Nat.max_eq_left jp] using le
      have side : u.index ≤ j ∨ ∀ v ∈ configurationHistory (r.take (max j 1)), u.index ≤ v.index := .inl within
      useSite s.site finish ⟨u,⟨left,right,side⟩,left,⟨right,side⟩,right,side,within,s.leftLe,s.rightLe,s.left,s.right,
        s.leftNE,s.rightNE,s.same,lh,rh,both,head⟩
    case first =>
      obtain ⟨u,left,yes⟩ := List.any_eq_true.mp check
      obtain ⟨one,right⟩ := of_decide_eq_true yes
      have first : ∀ v ∈ configurationHistory (r.take (max j 1)), u.index ≤ v.index := fun v m => one ▸ Counted.positive_index m
      have side : u.index ≤ j ∨ ∀ v ∈ configurationHistory (r.take (max j 1)), u.index ≤ v.index := .inr first
      useSite s.site finish ⟨u,⟨left,right,side⟩,left,⟨right,side⟩,right,side,first,s.right,s.rightNE,s.same,
        s.leftLe,s.rightLe,rh,both,head,s.left,s.leftNE,lh⟩
  · obtain ⟨eq,gap⟩ : l.take (max b d) = r.take (max b d) ∧ d < i := by
      simpa only [Pairs.test,Bool.and_eq_true,beq_iff_eq,decide_eq_true_eq] using passed
    have core : FromCore c l r b d := ⟨k,i,pair,gap,eq⟩
    obtain ⟨s⟩ := Overlap.sufficient c (.inl core)
    rcases Nat.eq_zero_or_pos (max b d) with zero | pos
    · have one : l.take 1 = r.take 1 := (s.left.head s.leftNE).trans (s.right.head s.rightNE).symm
      obtain ⟨s'⟩ := seedAt c (j := 1) (.inl ⟨core,one,by omega,by omega⟩)
      exact positive c s' (by decide)
    · exact positive c s pos
end

def exactReader (kind : Kind) : Exact (column kind) where
  eval := reader kind
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,show sig s.context (column kind) ↔ Result s.context kind from
      ⟨necessary s.context kind,sufficient s.context kind⟩]
    cases kind <;> simp only [Result,reader,Bool.or_eq_true,Overlap.reader_iff,Pairs.reader_iff,
      reduceCtorEq,false_and,true_and,Bool.false_eq_true,or_false]

end ConsensusCoverage.HandReadersElection.RootedRows
