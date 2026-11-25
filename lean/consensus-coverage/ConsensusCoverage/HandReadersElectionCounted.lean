module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionZip
import all ConsensusCoverage.HandReadersElectionOverlap
import all ConsensusCoverage.OverlapInductionB
import all ConsensusCoverage.ReachPath
public meta import ConsensusCoverage.ReachPath
public meta import Lean
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.Counted

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger
open ActionProfile SolvedWitnesses HandReadersA Overlap
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

def test (positive : Bool) : Test := fun _ _ b d => decide (0 < max b d) == positive

abbrev filt (cs : List Configuration) (n : Nat) := cs.filter fun u => u.index ≤ n

open Lean Elab Term Meta in
local elab "countSites% " a:term:arg* : term => do
  let root := ``step_chosen_bound_counted_pos
  let names := ReachPath.children root.getPrefix (← getConstInfo root).value!
  let mut arms := #[]
  for site in names do
    let name := mkIdent site
    arms := arms.push (← elabTerm (← `($name $a*)) (some (.sort .zero)))
  return arms.pop.foldr (mkApp2 (mkConst ``Or)) arms.back!

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev Sites (cs : List Configuration) (z : Nat) := countSites% f t c cs z
abbrev Origin (cs : List Configuration) (z : Nat) :=
  (reach% step_chosen_bound_counted_pos[0]) f t c cs z ∨
  (reach% step_chosen_bound_counted_pos[3]) f t c cs z ∨
  (reach% step_chosen_bound_counted_pos[5]) f t c cs z

private theorem genesis {l : List Entry} (head : l.take 1 = [Config.GENESIS]) :
    ∃ u ∈ configurationHistory l, u.index = 1 := by
  obtain ⟨nodes,some⟩ := Option.isSome_iff_exists.mp Config.GENESIS_configured
  obtain ⟨_,eq,_⟩ := configurationHistory_split l 1
  refine ⟨⟨1,nodes⟩,?_,rfl⟩
  rw [eq,head]
  simp [configurationHistory,some]

omit [Config.InitialConfiguration] in
theorem positive_index {l : List Entry} {u : Configuration} (mem : u ∈ configurationHistory l) : 0 < u.index := by
  obtain ⟨p,m,hm⟩ := List.mem_filterMap.mp mem
  obtain ⟨_,_,rfl⟩ := Option.map_eq_some_iff.mp hm
  exact (List.mem_zipIdx m).1

private theorem count_iff {l : List Entry} (head : l.take 1 = [Config.GENESIS]) (z : Nat) :
    0 < (filt (configurationHistory l) z).length ↔ 0 < z := by
  constructor
  · intro pos
    obtain ⟨u,h⟩ := List.exists_mem_of_ne_nil _ (List.length_pos_iff.mp pos)
    have ⟨m,le⟩ := List.mem_filter.mp h
    exact Nat.lt_of_lt_of_le (positive_index m) (of_decide_eq_true le)
  · intro pos
    obtain ⟨u,mem,one⟩ := genesis head
    exact List.length_pos_iff.mpr (List.ne_nil_of_mem (List.mem_filter.mpr ⟨mem,decide_eq_true (one ▸ pos)⟩))

local macro "along " h:term : tactic => `(tactic| {
  have spine := $h
  repeat' first | exact spine | exact spine.1
                | change _ ∧ _ at spine; obtain ⟨_,spine⟩ := spine
                | change Exists _ at spine; obtain ⟨_,spine⟩ := spine })

theorem sourceAt {cs z} (h : Sites c cs z) :
    ∃ l r b d j, Pivot c l r b d j ∧ z = max b d ∧ cs = configurationHistory (r.take (max j 1)) ∧
      (r.take (max j 1)).take 1 = [Config.GENESIS] := by
  rcases h with h | h | h | h | h | h | h | h | h | h | h
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    obtain ⟨l,r,other,k,⟨pivot,site,tail⟩,rest⟩ := h
    have eq : cs = configurationHistory (r.take k) := by along rest
    obtain rfl : k = max pivot 1 := by along tail
    have head : (r.take (max pivot 1)).take 1 = [Config.GENESIS] := by along tail
    have order : other ≤ z := by along rest
    first
    | refine ⟨l,r,other,z,pivot,Overlap.pivot_of_site c ?_,(Nat.max_eq_right order).symm,eq,head⟩
      solve | repeat' first | exact site | exact Or.inl site | apply Or.inr
    | refine ⟨l,r,z,other,pivot,Overlap.pivot_of_site c ?_,(Nat.max_eq_left order).symm,eq,head⟩
      repeat' first | exact site | exact Or.inl site | apply Or.inr

theorem necessary {cs z} (site : Sites c cs z) (pos : Bool) (guard : decide (0 < (filt cs z).length) = pos) :
    Evidence c (test pos) := by
  obtain ⟨l,r,b,d,_,pivot,rfl,rfl,head⟩ := sourceAt c site
  refine ⟨l,r,b,d,pivot.imp And.left And.left,beq_iff_eq.mpr ?_⟩
  simpa only [propext (count_iff head _)] using guard

theorem originAt {l r b d} (u : Zip.Cut c l r b d) :
    Origin c (configurationHistory (r.take u.k)) (max b d) := by
  obtain ⟨k,src,eq,bl,dl,head⟩ := u
  let cs := configurationHistory (r.take k)
  have ne := configurationHistory_ne_nil head Config.GENESIS_configured
  have positive := List.length_pos_iff.mpr ne
  have last := Nat.sub_one_lt (Nat.ne_of_gt positive)
  obtain ⟨ls,hl⟩ := configurationHistory_split l k
  obtain ⟨rs,hr⟩ := configurationHistory_split r k
  rcases src with src | src | src
  case' inl => left
  case' inr.inl => right; left
  case' inr.inr => right; right
  all_goals
    obtain ord | ord := Nat.le_total b d
    case' inl => rw [Nat.max_eq_right ord]; left; refine ⟨l,r,b,k,src,?_⟩
    case' inr => rw [Nat.max_eq_left ord]; right; refine ⟨l,r,d,k,src,?_⟩
    all_goals exact ⟨ls,hl,hl.1,hl.2,rs,hr,hr.1,hr.2,ord,eq,bl,dl,ne,configurationHistory_sorted _,
      positive,OverlapInductionB.countFilter,OverlapInductionB.inDrop,length_filter_le _ _,length_filter_le _ _,
      last,length_filter_index_mono cs ord,Nat.lt_of_le_of_lt (Nat.sub_le_sub_right (length_filter_le _ _) 1) last,rfl⟩

theorem sufficient {pos} (h : Evidence c (test pos)) :
    ∃ cs z, Origin c cs z ∧ cs.Pairwise (fun a b => a.index < b.index) ∧ 0 < cs.length ∧
      decide (0 < (filt cs z).length) = pos ∧ (pos = true → 0 < z) := by
  obtain ⟨l,r,b,d,enabled,yes⟩ := h
  obtain ⟨u⟩ := Zip.cut c enabled
  have guard := beq_iff_eq.mp yes
  change decide (0 < max b d) = pos at guard
  exact ⟨_,_,originAt c u,configurationHistory_sorted _,
    List.length_pos_iff.mpr (configurationHistory_ne_nil u.head Config.GENESIS_configured),
    by simpa only [propext (count_iff u.head _)] using guard,fun hp => of_decide_eq_true (guard.trans hp)⟩
end

end ConsensusCoverage.HandReadersElection.Counted
