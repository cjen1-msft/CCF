module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionBBridge
import all ConsensusCoverage.HandReadersElectionCounted
import all ConsensusCoverage.HandReadersElectionZip
import all ConsensusCoverage.OverlapInductionB
public meta import ConsensusCoverage.ReachPath
public meta import ConsensusCoverage.PinnedClasses
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElectionB.Choice

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile SolvedWitnesses HandReadersA HandReadersElection

set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private abbrev counted (xs : List Configuration) (b : Nat) := (Counted.filt xs b).length

private def check (within : Bool) (xs : List Configuration) (b : Nat) : Bool :=
  if within then decide (0 < counted xs b) else decide (counted xs b ≤ 1)

private theorem selected (within : Bool) {xs : List Configuration} {b : Nat}
    (sorted : xs.Pairwise fun a b => a.index < b.index)
    (valid : counted xs b - 1 < xs.length) :
    (if within then xs[counted xs b - 1].index ≤ b
      else ∀ v ∈ xs, xs[counted xs b - 1].index ≤ v.index) ↔ check within xs b := by
  have first (n : Nat) (lt : n < xs.length) :
      (∀ v ∈ xs, xs[n].index ≤ v.index) ↔ n = 0 := by
    have ne : 0 < xs.length := by omega
    constructor
    · intro h
      apply Classical.byContradiction
      intro nonzero
      exact (Nat.not_lt_of_ge (h _ (List.getElem_mem ne)))
        (List.pairwise_iff_getElem.mp sorted 0 n ne lt (Nat.pos_of_ne_zero nonzero))
    · rintro rfl v mem
      obtain ⟨i,hi,rfl⟩ := List.getElem_of_mem mem
      cases i with
      | zero => exact Nat.le_refl _
      | succ i => exact Nat.le_of_lt (List.pairwise_iff_getElem.mp sorted 0 _ ne hi (Nat.succ_pos _))
  cases within
  · simp only [Bool.false_eq_true,ite_false,check,decide_eq_true_eq,first _ valid]
    omega
  · simp only [ite_true,check,decide_eq_true_eq]
    constructor
    · intro le
      exact List.length_pos_iff.mpr (List.ne_nil_of_mem
        (List.mem_filter.mpr ⟨List.getElem_mem valid,decide_eq_true le⟩))
    · intro pos
      exact getElem_le_of_lt_length_filter sorted (Nat.sub_one_lt (Nat.ne_of_gt pos))

private def test (within : Bool) : Overlap.Test := fun _ r b d => check within (configurationHistory r) (max b d)

def column (within : Bool) : Classes.StepBranch := if within then .activeConfigurations_overlap_chosen_bound_inl
  else .activeConfigurations_overlap_chosen_bound_inr

open Lean Meta Elab Term in
private meta def bridge (h : Expr) (proof : Option Expr) : MetaM Expr := do
  let n := if proof.isSome then ``step_activeConfigurations_overlap_le_total_inl
    else ``step_activeConfigurations_overlap_chosen_bound_inr
  let sites := ReachPath.children n.getPrefix (←getConstInfo n).value!
  let ty ← inferType h
  let some i := sites.idxOf? ty.getAppFn.constName! | throwError "unexpected overlap origin"
  let rule := (`ConsensusCoverage.HandReadersElectionB.Bridge.origin).appendIndexAfter i
  let args := if let some pr := proof then ty.getAppArgs.push pr else ty.getAppArgs
  mkAppM (if proof.isSome then ``Iff.mpr else ``Iff.mp) #[mkAppN (Lean.mkConst rule) args,h]

open Lean Elab Term in
local elab "ordinary% " h:term:arg : term => do bridge (←elabTerm h none) none
open Lean Elab Term in
local elab "configured% " h:term:arg p:term:arg : term => do bridge (←elabTerm h none) (←elabTerm p none)

private theorem check_take (within) (r : List Entry) {z k : Nat} (le : z ≤ k) :
    check within (configurationHistory r) z = check within (configurationHistory (r.take k)) z := by
  obtain ⟨rest,eq,late⟩ := configurationHistory_split r k
  have lens := congrArg List.length (OverlapInductionB.countFilter eq late le)
  change counted (configurationHistory r) z = counted (configurationHistory (r.take k)) z at lens
  simp only [check,lens]

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

local macro "injectChoice " h:term : tactic => `(tactic|
  repeat' first | exact $h | exact Or.inl $h | apply Or.inr)

set_option maxHeartbeats 1200000 in
theorem necessary (within : Bool) (h : sig c (column within)) : Overlap.Evidence c (test within) := by
  cases within
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    obtain ⟨l,r,b,d,k,_,src,_,_,_,_,_,_,_,_,ord,guard,_,bl,dl,sorted,_,tail⟩ := h
    obtain ⟨j,site,_⟩ := ordinary% src
    refine ⟨l,r,b,d,Overlap.necessary c (j := j) (by injectChoice site),?_⟩
    unfold test
    rw [check_take _ _ (Nat.max_le.mpr ⟨bl,dl⟩)]
    first | rw [Nat.max_eq_right ord] | rw [Nat.max_eq_left ord]
    first
    | exact (selected false sorted _).mp guard
    | exact (selected true sorted _).mp guard

set_option maxHeartbeats 1200000 in
theorem sufficient (within : Bool) (h : Overlap.Evidence c (test within)) : sig c (column within) := by
  obtain ⟨l,r,b,d,enabled,pass⟩ := h
  obtain ⟨⟨k,src,eq,bl,dl,head⟩⟩ := Zip.cut c enabled
  obtain ⟨ls,hl⟩ := configurationHistory_split l k
  obtain ⟨rs,hr⟩ := configurationHistory_split r k
  let cs := configurationHistory (r.take k)
  have ne : cs ≠ [] := configurationHistory_ne_nil head Config.GENESIS_configured
  have pos := List.length_pos_iff.mpr ne
  have sorted : cs.Pairwise fun a b => a.index < b.index := configurationHistory_sorted _
  have last := Nat.sub_one_lt (Nat.ne_of_gt pos)
  change check within (configurationHistory r) (max b d) = true at pass
  rw [check_take _ _ (Nat.max_le.mpr ⟨bl,dl⟩)] at pass
  rcases src with src | src | src
  all_goals
    have rich := configured% src ne
    obtain ord | ord := Nat.le_total b d
    case' inl => rw [Nat.max_eq_right ord] at pass
    case' inr => rw [Nat.max_eq_left ord] at pass
    all_goals
      have hi (z : Nat) : counted cs z - 1 < cs.length :=
        Nat.lt_of_le_of_lt (Nat.sub_le_sub_right (length_filter_le cs z) 1) last
      have guard := (selected within sorted (hi _)).mpr pass
      cases within
      all_goals
        injectChoice ⟨l,r,b,d,k,ne,rich,ls,hl,hl.1,hl.2,rs,hr,hr.1,hr.2,ord,guard,eq,bl,dl,sorted,pos,
          OverlapInductionB.countFilter,OverlapInductionB.inDrop,length_filter_le _ _,length_filter_le _ _,last,
          length_filter_index_mono cs ord,hi _⟩
end

def exactReader (within : Bool) : Exact (column within) where
  eval := Overlap.reader (test within)
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,Overlap.reader_iff]
    exact ⟨necessary s.context within,sufficient s.context within⟩

end ConsensusCoverage.HandReadersElectionB.Choice
