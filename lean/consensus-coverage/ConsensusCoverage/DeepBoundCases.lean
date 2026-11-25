module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.DeepLeaderCases
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepBoundCases

open Consensus Consensus.Proofs Consensus.Model Consensus.Model.Node Safety SolvedWitnesses
open ActionProfile QueueSamplesA

set_option maxRecDepth 8192

theorem entered [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
    (elect : ElectStep f t c.actor c.post.currentTerm c.pre.log c.pre.commitIndex) :
    (reach% step_maxCommittableIndexBounded_signature_pos[0,0]) f t c
      c.actor c.post.currentTerm c.pre.log c.pre.commitIndex := by
  have after_ : Elected (f.advance t) c.actor c.post.currentTerm c.pre.log c.pre.commitIndex :=
    .inr ⟨f.current,rfl,elect⟩
  have prior : ¬ Elected f c.actor c.post.currentTerm c.pre.log c.pre.commitIndex := by
    intro e
    have was : Led f c.actor c.post.currentTerm := .inr ⟨_,_,e⟩
    have old := c.inv.led_cur _ _ _ c.pre_now was
    have new_ := (c.electStep elect).2.2.2.1
    rcases old with lt | ⟨eq,nc⟩ <;> rcases new_ with hi | ⟨same,cand⟩ <;> first
      | exact nc cand | omega
  exact ⟨⟨after_,prior⟩,elect,after_⟩

inductive Case where | nil | cons | signed | unsigned

def column : Case → Classes.StepBranch
  | .nil => .maxCommittableIndexBounded_values_nil
  | .cons => .maxCommittableIndexBounded_values_cons
  | .signed => .maxCommittableIndexBounded_signature_pos
  | .unsigned => .maxCommittableIndexBounded_signature_neg

private theorem sound (s : Step) (k : Case) (p : DeepLeaderCases.guardAt s true = true) :
    label s (.step (column k)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨old,primary,_,guard⟩ := DeepLeaderCases.ofGuard s true p
  have pos := of_decide_eq_true guard
  have won := (Summary.leader c.sum primary).resolve_left (fun prior => old prior.1)
  have elect := c.wins_elect won
  have call := entered c elect
  have raw := elect
  obtain ⟨st,stFacts⟩ := raw
  obtain ⟨w,mem,mem',log,idx,le,terms,turn,role,pfx,floor,xs,q,grants⟩ := stFacts
  have root : (reach% step_maxCommittableIndexBounded_signature_pos[0])
      _ _ c c.pre.log := by
    left
    refine ⟨_,_,_,_,call,st,⟨w,mem,mem',log,idx,le,terms,turn,role,pfx,floor,xs,q,grants⟩,
      w,?_,mem,?_,mem',?_,log,?_,idx,?_,le,?_,terms,?_,turn,?_,role,?_,pfx,?_,floor,
      ⟨xs,q,grants⟩,xs,⟨q,grants⟩,q,grants,Nat.lt_of_lt_of_le pos (Nat.le_max_left _ _),elect,rfl⟩
    all_goals repeat' first | assumption | exact ⟨xs,q,grants⟩ | apply And.intro
  have small : ∀ j, j ∈ List.range (c.pre.log.length+1) → j ≤ c.pre.log.length :=
    fun _ m => Nat.le_of_lt_succ (List.mem_range.mp m)
  apply (label_true s _).mpr
  apply (sig_iff c _).mpr
  cases k with
  | nil =>
    exact Or.inl (Or.inl ⟨_,_,_,_,call.1,elect,call.2.2⟩)
  | cons => exact Or.inl ⟨_,root,[],by simp,small⟩
  | signed =>
    exact Or.inl ⟨_,root,c.pre.commitIndex,[],by simp,0,by simpa using c.frontier_pre,
      Nat.zero_le _,(c.inv.frontier _ _ c.pre_now).2 pos,small,c.frontier_pre⟩
  | unsigned =>
    exact Or.inl ⟨_,root,0,[],by simp,0,by simp,Nat.zero_le _,
      by simp [isSignatureAt,entryAt?],small,Nat.zero_le _⟩

open DeepSchedules FrontierRows in
def certificates : List Certificate :=
  [.nil,.cons,.signed,.unsigned].map fun k =>
    checked (column k) (selected (threeTerms true) (by unfold Run.valid; decide) 20)
      (DeepLeaderCases.guardAt · true) (by decide +kernel) (sound · k)

end ConsensusCoverage.DeepBoundCases
