module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.ConfiguredOverlapB
import all ConsensusCoverage.OverlapCasesB
import all ConsensusCoverage.OverlapInductionB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ChoiceInductionB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open OverlapInductionB ConfiguredOverlapB

set_option maxRecDepth 8192

variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
  {l r : List Entry} {b k : Nat}

private abbrev common (r : List Entry) (k : Nat) := configurationHistory (r.take (max k 1))

def Counted (r : List Entry) (k b : Nat) := 0 < (filt (common r k) b).length

private theorem chosen (h : History c l r 0 b k) :
    (Counted r k b → step_activeConfigurations_overlap_chosen_bound_inl f t c) ∧
    (¬Counted r k b → step_activeConfigurations_overlap_chosen_bound_inr f t c) := by
  let s := OverlapCasesB.seed h.ordinary
  let xs := common r k
  have ne : xs ≠ [] := configured s
  have root : (reach% step_activeConfigurations_overlap_chosen_bound_inr[5]) f t c l r 0 b (max k 1) ne :=
    ⟨k,h.ordinary.right,h.ordinary.rightNE,h.configured,h.ordinary.left,h.ordinary.leftNE,h.ordinary.agree,
      h.ordinary.leftLe,h.ordinary.rightLe,h.ordinary.left.head h.ordinary.leftNE,
      h.ordinary.right.head h.ordinary.rightNE,eqK s,headK s,rfl,HEq.rfl⟩
  obtain ⟨ls, leq⟩ := configurationHistory_split l (max k 1)
  obtain ⟨rs, req⟩ := configurationHistory_split r (max k 1)
  have pos := List.length_pos_iff.mpr ne
  have last := Nat.sub_one_lt (Nat.ne_of_gt pos)
  have bound := length_filter_le xs b
  have valid := Nat.lt_of_le_of_lt (Nat.sub_le_sub_right bound 1) last
  let selected := xs[(filt xs b).length - 1]'valid
  have both := chosen_bound (sorted s) b pos
  have introFirst (no : ¬Counted r k b) (within : selected.index ≤ b) : False :=
    no (List.length_pos_iff.mpr (List.ne_nil_of_mem
      (List.mem_filter.mpr ⟨List.getElem_mem valid,by simpa only [decide_eq_true_eq] using within⟩)))
  constructor <;> intro counted <;> iterate 5 right
  all_goals refine Or.inl ⟨l,r,0,b,max k 1,ne,root,ls,leq,leq.1,leq.2,rs,req,req.1,req.2,
    Nat.zero_le _,?_,eqK s,Nat.zero_le _,Nat.le_trans h.ordinary.rightLe (Nat.le_max_left _ _),sorted s,pos,
    countFilter,inDrop,length_filter_le _ _,bound,last,length_filter_index_mono xs (Nat.zero_le b),valid⟩
  · exact getElem_le_of_lt_length_filter (sorted s) (Nat.sub_one_lt (Nat.ne_of_gt counted))
  · exact both.resolve_left (introFirst counted)

theorem within (h : History c l r 0 b k) (yes : Counted r k b) :
    step_activeConfigurations_overlap_chosen_bound_inl f t c := (chosen h).1 yes

theorem firstAndLater (h : History c l r 0 b k) (no : ¬Counted r k b)
    (later : ∃ x ∈ common r k, b + 1 < x.index) :
    step_activeConfigurations_overlap_chosen_bound_inr f t c ∧ step_chosen_bound_mem_cons_inr f t c := by
  obtain ⟨x,mem,gap⟩ := later
  exact ⟨(chosen h).2 no,laterMember (OverlapCasesB.seed h.ordinary) (Nat.zero_le _) no x mem gap⟩

end ConsensusCoverage.ChoiceInductionB
