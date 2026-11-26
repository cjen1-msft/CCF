module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.DeepLeaderCases
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepSignedCases

open Consensus Consensus.Proofs Consensus.Model Consensus.Model.Node Safety SolvedWitnesses
open ActionProfile QueueSamplesA

set_option maxRecDepth 8192

variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private theorem roots (old : c.pre.role ≠ .primary) (primary : c.post.role = .primary)
    (pos : 0 < c.pre.commitIndex) :
    (reach% step_signatureIndex_le_maxCommittableIndex_values_nil[0]) f t c ∧
    (reach% step_signatureIndex_le_maxCommittableIndex_mem_cons_inl[0]) f t c c.pre.log c.pre.commitIndex := by
  have wins := (Summary.leader c.sum primary).resolve_left (fun prior => old prior.1)
  have election := c.wins_elect wins
  have prefix_ := (c.electStep election).2.2.2.2.2.2.1
  have now := c.post_now
  have caller : (reach% step_signatureIndex_le_maxCommittableIndex_mem_cons_inl[0,0])
      f t c c c.actor c.post :=
    ⟨now,fun h => old ((c.now_pre h) ▸ primary),rfl⟩
  obtain ⟨cand,camp,quorum,adv⟩ := wins
  have wins' : Wins c.actor c.pre c.event c.post := ⟨cand,camp,quorum,adv⟩
  constructor <;> left <;> refine ⟨caller,now,now,wins',rfl,cand,⟨camp,quorum,adv⟩,
    camp,⟨quorum,adv⟩,camp.1,camp.2,camp.2.1,camp.2.2,camp.2.2.1,camp.2.2.2,
    quorum,adv,pos,now,election,?_⟩
  · exact prefix_
  · exact ⟨prefix_,rfl,rfl⟩

omit [Config.InitialConfiguration] in
private theorem above (l : List Entry) (values : List Nat) (best : Nat) :
    best ≤ values.foldl (fun b i => if isSignatureAt l i then max b i else b) best := by
  induction values generalizing best with
  | nil => exact Nat.le_refl _
  | cons h t ih =>
    simp only [List.foldl_cons]
    apply Nat.le_trans _ (ih _)
    split <;> first | exact Nat.le_max_left _ _ | exact Nat.le_refl _

inductive FoldCase where
  | nil | cons | head | tail | signed | unsigned

def column : FoldCase → Classes.StepBranch
  | .nil => .signatureIndex_le_maxCommittableIndex_values_nil
  | .cons => .signatureIndex_le_maxCommittableIndex_values_cons
  | .head => .signatureIndex_le_maxCommittableIndex_mem_cons_inl
  | .tail => .signatureIndex_le_maxCommittableIndex_mem_cons_inr
  | .signed => .signatureIndex_le_maxCommittableIndex_signature_pos
  | .unsigned => .signatureIndex_le_maxCommittableIndex_signature_neg

omit [Config.InitialConfiguration] in
theorem sound (s : Step) (k : FoldCase) (passed : DeepLeaderCases.guardAt s true = true) :
    label s (.step (column k)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨old,primary,_,guard⟩ := DeepLeaderCases.ofGuard s true passed
  have pos := of_decide_eq_true guard
  obtain ⟨whole,root⟩ := roots c old primary pos
  have sig_ := (c.inv.frontier _ _ c.pre_now).2 pos
  have bound := c.frontier_pre
  have fold := above c.pre.log
  apply (label_true s _).mpr
  apply (sig_iff c _).mpr
  cases k with
  | nil => exact Or.inl whole
  | cons => exact Or.inl ⟨_,_,root,[],by simp,sig_,bound,fold⟩
  | head => exact Or.inl ⟨_,_,root,[],by simp,by simp,sig_,bound,fold⟩
  | tail =>
    refine Or.inl ⟨_,_,root,0,[c.pre.commitIndex],?_,by simp,by simp,sig_,bound,fold⟩
    simpa [sig_] using fun best => Nat.le_max_right best c.pre.commitIndex
  | signed =>
    exact Or.inl ⟨_,_,root,[],by simp,0,by simp,by simp,c.pre.commitIndex,[],by simp,
      sig_,sig_,bound,by simp [sig_]⟩
  | unsigned =>
    exact Or.inl ⟨_,_,root,[],by simp,0,by simp,by simp,0,[],by simp,
      by simp [isSignatureAt,entryAt?],sig_,bound,by simp [sig_]⟩

open DeepSchedules FrontierRows in
def certificates : List Certificate :=
  [.nil,.cons,.head,.tail,.signed,.unsigned].map fun k =>
    checked (column k) (selected (threeTerms true) (by unfold Run.valid; decide) 20)
      (DeepLeaderCases.guardAt · true) (by decide +kernel) (sound · k)

end ConsensusCoverage.DeepSignedCases
