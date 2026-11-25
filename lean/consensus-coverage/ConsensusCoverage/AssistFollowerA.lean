module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.FollowerFoldCasesB
import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.AssistFollowerA

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile SolvedWitnesses FollowerFoldCasesB QueueSamplesA
set_option maxRecDepth 8192
set_option maxHeartbeats 600000

private theorem foldCases [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    (loop : Loop c 1 2) :
    sig c .isSignature_eq_true_content_transaction ∧ sig c .isSignature_eq_true_content_signature ∧
    sig c .recordCommit_eq_retire_neg := by
  have pair := positivePair loop
  have pos : 0 < maxCommittableIndex [sg,sg] := by decide +kernel
  have signed : (reach% step_isSignature_eq_true_content_signature[13,0,1]) f t c := by
    right; right; right
    exact ⟨_,_,pair,Nat.ne_of_gt pos,List.prefix_refl _,pos⟩
  have erased : (reach% step_isSignature_eq_true_content_signature[13]) f t c :=
    Or.inr (.inl signed)
  refine ⟨?_,?_,?_⟩
  · iterate 13 right
    exact .inl erased
  · iterate 13 right
    exact .inl erased
  · left
    refine ⟨1,{state [] with log := [sg]},1,?_,by decide +kernel⟩
    right; right; right
    exact ⟨2,loop,sg,[],Ledger.fromLeader_loop 1 2 [],state [],rfl,Nat.le_refl _,rfl,rfl⟩

private def foldStep := (ReceiveCasesB.asSample DeepSchedulesB.copyCommit 4 (by decide +kernel) (by decide +kernel)).s

private theorem foldLabels :
    label foldStep (.step .isSignature_eq_true_content_transaction) = true ∧
    label foldStep (.step .isSignature_eq_true_content_signature) = true ∧
    label foldStep (.step .recordCommit_eq_retire_neg) = true := by
  letI : Config.InitialConfiguration := ⟨foldStep.cfg⟩
  have ⟨a,b,d⟩ := foldCases (c := foldStep.context) copyLoop
  exact ⟨(label_true _ _).mpr ((sig_iff _ _).mpr a),(label_true _ _).mpr ((sig_iff _ _).mpr b),
    (label_true _ _).mpr ((sig_iff _ _).mpr d)⟩

def certificates : List Certificate :=
  [⟨_,foldStep,foldLabels.1⟩,⟨_,foldStep,foldLabels.2.1⟩,⟨_,foldStep,foldLabels.2.2⟩]

end ConsensusCoverage.AssistFollowerA
