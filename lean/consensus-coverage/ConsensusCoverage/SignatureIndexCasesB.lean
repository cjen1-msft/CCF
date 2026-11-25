module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.FollowerFoldCasesB
import all ConsensusCoverage.FollowerFoldCasesB
import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.SignatureIndexCasesB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile SolvedWitnesses DeepSchedulesB FollowerFoldCasesB

set_option maxRecDepth 8192
set_option maxHeartbeats 500000

private abbrev choose (log : List Entry) (best i : Nat) :=
  if isSignatureAt log i then max best i else best

private theorem monotone (log : List Entry) (values : List Nat) (best : Nat) :
    best ≤ values.foldl (choose log) best := by
  induction values generalizing best with
  | nil => exact Nat.le_refl _
  | cons i tail ih =>
    apply Nat.le_trans _ (ih (choose log best i))
    unfold choose
    split <;> first | exact Nat.le_max_left _ _ | exact Nat.le_refl _

public def questions : List Classes.StepBranch :=
  [.signatureIndex_le_maxCommittableIndex_values_nil, .signatureIndex_le_maxCommittableIndex_values_cons,
   .signatureIndex_le_maxCommittableIndex_mem_cons_inl, .signatureIndex_le_maxCommittableIndex_mem_cons_inr,
   .signatureIndex_le_maxCommittableIndex_signature_pos, .signatureIndex_le_maxCommittableIndex_signature_neg]

public theorem count : questions.Nodup ∧ questions.length = 6 := by decide +kernel

private theorem casesOf [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    {b : Classes.StepBranch} (mem : b ∈ questions) (seed : Loop c 1 2) : sig c b := by
  let log := [sg, sg]
  have pair := positivePair seed
  have pos : 0 < maxCommittableIndex log := by decide +kernel
  have nz := Nat.ne_of_gt pos
  have pre : log <+: log := List.prefix_refl _
  have entry : (reach% step_signatureIndex_le_maxCommittableIndex_values_cons[13]) f t c log 2 :=
    ⟨_, pair, nz, pre, pos, rfl⟩
  have nilIH (best : Nat) (h : 2 ∈ ([] : List Nat)) : 2 ≤ best := (List.not_mem_nil h).elim
  have ok : isSignatureAt log 2 = true := rfl
  have bound : 2 ≤ log.length := Nat.le_refl _
  simp only [questions, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl | rfl | rfl | rfl
  all_goals iterate 13 right
  all_goals left
  · exact ⟨_, _, pair, nz, pre, pos⟩
  · exact ⟨_, _, entry, [], nilIH, ok, bound, monotone log⟩
  · exact ⟨_, _, entry, [], nilIH, .head _, ok, bound, monotone log⟩
  · refine ⟨_, _, entry, 1, [2], ?_, .tail _ (.head _), .head _, ok, bound, monotone log⟩
    intro best _
    exact Nat.le_max_right _ _
  · exact ⟨_, _, entry, [], nilIH, 0, .head _, .head _, 2, [], fun _ => Nat.le_refl _,
      rfl, ok, bound, rfl⟩
  · exact ⟨_, _, entry, [], nilIH, 0, .head _, .head _, 0, [], fun _ => Nat.le_refl _,
      by decide +kernel, ok, bound, rfl⟩

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ questions) :
    ∃ s : Step, label s (.step b) = true := by
  let a := ReceiveCasesB.asSample copyCommit 4 (by decide +kernel) (by decide +kernel)
  letI : Config.InitialConfiguration := ⟨a.s.cfg⟩
  exact ⟨a.s, (label_true a.s _).mpr ((sig_iff a.s.context _).mpr (casesOf mem copyLoop))⟩

end ConsensusCoverage.SignatureIndexCasesB
