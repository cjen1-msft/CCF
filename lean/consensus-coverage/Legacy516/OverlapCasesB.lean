module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.AssistOverlapA
import all ConsensusCoverage.OverlapInductionB
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.OverlapCasesB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile SolvedWitnesses OverlapInductionB

set_option maxRecDepth 8192

private def seed [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    {l r a b k} (o : AssistOverlapA.Origin c l r a b k) : Seed c :=
  ⟨l, r, a, b, k, o.entered, o.left, o.right, o.leftNE, o.rightNE, o.agree, o.leftLe, o.rightLe⟩

private def zeroCases : List Classes.StepBranch :=
  [.activeConfigurations_overlap_le_total_inl, .activeConfigurations_overlap_le_total_inr,
   .zipIdx_sorted_log_nil, .zipIdx_sorted_log_cons, .chosen_bound_counted_neg, .chosen_bound_mem_cons_inl]

private def positiveCases : List Classes.StepBranch :=
  [.chosen_bound_counted_pos, .getElem_le_of_lt_length_filter_i_inl, .getElem_le_of_lt_length_filter_i_inr]

private theorem zeroSig [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    {l r} (o : AssistOverlapA.Origin c l r 0 0 0) {b : Classes.StepBranch} (mem : b ∈ zeroCases) : sig c b := by
  let s := seed o
  have h : r.take 1 = [Config.GENESIS] := o.right.head o.rightNE
  have no : ¬0 < (filt (hs s) s.b).length := by
    change ¬0 < (filt (configurationHistory (r.take 1)) 0).length
    rw [h]
    simp [filt, configurationHistory, Config.GENESIS]
  have ⟨l,r⟩ := ordered s rfl
  have ⟨nil,cons⟩ := zip s (Nat.le_refl _)
  have ⟨neg,head⟩ := zero s (Nat.le_refl _) no
  simp only [zeroCases, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl | rfl | rfl | rfl <;> assumption

private theorem positiveSig [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    {l r} (o : AssistOverlapA.Origin c l r 0 2 2) {b : Classes.StepBranch} (mem : b ∈ positiveCases) : sig c b := by
  let s := seed o
  have h := headK s
  obtain ⟨nodes, some⟩ := Option.isSome_iff_exists.mp Config.GENESIS_configured
  obtain ⟨rest, eq, _⟩ := configurationHistory_split (s.right.take (K s)) 1
  have member : ({index := 1, nodes} : Configuration) ∈ hs s := by
    change _ ∈ configurationHistory _
    rw [eq, h]
    simp [configurationHistory, some]
  have yes : 0 < (filt (hs s) s.b).length := List.length_pos_iff.mpr
    (List.ne_nil_of_mem (List.mem_filter.mpr ⟨member, by rfl⟩))
  have ⟨pos,zero,succ⟩ := positive s (Nat.zero_le _) (by change 0 < 2; decide) yes
  simp only [positiveCases, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl <;> assumption

public def questions : List Classes.StepBranch := zeroCases ++ positiveCases

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ questions) :
    ∃ s : Step, label s (.step b) = true := by
  rcases List.mem_append.mp mem with zero | pos
  · let s := AssistOverlapA.zeroStep
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    obtain ⟨l,o⟩ := AssistOverlapA.zeroOrigin
    exact ⟨s, (label_true s _).mpr ((sig_iff s.context _).mpr (zeroSig o zero))⟩
  · let s := AssistOverlapA.positiveStep
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    obtain ⟨l,o⟩ := AssistOverlapA.positiveOrigin
    exact ⟨s, (label_true s _).mpr ((sig_iff s.context _).mpr (positiveSig o pos))⟩

end ConsensusCoverage.OverlapCasesB
