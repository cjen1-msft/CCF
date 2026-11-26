module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.AssistOverlapA
import all ConsensusCoverage.ChoiceInductionB
import all ConsensusCoverage.ConfiguredOverlapB
import all ConsensusCoverage.DeepHistoryCases
import all ConsensusCoverage.DeepSchedules
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ChoiceCasesB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open ActionProfile ReadersAtoms GuardedDomain ChoiceInductionB QueueSamplesA

set_option maxRecDepth 8192

-- Node 1 wins before it learns that node 0 committed the new membership.
-- Two voters have the membership at index 2 while their commit bounds are zero.
open DeepSchedules in
private def reconfigured : Script := { divergent with
  ops := [.input 0 (.append [
    {content := .transaction 1 {configuration := some {1,2}}},
    {content := .signature, flushes := [(1,3),(2,3)]}])] ++ (splitLeaders.drop 1).take 4 ++
      [.msg 2 0 .appendEntriesResponse] ++ splitLeaders.drop 6 }

private def secondStep : Step := (selected reconfigured (by unfold FrontierRows.Run.valid; decide) 8).get
  (by decide +kernel)

private def contextCheck (s : Step) (e i k : Nat) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x =>
    let pre := x.base.pre
    decide (pre.role ≠ .primary ∧ x.base.post.role = .primary ∧ e < x.base.post.currentTerm ∧
      pre.commitIndex < i ∧ pre.commitIndex ≤ k) &&
    ((x.base.before :: x.base.past).flatMap fun a => a.nodes.map (·.2.log)).any fun l =>
      decide ((e,l.take i) ∈ x.committedBefore ∧ l.take k = pre.log.take k) && DeepHistoryCases.oldFacts x l e 0 i

private def guard (r : List Entry) (k b : Nat) (counted : Bool) : Bool :=
  let n := (OverlapInductionB.filt (common r k) b).length
  if counted then decide (0 < n) else decide (¬0 < n) && (common r k).any fun x => b + 1 < x.index

private def branchCheck (s : Step) (k : Nat) (counted : Bool) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x => guard x.base.pre.log k x.base.pre.commitIndex counted

private theorem sound (s : Step) {e i k : Nat} (checked : contextCheck s e i k = true) :
    (branchCheck s k true = true → label s (.step .activeConfigurations_overlap_chosen_bound_inl) = true) ∧
    (branchCheck s k false = true → label s (.step .activeConfigurations_overlap_chosen_bound_inr) = true ∧
      label s (.step .chosen_bound_mem_cons_inr) = true) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [contextCheck,made,Option.any_some,Bool.and_eq_true,decide_eq_true_eq,List.any_eq_true] at checked
  obtain ⟨⟨pre,post,lt,gap,le⟩,l,_,⟨mem,agree⟩,facts⟩ := checked
  rw [← View.pre_eq ok.1] at pre gap le agree
  rw [← View.post_eq ok.1] at post lt
  have elect := c.wins_elect ((Summary.leader c.sum post).resolve_left fun old => pre old.1)
  have h := ConfiguredOverlapB.origin elect lt ((X.committed_before ok e (l.take i)).mpr mem)
    (DeepHistoryCases.oldFacts_sound ok facts) gap agree le
  constructor <;> intro yes
  all_goals simp only [branchCheck,made,Option.any_some,← View.pre_eq ok.1,guard,
    Bool.false_eq_true,ite_false,ite_true,Bool.and_eq_true,decide_eq_true_eq,List.any_eq_true] at yes
  · exact (label_true s _).mpr ((sig_iff c _).mpr (within h yes))
  · obtain ⟨first,later⟩ := firstAndLater h yes.1 yes.2
    exact ⟨(label_true s _).mpr ((sig_iff c _).mpr first),(label_true s _).mpr ((sig_iff c _).mpr later)⟩

public def questions : List Classes.StepBranch :=
  [.activeConfigurations_overlap_chosen_bound_inl,.activeConfigurations_overlap_chosen_bound_inr,
   .chosen_bound_mem_cons_inr]

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ questions) :
    ∃ s : Step, label s (.step b) = true := by
  simp only [questions,List.mem_cons,List.not_mem_nil,or_false] at mem
  have pair := (sound secondStep (e := 2) (i := 3) (k := 2) (by decide +kernel)).2 (by decide +kernel)
  rcases mem with rfl | rfl | rfl
  · exact ⟨AssistOverlapA.positiveStep,
      (sound _ (e := 3) (i := 3) (k := 2) (by decide +kernel)).1 (by decide +kernel)⟩
  · exact ⟨_,pair.1⟩
  · exact ⟨_,pair.2⟩

end ConsensusCoverage.ChoiceCasesB
