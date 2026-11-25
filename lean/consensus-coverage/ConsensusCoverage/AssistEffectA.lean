module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.BatchArmsB
import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.QueueSamplesA
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.AssistEffectA

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile SolvedWitnesses QueueSamplesA BatchArmsB DeepSchedulesB
set_option maxRecDepth 8192

private def item (confirmed : Bool) : EntryContent :=
  .transaction 1 {retirementConfirmations := if confirmed then {0} else ∅}

private theorem effects [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    (s : Seed c) (confirmed : Bool) :
    sig c (if confirmed then .ite__condition_pos_2 else .ite__condition_neg_2) := by
  let v := item confirmed
  have batch := start s
  have caller := itemCaller s v batch
  have pushed := batch.push v
  let next : NodeState := {s.before with log := s.before.log ++ [(⟨s.before.currentTerm,v⟩ : Entry)]}
  let m : NodeEffect NodeState := do
    guard (v.metadata.retirementConfirmations ⊆ s.before.retirementCompletedNodes \ retiredCommittedNodes s.before.log)
    pure next
  cases confirmed <;> (iterate 6 right) <;> left
  all_goals
    refine ⟨fun z out => BatchState s.self s.before z ([] ++ out),
      v.metadata.retirementConfirmations.Nonempty,m,pure next,?_,?_,?_,?_⟩
    · iterate 17 right
      exact .inl ⟨s.self,s.before,s.before,[],v,caller,by decide,batch,rfl,rfl,rfl,rfl⟩
    · decide
    · intro _
      apply Sends.guard_bind
      intro _
      apply Sends.pure'
      simpa using pushed
    · intro _
      apply Sends.pure'
      simpa using pushed

private def sample := ReceiveCasesB.asSample DeepSchedulesB.batch 0 (by decide +kernel) (by decide +kernel)

private theorem labelAt (confirmed : Bool) :
    label sample.s (.step (if confirmed then .ite__condition_pos_2 else .ite__condition_neg_2)) = true := by
  letI : Config.InitialConfiguration := ⟨sample.s.cfg⟩
  have s := seedOf (c := sample.s.context) (x := sample.x) sample.ok
    (by decide +kernel) (by decide +kernel) (by decide +kernel)
  exact (label_true _ _).mpr ((sig_iff _ _).mpr (effects s confirmed))

def certificates : List Certificate := [⟨_,sample.s,labelAt true⟩,⟨_,sample.s,labelAt false⟩]

end ConsensusCoverage.AssistEffectA
