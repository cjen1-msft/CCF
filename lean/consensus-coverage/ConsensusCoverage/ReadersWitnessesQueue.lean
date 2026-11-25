module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.CaseWitnesses
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersPolar
import all ConsensusCoverage.ReadersPolarQueue
import all ConsensusCoverage.ReadersPolarReceiveQueue
import all ConsensusCoverage.ReadersPolarCompiler
import ConsensusCoverage.SolvedWitnesses

namespace ConsensusCoverage.ReadersWitnessesQueue

open ActionProfile FrontierRows ReadersAtoms Consensus.Proofs

set_option maxHeartbeats 0
set_option maxRecDepth 8192
set_option Elab.async false

private def appendBatch : Run :=
  ⟨{0, 1}, [0, 1, 2, 3], [.input 0 (.append [
    {content := .signature, flushes := [(1, 2)]},
    {content := .transaction 1 {configuration := some {0, 1, 2, 3}}, flushes := [(1, 3)]}])]⟩

private theorem appendBatchValid : appendBatch.valid := by
  unfold Run.valid
  decide

private def appendStep : Option Step := CaseWitnesses.selected appendBatch [] appendBatchValid 0

private def retireStep : Option Step := ReadersCorpus.caseStepAt 30 10

private def firstAck : Run :=
  ⟨{0, 1, 2}, [0, 1, 2], [.input 0 (.append [{content := .signature, flushes := [(1, 2)]}]),
    .deliver 0 1, .deliver 1 0]⟩

private theorem firstAckValid : firstAck.valid := by
  unfold Run.valid
  decide

private def receiveStep : Option Step := CaseWitnesses.selected firstAck [] firstAckValid 1

private def readView [Config.InitialConfiguration] (x : XView) (pools : ReadersPolar.Pools)
    (b : Classes.StepBranch) : Option Bool :=
  (ReadersPolarQueue.readView x pools b).orElse fun _ => ReadersPolarReceiveQueue.readView x pools b

private def reads (b : Classes.StepBranch) (s : Step) : Option Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).bind fun x =>
    @readView ⟨s.cfg⟩ x (ReadersPolar.prepare s.cfg x) b

private theorem certify {b : Classes.StepBranch} (candidate : Option Step)
    (yes : candidate.any (fun s => reads b s == some true) = true) :
    ∃ s : Step, label s (.step b) = true := by
  cases found : candidate with
  | none => simp [found] at yes
  | some s =>
    simp only [found, Option.any_some, beq_iff_eq] at yes
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    obtain ⟨x, made, ok⟩ := ofXAction_matches s
    let pools := ReadersPolar.prepare s.cfg x
    have answer : readView x pools b = some true := by
      simpa only [reads, made, Option.bind_some] using yes
    have agrees := ReadersPolarCompiler.picked_some answer
      (ReadersPolarCompiler.picked_orElse
        (@ReadersPolarQueue.readView_correct ⟨s.cfg⟩ s.frame s.after s.context b x ok pools)
        (@ReadersPolarReceiveQueue.readView_correct ⟨s.cfg⟩ s.frame s.after s.context b x ok pools))
    exact ⟨s, (label_true s (.step b)).mpr ((SolvedWitnesses.sig_iff s.context b).mpr (agrees.mp rfl))⟩

private theorem noPeers : ∃ s : Step, label s (.step .appendEntry_batch_peers_none) = true :=
  certify appendStep (by decide +kernel)

private theorem somePeers : ∃ s : Step, label s (.step .appendEntry_batch_peers_some) = true :=
  certify appendStep (by decide +kernel)

private theorem retired : ∃ s : Step, label s (.step .recordCommit_eq_retire_pos) = true :=
  certify retireStep (by decide +kernel)

private theorem entriesNil : ∃ s : Step, label s (.step .fromLeader_loop_entries_nil) = true :=
  certify receiveStep (by decide +kernel)

public def witnessed : List Classes.StepBranch :=
  [.appendEntry_batch_peers_none, .appendEntry_batch_peers_some, .recordCommit_eq_retire_pos,
    .fromLeader_loop_entries_nil]

public theorem count : witnessed.Nodup ∧ witnessed.length = 4 := by decide

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true := by
  simp only [witnessed, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl | rfl
  · exact noPeers
  · exact somePeers
  · exact retired
  · exact entriesNil

end ConsensusCoverage.ReadersWitnessesQueue
