module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.CensusQueueHints
import all ConsensusCoverage.CensusQueueElection
import all ConsensusCoverage.CensusQueueSearch
import all ConsensusCoverage.CensusQueueStep
import all ConsensusCoverage.SolvedWitnesses
meta import ConsensusCoverage.CensusQueueCertificate

namespace ConsensusCoverage.CensusQueueReaderCases

open Consensus Consensus.Model Consensus.Model.Node ActionProfile FrontierRows
set_option maxRecDepth 16384
set_option maxHeartbeats 35000
set_option Elab.async false

private def retire : Run :=
  ⟨{0, 1, 2}, [0, 1, 2], [
    .input 0 (.append [{content := .transaction 1 {configuration := some {1, 2}}},
      {content := .signature, flushes := [(1, 3), (2, 3)]}]),
    .deliver 0 1, .deliver 0 2, .deliver 1 0, .deliver 2 0,
    .input 0 (.append [{content := .transaction 2 {configuration := some {1}}},
      {content := .signature, flushes := [(2, 5)]},
      {content := .transaction 3 {retirementConfirmations := {0}}},
      {content := .signature, flushes := [(1, 7)]}]),
    .deliver 0 1, .deliver 0 2, .deliver 1 0, .deliver 2 0,
    .input 0 (.append [{content := .transaction 4 {}}])]⟩

private def batch : Run :=
  ⟨{0, 1}, [0, 1, 2, 3], [.input 0 (.append [
    {content := .signature, flushes := [(1, 2)]},
    {content := .transaction 1 {configuration := some {0, 1, 2, 3}}, flushes := [(1, 3)]}])]⟩

private def firstAck : Run :=
  ⟨{0, 1, 2}, [0, 1, 2], [.input 0 (.append [{content := .signature, flushes := [(1, 2)]}]),
    .deliver 0 1, .deliver 1 0]⟩

local macro "queued_step " r:ident n:num : term =>
  `(let selected := CensusQueueStep.selected $r (by unfold Run.valid; decide) [] $n
    selected.get (by decide +kernel))

private def retireStep : Step := queued_step retire 10
private def batchStep : Step := queued_step batch 0
private def receiveStep : Step := queued_step firstAck 1

private theorem retired : label retireStep (.step .recordCommit_eq_retire_pos) = true := by queue_certify retireStep
private theorem noPeers : label batchStep (.step .appendEntry_batch_peers_none) = true := by queue_certify batchStep
private theorem somePeers : label batchStep (.step .appendEntry_batch_peers_some) = true := by queue_certify batchStep
private theorem emptyLoop : label receiveStep (.step .fromLeader_loop_entries_nil) = true := by queue_certify receiveStep

public def witnessed : List Classes.StepBranch :=
  [.recordCommit_eq_retire_pos, .appendEntry_batch_peers_none, .appendEntry_batch_peers_some, .fromLeader_loop_entries_nil]

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) : ∃ s : Step, label s (.step b) = true := by
  simp only [witnessed, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl | rfl
  · exact ⟨retireStep, retired⟩
  · exact ⟨batchStep, noPeers⟩
  · exact ⟨batchStep, somePeers⟩
  · exact ⟨receiveStep, emptyLoop⟩

end ConsensusCoverage.CensusQueueReaderCases
