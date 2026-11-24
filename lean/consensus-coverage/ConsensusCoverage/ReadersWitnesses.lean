module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersWitnessProof
public import ConsensusCoverage.CaseWitnesses
import all ConsensusCoverage.ReadersWitnessProof
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersPolarGenerated
import all ConsensusCoverage.ReadersPolar
import all ConsensusCoverage.ReplayAnswers
import all ConsensusCoverage.CaseWitnesses

namespace ConsensusCoverage.ReadersWitnesses

open ActionProfile ReadersWitnessProof

set_option maxHeartbeats 0
set_option maxRecDepth 8192

-- Replay the observed offsets with the kernel; the measurements are not proofs.
private def claim0 : Claim :=
  ⟨0, 0, [.seen_after_seen_inl], by decide +kernel⟩
private def claim1 : Claim :=
  ⟨15, 0, [.summary_event_internal], by decide +kernel⟩

private def claims : List Claim := [claim0, claim1]

/-- Cases witnessed by an executable reader on a replayed corpus step. -/
public def witnessed : List Classes.StepBranch := claims.flatMap (·.questions)

public theorem count : witnessed.Nodup ∧ witnessed.length = 2 := by decide

public theorem union_count :
    (witnessed ++ CaseWitnesses.witnessed).eraseDups.length = 45 := by decide

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true := by
  obtain ⟨c, _, found⟩ := List.mem_flatMap.mp mem
  exact c.occurs found

end ConsensusCoverage.ReadersWitnesses
