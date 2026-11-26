module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.DeepSchedules
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.JointWitnesses

namespace ConsensusCoverage.QueueSamplesA

open ActionProfile FrontierRows DeepSchedules

abbrev Certificate := {b : Classes.StepBranch // ∃ s : Step, label s (.step b) = true}

def selected (script : Script) (valid : script.run.valid) (offset : Nat) : Option Step := do
  let r := script.run
  let steps ← JointWitnesses.recordedAt { r with schedule := r.schedule.take (offset + 1) }
    valid script.choices
  return (← steps[offset]?).val

def checked (b : Classes.StepBranch) (chosen : Option Step) (test : Step → Bool)
    (passed : chosen.any test = true) (sound : ∀ s, test s = true → label s (.step b) = true) :
    Certificate := by
  refine ⟨b, ?_⟩
  cases chosen with
  | none => cases passed
  | some s => exact ⟨s, sound s passed⟩

end ConsensusCoverage.QueueSamplesA
