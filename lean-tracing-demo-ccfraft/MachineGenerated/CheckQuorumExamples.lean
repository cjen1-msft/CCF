-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.ModelProofs

set_option autoImplicit false

namespace CCFRaft.CheckQuorumExamples

def node0 : Node := ⟨0, by decide⟩

/-- The canonical multi-node leader may fail its quorum check and step down. -/
theorem canonicalLeaderCanCheckQuorum :
    let before := (initialState : State Node (Fin 1))
    let after := next before (.checkQuorum node0)
    Enabled before (.checkQuorum node0) /\
      (after.nodes node0).role = .follower /\
      (after.nodes node0).currentTerm = (before.nodes node0).currentTerm /\
      (after.nodes node0).log = (before.nodes node0).log /\
      after.network node0 = before.network node0 := by
  decide

def singletonBootstrap : Bootstrap Node where
  configuration := {node0}
  leader := node0
  leader_mem := by decide

section Singleton

local instance : Bootstrap Node := singletonBootstrap

/-- CheckQuorum is disabled without another configured replica. -/
theorem singletonLeaderCannotCheckQuorum :
    let state := (initialState : State Node (Fin 1))
    Not (Enabled state (.checkQuorum node0)) := by
  decide

end Singleton

end CCFRaft.CheckQuorumExamples
