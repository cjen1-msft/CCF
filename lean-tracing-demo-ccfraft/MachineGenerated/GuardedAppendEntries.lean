-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.Guarded
import MachineGenerated.MessageEquality
import MachineGenerated.AppendEntriesMappingProofs

set_option autoImplicit false

namespace CCFRaft.GuardedAppendEntries

open TraceSmt TransactionMapping MessageEquality

def step {holes : Nat}
    (state : State Node (NatTerm holes))
    (source destination : Node) (batchEnd : Nat) :
    Guarded holes (State Node (NatTerm holes)) :=
  .pure (next state (.appendEntries source destination batchEnd))

theorem step_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (state : State Node (NatTerm holes))
    (source destination : Node) (batchEnd : Nat) :
    mapState (NatTerm.eval assignment)
        ((step state source destination batchEnd).eval assignment) =
      next (mapState (NatTerm.eval assignment) state)
        (.appendEntries source destination batchEnd) := by
  simpa [step, Guarded.eval] using
    mapState_appendEntries (NatTerm.eval assignment)
      state source destination batchEnd

end CCFRaft.GuardedAppendEntries
