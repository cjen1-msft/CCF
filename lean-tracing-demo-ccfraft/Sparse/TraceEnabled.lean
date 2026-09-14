-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model

set_option autoImplicit false

namespace CCFRaft

/-- TLA's trace heartbeat choice, with data batches reduced to single entries. -/
def appendBatchAllowed (previous length batchEnd : Nat) : Prop :=
  previous <= batchEnd /\ batchEnd <= min (previous + 1) length

instance (previous length batchEnd : Nat) :
    Decidable (appendBatchAllowed previous length batchEnd) := by
  unfold appendBatchAllowed
  infer_instance

/-- Traceccfraft's send policy; all other actions retain the base Model guard. -/
def TraceEnabled {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]
    (state : State N T) : Action N T -> Prop
  | .appendEntries source destination batchEnd =>
      state.allocated source /\
        state.allocated destination /\
        (state.nodes source).role = .leader /\
        source ≠ destination /\
        (destination ∈ activeNodeUnion (state.nodes source) \/
          destination ∈ state.retirementCompleted source) /\
        appendBatchAllowed ((state.nodes source).sentIndex destination)
          (state.nodes source).log.length batchEnd /\
        ((state.nodes source).membershipState ≠ .retiredCommitted \/
          (state.nodes source).sentIndex destination < batchEnd)
  | action => Enabled state action

instance {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]
    (state : State N T) (action : Action N T) : Decidable (TraceEnabled state action) := by
  cases action <;> simp only [TraceEnabled] <;> infer_instance

theorem append_batch_allowed_cases (previous length batchEnd : Nat)
    (allowed : appendBatchAllowed previous length batchEnd) :
    batchEnd = previous \/ batchEnd = min (previous + 1) length := by
  have cap := Nat.min_le_left (previous + 1) length
  unfold appendBatchAllowed at allowed
  omega

theorem trace_send_payload_length_le_one {N T : Type}
    [DecidableEq N] [DecidableEq T] [Bootstrap N]
    (state : State N T) (source destination : N) (batchEnd : Nat)
    (enabled : TraceEnabled state (.appendEntries source destination batchEnd)) :
    (makeAppendEntriesRequest state source destination batchEnd).entries.length <= 1 := by
  have cap := enabled.2.2.2.2.2.1.2.trans
    (Nat.min_le_left ((state.nodes source).sentIndex destination + 1)
      (state.nodes source).log.length)
  simp only [makeAppendEntriesRequest, messageEntries, List.length_take, List.length_drop]
  omega

end CCFRaft

run_cmd do
  for name in [``CCFRaft.append_batch_allowed_cases, ``CCFRaft.trace_send_payload_length_le_one] do
    for axiomName in (<- Lean.collectAxioms name) do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "unexpected axiom in {name}: {axiomName}"
