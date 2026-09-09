-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.GuardedAppendEntries

set_option autoImplicit false

namespace CCFRaft.GuardedAppendEntries.Tests

open TraceSmt TransactionMapping

private def source : Node := ⟨0, by decide⟩
private def destination : Node := ⟨1, by decide⟩
private def old : NatTerm 2 := .unknown 0
private def fresh : NatTerm 2 := .unknown 1

private def withTransaction (transaction : NatTerm 2) : State Node (NatTerm 2) :=
  next initialState (.clientRequest source transaction)

private def prior : Message Node (NatTerm 2) :=
  .appendEntriesRequest
    (makeAppendEntriesRequest (withTransaction old) source destination 1)

private def entry : State Node (NatTerm 2) :=
  { withTransaction fresh with
    network := fun node => if node = destination then [prior] else [] }

private def aliased : Fin 2 -> Nat := fun _ => 0
private def distinct : Fin 2 -> Nat := fun index => index.val

private def symbolic := step entry source destination 1

#guard ((symbolic.eval aliased).network destination).length == 1
#guard ((symbolic.eval distinct).network destination).length == 2
#guard ((symbolic.eval aliased).nodes source).sentIndex destination == 1
#guard ((symbolic.eval distinct).nodes source).sentIndex destination == 1

#guard ((next entry (.appendEntries source destination 1)).network destination).length == 2
#guard ((next (mapState (NatTerm.eval aliased) entry)
  (.appendEntries source destination 1)).network destination).length == 1

example (assignment : Fin 2 -> Nat) :
    mapState (NatTerm.eval assignment) (symbolic.eval assignment) =
      next (mapState (NatTerm.eval assignment) entry)
        (.appendEntries source destination 1) :=
  step_correct assignment entry source destination 1

end CCFRaft.GuardedAppendEntries.Tests
