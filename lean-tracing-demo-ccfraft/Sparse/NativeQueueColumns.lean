-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEncode
import Sparse.NativeQueueScalars
import Sparse.NativeQueuePoint

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def queueCellsTy (width : PNat) : Ty :=
  .array .int (.array .int (.array .int (packetTy width)))

def queueCellsTerm {context : List Ty} {width : PNat} (column : Nat)
    (destination source : Term context .int) : Term context (.array .int (packetTy width)) :=
  .select (.select (.free (queueCellsTy width) column) destination) source

noncomputable def queueRow {width : PNat} (assignment : Assignment) (columns : Columns)
    (destination source : Fin width) : NativeArrayQueue.Queue (Message (Fin width) Nat) :=
  modelQueue source
    (assignment (.array .int (.array .int .int)) columns.queueHead destination.val source.val).toNat
    (assignment (.array .int (.array .int .int)) columns.queueLength destination.val source.val).toNat
    (assignment (queueCellsTy width) columns.queueCells destination.val source.val)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
