-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveTerms
import Sparse.NativeNodeRowWrites

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def appendReceiveCandidateRowTerms {width : PNat}
    (columns : Columns) (destination : Fin width)
    (packet : Expr (packetTy width)) (grows : Expr .bool)
    (logLength : Expr .int)
    (logEntries : Expr (.array .int (entryTy width)))
    (commit : Expr .int) : NodeRowTerms width :=
  let old := nodeRowSnapshot columns destination
  let branches := appendReceiveTerms columns destination packet
  { old with
    logLength
    logEntries
    commit
    newFollower :=
      .ite (.and grows branches.conflict) (.boolean false) old.newFollower }

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
