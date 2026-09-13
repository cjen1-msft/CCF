-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNodeRowWrites

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def writeRetirementRow {width : PNat} (source : Fin width)
    (values : NodeRowTerms width) (completed : Expr (.bits width)) :
    EncodeM width Unit := do
  let before <- get
  if completed.symbols.all (fun symbol => symbol.2 < before.next) then
    writeNodeRow source values
    let retiredNodes <- define
      (.store (.free (.array .int (.bits width)) before.retirementCompleted)
        (.integer source.val) completed)
    modify fun after => { after with retirementCompleted := retiredNodes }
  else
    throw "internal encoder error: retirement write references an unallocated SMT symbol"

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
