-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAllocation

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def membershipWrites {width : PNat} (source : Fin width) (added : Expr (.bits width))
    (values : NodeRowTerms width) (completed : Expr (.bits width)) : EncodeM width Unit := do
  let before <- get
  if added.symbols.all (fun symbol => symbol.2 < before.next) &&
      completed.symbols.all (fun symbol => symbol.2 < before.next) &&
      (nodeRowWriteDefinitions before.toColumns source values).all
        (fun item => item.2.symbols.all (fun symbol => symbol.2 < before.next)) then
    allocateNodes added
    writeNodeRow source values
    let joined <- define (.bitsOr (.free (.bits width) before.hasJoined) added)
    let retiredNodes <- define
      (.store (.free (.array .int (.bits width)) before.retirementCompleted)
        (.integer source.val) completed)
    modify fun after => { after with hasJoined := joined, retirementCompleted := retiredNodes }
  else
    throw "internal encoder error: membership writes reference an unallocated SMT symbol"

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
