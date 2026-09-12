-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNodeRowWrites
import Sparse.NativeQueuePop

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def appendReceiveWrites {width : PNat} (source destination : Fin width)
    (stepDown : Expr .bool) (values : NodeRowTerms width)
    (response : Expr (packetTy width)) (completed : Expr (.bits width)) :
    EncodeM width Unit := do
  let before <- get
  if stepDown.symbols.all (fun symbol => symbol.2 < before.next) &&
      response.symbols.all (fun symbol => symbol.2 < before.next) &&
      completed.symbols.all (fun symbol => symbol.2 < before.next) then
    writeNodeRow destination values
    popQueue destination source
    pushQueue source destination response
    let consumed <- get
    let queueLength <- define (.ite stepDown
      (.free (.array .int (.array .int .int)) before.queueLength)
      (.free (.array .int (.array .int .int)) consumed.queueLength))
    let queueHead <- define (.ite stepDown
      (.free (.array .int (.array .int .int)) before.queueHead)
      (.free (.array .int (.array .int .int)) consumed.queueHead))
    let queueCells <- define (.ite stepDown
      (.free (queueCellsTy width) before.queueCells)
      (.free (queueCellsTy width) consumed.queueCells))
    let original : Expr (.array .int (.bits width)) := .free _ before.retirementCompleted
    let retirementCompleted <- define
      (.ite stepDown original (.store original (.integer destination.val) completed))
    modify fun after => { after with queueLength, queueHead, queueCells, retirementCompleted }
  else
    throw "internal encoder error: append receive inputs reference an unallocated SMT symbol"

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
