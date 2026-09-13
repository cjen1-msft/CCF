-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNatSetInsert

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def submittedWriteColumns (before : Columns) (base : Nat) : Columns :=
  { before with submittedTxIds := base, submittedTxLimit := base + 1 }

def insertSubmitted {width : PNat} (value : Expr .int) : EncodeM width Unit := do
  let before <- get
  if value.symbols.all (fun symbol => symbol.2 < before.next) then
    let cells <- fresh
    let limit <- fresh
    assertion (natSetInsertConstraints before.submittedTxIds before.submittedTxLimit
      cells limit value)
    modify fun after => { after with submittedTxIds := cells, submittedTxLimit := limit }
  else
    throw "internal encoder error: submitted transaction references an unallocated SMT symbol"

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
