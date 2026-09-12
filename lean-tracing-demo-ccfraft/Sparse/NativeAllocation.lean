-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNodeRowWrites

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def allocateNode {width : PNat} (node : Fin width) (enabled : Expr .bool) :
    EncodeM width Unit := do
  let before <- get
  if enabled.symbols.all (fun symbol => symbol.2 < before.next) then
    -- Snapshot reads supply fresh values for absent nodes before exposing them.
    writeNodeRow node (nodeRowSnapshot before.toColumns node)
    let allocation <- define
      (.store (.free (.array .int .bool) before.allocated) (.integer node.val)
        (.or (allocated before.toColumns node.val) enabled))
    modify fun after => { after with allocated := allocation }
  else
    throw "internal encoder error: allocation condition references an unallocated SMT symbol"

def allocateNodeList {width : PNat} (added : Expr (.bits width)) :
    List (Fin width) -> EncodeM width Unit
  | [] => pure ()
  | node :: rest => do
    allocateNode node (.bit added node)
    allocateNodeList added rest

def allocateNodes {width : PNat} (added : Expr (.bits width)) : EncodeM width Unit := do
  let before <- get
  if added.symbols.all (fun symbol => symbol.2 < before.next) then
    allocateNodeList added (List.finRange width)
  else
    throw "internal encoder error: allocation set references an unallocated SMT symbol"

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
