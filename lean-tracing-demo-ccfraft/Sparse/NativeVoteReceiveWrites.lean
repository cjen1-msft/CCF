-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeVoteReceiveTerms
import Sparse.NativeQueuePop
import Sparse.NativeQueueStore

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def voteReceiveVotedFor {width : PNat} (columns : Columns) (source destination : Fin width)
    (packet : Expr (packetTy width)) (signature : Expr .int) :
    Expr (.array .int optionalIntTy) :=
  let previous : Expr (.array .int optionalIntTy) := .free _ columns.votedFor
  .ite (voteGrantTerm columns destination packet signature)
    (.store previous (.integer destination.val) (.inr (.integer source.val)))
    previous

def voteReceiveWrites {width : PNat} (source destination : Fin width)
    (packet : Expr (packetTy width)) (signature : Expr .int) : EncodeM width Unit := do
  let before <- get
  if packet.symbols.all (fun symbol => symbol.2 < before.next) &&
      signature.symbols.all (fun symbol => symbol.2 < before.next) then
    let votedFor <- define
      (voteReceiveVotedFor before.toColumns source destination packet signature)
    modify fun state => { state with votedFor }
    popQueue destination source
    pushQueue source destination
      (voteResponseTerm before.toColumns destination packet signature)
  else
    throw "internal encoder error: vote receive inputs reference an unallocated SMT symbol"

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
