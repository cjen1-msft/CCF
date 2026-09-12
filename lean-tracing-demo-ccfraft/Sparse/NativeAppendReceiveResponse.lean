-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveTerms
import Sparse.NativeAppendResponseTerm
import Sparse.NativeVotePacket

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def appendReceiveNackHint {width : PNat} (columns : Columns)
    (destination : Fin width) (packet : Expr (packetTy width)) : Expr .bool :=
  let previous := (appendRequestPayloadTerm packet).fst
  let currentTerm : Expr .int :=
    read columns columns.currentTerm destination.val (.integer 0)
  let logLength : Expr .int := length columns destination.val
  all [
    .not (lt packet.fst.fst currentTerm),
    .not (.equal previous (.integer 0)),
    .le previous logLength,
    .not (.equal (logTermAt width columns destination.val logLength) (.integer 0))]

def appendReceiveResponseTerm {width : PNat} (columns : Columns)
    (source destination : Fin width) (packet : Expr (packetTy width))
    (best : Expr .int) : Expr (packetTy width) :=
  let branches := appendReceiveTerms columns destination packet
  let payload := appendRequestPayloadTerm packet
  let previous := payload.fst
  let payloadLength := payload.snd.snd.snd.fst
  let currentTerm : Expr .int :=
    read columns columns.currentTerm destination.val (.integer 0)
  let logLength : Expr .int := length columns destination.val
  let hint := appendReceiveNackHint columns destination packet
  let responseTerm := .ite (.and branches.rejects hint)
    (.ite (.equal best (.integer 0)) (.integer TERM_ONE)
      (logTermAt width columns destination.val best))
    currentTerm
  let responseIndex := .ite branches.rejects
    (.ite hint best logLength) (.add previous payloadLength)
  appendResponseTerm width destination source responseTerm
    (.not branches.rejects) responseIndex

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
