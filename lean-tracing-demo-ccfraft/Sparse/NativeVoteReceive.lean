-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeVoteReceiveGuard
import Sparse.NativeVoteReceiveWrites
import Sparse.NativeSignatureEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def receiveVotePrefix {width : PNat} (columns : Columns) (source destination : Fin width) :
    EncodeM width Nat := do
  assertAll (voteReceiveGuards columns source destination)
  let signature <- fresh
  assertAll [signatureIndexTerm width destination.val (.free .int signature)]
  return signature

def receiveVoteTail {width : PNat} (columns : Columns) (source destination : Fin width)
    (signature : Nat) : EncodeM width Unit :=
  voteReceiveWrites source destination
    (queueHeadPacketTerm columns source destination) (.free .int signature)

def receiveVote {width : PNat} (source destination : Fin width) : EncodeM width Unit :=
  fun before =>
    (receiveVotePrefix before.toColumns source destination >>= fun signature =>
      receiveVoteTail before.toColumns source destination signature).run before

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
