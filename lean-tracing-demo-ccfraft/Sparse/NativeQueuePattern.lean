-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativePacketPatternTerm
import Sparse.NativePacketArrayHint
import Sparse.NativeQueuePoint

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def packetArrayHintLimit : Nat := 32

def queuePatternDomain {context : List Ty} {width : PNat} (source : Fin width)
    (value : Term context (packetTy width))
    (expected : NativePacketPattern.Pattern (Fin width) Nat) : Term context .bool :=
  let domain := queuePacketDomain (.integer source.val) value
  match expected.payload with
  | .appendEntriesRequest _ _ _ (some count) none =>
    if count <= packetArrayHintLimit then .and domain (packetArrayHint count value)
    else domain
  | _ => domain

def queuePattern {context : List Ty} {width : PNat} (source : Fin width)
    (head length : Term context .int) (cells : Term context (.array .int (packetTy width)))
    (index : Nat) (expected : NativePacketPattern.Pattern (Fin width) Nat) : Term context .bool :=
  let value := Term.select cells (.add head (.integer index))
  .and (lt (.integer index) length)
    (.ite (queuePatternDomain source value expected)
      (packetPatternTerm expected value)
      (.boolean (expected.matches (defaultQueuePacket source))))

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
