-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendGuard
import Sparse.NativeAppendPacket
import Sparse.NativeQueueStore

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def appendSentIndex {width : PNat} (columns : Columns) (source destination : Fin width)
    (batchEnd : Nat) : Expr (.array .int (.array .int .int)) :=
  storePair (.free _ columns.sentIndex) (.integer source.val) (.integer destination.val)
    (.integer batchEnd)

def appendSendBody {width : PNat} (columns : Columns) (source destination : Fin width)
    (batchEnd : Nat) : EncodeM width Unit := do
  let sentIndex <- define (appendSentIndex columns source destination batchEnd)
  modify fun state => { state with sentIndex }
  pushQueue destination source (appendPacketTerm columns source destination)

def appendSendGuard {width : PNat} (columns : Columns) (bootstrap : BitVec width)
    (source destination : Fin width) (batchEnd : Nat) : EncodeM width Unit := do
  let base <- fresh
  let _ <- fresh
  assertAll (appendGuards columns bootstrap source destination batchEnd base)

def sendAppend {width : PNat} (source destination : Fin width) (batchEnd : Nat) :
    EncodeM width Unit := do
  let before <- get
  appendSendGuard before.toColumns before.bootstrap source destination batchEnd
  appendSendBody before.toColumns source destination batchEnd

end CCFRaft.NativeEncode
