-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeVoteGuards
import Sparse.NativeQueueStore

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def sendVote {width : PNat} (preVote : Bool) (source destination : Fin width) : EncodeM width Unit := do
  let before <- get
  let base <- fresh
  let _ <- fresh
  let _ <- fresh
  assertAll (voteGuards before.toColumns before.bootstrap preVote source destination base)
  pushQueue destination source (votePacketTerm before.toColumns preVote source destination (.free .int (base + 2)))

end CCFRaft.NativeEncode
