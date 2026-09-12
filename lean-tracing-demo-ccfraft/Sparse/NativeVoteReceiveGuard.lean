-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeVoteReceiveTerms
import Sparse.NativeQueueHead

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def voteReceiveGuards {width : PNat} (columns : Columns) (source destination : Fin width) :
    List (Expr .bool) :=
  let packet := queueHeadPacketTerm columns source destination
  [allocated columns destination.val,
    lt (.integer 0) (queueScalarTerm columns.queueLength (.integer destination.val) (.integer source.val)),
    isVoteRequestTerm packet,
    .equal (.snd (.snd (.fst packet))) (.integer destination.val),
    .le (.fst (.fst packet)) (read columns columns.currentTerm destination.val (.integer 0))]

end CCFRaft.NativeEncode
