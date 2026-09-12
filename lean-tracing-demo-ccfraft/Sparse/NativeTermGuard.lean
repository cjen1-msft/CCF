-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeQueueHead

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def termUpdateGuards {width : PNat} (columns : Columns) (source destination : Fin width) :
    List (Expr .bool) :=
  let packet := queueHeadPacketTerm columns source destination
  [allocated destination.val,
    lt (.integer 0) (queueScalarTerm columns.queueLength (.integer destination.val) (.integer source.val)),
    packetSourceAllowedTerm packet (allocated source.val),
    lt (read columns.currentTerm destination.val (.integer 0)) (.fst (.fst packet))]

end CCFRaft.NativeEncode
