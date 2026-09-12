-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEncode
import Sparse.NativeNatSet

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def initialFrameAssertions (width : PNat) : List (Expr .bool) :=
  initialAssertions width ++ [natSetDomain 20]

def initialFrameDomains (width : PNat) : EncodeM width Unit :=
  assertAll (initialFrameAssertions width)

end CCFRaft.NativeEncode
