-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeFrameEncode

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeAppendReceiveFixtures

open Lean NativeEncode

def fixtureInstruction (width : PNat) (names : Array String) (value : Json) :
    Except String (FrameInstruction width ⊕ (Fin width × Fin width)) := do
  if (<- (<- field value "kind").getStr?) = "receiveAppendEntries" then
    fields value ["kind", "source", "destination"]
    return .inr ((<- resolve width names (<- field value "source")),
      (<- resolve width names (<- field value "destination")))
  else
    return .inl (<- decodeFrameInstruction width names value)

end CCFRaft.NativeAppendReceiveFixtures
