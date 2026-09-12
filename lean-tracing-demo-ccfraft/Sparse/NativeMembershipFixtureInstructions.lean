-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeFrameEncode

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeMembershipFixtures

open Lean NativeEncode

def fixtureInstruction (width : PNat) (names : Array String) (value : Json) :
    Except String (FrameInstruction width ⊕ (Fin width × Finset (Fin width))) := do
  if (<- (<- field value "kind").getStr?) = "changeConfiguration" then
    fields value ["kind", "source", "configuration"]
    return .inr ((<- resolve width names (<- field value "source")),
      (<- decodeNodeSet width names (<- field value "configuration")))
  else
    return .inl (<- decodeFrameInstruction width names value)

end CCFRaft.NativeMembershipFixtures
