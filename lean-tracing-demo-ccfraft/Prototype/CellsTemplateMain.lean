-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeParameterizedFrame

set_option autoImplicit false

def main (arguments : List String) : IO UInt32 := do
  let result : Except String String := do
    let [text] := arguments | throw "expected node width"
    let some size := text.toNat? | throw "invalid node width"
    if positive : 0 < size then
      let width : PNat := ⟨size, positive⟩
      let value : CCFRaft.NativeEncode.Expr (CCFRaft.NativeEncode.entryTy width) := .free _ 0
      return CCFRaft.NativeSmt.renderScript [
        .equal (CCFRaft.NativeEncode.normalizedEntryTerm value) value]
    else throw "positive width required"
  match result with
  | .ok script => IO.println script; return 0
  | .error error => (← IO.getStderr).putStrLn error; return 2
