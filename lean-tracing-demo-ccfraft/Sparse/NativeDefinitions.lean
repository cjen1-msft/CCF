-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEncode

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

abbrev TypedDefinition := Sigma Expr

def definitionIds : List TypedDefinition -> Nat -> List Nat
  | [], _ => []
  | _ :: rest, next => next :: definitionIds rest (next + 1)

def definitionClauses : List TypedDefinition -> Nat -> List (Expr .bool)
  | [], _ => []
  | ⟨sort, value⟩ :: rest, next =>
    .equal (.free sort next) value :: definitionClauses rest (next + 1)

def definitions {width : PNat} : List TypedDefinition -> EncodeM width (List Nat)
  | [] => pure []
  | ⟨_, value⟩ :: rest => do
    let id <- define value
    let ids <- definitions rest
    return id :: ids

end CCFRaft.NativeEncode
