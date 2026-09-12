-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEncode

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeObservationNormalizeFixtures

open Lean NativeSmt NativeEncode

def fixture (name : String) (term : Int) (content : Expr (contentTy 3))
    (decodedContent : EntryContent (Fin 3) Nat) (present : Bool)
    (liveLength index mutation : Nat) : Except String Json := do
  let decoded : Entry (Fin 3) Nat := { term := term.toNat, content := decodedContent }
  let expected := match mutation with
    | 0 => decoded
    | 1 => { decoded with term := decoded.term + 1 }
    | _ => { decoded with content := if decoded.content = .signature then .transaction 7 else .signature }
  let observed <- observationClauses (width := 3) {} (.entry 0 index expected)
  let assertions : List (Expr .bool) := [
    .equal (allocated 0) (.boolean present),
    .equal (read 3 0 (.integer 0)) (.integer (if present then liveLength else 0)),
    .equal (entryAt 3 0 (.integer index)) (.pair (.integer term) content)] ++ observed
  return Json.mkObj [("name", toJson name), ("script", toJson (renderScript assertions)),
    ("expected", toJson (if present && index < liveLength && mutation == 0 then "sat" else "unsat"))]

def cases : Except String (List Json) := do
  let contents : List (Expr (contentTy 3) × EntryContent (Fin 3) Nat) := [
    (.inl .unit, .signature),
    (.inr (.inl (.integer (-7))), .transaction 0),
    (.inr (.inl (.integer 0)), .transaction 0),
    (.inr (.inl (.integer (10 ^ 30))), .transaction (10 ^ 30)),
    (.inr (.inr (.inl (.bits (encodeBits (width := 3) {0, 2})))), .reconfiguration {0, 2}),
    (.inr (.inr (.inr (.bits (encodeBits (width := 3) {1, 2})))), .retiredCommitted {1, 2})]
  let parameters := contents.zipIdx.flatMap fun ((content, decoded), tag) =>
    ([-5, 0, 3, 10 ^ 30] : List Int).flatMap fun term =>
      [false, true].flatMap fun present =>
        [0, 1].flatMap fun liveLength =>
          [0, 1].flatMap fun index =>
            [0, 1, 2].map fun mutation => (content, decoded, tag, term, present, liveLength, index, mutation)
  parameters.mapM fun (content, decoded, tag, term, present, liveLength, index, mutation) =>
    fixture s!"normalized-observation-{tag}-{term}-{present}-{liveLength}-{index}-{mutation}"
      term content decoded present liveLength index mutation

end CCFRaft.NativeObservationNormalizeFixtures

def main : IO Unit :=
  match CCFRaft.NativeObservationNormalizeFixtures.cases with
  | .ok fixtures => IO.println (Lean.toJson fixtures).compress
  | .error error => throw (IO.userError error)
