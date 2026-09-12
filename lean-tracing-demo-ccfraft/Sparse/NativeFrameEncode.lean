-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEncode
import Sparse.NativeArrayVote

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open Lean NativeSmt

abbrev FrameInstruction (width : PNat) := NativeArrayVote.Instruction (Fin width) Nat
abbrev FrameDecoded := TypedDocument FrameInstruction

def decodeFrameInstruction (width : PNat) (names : Array String) (value : Json) :
    Except String (FrameInstruction width) := do
  let kind <- (<- field value "kind").getStr?
  if kind = "hasJoined" then
    fields value ["kind", "value"]
    return .hasJoined (<- decodeNodeSet width names (<- field value "value"))
  else
    return .node (<- decodeInstruction width names value)

def decodeFrameDocument (document : Json) : Except String FrameDecoded :=
  decodeDocumentWith decodeFrameInstruction document

def frameObservationClauses {width : PNat} (columns : Columns) :
    FrameInstruction width -> Except String (List (Expr .bool))
  | .node item => observationClauses columns item
  | .hasJoined expected =>
    .ok [.equal (.free (.bits width) columns.hasJoined) (.bits (encodeBits expected))]
  | _ => .error "unsupported native Lean frame observation"

def frameInstruction {width : PNat} (item : FrameInstruction width) : EncodeM width Unit :=
  match item with
  | .node nodeInstruction => instruction nodeInstruction
  | _ => do
    let state <- get
    assertAll (<- frameObservationClauses state.toColumns item)

def compileFrameDecoded (input : FrameDecoded) : Except String Compiled := do
  let (_, start) <- (initialDomains input.width).run (initialEncoding input.width input.bootstrap)
  let groups := #[{ instruction := none, start := 0, stop := start.assertions.size : Group }]
  let (groups, final) <-
    (compileInstructionsWith frameInstruction 0 groups input.instructions.toList).run start
  return { assertions := final.assertions, groups }

def compileFrame (document : Json) : Except String Compiled := do
  compileFrameDecoded (<- decodeFrameDocument document)

def encodeFrame (document : Json) : Except String String := do
  return renderScript (<- compileFrame document).assertions.toList

def encodeFrameDetails (document : Json) : Except String Json := do
  return compiledDetails document (<- compileFrame document)

end CCFRaft.NativeEncode
