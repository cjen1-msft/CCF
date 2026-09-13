-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeFrameEncode
import Sparse.NativeClientRequest
import Sparse.NativeNatParameters

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open Lean NativeSmt

inductive ParameterizedFrameInstruction (width : PNat) (count : Nat) where
  | core (instruction : FrameInstruction width)
  | clientRequest (source : Fin width) (transaction : NatArgument count)

structure ParameterizedFrameDecoded where
  unknowns : Array String
  unknownsDistinct : unknowns.toList.Nodup
  frame : TypedDocument (fun width => ParameterizedFrameInstruction width unknowns.size)

def decodeNatArgument (names : Array String) (value : Json) :
    Except String (NatArgument names.size) := do
  match value with
  | .num _ => return .literal (<- natural value)
  | .obj _ =>
    fields value ["unknown"]
    let name <- (<- field value "unknown").getStr?
    match names.toList.idxOf? name with
    | some index =>
      if within : index < names.size then return .parameter ⟨index, within⟩
      else throw "internal encoder error: transaction parameter exceeds its declared range"
    | none => throw s!"undeclared transaction parameter {name}"
  | _ => throw "expected a natural transaction value or an unknown reference"

def decodeParameterizedFrameInstruction (unknowns : Array String)
    (width : PNat) (names : Array String) (value : Json) :
    Except String (ParameterizedFrameInstruction width unknowns.size) := do
  if (<- (<- field value "kind").getStr?) = "clientRequest" then
    fields value ["kind", "node", "transaction"]
    return .clientRequest (<- resolve width names (<- field value "node"))
      (<- decodeNatArgument unknowns (<- field value "transaction"))
  else
    return .core (<- decodeFrameInstruction width names value)

def decodeParameterizedFrameDocument (document : Json) :
    Except String ParameterizedFrameDecoded := do
  let object <- document.getObj?
  let hasUnknowns := (object.toList.map Prod.fst).contains "unknowns"
  fields document (["nodes", "bootstrap", "instructions"] ++
    if hasUnknowns then ["unknowns"] else [])
  let unknowns <- if hasUnknowns then
    (<- (<- field document "unknowns").getArr?).mapM Json.getStr?
    else pure #[]
  unless unknowns.all (fun name => !name.isEmpty) do
    throw "transaction parameter names must be nonempty strings"
  if distinct : unknowns.toList.Nodup then
    let coreDocument := Json.mkObj [
      ("nodes", <- field document "nodes"),
      ("bootstrap", <- field document "bootstrap"),
      ("instructions", <- field document "instructions")]
    let frame <- decodeDocumentWith (decodeParameterizedFrameInstruction unknowns) coreDocument
    return { unknowns, unknownsDistinct := distinct, frame }
  else throw "transaction parameter names must be distinct"

def parameterizedFrameInstruction {width : PNat} {count : Nat} (base : Nat) :
    ParameterizedFrameInstruction width count -> EncodeM width Unit
  | .core instruction => frameInstruction instruction
  | .clientRequest source transaction => clientRequest source (transaction.term base)

def compileParameterizedFrameDecoded (input : ParameterizedFrameDecoded) :
    Except String Compiled := do
  let (_, initial) <- (initialFrameDomains input.frame.width).run
    (initialEncoding input.frame.width input.frame.bootstrap)
  let (_, started) <- (declareNatParameters input.unknowns.size).run initial
  let groups := #[{ instruction := none, start := 0, stop := started.assertions.size : Group }]
  let (groups, final) <- (compileInstructionsWith
    (parameterizedFrameInstruction initial.next) 0 groups
    input.frame.instructions.toList).run started
  return { assertions := final.assertions, groups }

def compileParameterizedFrame (document : Json) : Except String Compiled := do
  compileParameterizedFrameDecoded (<- decodeParameterizedFrameDocument document)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
