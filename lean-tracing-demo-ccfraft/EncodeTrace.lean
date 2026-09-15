-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.TraceEncodingProofs
import MachineGenerated.SymbolicTransitionCompleteness
import TraceCertificate
import SymbolicTraceOutput
import Lean

set_option autoImplicit false

run_cmd do
  for encoder in [``CCFRaft.TraceEncoding.checkedEncoder,
      ``CCFRaft.SymbolicTransition.checkedEncoder,
      ``CCFRaft.SymbolicTransition.checkedEncoder_satisfiable_iff] do
    for name in ← Lean.collectAxioms encoder do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "{encoder} depends on unapproved axiom {name}"

namespace CCFRaft.EncodeTrace

open Lean TraceInstructions TraceCertificate

def boundsJson (bounds : BoundedState.Bounds) : Json :=
  Json.mkObj
    [("transaction_count", toJson bounds.transactionCount),
     ("log_capacity", toJson bounds.logCapacity),
     ("term_count", toJson bounds.termCount),
     ("index_count", toJson bounds.indexCount),
     ("queue_capacity", toJson bounds.queueCapacity)]

def constraintMap (input : Input)
    (formula : TraceSmt.Prepared)
    (inspectGroup : Option Nat) : Json :=
  let groups : List Json := formula.groups.zipIdx.map fun (group, index) =>
    let source := input.rawSteps[index - 1]?
    let isInstruction := index > 0 && index <= input.trace.length
    let clauses : List Json := group.clauses.zipIdx.map fun
        ((clause, clauseIndex) : TraceSmt.PrintedClause × Nat) =>
      Json.mkObj
        [("name", toJson (TraceSmt.clauseName index clauseIndex)),
         ("label", toJson clause.label),
         ("expression", toJson clause.expression)]
    Json.mkObj
      [("index", toJson index),
       ("name", toJson (TraceSmt.groupName index)),
       ("label", toJson group.label),
       ("instruction_index", if isInstruction then toJson index else Json.null),
       ("instruction", if isInstruction then source.getD Json.null else Json.null),
       ("kind", toJson (if !isInstruction then "bounds"
          else if (input.trace[index - 1]?).any TraceInstructions.Instruction.isAction
            then "action" else "observation")),
       ("clauses", toJson clauses)]
  Json.mkObj
    [("schema_version", toJson "ccfraft-trace-constraints/v1"),
     ("certificate_schema", toJson input.schemaVersion),
     ("supported_actions", toJson input.acceptedActions),
     ("entry", toJson input.entryProfile),
     ("bounds", boundsJson input.bounds),
     ("unknowns", toJson input.unknowns),
     ("theorem", toJson "CCFRaft.TraceEncoding.encode_correct"),
     ("inspect_group", toJson inspectGroup),
     ("groups", toJson groups)]

def inspectIndex (raw : Option String) : Except String (Option Nat) := do
  raw.mapM fun value =>
    match value.toNat? with
    | some index => pure index
    | none => throw "inspect-group must be a natural number"

def inspectArgument (input : Input) (raw : Option String) : Except String (Option Nat) := do
  match ← inspectIndex raw with
  | none => pure none
  | some index =>
      if index = 0 then
        throw "inspect-group must select an action, not the unknown domains"
      match input.trace[index - 1]? with
      | some instruction =>
          if instruction.isAction then pure (some index)
          else throw "inspect-group must select an action"
      | none => throw "inspect-group must select an action"

inductive PreparationError where
  | input : String → PreparationError
  | serialization : String → PreparationError

def prepare (json : Json) (rawInspect : Option String) :
    Except PreparationError (String × Json) := do
  let schema ← (TraceJson.field json "schema_version" >>= Json.getStr?).mapError .input
  if schema == "ccfraft-symbolic-trace/v1" then
    let input ← (SymbolicTraceCertificate.decode json).mapError .input
    let inspectGroup ← (inspectIndex rawInspect).mapError .input
    (SymbolicTraceOutput.inspect input inspectGroup).mapError .input
    unless SymbolicTransition.traceInputsAtOrAfter
        (SymbolicModel.entryWidth input.bounds) input.trace do
      throw (.input "transaction inputs must follow the structural entry inputs")
    let encoder : {encode // BoundedSymbolicTrace.VerifiedEncoder encode} :=
      SymbolicTransition.checkedEncoder
    let formula := encoder.val input.bounds input.unknowns.size input.entry input.trace
    let prepared ← (SymbolicTraceOutput.prepare input formula inspectGroup).mapError
      .serialization
    return (prepared.smt, prepared.constraintMap)
  else
    let input ← (TraceCertificate.decode json).mapError .input
    let inspectGroup ← (inspectArgument input rawInspect).mapError .input
    let encoder : BoundedTrace.VerifiedEncoder input.unknowns.size :=
      TraceEncoding.checkedEncoder input.unknowns.size
    let formula := encoder.encode input.bounds input.entry input.trace
    let prepared ← formula.prepare.mapError .serialization
    return (prepared.toSmt inspectGroup, constraintMap input prepared inspectGroup)

end CCFRaft.EncodeTrace

def main (args : List String) : IO UInt32 := do
  let stderr <- IO.getStderr
  unless args.length = 2 || args.length = 3 do
    stderr.putStrLn "usage: encode_trace CERTIFICATE OUTPUT_DIR [INSPECT_GROUP]"
    return 1
  let text <- IO.FS.readFile args[0]!
  let decoded := do
    let json ← (Lean.Json.parse text).mapError CCFRaft.EncodeTrace.PreparationError.input
    CCFRaft.EncodeTrace.prepare json args[2]?
  match decoded with
  | .error error =>
      match error with
      | .input message => stderr.putStrLn s!"encoding error: {message}"
      | .serialization message => stderr.putStrLn s!"SMT serialization error: {message}"
      return 1
  | .ok (smt, metadata) =>
      let output := System.FilePath.mk args[1]!
      IO.FS.createDirAll output
      IO.FS.writeFile (output / "formula.smt2") smt
      IO.FS.writeFile (output / "constraint-map.json") (metadata.pretty ++ "\n")
      return 0
