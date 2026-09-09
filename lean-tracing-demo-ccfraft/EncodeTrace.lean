-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.TraceEncodingProofs
import TraceCertificate
import Lean

set_option autoImplicit false

run_cmd do
  for name in ← Lean.collectAxioms ``CCFRaft.TraceEncoding.checkedEncoder do
    unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
      throwError "trace encoder correctness depends on unapproved axiom {name}"

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

def inspectArgument (input : Input) (raw : Option String) : Except String (Option Nat) := do
  match raw with
  | none => pure none
  | some raw =>
      let index <- match raw.toNat? with
        | some index => pure index
        | none => throw "inspect-group must be a natural number"
      if index = 0 then
        throw "inspect-group must select an action, not the unknown domains"
      match input.trace[index - 1]? with
      | some instruction =>
          if instruction.isAction then pure (some index)
          else throw "inspect-group must select an action"
      | none => throw "inspect-group must select an action"

end CCFRaft.EncodeTrace

def main (args : List String) : IO UInt32 := do
  let stderr <- IO.getStderr
  unless args.length = 2 || args.length = 3 do
    stderr.putStrLn "usage: EncodeTrace.lean CERTIFICATE OUTPUT_DIR [INSPECT_GROUP]"
    return 1
  let text <- IO.FS.readFile args[0]!
  let decoded := do
    let input <- Lean.Json.parse text >>= CCFRaft.TraceCertificate.decode
    let inspectGroup <- CCFRaft.EncodeTrace.inspectArgument input args[2]?
    pure (input, inspectGroup)
  match decoded with
  | .error error =>
      stderr.putStrLn s!"encoding error: {error}"
      return 1
  | .ok (input, inspectGroup) =>
      let encoder : CCFRaft.BoundedTrace.VerifiedEncoder input.unknowns.size :=
        CCFRaft.TraceEncoding.checkedEncoder input.unknowns.size
      let formula := encoder.encode input.bounds input.entry input.trace
      match formula.prepare with
      | .error error =>
          stderr.putStrLn s!"SMT serialization error: {error}"
          return 1
      | .ok prepared =>
          let output := System.FilePath.mk args[1]!
          IO.FS.createDirAll output
          IO.FS.writeFile (output / "formula.smt2") (prepared.toSmt inspectGroup)
          IO.FS.writeFile (output / "constraint-map.json")
            ((CCFRaft.EncodeTrace.constraintMap input prepared inspectGroup).pretty ++ "\n")
          return 0
