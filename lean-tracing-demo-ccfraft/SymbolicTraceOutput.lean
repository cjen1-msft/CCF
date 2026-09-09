-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import SymbolicTraceCertificate
import Shared.SymbolicSmt

set_option autoImplicit false

namespace CCFRaft.SymbolicTraceOutput

open Lean Symbolic SymbolicTraceCertificate

/-- Serialization only. The caller must supply the audited encoder's formula. -/
structure Output where
  smt : String
  constraintMap : Json

def supportedActions : List String :=
  ["clientRequest", "signCommittableMessages", "changeConfiguration",
   "appendRetiredCommitted", "appendEntries", "receive", "timeout",
   "becomePreVoteCandidate", "becomeCandidate", "advanceCommitIndex",
   "checkQuorum", "updateTerm", "becomeLeader", "requestVote",
   "requestPreVote", "proposeVote", "advanceCommitIndexAndProposeVote"]

def actionName : SymbolicTraceCertificate.Action -> String
  | .clientRequest .. => "clientRequest"
  | .signCommittableMessages .. => "signCommittableMessages"
  | .changeConfiguration .. => "changeConfiguration"
  | .appendRetiredCommitted .. => "appendRetiredCommitted"
  | .appendEntries .. => "appendEntries"
  | .receive .. => "receive"
  | .timeout .. => "timeout"
  | .becomePreVoteCandidate .. => "becomePreVoteCandidate"
  | .becomeCandidate .. => "becomeCandidate"
  | .advanceCommitIndex .. => "advanceCommitIndex"
  | .checkQuorum .. => "checkQuorum"
  | .updateTerm .. => "updateTerm"
  | .becomeLeader .. => "becomeLeader"
  | .requestVote .. => "requestVote"
  | .requestPreVote .. => "requestPreVote"
  | .proposeVote .. => "proposeVote"
  | .advanceCommitIndexAndProposeVote .. => "advanceCommitIndexAndProposeVote"

def splitInstruction : Expr .bool -> Except String (List (Expr .bool))
  | .and before condition => .ok [before, condition]
  | _ => .error "instruction formula must be a conjunction of bounds and condition"

theorem splitInstruction_correct (assignment : Assignment) (formula : Expr .bool)
    (clauses : List (Expr .bool)) (split : splitInstruction formula = .ok clauses) :
    Trace.Holds assignment clauses ↔ formula.eval assignment = true := by
  cases formula <;> simp_all [splitInstruction, Trace.Holds, Expr.eval]
  subst clauses
  simp

private structure Group where
  label : String
  kind : String
  instructionIndex : Option Nat
  instruction : Json
  clauses : List (String × Expr .bool)

private def inspect (input : Input) (index : Option Nat) : Except String Unit := do
  if let some index := index then
    if index = 0 then
      throw "inspect-group must select an action, not the unknown domains"
    match input.trace[index - 1]? with
    | some (.action _) => pure ()
    | _ => throw "inspect-group must select an action"

private def groups (input : Input) (formula : List (Expr .bool)) :
    Except String (List Group) := do
  unless formula.length == input.trace.length + 2 do
    throw "formula must contain domains, one group per instruction, and final bounds"
  unless input.rawSteps.size == input.trace.length do
    throw "raw step count does not match the decoded trace"
  formula.zipIdx.mapM fun (expression, index) => do
    if index = 0 then
      return ⟨"unknown transaction domains", "bounds", none, .null,
        [("transaction_domains", expression)]⟩
    if index = input.trace.length + 1 then
      return ⟨"final state bounds", "bounds", none, .null, [("final_bounds", expression)]⟩
    let some instruction := input.trace[index - 1]?
      | throw s!"missing instruction for group {index}"
    let some source := input.rawSteps[index - 1]?
      | throw s!"missing raw step for group {index}"
    let kind ← TraceJson.field source "kind" >>= Json.getStr?
    let (label, conditionLabel) ← match instruction with
      | .action action => do
          unless kind == "action" do
            throw s!"raw step kind does not match action group {index}"
          let name ← TraceJson.field source "action" >>= Json.getStr?
          unless name == actionName action do
            throw s!"raw action does not match decoded action at group {index}"
          pure (name, "enabled_and_successor_bounds")
      | .observation _ => do
          unless kind == "observation" do
            throw s!"raw step kind does not match observation group {index}"
          pure ("observation", "observation")
    let clauses ← splitInstruction expression
    return ⟨label, kind, some index, source, ["before_bounds", conditionLabel].zip clauses⟩

private def boundsJson (bounds : BoundedState.Bounds) : Json :=
  Json.mkObj
    [("transaction_count", toJson bounds.transactionCount),
     ("log_capacity", toJson bounds.logCapacity),
     ("term_count", toJson bounds.termCount),
     ("index_count", toJson bounds.indexCount),
     ("queue_capacity", toJson bounds.queueCapacity)]

def prepare (input : Input) (formula : List (Expr .bool))
    (inspectGroup : Option Nat := none) : Except String Output := do
  inspect input inspectGroup
  let sourceGroups ← groups input formula
  let (expressions, printing) ← prepareGroups
    (sourceGroups.map fun group => group.clauses.map Prod.snd)
  let mut metadata : List Json := []
  let mut assertions : List String := []
  for (group, index) in sourceGroups.zipIdx do
    let some expressions := expressions[index]?
      | throw s!"missing prepared group {index}"
    let clauses ← expressions.zipIdx.mapM fun (expression, clauseIndex) => do
      let label ← match group.clauses[clauseIndex]? with
        | some (label, _) => pure label
        | none =>
            if index = 0 then pure "entry_definition"
            else if group.kind == "action" then pure "successor_definition"
            else throw s!"state definition owned by non-action group {index}"
      pure (label, expression)
    let clauseMetadata := clauses.zipIdx.map fun ((label, expression), clauseIndex) =>
      Json.mkObj
        [("name", toJson (TraceSmt.clauseName index clauseIndex)),
         ("label", toJson label), ("expression", toJson expression)]
    metadata := metadata ++ [Json.mkObj
      [("index", toJson index), ("name", toJson (TraceSmt.groupName index)),
       ("label", toJson group.label), ("kind", toJson group.kind),
       ("instruction_index", toJson group.instructionIndex),
       ("instruction", group.instruction), ("clauses", toJson clauseMetadata)]]
    let namedAssertions :=
      if inspectGroup == some index then
        clauses.zipIdx.map fun ((_, expression), clauseIndex) =>
          TraceSmt.assertion (TraceSmt.clauseName index clauseIndex) expression
      else
        [TraceSmt.assertion (TraceSmt.groupName index)
          (TraceSmt.conjunction (clauses.map Prod.snd))]
    assertions := assertions ++ namedAssertions
  let smt := String.intercalate "\n" <|
    ["(set-option :produce-unsat-cores true)"] ++ printing.preamble ++
      assertions ++ ["(check-sat)", ""]
  let constraintMap := Json.mkObj
    [("schema_version", toJson "ccfraft-trace-constraints/v1"),
     ("certificate_schema", toJson "ccfraft-symbolic-trace/v1"),
     ("supported_actions", toJson supportedActions), ("entry", toJson "symbolic"),
     ("bounds", boundsJson input.bounds), ("unknowns", toJson input.unknowns),
     ("theorem", toJson "CCFRaft.SymbolicTraceEncoding.encode_holds_correct"),
     ("inspect_group", toJson inspectGroup), ("groups", toJson metadata)]
  return { smt, constraintMap }

end CCFRaft.SymbolicTraceOutput
