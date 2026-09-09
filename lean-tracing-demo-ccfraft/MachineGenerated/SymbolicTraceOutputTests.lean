-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import SymbolicTraceOutput

set_option autoImplicit false

namespace CCFRaft.SymbolicTraceOutput.Tests

open Lean Symbolic SymbolicModel

private def bounds : BoundedState.Bounds :=
  { transactionCount := 3, logCapacity := 4, termCount := 5,
    indexCount := 6, queueCapacity := 7 }
private def source : Node := ⟨2, by decide⟩
private def destination : Node := ⟨7, by decide⟩
private def send : Json := Json.mkObj
  [("kind", .str "action"), ("action", .str "appendEntries"),
   ("node", toJson source.val), ("destination", toJson destination.val),
   ("batchEnd", toJson (1 : Nat)),
   ("provenance", toJson [Json.mkObj [("line", toJson (99 : Nat))]]),
   ("rule", .str "raw-send")]
private def observation : Json := Json.mkObj
  [("kind", .str "observation"), ("variable", .str "logLength"),
   ("node", toJson destination.val), ("value", toJson (2 : Nat)),
   ("provenance", toJson [Json.mkObj [("line", toJson (100 : Nat))]])]
private def input : SymbolicTraceCertificate.Input :=
  { bounds, unknowns := #["x", "y"], entry := freshEntry bounds
    trace := [.action (.appendEntries source destination 1),
      .observation (.logLength destination 2)]
    rawSteps := #[send, observation] }

-- Synthetic expressions exercise output ownership, not Model transition validity.
private def initial : Expr .nat := .named 0 0 (.nat 0)
private def successor : Expr .nat := .named 1 0 (.add initial (.nat 1))
private def formula : List (Expr .bool) :=
  [BoundedSymbolicTrace.transactionDomains bounds input.unknowns.size,
   .and (.bool true) (.bool true),
   .and (.bool true) (.eq successor (.nat 2)),
   .bool true]

private def group (output : Output) (index : Nat) : Except String Json := do
  let groups ← output.constraintMap.getObjVal? "groups" >>= Json.getArr?
  match groups[index]? with
  | some value => pure value
  | none => throw s!"missing output group {index}"

private def labels (group : Json) : Except String (Array String) := do
  let clauses ← group.getObjVal? "clauses" >>= Json.getArr?
  clauses.mapM fun clause => clause.getObjVal? "label" >>= Json.getStr?

private def metadataCorrect : Except String Bool := do
  let output ← prepare input formula
  let root := output.constraintMap
  let domains ← group output 0
  let action ← group output 1
  let observed ← group output 2
  let final ← group output 3
  let expectedBounds := Json.mkObj
    [("transaction_count", toJson (3 : Nat)), ("log_capacity", toJson (4 : Nat)),
     ("term_count", toJson (5 : Nat)), ("index_count", toJson (6 : Nat)),
     ("queue_capacity", toJson (7 : Nat))]
  return (
    (← root.getObjVal? "schema_version") == .str "ccfraft-trace-constraints/v1" &&
    (← root.getObjVal? "certificate_schema") == .str "ccfraft-symbolic-trace/v1" &&
    (← root.getObjVal? "entry") == .str "symbolic" &&
    (← root.getObjVal? "bounds") == expectedBounds &&
    (← root.getObjVal? "unknowns") == toJson #["x", "y"] &&
    (← root.getObjVal? "theorem") == .str "CCFRaft.SymbolicTraceEncoding.encode_holds_correct" &&
    (← root.getObjVal? "inspect_group") == .null &&
    (← root.getObjVal? "supported_actions") == toJson supportedActions &&
    (← domains.getObjVal? "instruction") == .null &&
    (← domains.getObjVal? "instruction_index") == .null &&
    (← domains.getObjVal? "kind") == .str "bounds" &&
    (← labels domains) == #["transaction_domains", "entry_definition"] &&
    (← action.getObjVal? "instruction") == send &&
    (← action.getObjVal? "instruction_index") == toJson (1 : Nat) &&
    (← action.getObjVal? "label") == .str "appendEntries" &&
    (← action.getObjVal? "kind") == .str "action" &&
    (← labels action) == #["before_bounds", "enabled_and_successor_bounds", "successor_definition"] &&
    (← observed.getObjVal? "instruction") == observation &&
    (← observed.getObjVal? "instruction_index") == toJson (2 : Nat) &&
    (← observed.getObjVal? "kind") == .str "observation" &&
    (← labels observed) == #["before_bounds", "observation"] &&
    (← final.getObjVal? "instruction") == .null &&
    (← final.getObjVal? "instruction_index") == .null &&
    (← final.getObjVal? "kind") == .str "bounds" &&
    (← labels final) == #["final_bounds"])

private def mapAgreement (inspectGroup : Option Nat) : Except String Bool := do
  let output ← prepare input formula inspectGroup
  let groups ← output.constraintMap.getObjVal? "groups" >>= Json.getArr?
  let mut expected := []
  for metadata in groups do
    let index ← metadata.getObjVal? "index" >>= Json.getNat?
    let name ← metadata.getObjVal? "name" >>= Json.getStr?
    let clauses ← metadata.getObjVal? "clauses" >>= Json.getArr?
    if inspectGroup == some index then
      for clause in clauses do
        let name ← clause.getObjVal? "name" >>= Json.getStr?
        let expression ← clause.getObjVal? "expression" >>= Json.getStr?
        expected := expected ++ [s!"(assert (! {expression} :named {name}))"]
    else
      let expressions ← clauses.toList.mapM fun clause =>
        clause.getObjVal? "expression" >>= Json.getStr?
      let body := match expressions with
        | [] => "true"
        | [single] => single
        | _ => "(and " ++ String.intercalate " " expressions ++ ")"
      expected := expected ++ [s!"(assert (! {body} :named {name}))"]
  let actual := (output.smt.splitOn "\n").filter (·.startsWith "(assert (! ")
  return actual == expected &&
    (← output.constraintMap.getObjVal? "inspect_group") == toJson inspectGroup

#guard metadataCorrect.toOption == some true
#guard (mapAgreement none).toOption == some true
#guard (mapAgreement (some 1)).toOption == some true
#guard supportedActions.length == 17
#guard supportedActions.Nodup

private def actions : List SymbolicTraceCertificate.Action :=
  [.clientRequest source (.unknown 0), .signCommittableMessages source,
   .changeConfiguration source {source, destination}, .appendRetiredCommitted source,
   .appendEntries source destination 1, .receive source destination, .timeout source,
   .becomePreVoteCandidate source, .becomeCandidate source, .advanceCommitIndex source,
   .checkQuorum source, .updateTerm source destination, .becomeLeader source,
   .requestVote source destination, .requestPreVote source destination,
   .proposeVote source destination, .advanceCommitIndexAndProposeVote source destination]
#guard actions.map actionName == supportedActions

private def rejected (input : SymbolicTraceCertificate.Input) (formula : List (Expr .bool))
    (inspectGroup : Option Nat := none) : Bool :=
  match prepare input formula inspectGroup with
  | .error _ => true
  | .ok _ => false

#guard [0, 2, 3, 4, 100].all fun index => rejected input formula (some index)
#guard rejected input []
#guard rejected input (formula.take 3)
#guard rejected input (formula ++ [.bool true])
#guard rejected { input with rawSteps := #[send] } formula
#guard rejected { input with rawSteps := #[send, observation, observation] } formula
#guard rejected { input with rawSteps := #[observation, observation] } formula
#guard rejected { input with rawSteps := #[send, send] } formula
#guard rejected { input with rawSteps := #[.null, observation] } formula
#guard rejected { input with rawSteps := #[Json.mkObj
  [("kind", .str "action"), ("action", .str "timeout")], observation] } formula
#guard rejected input (formula.modify 1 (fun _ => .bool true))
#guard rejected input (formula.modify 2 (fun _ => .named 0 8 (.bool true)))
#guard rejected input (formula.modify 3 (fun _ => .named 2 1 (.bool true)))
#guard rejected input (formula.modify 3 (fun _ => .named 3 1 (.bool true)))
#guard rejected input (formula.modify 3 (fun _ => .named 9 1 (.bool true)))
#guard !(rejected { input with trace := [], rawSteps := #[] } [.bool true, .bool true])

private def checked {α : Type} (result : Except String α) : IO α :=
  match result with
  | .ok value => pure value
  | .error message => throw (IO.userError message)

private def expect (solver text expected : String) : IO String := do
  let result ← IO.Process.output { cmd := solver, args := #["--lang=smt2"] } (some text)
  unless result.exitCode == 0 do
    throw (IO.userError s!"solver failed: {result.stderr}\n{result.stdout}")
  unless (result.stdout.splitOn "\n").head? == some expected do
    throw (IO.userError s!"expected {expected}, got: {result.stdout}")
  return result.stdout

def run (solver : String) : IO Unit := do
  for selected in [none, some 1] do
    let output ← checked (prepare input formula selected)
    let core ← expect solver (output.smt ++ "(get-unsat-core)\n") "unsat"
    let owner := if selected.isSome then "group_1_clause_2" else "group_1"
    let tokens := (core.replace "(" " " |>.replace ")" " " |>.replace "\n" " ").splitOn " "
    unless tokens.contains "group_0" && tokens.contains owner && tokens.contains "group_2" do
      throw (IO.userError s!"output core lost a causal owner: {core}")
    let withoutOwner := String.intercalate "\n" <|
      (output.smt.splitOn "\n").filter fun line =>
        !((line.splitOn s!":named {owner})").length > 1)
    discard <| expect solver withoutOwner "sat"
  IO.println "symbolic output metadata, coarse/fine clauses, and owner retention passed"

end CCFRaft.SymbolicTraceOutput.Tests

run_cmd do
  for axiomName in ← Lean.collectAxioms ``CCFRaft.SymbolicTraceOutput.splitInstruction_correct do
    unless axiomName == ``propext || axiomName == ``Classical.choice ||
        axiomName == ``Quot.sound do
      throwError "symbolic output clause splitting depends on unapproved axiom {axiomName}"

def main (args : List String) : IO Unit :=
  match args with
  | [solver] => CCFRaft.SymbolicTraceOutput.Tests.run solver
  | _ => throw (IO.userError "usage: SymbolicTraceOutputTests.lean /path/to/cvc5")
