-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeReferences
import Sparse.NativeScriptText

set_option autoImplicit false

namespace CCFRaft.NativeSmt

open NativeSExpr (Expr)

def unwrapAssertion (index : Nat) : Expr -> Option Expr
  | .list [.atom "!", expression, .atom ":named", .atom name] =>
    if name = assertionName index then some expression else none
  | expression => some expression

theorem Term.unwrap_syntax {context : List Ty} {sort : Ty} (expression : Term context sort) (index : Nat) :
    unwrapAssertion index expression.syntax = some expression.syntax := by
  cases expression <;> try simp [Term.syntax, unwrapAssertion]
  case integer value => cases value <;> simp [Term.syntax, unwrapAssertion]
  case defaultValue => cases sort <;> simp [Ty.defaultSyntax]

theorem unwrap_emitted (named : Bool) (index : Nat) (expression : Term [] .bool) :
    unwrapAssertion index
      (if named then .list [.atom "!", expression.syntax, .atom ":named", .atom (assertionName index)]
       else expression.syntax) = some expression.syntax := by
  cases named
  · exact expression.unwrap_syntax index
  · simp [unwrapAssertion]

theorem assertionName_injective {first second : Nat}
    (same : assertionName first = assertionName second) : first = second := by
  have characters := congrArg String.toList same
  simp only [assertionName, String.toList_append] at characters
  have digits : (toString first).toList = (toString second).toList := List.append_cancel_left characters
  apply binderName_injective
  have binders : (binderName first).toList = (binderName second).toList := by
    simp only [binderName, String.toList_append]
    rw [digits]
  simpa using congrArg String.ofList binders

theorem indexed_assertion_names_unique (count : Nat) :
    ((List.range count).map assertionName).Nodup :=
  List.Nodup.map (fun _ _ => assertionName_injective) (List.nodup_range)

attribute [local instance] Classical.propDecidable

noncomputable def runAssertions (assignment : Assignment) (declared : List (Ty × Nat)) (index : Nat) :
    List Expr -> Option Bool
  | [.list [.atom "check-sat"]] => some true
  | .list [.atom "assert", body] :: rest => do
    let expression <- unwrapAssertion index body
    if _covered : forall symbol, symbol ∈ syntaxSymbols expression -> symbol ∈ declared then
      let value <- evalSyntax assignment (fun _ => none) expression
      let value <- value.asType .bool
      let suffix <- runAssertions assignment declared (index + 1) rest
      return value && suffix
    else none
  | _ => none

noncomputable def runDeclarations (assignment : Assignment) (declared : List (Ty × Nat)) :
    List Expr -> Option Bool
  | .list [.atom "declare-const", .atom name, sort] :: rest => do
    let symbol <- parseDeclaration (.list [.atom "declare-const", .atom name, sort])
    if symbol ∈ declared then none else runDeclarations assignment (symbol :: declared) rest
  | commands => runAssertions assignment declared 0 commands

noncomputable def runScriptSyntax (assignment : Assignment) (commands : List Expr) : Option Bool :=
  if commands.take 4 = preludeSyntax then runDeclarations assignment [] (commands.drop 4) else none

noncomputable def runScriptText (assignment : Assignment) (text : String) : Option Bool :=
  (NativeSExpr.parseLines text).bind (runScriptSyntax assignment)

theorem run_script_text (assignment : Assignment) (assertions : List (Term [] .bool)) (named : Bool) :
    runScriptText assignment (renderScript assertions named) =
      runScriptSyntax assignment (scriptSyntax assertions named) := by
  rw [runScriptText, script_text_parses, Option.bind_some]

theorem declaration_step (assignment : Assignment) (declared : List (Ty × Nat)) (symbol : Ty × Nat)
    (commands : List Expr) (fresh : symbol ∉ declared) :
    runDeclarations assignment declared (declarationSyntax symbol :: commands) =
      runDeclarations assignment (symbol :: declared) commands := by
  rcases symbol with ⟨sort, id⟩
  rw [declarationSyntax, runDeclarations]
  have parsed := parse_declaration (sort, id)
  simp only [declarationSyntax] at parsed
  simp [parsed, fresh]

theorem declarations_run (assignment : Assignment) (declared symbols : List (Ty × Nat))
    (commands : List Expr) (unique : symbols.Nodup)
    (fresh : forall symbol, symbol ∈ symbols -> symbol ∉ declared) :
    runDeclarations assignment declared (symbols.map declarationSyntax ++ commands) =
      runDeclarations assignment (symbols.reverse ++ declared) commands := by
  induction symbols generalizing declared with
  | nil => simp
  | cons symbol rest ih =>
    rw [List.nodup_cons] at unique
    simp only [List.map_cons, List.cons_append]
    rw [declaration_step assignment declared symbol _ (fresh symbol (by simp))]
    have remaining : forall item, item ∈ rest -> item ∉ symbol :: declared := by
      intro item present
      have old := fresh item (by simp [present])
      have different : item ≠ symbol := by
        intro same
        subst item
        exact unique.1 present
      simp [old, different]
    rw [ih (symbol :: declared) unique.2 remaining]
    simp [List.reverse_cons, List.append_assoc]

theorem assertion_step (assignment : Assignment) (declared : List (Ty × Nat)) (named : Bool) (index : Nat)
    (expression : Term [] .bool) (commands : List Expr)
    (covered : forall symbol, symbol ∈ syntaxSymbols expression.syntax -> symbol ∈ declared) :
    runAssertions assignment declared index (assertionSyntax named index expression :: commands) =
      (runAssertions assignment declared (index + 1) commands).map
        (fun suffix => expression.eval assignment Locals.empty && suffix) := by
  have evaluated := expression.syntax_eval assignment (fun _ => none) Locals.empty (NamedLocals.empty _)
  rw [assertionSyntax, runAssertions]
  simp only [unwrap_emitted, Bind.bind, Option.bind, evaluated, Value.asType_mk]
  rw [dif_pos covered]
  cases runAssertions assignment declared (index + 1) commands <;> rfl

theorem assertions_run (assignment : Assignment) (declared : List (Ty × Nat)) (named : Bool) (index : Nat)
    (assertions : List (Term [] .bool))
    (covered : forall expression, expression ∈ assertions ->
      forall symbol, symbol ∈ syntaxSymbols expression.syntax -> symbol ∈ declared) :
    runAssertions assignment declared index
      (assertions.mapIdx (fun offset expression => assertionSyntax named (index + offset) expression) ++
        [.list [.atom "check-sat"]]) =
      some (decide (Holds assertions assignment)) := by
  induction assertions generalizing index with
  | nil => simp [runAssertions, Holds]
  | cons expression rest ih =>
    simp only [List.mapIdx_cons, List.cons_append, Nat.add_zero]
    rw [assertion_step assignment declared named index expression _ (covered expression (by simp))]
    have shifted : (fun offset item => assertionSyntax named (index + (offset + 1)) item) =
        (fun offset item => assertionSyntax named (index + 1 + offset) item) := by
      funext offset item
      congr 1
      omega
    rw [shifted, ih (index + 1) (fun item member => covered item (by simp [member]))]
    simp [Holds]
    apply Bool.eq_iff_iff.mpr
    simp

theorem assertions_phase (assignment : Assignment) (declared : List (Ty × Nat)) (named : Bool)
    (assertions : List (Term [] .bool)) :
    runDeclarations assignment declared
      (assertions.mapIdx (assertionSyntax named) ++ [.list [.atom "check-sat"]]) =
      runAssertions assignment declared 0
        (assertions.mapIdx (assertionSyntax named) ++ [.list [.atom "check-sat"]]) := by
  cases assertions <;> simp [List.mapIdx_cons, assertionSyntax, runDeclarations]

theorem run_prelude (assignment : Assignment) (commands : List Expr) :
    runScriptSyntax assignment (preludeSyntax ++ commands) = runDeclarations assignment [] commands := by
  simp [runScriptSyntax, preludeSyntax]

theorem script_syntax_eval (assignment : Assignment) (assertions : List (Term [] .bool)) (named : Bool) :
    runScriptSyntax assignment (scriptSyntax assertions named) =
      some (decide (Holds assertions assignment)) := by
  rw [scriptSyntax, List.append_assoc, List.append_assoc, run_prelude]
  rw [declarations_run assignment [] _ _ (List.nodup_dedup _) (by simp)]
  simp only [List.append_nil]
  rw [assertions_phase]
  have covered (expression : Term [] .bool) (member : expression ∈ assertions)
      (symbol : Ty × Nat) (occurs : symbol ∈ syntaxSymbols expression.syntax) :
      symbol ∈ (assertions.flatMap Term.symbols).dedup.reverse := by
    simpa using declared_syntax_symbols assertions expression member symbol occurs
  simpa only [Nat.zero_add] using assertions_run assignment _ named 0 assertions covered

theorem script_text_holds (assignment : Assignment) (assertions : List (Term [] .bool)) (named : Bool) :
    runScriptText assignment (renderScript assertions named) = some true <-> Holds assertions assignment := by
  rw [run_script_text, script_syntax_eval]
  simp

example (assignment : Assignment) :
    runDeclarations assignment [(.bool, 0)] [declarationSyntax (.bool, 0), .list [.atom "check-sat"]] = none := by
  simp [runDeclarations, declarationSyntax, parseDeclaration, parse_symbol_name, parse_sort_syntax]

example (assignment : Assignment) :
    runAssertions assignment [] 0 [.list [.atom "assert", .atom "0"], .list [.atom "check-sat"]] = none := by
  have references : syntaxSymbols (.atom "0") = [] := by rw [syntaxSymbols]; rfl
  have number : evalSyntax assignment (fun _ => none) (.atom "0") = some ⟨.int, 0⟩ := by
    rw [evalSyntax]
    rfl
  rw [runAssertions]
  simp [unwrapAssertion, references, number, Value.asType]

example (assignment : Assignment) :
    runAssertions assignment [] 0 [.list [.atom "check-sat"], .list [.atom "check-sat"]] = none := rfl

example (assignment : Assignment) :
    runAssertions assignment [] 0
      [.list [.atom "assert", .atom (symbolName .bool 0)], .list [.atom "check-sat"]] = none := by
  simp [runAssertions, unwrapAssertion, syntaxSymbols, free_symbols]

example (assignment : Assignment) :
    runAssertions assignment [] 0
      [.list [.atom "assert", .list [.atom "!", .atom "true", .atom ":named", .atom "assertion_1"]],
        .list [.atom "check-sat"]] = none := by
  have wrong : "assertion_1" ≠ assertionName 0 := by decide +kernel
  simp [runAssertions, unwrapAssertion, wrong]

example (assignment : Assignment) :
    runAssertions assignment [] 0
      [assertionSyntax false 0 (.boolean false), declarationSyntax (.bool, 0),
        .list [.atom "check-sat"]] = none := by
  rw [assertion_step assignment [] false 0 (.boolean false) _ (by
    rw [(Term.boolean (context := []) false).syntax_symbols]
    simp [Term.symbols])]
  rfl

end CCFRaft.NativeSmt

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeSmt).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
