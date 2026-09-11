import Sparse.SmtScriptText
import Sparse.SymbolBounds

set_option autoImplicit false

namespace CCFRaft.Sparse.NativeSorts

open Smt SmtScript

def allTypes : List Ty := [.bool, .int, .nodes, .content, .entry]

def signatures : Formula :=
  allTypes.map (fun ty => Term.equal (.unknown ty 0) (.unknown ty 0)) ++
    allTypes.flatMap (fun domain => allTypes.map (fun result =>
      Term.equal (.app domain result 0 (.unknown domain 0))
        (.app domain result 0 (.unknown domain 0))))

theorem all_signatures_count : (declarations signatures).length = 30 := by
  decide +kernel

theorem all_signatures_roundtrip :
    SmtScriptText.parse (render signatures) = some (compile signatures) :=
  SmtScriptText.parse_render signatures

theorem all_signatures_eval (assignment : Assignment) :
    SmtScriptText.runText assignment (render signatures) = some true := by
  rw [SmtScriptText.runText_render, compile_eval]
  simp [signatures, allTypes, Term.eval]

theorem all_sort_names (ty : Ty) (id : Nat) :
    SmtText.parseSymbol (Symbol.constant ty id).name = some (.constant ty id) :=
  SmtText.parseSymbol_name _

theorem all_function_names (domain result : Ty) (id : Nat) :
    SmtText.parseSymbol (Symbol.unary domain result id).name =
      some (.unary domain result id) := SmtText.parseSymbol_name _

theorem native_name_bytes :
    (Symbol.constant .nodes 5).name = "cv__101" /\
    (Symbol.constant .content 5).name = "cd__101" /\
    (Symbol.constant .entry 5).name = "ce__101" /\
    (Symbol.unary .int .entry 5).name = "fie_101" := by
  decide +kernel

def reservedNames : List String :=
  ["CCFContent", "CCFEntry", "ccf_tx", "ccf_tx_id", "ccf_sig", "ccf_cfg",
   "ccf_cfg_nodes", "ccf_retired", "ccf_retired_nodes", "ccf_entry", "ccf_term", "ccf_content"]

theorem reserved_names_not_symbols (name : String)
    (reserved : Membership.mem reservedNames name) (symbol : Symbol) :
    Not (symbol.name = name) := by
  have rejected : reservedNames.all (fun text => (SmtText.parseSymbol text).isNone) = true := by
    decide +kernel
  have missing := List.all_eq_true.mp rejected name reserved
  intro same
  rw [<- same, SmtText.parseSymbol_name] at missing
  cases missing

def reflexive (ty : Ty) : Formula :=
  [.equal (.unknown ty 0) (.unknown ty 0)]

theorem minimal_preludes :
    prelude (reflexive .int) = [.setLogic] /\
    prelude (reflexive .nodes) = [.setNativeLogic] /\
    prelude (reflexive .content) = [.setNativeLogic, .declareSchema .content] /\
    prelude (reflexive .entry) =
      [.setNativeLogic, .declareSchema .content, .declareSchema .entry] := by
  exact And.intro rfl (And.intro rfl (And.intro rfl rfl))

theorem nodes_script_bytes :
    render (reflexive .nodes) =
      "(set-logic ALL)\n(declare-fun cv__ () (_ BitVec 15))\n(assert (= cv__ cv__))\n(check-sat)\n" := by
  simp [render, renderCommands, compile, prelude, requiredTypes, compiledBody,
    reflexive, declarations, symbols, termSymbols, symbolTypes, symbolDomain, symbolResult,
    List.flatMap_cons, List.flatMap_nil, List.map_cons, List.map_nil, List.nil_append,
    List.cons_append, List.dedup_nil, List.mem_cons, List.not_mem_nil,
    or_false, Command.render, Declaration.render, Declaration.ofSymbol, Term.lower,
    call, SExpr.render, Atom.render, Ty.render]
  decide +kernel

theorem native_alias (assignment : Assignment) (ty : Ty) :
    (Term.equal (.unknown ty 0) (.unknown ty 0)).lower.eval assignment =
      some (.boolean true) := by
  simp [lower_correct, Term.eval, embed]

theorem native_ite (assignment : Assignment) (ty : Ty) (condition : Bool)
    (left right : Term ty) :
    (Term.ite (.boolean condition) left right).lower.eval assignment =
      some (embed ty (if condition then left.eval assignment else right.eval assignment)) := by
  rw [lower_correct]
  rfl

theorem native_unselected_sort_error (assignment : Assignment) :
    (call (.operator .ite)
      [.atom (.boolean false), .atom (.symbol (.constant .entry 0)),
        .atom (.numeral 0)]).eval assignment = none := by
  simp [call, SExpr.eval, applyHead, embed]

theorem missing_schemas (assignment : Assignment) :
    run assignment [.setNativeLogic, .declare (Declaration.ofSymbol (.constant .content 0)),
      .checkSat] = none /\
    run assignment [.setNativeLogic, .declareSchema .content,
      .declare (Declaration.ofSymbol (.constant .entry 0)), .checkSat] = none /\
    run assignment [.setLogic, .declare (Declaration.ofSymbol (.constant .nodes 0)),
      .checkSat] = none := by
  simp [run, schemaCheck, available, Declaration.ofSymbol, symbolDomain, symbolResult,
    Schema.dependencies]

theorem malformed_schema_order (assignment : Assignment) :
    run assignment [.setNativeLogic, .declareSchema .entry, .declareSchema .content,
      .checkSat] = none /\
    run assignment [.setNativeLogic, .declareSchema .content, .declareSchema .content,
      .checkSat] = none /\
    run assignment [.setNativeLogic, .declareSchema .content, .declareSchema .entry,
      .declareSchema .entry, .checkSat] = none /\
    run assignment [.setLogic, .declareSchema .content, .checkSat] = none := by
  simp [run, schemaCheck, Schema.dependencies]

theorem schema_use_before_declaration (assignment : Assignment) :
    run assignment [.setNativeLogic,
      .declare (Declaration.ofSymbol (.constant .entry 0)),
      .declareSchema .content, .declareSchema .entry, .checkSat] = none := by
  simp [run, schemaCheck, available, Declaration.ofSymbol, symbolDomain, symbolResult]

theorem false_assertion_checks_schemas (assignment : Assignment) :
    run assignment [.setNativeLogic, .assertion (.atom (.boolean false)),
      .declareSchema .entry, .checkSat] = none /\
    run assignment [.setNativeLogic, .declareSchema .content,
      .assertion (.atom (.boolean false)), .declareSchema .content, .checkSat] = none := by
  simp [run, schemaCheck, Schema.dependencies, exprSymbols]

theorem false_assertion_checks_native_duplicates (assignment : Assignment) :
    run assignment [.setNativeLogic,
      .declare (Declaration.ofSymbol (.constant .nodes 0)),
      .assertion (.atom (.boolean false)),
      .declare (Declaration.ofSymbol (.constant .nodes 0)), .checkSat] = none := by
  simp [run, schemaCheck, available, Declaration.ofSymbol, symbolDomain, symbolResult,
    exprSymbols, runBody, Covered, Declaration.Valid, SExpr.eval, Value.asType]

theorem native_missing_user_declaration (assignment : Assignment) :
    run assignment [.setNativeLogic, .declareSchema .content, .declareSchema .entry,
      .assertion (Term.equal (.unknown .entry 0) (.unknown .entry 0)).lower,
      .checkSat] = none := by
  simp [run, schemaCheck, Schema.dependencies, available, exprSymbols, symbolTypes,
    symbolDomain, symbolResult, Term.lower, call, runBody, Covered]

def deadNativeBranch : Formula :=
  [.ite (.boolean false)
    (.equal (.unknown .entry 0) (.unknown .entry 0)) (.boolean true)]

theorem dead_branch_needs_schemas :
    prelude deadNativeBranch = [.setNativeLogic, .declareSchema .content, .declareSchema .entry] := rfl

theorem native_wrong_written_signature (assignment : Assignment) :
    SmtScriptText.runText assignment
      "(set-logic ALL)\n(declare-fun cv__ () Int)\n(check-sat)\n" = none := by
  rfl

theorem canonical_signature_rejections :
    (SmtScriptText.parse
      "(set-logic ALL)\n(declare-fun cv__ () (_ BitVec 16))\n(check-sat)\n").isNone = true /\
    (SmtScriptText.parse
      "(set-logic ALL)\n(declare-fun fvv_ ((_ BitVec 15) (_ BitVec 15)) (_ BitVec 15))\n(check-sat)\n").isNone = true /\
    (SmtScriptText.parse
      "(set-logic ALL)\n(declare-fun ce__ () CCFEntryExtra)\n(check-sat)\n").isNone = true := by
  decide +kernel

theorem malformed_schema_text :
    (SmtScriptText.parseLine
      "(declare-datatype CCFEntry ((ccf_entry (ccf_term Bool) (ccf_content CCFContent))))".toList).isNone = true /\
    (SmtScriptText.parseLine
      "(declare-datatype CCFContent ((ccf_tx (ccf_tx_id Int)) (ccf_sig) (ccf_cfg (ccf_cfg_nodes (_ BitVec 16))) (ccf_retired (ccf_retired_nodes (_ BitVec 15)))))".toList).isNone = true := by
  decide +kernel

theorem native_symbol_bound :
    SymbolBounds.formulaMax
      [.equal (.unknown .entry 99) (.app .nodes .entry 7 (.unknown .nodes 2))] = 99 := rfl

end CCFRaft.Sparse.NativeSorts

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.NativeSorts).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit native-sort axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"NativeSorts: {checked} declarations passed the allowed-axiom gate."
