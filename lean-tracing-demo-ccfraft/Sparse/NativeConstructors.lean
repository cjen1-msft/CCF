import Sparse.NativeSorts

set_option autoImplicit false

namespace CCFRaft.Sparse.NativeConstructors

open Smt SmtScript

theorem nodes_roundtrip (value : BitVec NODE_COUNT) :
    SmtExpressionText.parseAtom (Term.nodes value).render = some (.nodes value) := by
  simpa only [Term.render, Term.lower, SExpr.render] using
    SmtExpressionText.parseAtom_render (.nodes value)

theorem mask_bytes :
    (Term.nodes 0).render = "#b000000000000000" /\
    (Term.nodes 32767).render = "#b111111111111111" /\
    (Term.nodes 16384).render = "#b100000000000000" /\
    (Term.nodes 1).render = "#b000000000000001" := by
  simp only [Term.render, Term.lower, SExpr.render, Atom.render]
  decide +kernel

theorem invalid_masks :
    ["#b", "#b0", "#b00000000000000", "#b0000000000000000", "#b000000000000002",
      "#B000000000000000", "#x0000", "#b000000000000000junk"].all
      (fun text => (SmtExpressionText.parseAtom text).isNone) = true := by
  decide +kernel

theorem content_values (assignment : Assignment) (tx : Int) (mask : BitVec NODE_COUNT) :
    (Term.transaction (.integer tx)).lower.eval assignment = some (.content (.transaction tx)) /\
    Term.signature.lower.eval assignment = some (.content .signature) /\
    (Term.reconfiguration (.nodes mask)).lower.eval assignment =
      some (.content (.reconfiguration mask)) /\
    (Term.retiredCommitted (.nodes mask)).lower.eval assignment =
      some (.content (.retiredCommitted mask)) := by
  simp [lower_correct, Term.eval, embed]

theorem entry_value (assignment : Assignment) (term : Term .int) (content : Term .content) :
    (Term.entry term content).lower.eval assignment =
      some (.entry { term := term.eval assignment, content := content.eval assignment }) := by
  simp [lower_correct, Term.eval, embed]

theorem entry_projections (assignment : Assignment) (term : Term .int) (content : Term .content) :
    (Term.entryTerm (.entry term content)).lower.eval assignment =
      some (.integer (term.eval assignment)) /\
    (Term.entryContent (.entry term content)).lower.eval assignment =
      some (.content (content.eval assignment)) := by
  simp [lower_correct, Term.eval, embed]

theorem entry_reconstruction (assignment : Assignment) (value : Term .entry) :
    (Term.equal (.entry (.entryTerm value) (.entryContent value)) value).eval assignment = true := by
  simp [Term.eval]

theorem content_identity (assignment : Assignment) (left right : Term .int)
    (a b : Term .nodes) :
    (Term.equal (.transaction left) (.transaction right)).eval assignment =
      decide (left.eval assignment = right.eval assignment) /\
    (Term.equal (.reconfiguration a) (.reconfiguration b)).eval assignment =
      decide (a.eval assignment = b.eval assignment) /\
    (Term.equal (.retiredCommitted a) (.retiredCommitted b)).eval assignment =
      decide (a.eval assignment = b.eval assignment) /\
    (Term.equal (.reconfiguration a) (.retiredCommitted b)).eval assignment = false := by
  simp [Term.eval]

theorem negative_fields (assignment : Assignment) :
    (Term.entry (.integer (-2)) (.transaction (.integer (-5)))).lower.eval assignment =
      some (.entry { term := -2, content := .transaction (-5) }) := by
  simp [lower_correct, Term.eval, embed]

theorem aliases_and_ite (assignment : Assignment) (condition : Bool) :
    (Term.equal
      (.entry (.add (.integer (-3)) (.integer 1)) (.transaction (.integer (-5))))
      (.ite (.boolean condition)
        (.entry (.integer (-2)) (.transaction (.integer (-5))))
        (.entry (.integer (-2)) (.transaction (.integer (-5)))))).lower.eval assignment =
      some (.boolean true) := by
  simp [lower_correct, Term.eval, embed]

def literalFormula : Formula :=
  [.equal (.entryTerm (.entry (.integer (-2)) (.transaction (.integer (-5))))) (.integer (-2)),
   .equal (.entryContent (.entry (.integer 0) .signature)) .signature,
   .not (.equal (.reconfiguration (.nodes 32767)) (.retiredCommitted (.nodes 32767))),
   .equal (.nodes 16384) (.nodes 16384)]

theorem no_user_symbols : symbols literalFormula = [] := rfl

theorem literal_prelude :
    prelude literalFormula = [.setNativeLogic, .declareSchema .content, .declareSchema .entry] := rfl

theorem literal_script_roundtrip :
    SmtScriptText.parse (render literalFormula) = some (compile literalFormula) :=
  SmtScriptText.parse_render literalFormula

theorem literal_script_true (assignment : Assignment) :
    SmtScriptText.runText assignment (render literalFormula) = some true := by
  rw [SmtScriptText.runText_render, compile_eval]
  simp [literalFormula, Term.eval]

theorem constructor_text :
    (Term.transaction (.integer 3)).render = "(ccf_tx 3)" /\
    Term.signature.render = "ccf_sig" /\
    (Term.reconfiguration (.nodes 0)).render = "(ccf_cfg #b000000000000000)" /\
    (Term.retiredCommitted (.nodes 16384)).render = "(ccf_retired #b100000000000000)" /\
    (Term.entry (.integer 1) .signature).render = "(ccf_entry 1 ccf_sig)" /\
    (Term.entryTerm (.entry (.integer 1) .signature)).render = "(ccf_term (ccf_entry 1 ccf_sig))" /\
    (Term.entryContent (.entry (.integer 1) .signature)).render = "(ccf_content (ccf_entry 1 ccf_sig))" := by
  simp only [Term.render, Term.lower, signedLiteral, call, SExpr.render, Atom.render,
    List.map_cons, List.map_nil]
  decide +kernel

theorem negative_text :
    (Term.entry (.integer (Int.negSucc 1)) (.transaction (.integer (Int.negSucc 4)))).render =
      "(ccf_entry (- 2) (ccf_tx (- 5)))" := by
  simp only [Term.render, Term.lower, signedLiteral, call, SExpr.render, Atom.render,
    List.map_cons, List.map_nil]
  decide +kernel

theorem minimal_literal_preludes :
    prelude [.equal (.nodes 0) (.nodes 0)] = [.setNativeLogic] /\
    prelude [.equal .signature .signature] = [.setNativeLogic, .declareSchema .content] /\
    prelude [.equal (.transaction (.integer 0)) .signature] =
      [.setNativeLogic, .declareSchema .content] := by
  exact And.intro rfl (And.intro rfl rfl)

def deadLiteralBranch : Term .bool :=
  .ite (.boolean false)
    (.equal (.entryTerm (.entry (.integer 0) .signature)) (.integer 0))
    (.boolean true)

theorem dead_literal_prelude :
    prelude [deadLiteralBranch] =
      [.setNativeLogic, .declareSchema .content, .declareSchema .entry] := rfl

theorem missing_native_schema_after_false (assignment : Assignment) :
    run assignment [.setLogic, .assertion (.atom (.boolean false)),
      .assertion (Term.equal (.nodes 0) (.nodes 0)).lower, .checkSat] = none /\
    run assignment [.setNativeLogic, .assertion (.atom (.boolean false)),
      .assertion (Term.equal .signature .signature).lower, .checkSat] = none /\
    run assignment [.setNativeLogic, .declareSchema .content,
      .assertion (.atom (.boolean false)), .assertion deadLiteralBranch.lower, .checkSat] = none := by
  simp [run, schemaCheck, exprSymbols, exprNativeTypes, atomNativeTypes, operatorNativeTypes,
    available, Schema.dependencies, deadLiteralBranch, Term.lower, signedLiteral, call]

theorem invalid_native_applications (assignment : Assignment) :
    (call (.operator .transaction) [.atom .signature]).eval assignment = none /\
    (call (.operator .entry) [.atom (.numeral 1)]).eval assignment = none /\
    (call (.operator .entryTerm) [.atom .signature]).eval assignment = none /\
    (call (.operator .entryContent) [.atom (.nodes 0)]).eval assignment = none /\
    (call (.operator .ite) [.atom (.boolean true), .atom .signature,
      call (.operator .entryContent) [.atom .signature]]).eval assignment = none := by
  simp [call, SExpr.eval, applyHead]

theorem unstructured_testers_absent :
    ["is-ccf_tx", "is-ccf_cfg", "is-ccf_retired", "is-ccf_sig"].all
      (fun text => (SmtExpressionText.parseAtom text).isNone) = true := by
  decide +kernel

theorem native_children_symbol_bound :
    SymbolBounds.formulaMax
      [.equal (.entryTerm (.entry (.unknown .int 99)
        (.reconfiguration (.app .nodes .nodes 7 (.unknown .nodes 2))))) (.integer 0)] = 99 := rfl

theorem scalar_empty_unchanged :
    render [] = "(set-logic QF_UFLIA)\n(check-sat)\n" := by
  decide +kernel

end CCFRaft.Sparse.NativeConstructors

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.NativeConstructors).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit native constructor axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"NativeConstructors: {checked} declarations passed the allowed-axiom gate."
