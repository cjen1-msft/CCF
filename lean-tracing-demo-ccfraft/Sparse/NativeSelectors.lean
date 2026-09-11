import Sparse.NativeConstructors
import Sparse.QueueEncoding
import Sparse.IntervalQueryEncoding

set_option autoImplicit false

namespace CCFRaft.Sparse.NativeSelectors

open Smt SmtScript EntryValue EntrySelectorSemantics

def txOr (value : Term .content) (fallback : Term .int) : Term .int :=
  .ite (.isContent .transaction value) (.transactionId value) fallback

def cfgOr (value : Term .content) (fallback : Term .nodes) : Term .nodes :=
  .ite (.isContent .reconfiguration value) (.configurationNodes value) fallback

def retiredOr (value : Term .content) (fallback : Term .nodes) : Term .nodes :=
  .ite (.isContent .retiredCommitted value) (.retiredNodes value) fallback

theorem txOr_lower (assignment : Assignment) (value : Term .content) (fallback : Term .int) :
    (txOr value fallback).lower.eval assignment =
      some (.integer ((value.eval assignment).transaction?.getD (fallback.eval assignment))) := by
  rw [lower_correct]
  simp only [txOr, Term.eval, ContentTag.test, guarded_tx_eq_getD, embed]

theorem cfgOr_lower (assignment : Assignment) (value : Term .content) (fallback : Term .nodes) :
    (cfgOr value fallback).lower.eval assignment =
      some (.nodes ((value.eval assignment).reconfiguration?.getD (fallback.eval assignment))) := by
  rw [lower_correct]
  simp only [cfgOr, Term.eval, ContentTag.test, guarded_cfg_eq_getD, embed]

theorem retiredOr_lower (assignment : Assignment) (value : Term .content) (fallback : Term .nodes) :
    (retiredOr value fallback).lower.eval assignment =
      some (.nodes ((value.eval assignment).retiredCommitted?.getD (fallback.eval assignment))) := by
  rw [lower_correct]
  simp only [retiredOr, Term.eval, ContentTag.test, guarded_retired_eq_getD, embed]

theorem txOr_independent (left right : Assignment) (value : Term .content) (fallback : Term .int)
    (sameValue : value.eval left = value.eval right)
    (sameFallback : fallback.eval left = fallback.eval right) :
    (txOr value fallback).lower.eval left = (txOr value fallback).lower.eval right := by
  rw [txOr_lower, txOr_lower, sameValue, sameFallback]

theorem cfgOr_independent (left right : Assignment) (value : Term .content) (fallback : Term .nodes)
    (sameValue : value.eval left = value.eval right)
    (sameFallback : fallback.eval left = fallback.eval right) :
    (cfgOr value fallback).lower.eval left = (cfgOr value fallback).lower.eval right := by
  rw [cfgOr_lower, cfgOr_lower, sameValue, sameFallback]

theorem retiredOr_independent (left right : Assignment) (value : Term .content) (fallback : Term .nodes)
    (sameValue : value.eval left = value.eval right)
    (sameFallback : fallback.eval left = fallback.eval right) :
    (retiredOr value fallback).lower.eval left = (retiredOr value fallback).lower.eval right := by
  rw [retiredOr_lower, retiredOr_lower, sameValue, sameFallback]

theorem raw_interpretations_complete (original : Assignment)
    (tx : Content -> Int) (cfg retired : Content -> BitVec NODE_COUNT)
    (tx_matching : forall value, tx (.transaction value) = value)
    (cfg_matching : forall mask, cfg (.reconfiguration mask) = mask)
    (retired_matching : forall mask, retired (.retiredCommitted mask) = mask) :
    exists assignment : Assignment,
      assignment.constant = original.constant /\ assignment.unary = original.unary /\
      rawTx assignment.selectors = tx /\ rawCfg assignment.selectors = cfg /\
      rawRetired assignment.selectors = retired := by
  cases raw_selectors_complete tx cfg retired tx_matching cfg_matching retired_matching with
  | intro interpretation laws =>
    exact Exists.intro { original with selectors := interpretation } (And.intro rfl (And.intro rfl laws))

theorem selector_coherence (assignment : Assignment) (left right : Term .content)
    (same : left.eval assignment = right.eval assignment) :
    (Term.transactionId left).lower.eval assignment = (Term.transactionId right).lower.eval assignment /\
    (Term.configurationNodes left).lower.eval assignment = (Term.configurationNodes right).lower.eval assignment /\
    (Term.retiredNodes left).lower.eval assignment = (Term.retiredNodes right).lower.eval assignment := by
  simp [lower_correct, Term.eval, same]

theorem matching_payloads (assignment : Assignment) (tx : Int) (mask : BitVec NODE_COUNT) :
    (Term.transactionId (.transaction (.integer tx))).lower.eval assignment = some (.integer tx) /\
    (Term.configurationNodes (.reconfiguration (.nodes mask))).lower.eval assignment = some (.nodes mask) /\
    (Term.retiredNodes (.retiredCommitted (.nodes mask))).lower.eval assignment = some (.nodes mask) := by
  simp [lower_correct, Term.eval, embed]

theorem wrong_payloads (assignment : Assignment) (mask : BitVec NODE_COUNT) :
    (Term.transactionId .signature).lower.eval assignment = some (.integer (assignment.selectors.txWrong .signature)) /\
    (Term.configurationNodes (.retiredCommitted (.nodes mask))).lower.eval assignment =
      some (.nodes (assignment.selectors.cfgWrong (.retiredCommitted mask))) /\
    (Term.retiredNodes (.reconfiguration (.nodes mask))).lower.eval assignment =
      some (.nodes (assignment.selectors.retiredWrong (.reconfiguration mask))) := by
  simp [lower_correct, Term.eval, rawTx, rawCfg, rawRetired, embed]

theorem tester_tags (assignment : Assignment) (tx : Int) (mask : BitVec NODE_COUNT) :
    (Term.isContent .transaction (.transaction (.integer tx))).eval assignment = true /\
    (Term.isContent .signature .signature).eval assignment = true /\
    (Term.isContent .reconfiguration (.reconfiguration (.nodes mask))).eval assignment = true /\
    (Term.isContent .retiredCommitted (.retiredCommitted (.nodes mask))).eval assignment = true /\
    (Term.isContent .reconfiguration (.retiredCommitted (.nodes mask))).eval assignment = false /\
    (Term.isContent .retiredCommitted (.reconfiguration (.nodes mask))).eval assignment = false := by
  simp [Term.eval, ContentTag.test, Content.isTransaction, Content.isSignature,
    Content.isReconfiguration, Content.isRetiredCommitted, Content.transaction?,
    Content.reconfiguration?, Content.retiredCommitted?]

theorem structured_tester_text :
    (Term.isContent .transaction .signature).render = "((_ is ccf_tx) ccf_sig)" /\
    (Term.isContent .signature .signature).render = "((_ is ccf_sig) ccf_sig)" /\
    (Term.isContent .reconfiguration .signature).render = "((_ is ccf_cfg) ccf_sig)" /\
    (Term.isContent .retiredCommitted .signature).render = "((_ is ccf_retired) ccf_sig)" := by
  simp only [Term.render, Term.lower, tester, ContentTag.atom, SExpr.render, Atom.render,
    List.map_cons, List.map_nil]
  decide +kernel

theorem selector_text :
    (Term.transactionId .signature).render = "(ccf_tx_id ccf_sig)" /\
    (Term.configurationNodes .signature).render = "(ccf_cfg_nodes ccf_sig)" /\
    (Term.retiredNodes .signature).render = "(ccf_retired_nodes ccf_sig)" := by
  simp only [Term.render, Term.lower, call, SExpr.render, Atom.render, List.map_cons, List.map_nil]
  decide +kernel

theorem tester_roundtrip (tag : ContentTag) (value : Term .content) :
    SmtExpressionText.parse (Term.isContent tag value).render =
      some (Term.isContent tag value).lower :=
  SmtExpressionText.parse_render _

theorem tester_eval (assignment : Assignment) (tag : ContentTag) (value : Term .content) :
    SmtExpressionText.eval assignment (Term.isContent tag value).render =
      some (.boolean (tag.test (value.eval assignment))) := by
  simp only [SmtExpressionText.eval, tester_roundtrip, Option.bind_some, lower_correct, Term.eval, embed]

private def zeros : WrongSelectors :=
  { txWrong := fun _ => 0, cfgWrong := fun _ => 0, retiredWrong := fun _ => 0 }

private def ones : WrongSelectors :=
  { txWrong := fun _ => 1, cfgWrong := fun _ => 1, retiredWrong := fun _ => 1 }

theorem unguarded_disagreement (original : Assignment) :
    Not ((Term.transactionId .signature).lower.eval { original with selectors := zeros } =
      (Term.transactionId .signature).lower.eval { original with selectors := ones }) /\
    Not ((Term.configurationNodes .signature).lower.eval { original with selectors := zeros } =
      (Term.configurationNodes .signature).lower.eval { original with selectors := ones }) /\
    Not ((Term.retiredNodes .signature).lower.eval { original with selectors := zeros } =
      (Term.retiredNodes .signature).lower.eval { original with selectors := ones }) := by
  simp [lower_correct, Term.eval, rawTx, rawCfg, rawRetired, zeros, ones, embed]
  decide +kernel

theorem guarded_unknown_independent (original : Assignment) (left right : WrongSelectors) (id : Nat) :
    (txOr (.unknown .content id) (.integer (-7))).lower.eval { original with selectors := left } =
      (txOr (.unknown .content id) (.integer (-7))).lower.eval { original with selectors := right } /\
    (cfgOr (.unknown .content id) (.nodes 32767)).lower.eval { original with selectors := left } =
      (cfgOr (.unknown .content id) (.nodes 32767)).lower.eval { original with selectors := right } /\
    (retiredOr (.unknown .content id) (.nodes 16384)).lower.eval { original with selectors := left } =
      (retiredOr (.unknown .content id) (.nodes 16384)).lower.eval { original with selectors := right } := by
  exact And.intro (txOr_independent _ _ _ _ rfl rfl)
    (And.intro (cfgOr_independent _ _ _ _ rfl rfl) (retiredOr_independent _ _ _ _ rfl rfl))

theorem mismatched_operand_disagreement (original : Assignment) :
    Not ((Term.ite (.isContent .transaction (.transaction (.integer 4)))
        (.transactionId .signature) (.integer 9)).lower.eval { original with selectors := zeros } =
      (Term.ite (.isContent .transaction (.transaction (.integer 4)))
        (.transactionId .signature) (.integer 9)).lower.eval { original with selectors := ones }) := by
  simp [lower_correct, Term.eval, ContentTag.test, Content.isTransaction, Content.transaction?,
    rawTx, zeros, ones, embed]

def formula : Formula :=
  [.isContent .signature .signature,
   .equal (txOr .signature (.integer (-7))) (.integer (-7)),
   .equal (cfgOr (.reconfiguration (.nodes 32767)) (.nodes 0)) (.nodes 32767),
   .equal (retiredOr (.retiredCommitted (.nodes 16384)) (.nodes 0)) (.nodes 16384),
   .not (.isContent .transaction .signature)]

theorem formula_prelude :
    prelude formula = [.setNativeLogic, .declareSchema .content] := rfl

theorem formula_symbols : symbols formula = [] := rfl

theorem formula_roundtrip : SmtScriptText.parse (render formula) = some (compile formula) :=
  SmtScriptText.parse_render _

theorem formula_true (assignment : Assignment) :
    SmtScriptText.runText assignment (render formula) = some true := by
  rw [SmtScriptText.runText_render, compile_eval]
  simp [formula, txOr, cfgOr, retiredOr, Term.eval, ContentTag.test,
    Content.isTransaction, Content.isSignature, Content.isReconfiguration,
    Content.isRetiredCommitted, Content.transaction?, Content.reconfiguration?, Content.retiredCommitted?]

theorem operation_requirements (tag : ContentTag) (value : Term .content) :
    termNativeTypes (.isContent tag value) = .content :: termNativeTypes value /\
    termNativeTypes (.transactionId value) = .content :: termNativeTypes value /\
    termNativeTypes (.configurationNodes value) = .content :: termNativeTypes value /\
    termNativeTypes (.retiredNodes value) = .content :: termNativeTypes value := by
  exact And.intro rfl (And.intro rfl (And.intro rfl rfl))

def deadBranch : Term .bool :=
  .ite (.boolean false) (.equal (.transactionId .signature) (.integer 0)) (.boolean true)

theorem dead_branch_prelude :
    prelude [deadBranch] = [.setNativeLogic, .declareSchema .content] := rfl

theorem missing_schema_after_false (assignment : Assignment) :
    run assignment [.setNativeLogic, .assertion (.atom (.boolean false)),
      .assertion (Term.isContent .signature .signature).lower, .checkSat] = none /\
    run assignment [.setNativeLogic, .assertion (.atom (.boolean false)),
      .assertion deadBranch.lower, .checkSat] = none := by
  simp [run, schemaCheck, exprSymbols, exprNativeTypes, atomNativeTypes, operatorNativeTypes,
    available, deadBranch, Term.lower, signedLiteral, call, tester, ContentTag.atom]

theorem malformed_applications (assignment : Assignment) :
    (tester .transaction (.atom (.numeral 1))).eval assignment = none /\
    (call (.operator .transactionId) [.atom (.numeral 1)]).eval assignment = none /\
    (call (.operator .configurationNodes) []).eval assignment = none /\
    (call (.operator .retiredNodes) [.atom .signature, .atom .signature]).eval assignment = none /\
    (SExpr.list [.list [.atom .indexMarker, .atom .isKeyword, .atom (.operator .entry)],
      .atom .signature]).eval assignment = none /\
    (SExpr.list [.list [.atom .isKeyword, .atom .indexMarker, .atom .signature],
      .atom .signature]).eval assignment = none /\
    (SExpr.list [.list [.atom .indexMarker, .atom .isKeyword, .atom .signature]]).eval assignment = none := by
  simp [tester, call, SExpr.eval, applyHead, applyTester, ContentTag.atom, ContentTag.parseAtom]

theorem malformed_dead_branch (assignment : Assignment) :
    (call (.operator .ite) [.atom (.boolean false),
      call (.operator .transactionId) [.atom (.numeral 1)], .atom (.numeral 9)]).eval assignment = none /\
    (call (.operator .ite) [.atom (.boolean true), .atom (.boolean true),
      tester .signature (.atom (.numeral 1))]).eval assignment = none := by
  simp [call, tester, SExpr.eval, applyHead, applyTester, ContentTag.atom]

theorem no_compound_atoms :
    ["(_ is ccf_tx)", "(_ is ccf_sig)", "(_ is ccf_cfg)", "(_ is ccf_retired)"].all
      (fun text => (SmtExpressionText.parseAtom text).isNone) = true := by
  decide +kernel

theorem selector_symbol_bound :
    SymbolBounds.formulaMax
      [.isContent .transaction (.unknown .content 99),
       .equal (.transactionId (.unknown .content 98)) (.integer 0),
       .equal (.configurationNodes (.unknown .content 97)) (.retiredNodes (.unknown .content 96))] = 99 := rfl

theorem explicit_interpretation_preserved (original : Assignment) (interpretation : WrongSelectors) :
    (QueueEncoding.installCounts { original with selectors := interpretation } 10
      (fun _ : Fin 2 => fun _ => 3)).selectors = interpretation /\
    (IntervalQueryEncoding.setZero { original with selectors := interpretation } 10).selectors =
      interpretation := by
  simp

end CCFRaft.Sparse.NativeSelectors

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.NativeSelectors).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit native selector axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"NativeSelectors: {checked} declarations passed the allowed-axiom gate."
