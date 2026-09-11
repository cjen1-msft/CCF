import Sparse.NativeSelectors

set_option autoImplicit false

namespace CCFRaft.Sparse.NativeNodeOperations

open Smt SmtScript NodeSetCodec

theorem decode_and (left right : BitVec NODE_COUNT) :
    decodeNodes (left &&& right) = Inter.inter (decodeNodes left) (decodeNodes right) := by
  ext node
  simp

theorem decode_not (value : BitVec NODE_COUNT) :
    decodeNodes (~~~value) = SDiff.sdiff (Finset.univ : Finset Node) (decodeNodes value) := by
  ext node
  simp

theorem decode_difference (left right : BitVec NODE_COUNT) :
    decodeNodes (left &&& ~~~right) = SDiff.sdiff (decodeNodes left) (decodeNodes right) := by
  ext node
  simp

theorem and_singleton_iff (value : BitVec NODE_COUNT) (node : Node) :
    value &&& encodeNodes {node} = encodeNodes {node} <->
      Membership.mem (decodeNodes value) node := by
  rw [<- bits_eq_iff, decode_and, decode_encode_nodes]
  constructor
  next =>
    intro same
    have present : Membership.mem (Inter.inter (decodeNodes value) {node}) node := by
      rw [same]
      simp
    exact (Finset.mem_inter.mp present).1
  next =>
    intro present
    ext other
    simp only [Finset.mem_inter, Finset.mem_singleton]
    constructor
    next => exact And.right
    next =>
      intro same
      subst other
      exact And.intro present rfl

def member (node : Node) (value : Term .nodes) : Term .bool :=
  .equal (.nodesAnd value (.nodes (encodeNodes {node}))) (.nodes (encodeNodes {node}))

theorem member_eval (assignment : Assignment) (node : Node) (value : Term .nodes) :
    (member node value).eval assignment =
      decide (Membership.mem (decodeNodes (value.eval assignment)) node) := by
  simp only [member, Term.eval, and_singleton_iff]

theorem member_text (assignment : Assignment) (node : Node) (value : Term .nodes) :
    SmtScriptText.runText assignment (render [member node value]) =
      some (decide (Membership.mem (decodeNodes (value.eval assignment)) node)) := by
  rw [SmtScriptText.runText_render, compile_eval]
  simp [member_eval]

theorem and_finset (assignment : Assignment) (left right : Term .nodes) :
    decodeNodes ((Term.nodesAnd left right).eval assignment) =
      Inter.inter (decodeNodes (left.eval assignment)) (decodeNodes (right.eval assignment)) :=
  decode_and _ _

theorem or_finset (assignment : Assignment) (left right : Term .nodes) :
    decodeNodes ((Term.nodesOr left right).eval assignment) =
      Union.union (decodeNodes (left.eval assignment)) (decodeNodes (right.eval assignment)) :=
  decode_or _ _

theorem not_finset (assignment : Assignment) (value : Term .nodes) :
    decodeNodes ((Term.nodesNot value).eval assignment) =
      SDiff.sdiff (Finset.univ : Finset Node) (decodeNodes (value.eval assignment)) :=
  decode_not _

theorem encode_inter (left right : Finset Node) :
    encodeNodes (Inter.inter left right) = encodeNodes left &&& encodeNodes right := by
  rw [<- bits_eq_iff, decode_and]
  simp

theorem encode_complement (value : Finset Node) :
    encodeNodes (SDiff.sdiff (Finset.univ : Finset Node) value) = ~~~(encodeNodes value) := by
  rw [<- bits_eq_iff, decode_not]
  simp

theorem encode_difference (left right : Finset Node) :
    encodeNodes (SDiff.sdiff left right) = encodeNodes left &&& ~~~(encodeNodes right) := by
  rw [<- bits_eq_iff, decode_difference]
  simp

theorem and_text (assignment : Assignment) (left right : Term .nodes) :
    SmtExpressionText.eval assignment (Term.nodesAnd left right).render =
      some (.nodes (encodeNodes
        (Inter.inter (decodeNodes (left.eval assignment)) (decodeNodes (right.eval assignment))))) := by
  rw [SmtExpressionText.typed_render_eval]
  simp only [Term.eval, embed, <- decode_and, encode_decode_bits]

theorem or_text (assignment : Assignment) (left right : Term .nodes) :
    SmtExpressionText.eval assignment (Term.nodesOr left right).render =
      some (.nodes (encodeNodes
        (Union.union (decodeNodes (left.eval assignment)) (decodeNodes (right.eval assignment))))) := by
  rw [SmtExpressionText.typed_render_eval]
  simp only [Term.eval, embed, <- decode_or, encode_decode_bits]

theorem not_text (assignment : Assignment) (value : Term .nodes) :
    SmtExpressionText.eval assignment (Term.nodesNot value).render =
      some (.nodes (encodeNodes
        (SDiff.sdiff (Finset.univ : Finset Node) (decodeNodes (value.eval assignment))))) := by
  rw [SmtExpressionText.typed_render_eval]
  simp only [Term.eval, embed, <- decode_not, encode_decode_bits]

theorem singleton_membership (assignment : Assignment) (node other : Node) :
    (member node (.nodes (encodeNodes {other}))).eval assignment = decide (node = other) := by
  simp [member_eval, Term.eval]

theorem boundary_bytes :
    (Term.nodes (encodeNodes {Fin.mk 0 (by decide)})).render = "#b000000000000001" /\
    (Term.nodes (encodeNodes {Fin.mk 14 (by decide)})).render = "#b100000000000000" := by
  simp only [Term.render, Term.lower, SExpr.render, Atom.render]
  decide +kernel

theorem boundary_membership (assignment : Assignment) (node : Node) :
    (member node (.nodes 0)).eval assignment = false /\
    (member node (.nodes 32767)).eval assignment = true := by
  simp only [member_eval, Term.eval]
  constructor
  next => simp
  next =>
    have full : (32767 : BitVec NODE_COUNT) = ~~~(0 : BitVec NODE_COUNT) := by decide +kernel
    simp [full]

def formula : Formula :=
  [.equal (.nodesAnd (.nodes 16385) (.nodes 16386)) (.nodes 16384),
   .equal (.nodesOr (.nodes 16385) (.nodes 16386)) (.nodes 16387),
   .equal (.nodesAnd (.nodes 16385) (.nodesNot (.nodes 16386))) (.nodes 1),
   .equal (.nodesNot (.nodes 16385)) (.nodes 16382)]

theorem formula_true (assignment : Assignment) :
    SmtScriptText.runText assignment (render formula) = some true := by
  have values : (16385 : BitVec NODE_COUNT) &&& 16386 = 16384 /\
      (16385 : BitVec NODE_COUNT) ||| 16386 = 16387 /\
      (16385 : BitVec NODE_COUNT) &&& ~~~16386 = 1 /\
      ~~~(16385 : BitVec NODE_COUNT) = 16382 := by decide +kernel
  rw [SmtScriptText.runText_render, compile_eval]
  simpa [formula, Term.eval] using values

theorem formula_roundtrip : SmtScriptText.parse (render formula) = some (compile formula) :=
  SmtScriptText.parse_render _

theorem operator_bytes :
    (Term.nodesAnd (.nodes 1) (.nodes 2)).render =
      "(bvand #b000000000000001 #b000000000000010)" /\
    (Term.nodesOr (.nodes 1) (.nodes 2)).render =
      "(bvor #b000000000000001 #b000000000000010)" /\
    (Term.nodesNot (.nodes 1)).render = "(bvnot #b000000000000001)" := by
  simp only [Term.render, Term.lower, call, SExpr.render, Atom.render, List.map_cons, List.map_nil]
  decide +kernel

theorem no_symbols_or_extra_schemas :
    symbols formula = [] /\ prelude formula = [.setNativeLogic] := And.intro rfl rfl

theorem member_symbols (node : Node) (value : Term .nodes) :
    termSymbols (member node value) = termSymbols value := by
  simp [member, termSymbols]

theorem operator_maxima (left right : Term .nodes) :
    SymbolBounds.termMax (.nodesAnd left right) =
      max (SymbolBounds.termMax left) (SymbolBounds.termMax right) /\
    SymbolBounds.termMax (.nodesOr left right) =
      max (SymbolBounds.termMax left) (SymbolBounds.termMax right) /\
    SymbolBounds.termMax (.nodesNot left) = SymbolBounds.termMax left :=
  And.intro rfl (And.intro rfl rfl)

theorem member_maximum (node : Node) (value : Term .nodes) :
    SymbolBounds.termMax (member node value) = SymbolBounds.termMax value := by
  simp [member, SymbolBounds.termMax]

theorem native_requirements (left right : Term .nodes) :
    termNativeTypes (.nodesAnd left right) =
      .nodes :: (termNativeTypes left ++ termNativeTypes right) /\
    termNativeTypes (.nodesOr left right) =
      .nodes :: (termNativeTypes left ++ termNativeTypes right) /\
    termNativeTypes (.nodesNot left) = .nodes :: termNativeTypes left :=
  And.intro rfl (And.intro rfl rfl)

def deadBranch : Term .bool :=
  .ite (.boolean false) (.equal (.nodesNot (.nodes 0)) (.nodes 0)) (.boolean true)

theorem dead_branch_prelude : prelude [deadBranch] = [.setNativeLogic] := rfl

theorem missing_logic_after_false (assignment : Assignment) :
    run assignment [.setLogic, .assertion (.atom (.boolean false)),
      .assertion deadBranch.lower, .checkSat] = none := by
  simp [run, schemaCheck, exprSymbols, exprNativeTypes, atomNativeTypes, operatorNativeTypes,
    available, deadBranch, Term.lower, call]

theorem raw_operator_requirements :
    exprNativeTypes (call (.operator .nodesAnd) []) = [.nodes] /\
    exprNativeTypes (call (.operator .nodesOr) []) = [.nodes] /\
    exprNativeTypes (call (.operator .nodesNot) []) = [.nodes] := by
  simp [exprNativeTypes, atomNativeTypes, operatorNativeTypes, call]

theorem raw_missing_logic :
    schemaCheck false [] [.assertion (call (.operator .nodesAnd) [])] = false /\
    schemaCheck false [] [.assertion (call (.operator .nodesOr) [])] = false /\
    schemaCheck false [] [.assertion (call (.operator .nodesNot) [])] = false := by
  simp [schemaCheck, exprSymbols, exprNativeTypes, atomNativeTypes, operatorNativeTypes,
    available, call]

theorem malformed_applications (assignment : Assignment) :
    (call (.operator .nodesAnd) []).eval assignment = none /\
    (call (.operator .nodesAnd) [.atom (.nodes 0)]).eval assignment = none /\
    (call (.operator .nodesOr) [.atom (.nodes 0), .atom (.nodes 0), .atom (.nodes 0)]).eval assignment = none /\
    (call (.operator .nodesNot) []).eval assignment = none /\
    (call (.operator .nodesNot) [.atom (.nodes 0), .atom (.nodes 0)]).eval assignment = none /\
    (call (.operator .nodesAnd) [.atom (.nodes 0), .atom (.numeral 0)]).eval assignment = none /\
    (call (.operator .nodesOr) [.atom (.boolean false), .atom (.nodes 0)]).eval assignment = none /\
    (call (.operator .nodesNot) [.atom (.numeral 0)]).eval assignment = none := by
  simp [call, SExpr.eval, applyHead]

theorem malformed_dead_branches (assignment : Assignment) :
    (call (.operator .ite) [.atom (.boolean false),
      call (.operator .nodesAnd) [.atom (.nodes 0)], .atom (.nodes 0)]).eval assignment = none /\
    (call (.operator .ite) [.atom (.boolean true), .atom (.nodes 0),
      call (.operator .nodesNot) [.atom (.boolean true)]]).eval assignment = none := by
  simp [call, SExpr.eval, applyHead]

theorem malformed_after_false (assignment : Assignment) :
    run assignment [.setNativeLogic, .assertion (.atom (.boolean false)),
      .assertion (call (.operator .equal) [call (.operator .nodesNot) [], .atom (.nodes 0)]),
      .checkSat] = none := by
  simp [run, runBody, schemaCheck, exprSymbols, exprNativeTypes, atomNativeTypes,
    operatorNativeTypes, available, call, SExpr.eval, applyHead]

theorem function_aliases (assignment : Assignment) (id : Nat) (left right : Term .int)
    (same : left.eval assignment = right.eval assignment) (node : Node) :
    (member node (.app .int .nodes id left)).eval assignment =
      (member node (.app .int .nodes id right)).eval assignment := by
  simp only [member, Term.eval, same]

theorem copied_selector_membership (assignment : Assignment) (node : Node) (base : Nat)
    (counts : Fin 2 -> Int -> Int) :
    (member node (.nodesNot (.configurationNodes .signature))).eval
        (QueueEncoding.installCounts assignment base counts) =
      (member node (.nodesNot (.configurationNodes .signature))).eval assignment /\
    (member node (.nodesNot (.retiredNodes .signature))).eval
        (IntervalQueryEncoding.setZero assignment base) =
      (member node (.nodesNot (.retiredNodes .signature))).eval assignment := by
  simp [member, Term.eval]

end CCFRaft.Sparse.NativeNodeOperations

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.NativeNodeOperations).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit node-operation axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"NativeNodeOperations: {checked} declarations passed the allowed-axiom gate."
