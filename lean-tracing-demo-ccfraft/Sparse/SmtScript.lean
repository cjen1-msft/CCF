import Sparse.SymbolCollection

-- Command-AST semantics only, not an SMT-LIB text-parser or solver theorem.
set_option autoImplicit false

namespace CCFRaft.Sparse.SmtScript

open Smt

local notation:50 x:51 " IN " xs:51 => Membership.mem xs x

abbrev Formula := List (Term .bool)

def Holds (assignment : Assignment) (formula : Formula) : Prop :=
  forall term, term IN formula -> term.eval assignment = true

def termSymbols : {ty : Ty} -> Term ty -> List Symbol
  | _, .boolean _ | _, .integer _ | _, .nodes _ | _, .signature => []
  | _, .unknown ty id => [.constant ty id]
  | _, .app domain result id argument => .unary domain result id :: termSymbols argument
  | _, .add left right | _, .sub left right | _, .le left right
  | _, .equal left right | _, .and left right | _, .implies left right
  | _, .entry left right =>
    termSymbols left ++ termSymbols right
  | _, .not value | _, .transaction value | _, .reconfiguration value
  | _, .retiredCommitted value | _, .entryTerm value | _, .entryContent value => termSymbols value
  | _, .ite condition yes no => termSymbols condition ++ termSymbols yes ++ termSymbols no

def exprSymbols : SExpr -> List Symbol
  | .atom (.symbol sym) => [sym]
  | .atom _ => []
  | .list values => values.flatMap exprSymbols

theorem signedLiteral_symbols (value : Int) : exprSymbols (signedLiteral value) = [] := by
  cases value <;> simp [signedLiteral, call, exprSymbols]

theorem lower_symbols {ty : Ty} (term : Term ty) :
    exprSymbols term.lower = termSymbols term := by
  induction term <;>
    simp_all [Term.lower, termSymbols, exprSymbols, call, signedLiteral_symbols, List.append_assoc]

def symbols (formula : Formula) : List Symbol :=
  (formula.flatMap termSymbols).dedup

def collectedSymbols (formula : Formula) : List Symbol :=
  SymbolCollection.dedup (formula.flatMap termSymbols)

@[csimp] theorem symbols_eq_collected : symbols = collectedSymbols := by
  funext formula
  exact (SymbolCollection.dedup_eq (formula.flatMap termSymbols)).symm

theorem symbol_coverage (formula : Formula) (sym : Symbol) :
    sym IN symbols formula <->
      exists term, term IN formula /\ sym IN exprSymbols term.lower := by
  simp [symbols, lower_symbols]

theorem symbols_nodup (formula : Formula) : (symbols formula).Nodup :=
  List.nodup_dedup _

theorem symbol_names_nodup (formula : Formula) :
    ((symbols formula).map Symbol.name).Nodup :=
  (symbols_nodup formula).map symbol_name_injective

def symbolDomain : Symbol -> List Ty
  | .constant _ _ => []
  | .unary domain _ _ => [domain]

def symbolResult : Symbol -> Ty
  | .constant ty _ => ty
  | .unary _ result _ => result

structure Declaration where
  symbol : Symbol
  arguments : List Ty
  result : Ty
  deriving DecidableEq, Repr

def Declaration.ofSymbol (sym : Symbol) : Declaration :=
  { symbol := sym, arguments := symbolDomain sym, result := symbolResult sym }

@[simp]
theorem ofSymbol_symbol (sym : Symbol) : (Declaration.ofSymbol sym).symbol = sym := rfl

def Declaration.Valid (declaration : Declaration) : Prop :=
  declaration.arguments = symbolDomain declaration.symbol /\
    declaration.result = symbolResult declaration.symbol

instance (declaration : Declaration) : Decidable declaration.Valid := by
  unfold Declaration.Valid
  infer_instance

@[simp]
theorem ofSymbol_valid (sym : Symbol) : (Declaration.ofSymbol sym).Valid :=
  And.intro rfl rfl

def declarations (formula : Formula) : List Declaration :=
  (symbols formula).map Declaration.ofSymbol

def DeclarationsWellFormed (decls : List Declaration) : Prop :=
  (forall declaration, declaration IN decls -> declaration.Valid) /\
    (decls.map (fun declaration => declaration.symbol.name)).Nodup

theorem declarations_wellFormed (formula : Formula) :
    DeclarationsWellFormed (declarations formula) := by
  constructor
  next => simp [declarations]
  next => simpa [declarations, Declaration.ofSymbol, Function.comp_def] using symbol_names_nodup formula

theorem declaration_coverage (formula : Formula) (sym : Symbol) :
    Declaration.ofSymbol sym IN declarations formula <->
      exists term, term IN formula /\ sym IN exprSymbols term.lower := by
  rw [<- symbol_coverage]
  simp only [declarations, List.mem_map]
  constructor
  next =>
    intro h
    cases h with
    | intro s hs =>
      have same : s = sym := congrArg Declaration.symbol hs.2
      simpa [same] using hs.1
  next =>
    intro h
    exact Exists.intro sym (And.intro h rfl)

inductive Schema where
  | content
  | entry
  deriving DecidableEq, Repr

def Schema.body : Schema -> String
  | .content =>
    "CCFContent ((ccf_tx (ccf_tx_id Int)) (ccf_sig) (ccf_cfg (ccf_cfg_nodes (_ BitVec 15))) (ccf_retired (ccf_retired_nodes (_ BitVec 15)))))"
  | .entry =>
    "CCFEntry ((ccf_entry (ccf_term Int) (ccf_content CCFContent))))"

def Schema.render (schema : Schema) : String := "(declare-datatype " ++ schema.body

def Schema.dependencies : Schema -> List Schema
  | .content => []
  | .entry => [.content]

inductive Command where
  | setLogic
  | setNativeLogic
  | declareSchema (schema : Schema)
  | declare (declaration : Declaration)
  | assertion (expression : SExpr)
  | checkSat
  deriving Repr

def Covered (declared : List Symbol) (expression : SExpr) : Prop :=
  forall sym, sym IN exprSymbols expression -> sym IN declared

instance (declared : List Symbol) (expression : SExpr) : Decidable (Covered declared expression) := by
  unfold Covered
  infer_instance

def symbolTypes (symbol : Symbol) : List Ty :=
  symbolDomain symbol ++ [symbolResult symbol]

def termNativeTypes : {ty : Ty} -> Term ty -> List Ty
  | _, .boolean _ | _, .integer _ | _, .unknown _ _ => []
  | _, .nodes _ => [.nodes]
  | _, .signature => [.content]
  | _, .transaction value | _, .reconfiguration value | _, .retiredCommitted value =>
    .content :: termNativeTypes value
  | _, .entry left right => .entry :: (termNativeTypes left ++ termNativeTypes right)
  | _, .entryTerm value | _, .entryContent value => .entry :: termNativeTypes value
  | _, .app _ _ _ value | _, .not value => termNativeTypes value
  | _, .add left right | _, .sub left right | _, .le left right
  | _, .equal left right | _, .and left right | _, .implies left right =>
    termNativeTypes left ++ termNativeTypes right
  | _, .ite condition yes no =>
    termNativeTypes condition ++ termNativeTypes yes ++ termNativeTypes no

def operatorNativeTypes : Operator -> List Ty
  | .transaction | .reconfiguration | .retiredCommitted => [.content]
  | .entry | .entryTerm | .entryContent => [.entry]
  | .add | .minus | .le | .equal | .not | .and | .implies | .ite => []

def atomNativeTypes : Atom -> List Ty
  | .nodes _ => [.nodes]
  | .signature => [.content]
  | .operator op => operatorNativeTypes op
  | .boolean _ | .numeral _ | .symbol _ => []

def exprNativeTypes : SExpr -> List Ty
  | .atom atom => atomNativeTypes atom
  | .list values => values.flatMap exprNativeTypes

theorem signedLiteral_nativeTypes (value : Int) :
    exprNativeTypes (signedLiteral value) = [] := by
  cases value <;> simp only [signedLiteral, call, exprNativeTypes, atomNativeTypes, operatorNativeTypes,
    List.flatMap_cons, List.flatMap_nil, List.nil_append]

theorem lower_nativeTypes {ty : Ty} (term : Term ty) :
    exprNativeTypes term.lower = termNativeTypes term := by
  induction term <;>
    simp_all only [Term.lower, termNativeTypes, exprNativeTypes, atomNativeTypes, operatorNativeTypes, call,
      signedLiteral_nativeTypes, List.flatMap_cons, List.flatMap_nil,
      List.nil_append, List.append_nil, List.cons_append, List.append_assoc]

def requiredTypes (formula : Formula) : List Ty :=
  (symbols formula).flatMap symbolTypes ++ formula.flatMap termNativeTypes

def available (native : Bool) (schemas : List Schema) : Ty -> Bool
  | .bool | .int => true
  | .nodes => native
  | .content => native && schemas.contains .content
  | .entry => native && schemas.contains .entry

-- Independent preflight checks every command, even after a false assertion.
def schemaCheck (native : Bool) (schemas : List Schema) : List Command -> Bool
  | [] => true
  | .declareSchema schema :: rest =>
    native && !(schemas.contains schema) &&
      schema.dependencies.all (fun dependency => schemas.contains dependency) &&
      schemaCheck native (schema :: schemas) rest
  | .declare declaration :: rest =>
    (declaration.arguments ++ [declaration.result]).all (available native schemas) &&
      schemaCheck native schemas rest
  | .assertion expression :: rest =>
    (exprSymbols expression).all (fun symbol =>
      (symbolTypes symbol).all (available native schemas)) &&
      (exprNativeTypes expression).all (available native schemas) &&
      schemaCheck native schemas rest
  | .checkSat :: rest => schemaCheck native schemas rest
  | _ => false

-- Invalid declarations, undeclared references, and non-Boolean assertions fail.
-- False assertions still evaluate the remaining commands, so later errors remain errors.
def runBody (assignment : Assignment) (declared : List Symbol) : List Command -> Option Bool
  | [.checkSat] => some true
  | .declareSchema _ :: rest => runBody assignment declared rest
  | .declare declaration :: rest =>
    if declaration.Valid /\ Not (declaration.symbol IN declared) then
      runBody assignment (declaration.symbol :: declared) rest
    else none
  | .assertion expression :: rest =>
    if Covered declared expression then do
      let value <- (expression.eval assignment).bind (Value.asType .bool)
      let remaining <- runBody assignment declared rest
      pure (value && remaining)
    else none
  | _ => none

-- runBody handles user declarations/values; run also validates fixed sort schemas.
def run (assignment : Assignment) : List Command -> Option Bool
  | .setLogic :: rest =>
    if schemaCheck false [] rest then runBody assignment [] rest else none
  | .setNativeLogic :: rest =>
    if schemaCheck true [] rest then runBody assignment [] rest else none
  | _ => none

def prelude (formula : Formula) : List Command :=
  if .entry IN requiredTypes formula then
    [.setNativeLogic, .declareSchema .content, .declareSchema .entry]
  else if .content IN requiredTypes formula then
    [.setNativeLogic, .declareSchema .content]
  else if .nodes IN requiredTypes formula then [.setNativeLogic]
  else [.setLogic]

def compiledBody (formula : Formula) : List Command :=
  (declarations formula).map Command.declare ++
    (formula.map (fun term => Command.assertion term.lower)) ++ [.checkSat]

def compile (formula : Formula) : List Command := prelude formula ++ compiledBody formula

def compileCached (formula : Formula) : List Command :=
  let syms := symbols formula
  let types := syms.flatMap symbolTypes ++ formula.flatMap termNativeTypes
  let header :=
    if .entry IN types then
      [.setNativeLogic, .declareSchema .content, .declareSchema .entry]
    else if .content IN types then
      [.setNativeLogic, .declareSchema .content]
    else if .nodes IN types then [.setNativeLogic]
    else [.setLogic]
  header ++ ((syms.map Declaration.ofSymbol).map Command.declare ++
    formula.map (fun term => Command.assertion term.lower) ++ [.checkSat])

@[csimp] theorem compile_eq_cached : compile = compileCached := by
  funext formula
  rfl

def ScalarOnly (formula : Formula) : Prop :=
  forall ty, ty IN requiredTypes formula -> ty = .bool \/ ty = .int

theorem prelude_scalar (formula : Formula) (scalar : ScalarOnly formula) :
    prelude formula = [.setLogic] := by
  have absent (ty : Ty) (notBool : Not (ty = .bool)) (notInt : Not (ty = .int)) :
      Not (ty IN requiredTypes formula) := by
    intro present
    exact (scalar ty present).elim notBool notInt
  simp only [prelude, if_neg (absent .entry (by decide) (by decide)),
    if_neg (absent .content (by decide) (by decide)),
    if_neg (absent .nodes (by decide) (by decide))]

theorem scalar_compile_preserved (formula : Formula) (scalar : ScalarOnly formula) :
    compile formula =
      [.setLogic] ++ (declarations formula).map Command.declare ++
        formula.map (fun term => Command.assertion term.lower) ++ [.checkSat] := by
  rw [compile, prelude_scalar formula scalar]
  simp only [compiledBody, List.append_assoc]

theorem covered_lower (formula : Formula) {term : Term .bool} (ht : term IN formula) :
    Covered (symbols formula) term.lower := by
  intro sym hs
  exact (symbol_coverage formula sym).mpr (Exists.intro term (And.intro ht hs))

theorem run_declarations (assignment : Assignment) (decls declared : List Symbol)
    (rest : List Command) (distinct : decls.Nodup)
    (fresh : forall sym, sym IN decls -> Not (sym IN declared)) :
    runBody assignment declared
        ((decls.map (fun sym => Command.declare (Declaration.ofSymbol sym))) ++ rest) =
      runBody assignment (decls.reverse ++ declared) rest := by
  induction decls generalizing declared with
  | nil => simp
  | cons sym tail ih =>
    have nd := List.nodup_cons.mp distinct
    have newSymbol := fresh sym (by simp)
    have tailFresh : forall s, s IN tail -> Not (s IN sym :: declared) := by
      intro s hs present
      rcases List.mem_cons.mp present with same | old
      next =>
        subst s
        exact nd.1 hs
      next => exact fresh s (by simp [hs]) old
    have ready : (Declaration.ofSymbol sym).Valid /\
        Not ((Declaration.ofSymbol sym).symbol IN declared) :=
      And.intro (ofSymbol_valid sym) newSymbol
    simp only [List.map_cons, List.cons_append, runBody, if_pos ready]
    simp only [ofSymbol_symbol]
    rw [ih (sym :: declared) nd.2 tailFresh]
    simp [List.reverse_cons, List.append_assoc]

theorem run_assertions (assignment : Assignment) (formula : Formula) (declared : List Symbol)
    (covered : forall term, term IN formula -> Covered declared term.lower) :
    runBody assignment declared
        (formula.map (fun term => Command.assertion term.lower) ++ [.checkSat]) =
      some (formula.all (fun term => term.eval assignment)) := by
  induction formula with
  | nil => simp [runBody]
  | cons term tail ih =>
    have here := covered term (by simp)
    have later : forall t, t IN tail -> Covered declared t.lower :=
      fun t ht => covered t (by simp [ht])
    simp [runBody, here, lower_correct, embed, Value.asType, ih later]

theorem runBody_compiledBody (assignment : Assignment) (formula : Formula) :
    runBody assignment [] (compiledBody formula) =
      some (formula.all (fun term => term.eval assignment)) := by
  simp only [compiledBody, declarations, List.map_map, Function.comp_def, List.append_assoc]
  rw [run_declarations assignment (symbols formula) [] _ (symbols_nodup formula)
    (by simp)]
  apply run_assertions
  intro term ht sym hs
  simpa using covered_lower formula ht sym hs

theorem schemaCheck_declarations (native : Bool) (schemas : List Schema)
    (decls : List Declaration) (rest : List Command)
    (supported : forall declaration, declaration IN decls ->
      forall ty, ty IN declaration.arguments ++ [declaration.result] ->
        available native schemas ty = true) :
    schemaCheck native schemas (decls.map Command.declare ++ rest) =
      schemaCheck native schemas rest := by
  induction decls with
  | nil => simp
  | cons declaration tail ih =>
    have here := List.all_eq_true.mpr (supported declaration (by simp))
    have later := ih (fun d hd => supported d (by simp [hd]))
    simp only [List.map_cons, List.cons_append, schemaCheck, here, Bool.true_and, later]

theorem schemaCheck_assertions (native : Bool) (schemas : List Schema) (formula : Formula)
    (supported : forall term, term IN formula -> forall symbol,
      symbol IN exprSymbols term.lower -> forall ty, ty IN symbolTypes symbol ->
        available native schemas ty = true)
    (nativeSupported : forall term, term IN formula -> forall ty,
      ty IN termNativeTypes term -> available native schemas ty = true) :
    schemaCheck native schemas
      (formula.map (fun term => Command.assertion term.lower) ++ [.checkSat]) = true := by
  induction formula with
  | nil => rfl
  | cons term tail ih =>
    have here : (exprSymbols term.lower).all (fun symbol =>
        (symbolTypes symbol).all (available native schemas)) = true :=
      List.all_eq_true.mpr (fun symbol hs =>
        List.all_eq_true.mpr (supported term (by simp) symbol hs))
    have nativeHere : (exprNativeTypes term.lower).all (available native schemas) = true := by
      rw [lower_nativeTypes]
      exact List.all_eq_true.mpr (nativeSupported term (by simp))
    have later := ih (fun t ht => supported t (by simp [ht]))
      (fun t ht => nativeSupported t (by simp [ht]))
    simp only [List.map_cons, List.cons_append, schemaCheck, here, nativeHere, Bool.true_and, later]

theorem schemaCheck_compiledBody (native : Bool) (schemas : List Schema) (formula : Formula)
    (supported : forall ty, ty IN requiredTypes formula -> available native schemas ty = true) :
    schemaCheck native schemas (compiledBody formula) = true := by
  have symbolSupported (symbol : Symbol) (hs : symbol IN symbols formula)
      (ty : Ty) (ht : ty IN symbolTypes symbol) : available native schemas ty = true :=
    supported ty (List.mem_append.mpr (Or.inl
      (List.mem_flatMap.mpr (Exists.intro symbol (And.intro hs ht)))))
  unfold compiledBody
  rw [List.append_assoc, schemaCheck_declarations]
  next =>
    apply schemaCheck_assertions
    next =>
      intro term ht symbol hs
      exact symbolSupported symbol (covered_lower formula ht symbol hs)
    next =>
      intro term ht ty hty
      exact supported ty (List.mem_append.mpr (Or.inr
        (List.mem_flatMap.mpr (Exists.intro term (And.intro ht hty)))))
  next =>
    intro declaration hd
    cases List.mem_map.mp hd with
    | intro symbol hs =>
      rw [<- hs.2]
      exact symbolSupported symbol hs.1

theorem compile_eval (assignment : Assignment) (formula : Formula) :
    run assignment (compile formula) = some (formula.all (fun term => term.eval assignment)) := by
  by_cases entry : Ty.entry IN requiredTypes formula
  next =>
    have checked := schemaCheck_compiledBody true [.entry, .content] formula
      (by intro ty _; cases ty <;> rfl)
    simp [compile, prelude, entry, run, schemaCheck, Schema.dependencies,
      checked, runBody, runBody_compiledBody]
  next =>
    by_cases content : Ty.content IN requiredTypes formula
    next =>
      have checked := schemaCheck_compiledBody true [.content] formula
        (by intro ty ht; cases ty <;> simp_all [available])
      simp [compile, prelude, entry, content, run, schemaCheck, Schema.dependencies,
        checked, runBody, runBody_compiledBody]
    next =>
      by_cases nodes : Ty.nodes IN requiredTypes formula
      next =>
        have checked := schemaCheck_compiledBody true [] formula
          (by intro ty ht; cases ty <;> simp_all [available])
        simp [compile, prelude, entry, content, nodes, run, checked, runBody_compiledBody]
      next =>
        have checked := schemaCheck_compiledBody false [] formula
          (by intro ty ht; cases ty <;> simp_all [available])
        simp [compile, prelude, entry, content, nodes, run, checked, runBody_compiledBody]

theorem formula_holds_iff (assignment : Assignment) (formula : Formula) :
    Holds assignment formula <-> run assignment (compile formula) = some true := by
  rw [compile_eval]
  simp [Holds, List.all_eq_true]

def Declaration.render (declaration : Declaration) : String :=
  "(declare-fun " ++ declaration.symbol.name ++ " (" ++
    String.intercalate " " (declaration.arguments.map Ty.render) ++ ") " ++
    declaration.result.render ++ ")"

def Command.render : Command -> String
  | .setLogic => "(set-logic QF_UFLIA)"
  | .setNativeLogic => "(set-logic ALL)"
  | .declareSchema schema => schema.render
  | .declare declaration => declaration.render
  | .assertion expression => "(assert " ++ expression.render ++ ")"
  | .checkSat => "(check-sat)"

def renderCommands (commands : List Command) : String :=
  String.intercalate "\n" (commands.map Command.render) ++ "\n"

def render (formula : Formula) : String := renderCommands (compile formula)

theorem scalar_text_preserved (formula : Formula) (scalar : ScalarOnly formula) :
    render formula = renderCommands
      ([.setLogic] ++ (declarations formula).map Command.declare ++
        formula.map (fun term => Command.assertion term.lower) ++ [.checkSat]) :=
  congrArg renderCommands (scalar_compile_preserved formula scalar)

def repeatedFormula : Formula :=
  [.equal (.unknown .int 3) (.unknown .int 3),
   .equal (.app .int .int 3 (.unknown .int 3)) (.app .int .int 3 (.unknown .int 3))]

theorem repeated_symbols_regression : (declarations repeatedFormula).length = 2 := by
  decide +kernel

def mixedSignatureFormula : Formula :=
  [.unknown .bool 0,
   .equal (.unknown .int 0) (.integer 0),
   .app .bool .bool 0 (.boolean true),
   .equal (.app .bool .int 0 (.boolean false)) (.integer 0),
   .app .int .bool 0 (.integer 0),
   .equal (.app .int .int 0 (.integer 0)) (.integer 0)]

theorem mixed_signatures_regression :
    (declarations mixedSignatureFormula).length = 6 /\
      ((symbols mixedSignatureFormula).map Symbol.name).Nodup := by
  exact And.intro (by decide +kernel) (symbol_names_nodup mixedSignatureFormula)

theorem declaration_text_regression :
    (Declaration.ofSymbol (.constant .int 0)).render = "(declare-fun ci__ () Int)" /\
    (Declaration.ofSymbol (.unary .bool .int 0)).render = "(declare-fun fbi_ (Bool) Int)" := by
  decide +kernel

theorem empty_formula_regression (assignment : Assignment) :
    declarations [] = [] /\
    run assignment (compile []) = some true /\
    render [] = "(set-logic QF_UFLIA)\n(check-sat)\n" := by
  refine And.intro rfl (And.intro ?_ ?_)
  next => simp [compile_eval]
  next => decide +kernel

def signedFormula : Formula :=
  [.equal (.sub (.integer (Int.negSucc 1)) (.integer 3)) (.integer (Int.negSucc 4))]

theorem signed_formula_regression (assignment : Assignment) :
    Holds assignment signedFormula /\ run assignment (compile signedFormula) = some true := by
  have holds : Holds assignment signedFormula := by
    simp [Holds, signedFormula, Term.eval]
  exact And.intro holds ((formula_holds_iff assignment signedFormula).mp holds)

theorem signed_script_text_regression :
    render signedFormula =
      "(set-logic QF_UFLIA)\n(assert (= (- (- 2) 3) (- 5)))\n(check-sat)\n" := by
  simp only [render, renderCommands, compile, prelude, requiredTypes, compiledBody,
    declarations, symbols, signedFormula, termSymbols, termNativeTypes, Command.render, Term.lower,
    signedLiteral, call, SExpr.render, Atom.render, List.flatMap_cons, List.flatMap_nil,
    List.map_cons, List.map_nil, List.nil_append, List.cons_append, List.dedup_nil,
    List.not_mem_nil, if_false]
  decide +kernel

theorem missing_declaration_regression (assignment : Assignment) :
    run assignment
      [.setLogic, .assertion (.atom (.symbol (.constant .bool 0))), .checkSat] = none := by
  simp [run, schemaCheck, symbolTypes, symbolDomain, symbolResult, available,
    runBody, Covered, exprSymbols]

theorem wrong_signature_regression (assignment : Assignment) :
    run assignment
      [.setLogic,
       .declare { symbol := .unary .bool .int 0, arguments := [.int], result := .int },
       .checkSat] = none /\
    run assignment
      [.setLogic,
       .declare { symbol := .constant .int 0, arguments := [], result := .bool },
       .checkSat] = none := by
  simp [run, schemaCheck, available, runBody, Declaration.Valid, symbolDomain, symbolResult]

theorem duplicate_declaration_regression (assignment : Assignment) :
    run assignment
      [.setLogic, .declare (Declaration.ofSymbol (.constant .int 0)),
       .declare (Declaration.ofSymbol (.constant .int 0)), .checkSat] = none := by
  simp [run, schemaCheck, available, Declaration.ofSymbol, symbolDomain, symbolResult, runBody]

theorem assertion_error_regression (assignment : Assignment) :
    run assignment [.setLogic, .assertion (.atom (.numeral 1)), .checkSat] = none /\
    run assignment
      [.setLogic, .assertion (.atom (.boolean false)),
       .assertion (.atom (.symbol (.constant .bool 0))), .checkSat] = none /\
    run assignment (compile [.boolean false]) = some false := by
  simp [run, runBody, Covered, exprSymbols, SExpr.eval, Value.asType, compile,
    prelude, requiredTypes, termNativeTypes, compiledBody, schemaCheck, available, symbolTypes,
    symbolDomain, symbolResult, declarations, symbols, termSymbols, Term.lower, exprNativeTypes, atomNativeTypes]

end CCFRaft.Sparse.SmtScript

run_cmd do
  let env <- Lean.getEnv
  let mut checked := 0
  for (name, info) in env.constants.toList do
    if `CCFRaft.Sparse.SmtScript |>.isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit script axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected transitive axiom in {name}: {axiomName}"
  if checked = 0 then
    throwError "no script declarations audited"
  Lean.logInfo m!"Sparse.SmtScript: {checked} declarations passed the allowed-axiom gate."
