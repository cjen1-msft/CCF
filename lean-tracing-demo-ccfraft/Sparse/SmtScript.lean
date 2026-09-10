import Sparse.Smt
import Mathlib.Data.List.Dedup

-- Command-AST semantics only, not an SMT-LIB text-parser or solver theorem.
set_option autoImplicit false

namespace CCFRaft.Sparse.SmtScript

open Smt

local notation:50 x:51 " IN " xs:51 => Membership.mem xs x

abbrev Formula := List (Term .bool)

def Holds (assignment : Assignment) (formula : Formula) : Prop :=
  forall term, term IN formula -> term.eval assignment = true

def termSymbols : {ty : Ty} -> Term ty -> List Symbol
  | _, .boolean _ | _, .integer _ => []
  | _, .unknown ty id => [.constant ty id]
  | _, .app domain result id argument => .unary domain result id :: termSymbols argument
  | _, .add left right | _, .sub left right | _, .le left right
  | _, .equal left right | _, .and left right | _, .implies left right =>
    termSymbols left ++ termSymbols right
  | _, .not value => termSymbols value
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

inductive Command where
  | setLogic
  | declare (declaration : Declaration)
  | assertion (expression : SExpr)
  | checkSat
  deriving Repr

def Covered (declared : List Symbol) (expression : SExpr) : Prop :=
  forall sym, sym IN exprSymbols expression -> sym IN declared

instance (declared : List Symbol) (expression : SExpr) : Decidable (Covered declared expression) := by
  unfold Covered
  infer_instance

-- Invalid declarations, undeclared references, and non-Boolean assertions fail.
-- False assertions still evaluate the remaining commands, so later errors remain errors.
def runBody (assignment : Assignment) (declared : List Symbol) : List Command -> Option Bool
  | [.checkSat] => some true
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

-- One QF_UFLIA query: set-logic first, exactly one terminal check-sat.
def run (assignment : Assignment) : List Command -> Option Bool
  | .setLogic :: rest => runBody assignment [] rest
  | _ => none

def compile (formula : Formula) : List Command :=
  [.setLogic] ++ (declarations formula).map Command.declare ++
    (formula.map (fun term => Command.assertion term.lower)) ++ [.checkSat]

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

theorem compile_eval (assignment : Assignment) (formula : Formula) :
    run assignment (compile formula) = some (formula.all (fun term => term.eval assignment)) := by
  simp only [compile, declarations, List.map_map, Function.comp_def,
    List.cons_append, List.nil_append, List.append_assoc, run]
  rw [run_declarations assignment (symbols formula) [] _ (symbols_nodup formula)
    (by simp)]
  apply run_assertions
  intro term ht sym hs
  simpa using covered_lower formula ht sym hs

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
  | .declare declaration => declaration.render
  | .assertion expression => "(assert " ++ expression.render ++ ")"
  | .checkSat => "(check-sat)"

def renderCommands (commands : List Command) : String :=
  String.intercalate "\n" (commands.map Command.render) ++ "\n"

def render (formula : Formula) : String := renderCommands (compile formula)

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
  simp only [render, renderCommands, compile, declarations, symbols, signedFormula,
    termSymbols, Command.render, Term.lower, signedLiteral, call, SExpr.render, Atom.render,
    List.flatMap_cons, List.flatMap_nil, List.map_cons, List.map_nil,
    List.nil_append, List.cons_append, List.dedup_nil]
  decide +kernel

theorem missing_declaration_regression (assignment : Assignment) :
    run assignment
      [.setLogic, .assertion (.atom (.symbol (.constant .bool 0))), .checkSat] = none := by
  simp [run, runBody, Covered, exprSymbols]

theorem wrong_signature_regression (assignment : Assignment) :
    run assignment
      [.setLogic,
       .declare { symbol := .unary .bool .int 0, arguments := [.int], result := .int },
       .checkSat] = none /\
    run assignment
      [.setLogic,
       .declare { symbol := .constant .int 0, arguments := [], result := .bool },
       .checkSat] = none := by
  simp [run, runBody, Declaration.Valid, symbolDomain, symbolResult]

theorem duplicate_declaration_regression (assignment : Assignment) :
    run assignment
      [.setLogic, .declare (Declaration.ofSymbol (.constant .int 0)),
       .declare (Declaration.ofSymbol (.constant .int 0)), .checkSat] = none := by
  simp [run, runBody]

theorem assertion_error_regression (assignment : Assignment) :
    run assignment [.setLogic, .assertion (.atom (.numeral 1)), .checkSat] = none /\
    run assignment
      [.setLogic, .assertion (.atom (.boolean false)),
       .assertion (.atom (.symbol (.constant .bool 0))), .checkSat] = none /\
    run assignment (compile [.boolean false]) = some false := by
  simp [run, runBody, Covered, exprSymbols, SExpr.eval, Value.asType, compile,
    declarations, symbols, termSymbols, Term.lower]

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
