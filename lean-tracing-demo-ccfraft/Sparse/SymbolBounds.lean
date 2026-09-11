import Sparse.SmtScript
import Mathlib.Data.Finset.Lattice.Fold

set_option autoImplicit false

namespace CCFRaft.Sparse.SymbolBounds

open Smt

def symbolId : Symbol -> Nat
  | .constant _ id | .unary _ _ id => id

def termMax : {ty : Ty} -> Term ty -> Nat
  | _, .boolean _ | _, .integer _ | _, .nodes _ | _, .signature => 0
  | _, .unknown _ id => id
  | _, .app _ _ id argument => max id (termMax argument)
  | _, .add left right | _, .sub left right | _, .le left right
  | _, .equal left right | _, .and left right | _, .implies left right
  | _, .nodesAnd left right | _, .nodesOr left right
  | _, .entry left right =>
    max (termMax left) (termMax right)
  | _, .not value | _, .nodesNot value | _, .transaction value | _, .reconfiguration value
  | _, .retiredCommitted value | _, .entryTerm value | _, .entryContent value
  | _, .isContent _ value | _, .transactionId value
  | _, .configurationNodes value | _, .retiredNodes value => termMax value
  | _, .ite condition yes no => max (termMax condition) (max (termMax yes) (termMax no))

theorem termMax_correct {ty : Ty} (term : Term ty) :
    termMax term = (SmtScript.termSymbols term).toFinset.sup symbolId := by
  induction term <;>
    simp_all only [termMax, SmtScript.termSymbols, symbolId, List.toFinset_nil,
      List.toFinset_cons, List.toFinset_append, Finset.sup_empty, Finset.sup_insert,
      Finset.sup_union, show (Bot.bot : Nat) = 0 from rfl, Nat.max_zero, Nat.max_assoc]

def formulaMax : SmtScript.Formula -> Nat
  | [] => 0
  | term :: rest => max (termMax term) (formulaMax rest)

def freshBase (formula : SmtScript.Formula) : Nat := formulaMax formula + 1

theorem formulaMax_correct (formula : SmtScript.Formula) :
    formulaMax formula = (SmtScript.symbols formula).toFinset.sup symbolId := by
  have dedup (symbols : List Symbol) : symbols.dedup.toFinset = symbols.toFinset := by
    ext symbol
    simp
  induction formula with
  | nil => simp [formulaMax, SmtScript.symbols]
  | cons term rest ih =>
    simp_all [formulaMax, SmtScript.symbols, termMax_correct, Finset.sup_union]

theorem repeated_symbol_regression :
    formulaMax [
      .equal (.app .int .int 100 (.unknown .int 3)) (.unknown .int 3),
      .equal (.unknown .bool 100) (.unknown .bool 100)] = 100 := by
  decide +kernel

theorem literal_regression :
    formulaMax [.le (.integer 1000000000000) (.integer (-1))] = 0 := by
  decide +kernel

end CCFRaft.Sparse.SymbolBounds

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.SymbolBounds).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo "Sparse.SymbolBounds: allowed-axiom gate passed."
