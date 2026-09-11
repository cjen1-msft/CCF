import Sparse.TypedIntervalReadBlock

set_option autoImplicit false

namespace CCFRaft.Sparse.ScalarExtension

open Smt (Assignment Term Ty)

variable {count : Nat} {ty : Ty}

def install (original : Assignment) (first : Nat) (values : Fin count -> Int) : Assignment where
  constant sort id :=
    match sort with
    | .int =>
      if inside : first <= id /\ id < first + count then
        values (Fin.mk (id - first) (by omega))
      else original.constant .int id
    | sort => original.constant sort id
  unary := original.unary
  selectors := original.selectors

theorem at_index (original : Assignment) (first : Nat) (values : Fin count -> Int) (index : Fin count) :
    (install original first values).constant .int (first + index.val) = values index := by
  have inside : first <= first + index.val /\ first + index.val < first + count := by
    have bound := index.isLt
    omega
  simp [install, inside]

theorem outside (original : Assignment) (first : Nat) (values : Fin count -> Int)
    (sort : Ty) (id : Nat) (reserved : id < first \/ first + count <= id) :
    (install original first values).constant sort id = original.constant sort id := by
  have absent : Not (first <= id /\ id < first + count) := by omega
  cases sort <;> simp only [install, dif_neg absent]

theorem unary_preserved (original : Assignment) (first : Nat) (values : Fin count -> Int) :
    (install original first values).unary = original.unary := rfl

theorem selectors_preserved (original : Assignment) (first : Nat) (values : Fin count -> Int) :
    (install original first values).selectors = original.selectors := rfl

theorem eval_below (original : Assignment) (first : Nat) (values : Fin count -> Int)
    (term : Term ty) (below : SymbolBounds.termMax term < first) :
    term.eval (install original first values) = term.eval original := by
  induction term with
  | boolean _ | integer _ | nodes _ | signature => rfl
  | unknown sort id => exact outside original first values sort id (Or.inl below)
  | app domain result id argument ih =>
    have bounds : id < first /\ SymbolBounds.termMax argument < first := max_lt_iff.mp below
    exact congrArg (original.unary domain result id) (ih bounds.2)
  | add left right ihl ihr | sub left right ihl ihr | le left right ihl ihr
  | equal left right ihl ihr | and left right ihl ihr | implies left right ihl ihr
  | entry left right ihl ihr | nodesAnd left right ihl ihr | nodesOr left right ihl ihr =>
    have bounds : SymbolBounds.termMax left < first /\ SymbolBounds.termMax right < first := max_lt_iff.mp below
    simp only [Term.eval, ihl bounds.1, ihr bounds.2]
  | not value ih | transaction value ih | reconfiguration value ih | retiredCommitted value ih
  | entryTerm value ih | entryContent value ih | nodesNot value ih | isContent _ value ih =>
    simp only [Term.eval, ih below]
  | transactionId value ih | configurationNodes value ih | retiredNodes value ih =>
    simp only [Term.eval, ih below, selectors_preserved]
  | ite condition yes no ihc ihy ihn =>
    have bounds : SymbolBounds.termMax condition < first /\
        SymbolBounds.termMax yes < first /\ SymbolBounds.termMax no < first := by
      simpa only [SymbolBounds.termMax, max_lt_iff] using below
    simp only [Term.eval, ihc bounds.1, ihy bounds.2.1, ihn bounds.2.2]

theorem formula_below (original : Assignment) (first : Nat) (values : Fin count -> Int)
    (input : SmtScript.Formula) (below : SymbolBounds.formulaMax input < first) :
    SmtScript.Holds (install original first values) input <-> SmtScript.Holds original input := by
  apply forall_congr'
  intro term
  apply forall_congr'
  intro member
  rw [eval_below original first values term
    (Nat.lt_of_le_of_lt (TypedIntervalEncoding.formula_term_bound input term member) below)]

namespace Regression

theorem zero_and_witness (original : Assignment) (witness : Int) :
    (install original 10 (Fin.cases 0 (fun _ : Fin 1 => witness))).constant .int 10 = 0 /\
    (install original 10 (Fin.cases 0 (fun _ : Fin 1 => witness))).constant .int 11 = witness := by
  exact And.intro (at_index original 10 _ (0 : Fin 2)) (at_index original 10 _ (1 : Fin 2))

theorem whole_function_same_id (original : Assignment) (values : Fin 3 -> Int) :
    (install original 10 values).unary .int .entry 11 = original.unary .int .entry 11 := rfl

theorem nested_wrong_selector (original : Assignment) (values : Fin 3 -> Int) :
    (Term.nodesNot (.configurationNodes (.entryContent (.entry (.integer (-1)) .signature)))).eval
      (install original 10 values) =
    (Term.nodesNot (.configurationNodes (.entryContent (.entry (.integer (-1)) .signature)))).eval original := by
  apply eval_below
  decide +kernel

theorem outside_both_ends (original : Assignment) (values : Fin 3 -> Int) :
    (install original 10 values).constant .int 9 = original.constant .int 9 /\
    (install original 10 values).constant .int 13 = original.constant .int 13 :=
  And.intro (outside original 10 values .int 9 (Or.inl (by decide)))
    (outside original 10 values .int 13 (Or.inr (by decide)))

end Regression

end CCFRaft.Sparse.ScalarExtension

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.ScalarExtension).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse.ScalarExtension: allowed-axiom gate passed for {checked} declarations."
