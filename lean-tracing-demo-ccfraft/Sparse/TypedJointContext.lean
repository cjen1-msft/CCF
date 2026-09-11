import Sparse.TypedJointPredicateEncoding
import Sparse.ScalarExtension

set_option autoImplicit false

namespace CCFRaft.Sparse.TypedJointContext

open Smt (Assignment Term Ty)
open IntervalEncoding (natValue)
open EntryPredicate (Query)
open TypedIntervalEncoding (SymbolicGraph Observation interpret)
open TypedJointPredicateEncoding (localQueries Concrete Domains)
open TypedJointPredicateEncoding.Witness (Clause Existentials)
open VersionedIntervals (RootArrays)

variable {size roots count : Nat}

def Context (assignment : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (clauses : List (Clause size))
    (arrays : RootArrays roots EntryValue.Entry) : Prop :=
  SmtScript.Holds assignment input /\ Domains assignment graph queries points /\
    Concrete assignment graph queries points arrays /\ Existentials assignment graph clauses arrays

-- The caller's zero is a reservation boundary, not a scalar installed by this proof.
theorem install_context (original : Assignment) (first : Nat) (values : Fin count -> Int)
    (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (clauses : List (Clause size)) (arrays : RootArrays roots EntryValue.Entry)
    (reserved : TypedJointPredicateEncoding.Witness.zero input graph queries points clauses <= first) :
    Context (ScalarExtension.install original first values) input graph queries points clauses arrays <->
      Context original input graph queries points clauses arrays := by
  have bounds := TypedJointPredicateEncoding.allocation_bounds input graph queries points
  have old := Nat.le_trans (TypedJointPredicateEncoding.Witness.old_bound input graph queries points clauses) reserved
  have lift (id : Nat) (small : id < TypedJointPredicateEncoding.zeroId input graph queries points) :
      id < first := Nat.lt_of_lt_of_le small old
  have terms := fun {sort : Ty} (term : Term sort) below =>
    ScalarExtension.eval_below original first values term below
  have graph_eq := TypedJointPredicateEncoding.graph_congr _ _ first graph (lift _ bounds.2.1) terms
  have query_eq : localQueries (ScalarExtension.install original first values) queries = localQueries original queries := by
    apply List.map_congr_left
    intro query member
    exact TypedJointPredicateEncoding.query_congr _ _ first query
      (lift _ (Nat.lt_of_le_of_lt (TypedJointPredicateEncoding.query_bound queries query member) bounds.2.2.1)) terms
  have domains_eq : Domains (ScalarExtension.install original first values) graph queries points <->
      Domains original graph queries points := by
    apply forall_congr'
    intro id
    apply forall_congr'
    intro member
    rw [ScalarExtension.outside original first values .int id (Or.inl
      (lift id (TypedJointPredicateEncoding.metadata_bound input graph queries points id member)))]
  have points_eq :
      TypedIntervalEncoding.ObservationsHold (ScalarExtension.install original first values)
        (IntervalReadback.actual (interpret original graph) arrays) points <->
      TypedIntervalEncoding.ObservationsHold original
        (IntervalReadback.actual (interpret original graph) arrays) points := by
    apply forall_congr'
    intro point
    apply forall_congr'
    intro member
    have small := lift _ (Nat.lt_of_le_of_lt (TypedIntervalEncoding.observation_bound points point member) bounds.2.2.2)
    have position := ScalarExtension.outside original first values .int point.position
      (Or.inl (Nat.lt_of_le_of_lt (Nat.le_max_left _ _) small))
    have expected := terms point.expected (Nat.lt_of_le_of_lt (Nat.le_max_right _ _) small)
    simp only [natValue, position, expected]
  have witnesses_eq : Existentials (ScalarExtension.install original first values) graph clauses arrays <->
      Existentials original graph clauses arrays := by
    apply forall_congr'
    intro index
    have small := TypedJointPredicateEncoding.Witness.new_bound input graph queries points clauses index
    have query_below := Nat.lt_of_lt_of_le small.1 reserved
    have same_query := TypedJointPredicateEncoding.query_congr _ _ first clauses[index.val].toQuery query_below terms
    have lower := ScalarExtension.outside original first values .int clauses[index.val].lower
      (Or.inl (Nat.lt_of_le_of_lt clauses[index.val].toQuery.bounds.1 query_below))
    have upper := ScalarExtension.outside original first values .int clauses[index.val].upper
      (Or.inl (Nat.lt_of_le_of_lt clauses[index.val].toQuery.bounds.2.1 query_below))
    have enable := terms clauses[index.val].enable (Nat.lt_of_lt_of_le small.2 reserved)
    have predicate := fun cells => TypedJointPredicateEncoding.predicate_congr _ _ first clauses[index.val].predicate
      (Nat.lt_of_le_of_lt clauses[index.val].toQuery.bounds.2.2 query_below) cells terms
    dsimp only
    rw [lower, upper, enable, same_query, graph_eq]
    simp only [predicate]
  have input_eq : SmtScript.Holds (ScalarExtension.install original first values) input <->
      SmtScript.Holds original input :=
    ScalarExtension.formula_below original first values input (lift _ bounds.1)
  simp only [Context, Concrete, graph_eq, query_eq, input_eq, domains_eq, points_eq, witnesses_eq]

namespace Regression

def graph : SymbolicGraph 1 .entry 2 :=
  .push (.push .empty (.root 0))
    (.constant (.entry (.unknown .int 101) (.transaction (.unknown .int 102))))

def queries : List (Query 2) :=
  [{ lower := 103, upper := 104,
     predicate := .eq (.cell 0) (.input (.app .int .entry 105 (.integer 0))) }]

def points : List (Observation 1 2 .entry) :=
  [{ address := .version 0, position := 106,
     expected := .entry (.add (.transactionId .signature) (.unknown .int 108))
       (.entryContent (.app .int .entry 107 (.integer 0))) }]

def clauses : List (Clause 2) :=
  [{ lower := 110, upper := 111,
     predicate := .ne (.cell 0) (.input (.app .int .entry 112 (.integer 0))),
     enable := .app .int .bool 3000000 (.integer 0) },
   { lower := 113, upper := 114,
     predicate := .input (.equal (.unknown .int 2000000) (.integer 0)),
     enable := .boolean false }]

def input : SmtScript.Formula := [.equal (.unknown .int 100) (.integer 0)]

theorem metadata_boundary :
    TypedJointPredicateEncoding.Witness.zero input graph queries points clauses = 3000001 := by
  decide +kernel

theorem metadata_context (original : Assignment) (values : Fin count -> Int)
    (arrays : RootArrays 1 EntryValue.Entry) :
    Context (ScalarExtension.install original 3000001 values) input graph queries points clauses arrays <->
      Context original input graph queries points clauses arrays :=
  install_context original 3000001 values input graph queries points clauses arrays
    (Nat.le_of_eq metadata_boundary)

theorem empty_block (original : Assignment) (arrays : RootArrays 1 EntryValue.Entry) :
    Context (ScalarExtension.install original 3000001 (fun index : Fin 0 => Fin.elim0 index))
      input graph queries points clauses arrays <-> Context original input graph queries points clauses arrays :=
  metadata_context original _ arrays

theorem signed_values (original : Assignment) (arrays : RootArrays 1 EntryValue.Entry) :
    Context (ScalarExtension.install original 3000001
      (Fin.cases (-7) (Fin.cases 0 (fun _ : Fin 1 => 9)))) input graph queries points clauses arrays <->
      Context original input graph queries points clauses arrays :=
  metadata_context original _ arrays

theorem complete_nonconstants_and_boundaries (original : Assignment) (values : Fin 3 -> Int) :
    (ScalarExtension.install original 17 values).constant .int 16 = original.constant .int 16 /\
    (ScalarExtension.install original 17 values).constant .int 20 = original.constant .int 20 /\
    (ScalarExtension.install original 17 values).unary = original.unary /\
    (ScalarExtension.install original 17 values).selectors = original.selectors :=
  And.intro (ScalarExtension.outside original 17 values .int 16 (Or.inl (by decide)))
    (And.intro (ScalarExtension.outside original 17 values .int 20 (Or.inr (by decide)))
      (And.intro rfl rfl))

theorem overlap_changes_input (original : Assignment) (zero : original.constant .int 100 = 0) :
    SmtScript.Holds original input /\
      Not (SmtScript.Holds (ScalarExtension.install original 100 (fun _ : Fin 1 => -1)) input) := by
  simp [input, SmtScript.Holds, Term.eval, ScalarExtension.install, zero]

end Regression

end CCFRaft.Sparse.TypedJointContext

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.TypedJointContext).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit TypedJointContext axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"TypedJointContext: {checked} declarations passed the transitive axiom gate."
