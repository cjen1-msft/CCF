import Sparse.ConfigurationReaderEncoding
import Sparse.TypedJointContext

set_option autoImplicit false

namespace CCFRaft.Sparse.ConfigurationReaderComposition

open Smt (Assignment Term Ty)
open IntervalEncoding (natValue)
open EntryPredicate (Query)
open TypedIntervalEncoding (SymbolicGraph Observation interpret)
open TypedJointPredicateEncoding (Concrete Domains localQueries)
open TypedJointPredicateEncoding.Witness (Clause)
open TypedJointContext (Context)
open VersionedIntervals (RootArrays)
open ConfigurationReaderEncoding (Request Scalars Meaning Result constraints)

variable {size roots : Nat}

def Source (assignment : Assignment) (request : Request size) : Prop :=
  0 <= assignment.constant .int request.length /\
  0 <= assignment.constant .int request.frontier /\
  0 <= assignment.constant .int request.index

theorem source_of_scalars (assignment : Assignment) (request : Request size) (first : Nat)
    (scalars : Scalars assignment request first) : Source assignment request :=
  And.intro scalars.length_nonnegative (And.intro scalars.frontier_nonnegative scalars.index_nonnegative)

def install (original : Assignment) (request : Request size) (first : Nat) : Assignment :=
  ScalarExtension.install original first (Fin.cases
    ((min (natValue original request.frontier) (natValue original request.length) : Nat) : Int)
    (fun _ : Fin 1 => ((natValue original request.index - 1 : Nat) : Int)))

theorem install_outside (original : Assignment) (request : Request size) (first : Nat)
    (sort : Ty) (id : Nat) (outside : id < first \/ first + 2 <= id) :
    (install original request first).constant sort id = original.constant sort id :=
  ScalarExtension.outside original first _ sort id outside

theorem install_unary (original : Assignment) (request : Request size) (first : Nat) :
    (install original request first).unary = original.unary := rfl

theorem install_selectors (original : Assignment) (request : Request size) (first : Nat) :
    (install original request first).selectors = original.selectors := rfl

theorem install_term (original : Assignment) (request : Request size) (first : Nat)
    {sort : Ty} (term : Term sort) (below : SymbolBounds.termMax term < first) :
    term.eval (install original request first) = term.eval original :=
  ScalarExtension.eval_below original first _ term below

theorem install_input (original : Assignment) (request : Request size) (first : Nat)
    (input : SmtScript.Formula) (below : SymbolBounds.formulaMax input < first) :
    SmtScript.Holds (install original request first) input <-> SmtScript.Holds original input :=
  ScalarExtension.formula_below original first _ input below

theorem install_graph (original : Assignment) (request : Request size) (first : Nat)
    (graph : SymbolicGraph roots .entry size) (below : TypedIntervalEncoding.graphMax graph < first) :
    interpret (install original request first) graph = interpret original graph :=
  TypedJointPredicateEncoding.graph_congr _ _ first graph below (install_term original request first)

theorem source_bounds (request : Request size) (first : Nat) (below : request.maximum < first) :
    request.length < first /\ request.frontier < first /\ request.index < first /\
      SymbolBounds.termMax request.nodes < first := by
  simpa only [Request.maximum, max_lt_iff] using below

theorem install_request (original : Assignment) (request : Request size) (first : Nat)
    (below : request.maximum < first) :
    (install original request first).constant .int request.length = original.constant .int request.length /\
    (install original request first).constant .int request.frontier = original.constant .int request.frontier /\
    (install original request first).constant .int request.index = original.constant .int request.index /\
    request.nodes.eval (install original request first) = request.nodes.eval original := by
  have bounds := source_bounds request first below
  exact And.intro (install_outside original request first .int _ (Or.inl bounds.1))
    (And.intro (install_outside original request first .int _ (Or.inl bounds.2.1))
      (And.intro (install_outside original request first .int _ (Or.inl bounds.2.2.1))
        (install_term original request first request.nodes bounds.2.2.2)))

theorem install_values (original : Assignment) (request : Request size) (first : Nat) :
    (install original request first).constant .int first =
      ((min (natValue original request.frontier) (natValue original request.length) : Nat) : Int) /\
    (install original request first).constant .int (first + 1) =
      ((natValue original request.index - 1 : Nat) : Int) :=
  And.intro (ScalarExtension.at_index original first _ (0 : Fin 2))
    (ScalarExtension.at_index original first _ (1 : Fin 2))

theorem install_source (original : Assignment) (request : Request size) (first : Nat)
    (below : request.maximum < first) :
    Source (install original request first) request <-> Source original request := by
  have same := install_request original request first below
  simp only [Source, same.1, same.2.1, same.2.2.1]

theorem installed_scalars_iff (original : Assignment) (request : Request size) (first : Nat)
    (below : request.maximum < first) :
    Scalars (install original request first) request first <-> Source original request := by
  constructor
  next =>
    intro scalars
    exact (install_source original request first below).mp (source_of_scalars _ _ _ scalars)
  next =>
    intro source
    have installed := (install_source original request first below).mpr source
    have same := install_request original request first below
    refine
      { length_nonnegative := installed.1
        frontier_nonnegative := installed.2.1
        index_nonnegative := installed.2.2
        clip := ?_
        anchor := ?_ }
    next => simpa only [natValue, same.1, same.2.1] using (install_values original request first).1
    next => simpa only [natValue, same.2.2.1] using (install_values original request first).2

theorem install_context (original : Assignment) (request : Request size) (first : Nat)
    (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (clauses : List (Clause size)) (arrays : RootArrays roots EntryValue.Entry)
    (reserved : TypedJointPredicateEncoding.Witness.zero input graph queries points clauses <= first) :
    Context (install original request first) input graph queries points clauses arrays <->
      Context original input graph queries points clauses arrays :=
  TypedJointContext.install_context original first _ input graph queries points clauses arrays reserved

variable [bootstrap : Bootstrap Node]

theorem install_result (original : Assignment) (request : Request size) (first : Nat)
    (graph : SymbolicGraph roots .entry size) (arrays : RootArrays roots EntryValue.Entry)
    (below : request.maximum < first) (graph_below : TypedIntervalEncoding.graphMax graph < first) :
    Result (install original request first) graph arrays request <-> Result original graph arrays request := by
  have same := install_request original request first below
  have cells :
      ConfigurationReaderEncoding.cells (install original request first) graph arrays request =
        ConfigurationReaderEncoding.cells original graph arrays request := by
    funext position
    simp only [ConfigurationReaderEncoding.cells, install_graph original request first graph graph_below]
  simp only [Result, cells, natValue, same.1, same.2.1, same.2.2.1, same.2.2.2]

theorem installed_meaning_iff (original : Assignment) (request : Request size) (first : Nat)
    (graph : SymbolicGraph roots .entry size) (arrays : RootArrays roots EntryValue.Entry)
    (below : request.maximum < first) (graph_below : TypedIntervalEncoding.graphMax graph < first) :
    Meaning (install original request first) graph arrays request first <->
      Source original request /\ Result original graph arrays request := by
  rw [ConfigurationReaderEncoding.meaning_correct, installed_scalars_iff original request first below,
    install_result original request first graph arrays below graph_below]

-- All caller observations remain arguments to the same outer compiler.
def Assembled (assignment : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (clauses : List (Clause size))
    (arrays : RootArrays roots EntryValue.Entry) (request : Request size) (first : Nat) : Prop :=
  Context assignment (input ++ constraints request first) graph
    (ConfigurationReaderEncoding.queries request first ++ queries) points clauses arrays

theorem assembled_correct (assignment : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (clauses : List (Clause size))
    (arrays : RootArrays roots EntryValue.Entry) (request : Request size) (first : Nat) :
    Assembled assignment input graph queries points clauses arrays request first <->
      Context assignment input graph queries points clauses arrays /\ Meaning assignment graph arrays request first := by
  have concrete :
      Concrete assignment graph (ConfigurationReaderEncoding.queries request first ++ queries) points arrays <->
      VersionedIntervals.Realizes (interpret assignment graph)
        (IntervalQueries.schemas (localQueries assignment (ConfigurationReaderEncoding.queries request first))) arrays /\
      Concrete assignment graph queries points arrays := by
    simp [Concrete, VersionedIntervals.Realizes, IntervalQueries.schemas, localQueries,
      or_imp, forall_and, and_assoc]
  have domains :
      Domains assignment graph (ConfigurationReaderEncoding.queries request first ++ queries) points <->
      Domains assignment graph queries points /\
        0 <= assignment.constant .int request.index /\ 0 <= assignment.constant .int first /\
        0 <= assignment.constant .int (first + 1) := by
    simp only [Domains, TypedJointPredicateEncoding.boundIds, ConfigurationReaderEncoding.queries,
      List.cons_append, List.nil_append, List.flatMap_cons,
      ConfigurationReaderEncoding.anchorQuery, ConfigurationReaderEncoding.suffixQuery]
    simp [or_imp, forall_and, and_assoc, and_left_comm, and_comm]
  have derived (holds : SmtScript.Holds assignment (constraints request first)) :
      0 <= assignment.constant .int request.index /\ 0 <= assignment.constant .int first /\
        0 <= assignment.constant .int (first + 1) := by
    have scalars := ((ConfigurationReaderEncoding.constraints_correct assignment request first).mp holds).1
    exact And.intro scalars.index_nonnegative
      (And.intro (by rw [scalars.clip]; exact Int.natCast_nonneg _)
        (by rw [scalars.anchor]; exact Int.natCast_nonneg _))
  unfold Assembled
  rw [Context, QueueEncoding.holds_append, concrete, domains]
  unfold Context Meaning
  tauto

theorem installed_assembled_iff (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (clauses : List (Clause size))
    (arrays : RootArrays roots EntryValue.Entry) (request : Request size) (first : Nat)
    (source_below : request.maximum < first)
    (reserved : TypedJointPredicateEncoding.Witness.zero input graph queries points clauses <= first) :
    Assembled (install original request first) input graph queries points clauses arrays request first <->
      Context original input graph queries points clauses arrays /\
        Source original request /\ Result original graph arrays request := by
  have graph_below := Nat.lt_of_lt_of_le
    (TypedJointPredicateEncoding.allocation_bounds input graph queries points).2.1
    (Nat.le_trans (TypedJointPredicateEncoding.Witness.old_bound input graph queries points clauses) reserved)
  rw [assembled_correct, install_context original request first input graph queries points clauses arrays reserved,
    installed_meaning_iff original request first graph arrays source_below graph_below]

theorem assembled_exists_iff (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (clauses : List (Clause size)) (request : Request size) (first : Nat)
    (source_below : request.maximum < first)
    (reserved : TypedJointPredicateEncoding.Witness.zero input graph queries points clauses <= first) :
    (exists original : Assignment, exists arrays : RootArrays roots EntryValue.Entry,
      Assembled original input graph queries points clauses arrays request first) <->
    exists original : Assignment, exists arrays : RootArrays roots EntryValue.Entry,
      Context original input graph queries points clauses arrays /\
        Source original request /\ Result original graph arrays request := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro original witness =>
      cases witness with
      | intro arrays assembled =>
        have parts := (assembled_correct original input graph queries points clauses arrays request first).mp assembled
        have reader := (ConfigurationReaderEncoding.meaning_correct original graph arrays request first).mp parts.2
        exact Exists.intro original (Exists.intro arrays
          (And.intro parts.1 (And.intro (source_of_scalars _ _ _ reader.1) reader.2)))
  next =>
    intro witness
    cases witness with
    | intro original witness =>
      cases witness with
      | intro arrays facts =>
        exact Exists.intro (install original request first) (Exists.intro arrays
          ((installed_assembled_iff original input graph queries points clauses arrays request first
            source_below reserved).mpr facts))

def encode (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (clauses : List (Clause size)) (request : Request size) (first : Nat) : SmtScript.Formula :=
  TypedJointPredicateEncoding.Witness.encode (input ++ constraints request first) graph
    (ConfigurationReaderEncoding.queries request first ++ queries) points clauses

def render (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (clauses : List (Clause size)) (request : Request size) (first : Nat) : String :=
  TypedJointPredicateEncoding.Witness.render (input ++ constraints request first) graph
    (ConfigurationReaderEncoding.queries request first ++ queries) points clauses

theorem outer_reservation (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (clauses : List (Clause size)) (request : Request size) (first : Nat) :
    first + 2 <= TypedJointPredicateEncoding.Witness.zero (input ++ constraints request first) graph
      (ConfigurationReaderEncoding.queries request first ++ queries) points clauses := by
  have tail : SymbolBounds.formulaMax (constraints request first) <=
      SymbolBounds.formulaMax (input ++ constraints request first) := by
    induction input with
    | nil => exact Nat.le_refl _
    | cons head rest ih => exact Nat.le_trans ih (Nat.le_max_right _ _)
  have exact_max := ConfigurationReaderEncoding.constraints_maximum request first
  have formula_bound := (TypedJointPredicateEncoding.allocation_bounds (input ++ constraints request first)
    graph (ConfigurationReaderEncoding.queries request first ++ queries) points).1
  have outer := TypedJointPredicateEncoding.Witness.old_bound (input ++ constraints request first)
    graph (ConfigurationReaderEncoding.queries request first ++ queries) points clauses
  omega

theorem encode_exists_iff (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (clauses : List (Clause size)) (request : Request size) (first : Nat)
    (source_below : request.maximum < first)
    (reserved : TypedJointPredicateEncoding.Witness.zero input graph queries points clauses <= first) :
    (exists assignment : Assignment, SmtScript.Holds assignment
      (encode input graph queries points clauses request first)) <->
    exists original : Assignment, exists arrays : RootArrays roots EntryValue.Entry,
      Context original input graph queries points clauses arrays /\
        Source original request /\ Result original graph arrays request := by
  rw [encode, TypedJointPredicateEncoding.Witness.encode_exists_iff]
  exact assembled_exists_iff input graph queries points clauses request first source_below reserved

theorem rendered_exists_iff (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (clauses : List (Clause size)) (request : Request size) (first : Nat)
    (source_below : request.maximum < first)
    (reserved : TypedJointPredicateEncoding.Witness.zero input graph queries points clauses <= first) :
    (exists assignment : Assignment, SmtScriptText.runText assignment
      (render input graph queries points clauses request first) = some true) <->
    exists original : Assignment, exists arrays : RootArrays roots EntryValue.Entry,
      Context original input graph queries points clauses arrays /\
        Source original request /\ Result original graph arrays request := by
  rw [render, TypedJointPredicateEncoding.Witness.rendered_exists_iff]
  exact assembled_exists_iff input graph queries points clauses request first source_below reserved

namespace Regression

def request (mask : BitVec NODE_COUNT) : Request 1 :=
  { version := 0, length := 0, frontier := 1, index := 2, nodes := .nodes mask }

def graph : SymbolicGraph 1 .entry 1 := .push .empty (.root 0)

theorem empty_context (original : Assignment) (arrays : RootArrays 1 EntryValue.Entry)
    (length : original.constant .int 0 = 0) (frontier : 0 <= original.constant .int 1)
    (index : original.constant .int 2 = 0) :
    Assembled (install original (request (NodeSetCodec.encodeNodes INITIAL_CONFIGURATION)) 3)
      [] graph [] [] [] arrays (request (NodeSetCodec.encodeNodes INITIAL_CONFIGURATION)) 3 := by
  rw [installed_assembled_iff _ _ _ _ _ _ _ _ _ (by change 2 < 3; decide) (by decide)]
  refine And.intro ?_ (And.intro ?_ ?_)
  next =>
    simp [Context, SmtScript.Holds, Domains, TypedJointPredicateEncoding.boundIds,
      graph, VersionedIntervals.Graph.endpoints, VersionedIntervals.Version.endpoints,
      Concrete, VersionedIntervals.Realizes, IntervalQueries.schemas, localQueries,
      TypedIntervalEncoding.ObservationsHold, TypedJointPredicateEncoding.Witness.Existentials]
  next => simpa [Source, request, length, index] using frontier
  next =>
    simp only [Result, request, natValue, length, index, Int.toNat_zero, Term.eval]
    exact ConfigurationReaderEncoding.Regression.empty _ _

def signaturePoint : Observation 1 1 .entry :=
  { address := .root 0, position := 3, expected := .entry (.integer (-7)) .signature }

theorem conflicting_point (original : Assignment) (mask : BitVec NODE_COUNT)
    (index : original.constant .int 2 = 1) (position : original.constant .int 3 = 0) :
    Not (exists arrays : RootArrays 1 EntryValue.Entry,
      Assembled (install original (request mask) 4) [] graph [] [signaturePoint] [] arrays (request mask) 4) := by
  intro witness
  cases witness with
  | intro arrays assembled =>
    have parts := (installed_assembled_iff original [] graph [] [signaturePoint] [] arrays
      (request mask) 4 (by change 2 < 4; decide) (by decide)).mp assembled
    have observed := parts.1.2.2.1.2 signaturePoint (by simp)
    change arrays 0 (natValue original 3) = { term := -7, content := .signature } at observed
    simp only [natValue, position, Int.toNat_zero] at observed
    have result := parts.2.2
    rw [Result, ConfigurationReaderEncoding.current_storage_iff] at result
    have anchor := result.2.2.1 (by simp [request, natValue, index])
    have anchor_content : (arrays 0 0).content = .reconfiguration mask := by
      simpa [request, natValue, index, Term.eval, ConfigurationReaderEncoding.cells, graph,
        interpret, TypedIntervalEncoding.interpretNode, VersionedIntervals.evaluate,
        VersionedIntervals.Graph.values, VersionedIntervals.Version.value] using anchor
    rw [observed] at anchor_content
    contradiction

theorem negative_source_rejected (original : Assignment) (request : Request size) (first : Nat)
    (graph : SymbolicGraph roots .entry size) (arrays : RootArrays roots EntryValue.Entry)
    (below : request.maximum < first) (graph_below : TypedIntervalEncoding.graphMax graph < first)
    (negative : original.constant .int request.length < 0) :
    Not (Meaning (install original request first) graph arrays request first) := by
  rw [installed_meaning_iff original request first graph arrays below graph_below]
  intro facts
  exact not_lt_of_ge facts.1.1 negative

omit bootstrap in
def highRequest : Request 2 :=
  { version := 0, length := 10, frontier := 11, index := 12,
    nodes := .ite (.boolean true) (.nodes 0)
      (.nodesNot (.configurationNodes (.entryContent (.app .int .entry 4000000 (.unknown .int 13))))) }

omit bootstrap in
theorem high_reservation :
    ConfigurationReaderEncoding.freshBase highRequest
      (TypedJointPredicateEncoding.Witness.zero TypedJointContext.Regression.input
        TypedJointContext.Regression.graph TypedJointContext.Regression.queries
        TypedJointContext.Regression.points TypedJointContext.Regression.clauses) = 4000001 := by
  decide +kernel

theorem high_metadata_same_family (original : Assignment) (arrays : RootArrays 1 EntryValue.Entry) :
    Assembled (install original highRequest 4000001) TypedJointContext.Regression.input
      TypedJointContext.Regression.graph TypedJointContext.Regression.queries
      TypedJointContext.Regression.points TypedJointContext.Regression.clauses arrays highRequest 4000001 <->
    Context original TypedJointContext.Regression.input
      TypedJointContext.Regression.graph TypedJointContext.Regression.queries
      TypedJointContext.Regression.points TypedJointContext.Regression.clauses arrays /\
      Source original highRequest /\ Result original TypedJointContext.Regression.graph arrays highRequest :=
  installed_assembled_iff original _ _ _ _ _ arrays highRequest 4000001 (by decide) (by decide)

omit bootstrap in
theorem complete_interpretations (original : Assignment) :
    (install original highRequest 4000001).constant .int 4000000 = original.constant .int 4000000 /\
    (install original highRequest 4000001).constant .int 4000003 = original.constant .int 4000003 /\
    (install original highRequest 4000001).unary = original.unary /\
    (install original highRequest 4000001).selectors = original.selectors /\
    (Term.configurationNodes (.entryContent (.app .int .entry 4000000 (.unknown .int 13)))).eval
      (install original highRequest 4000001) =
    (Term.configurationNodes (.entryContent (.app .int .entry 4000000 (.unknown .int 13)))).eval original :=
  And.intro (install_outside original highRequest 4000001 .int 4000000 (Or.inl (by decide)))
    (And.intro (install_outside original highRequest 4000001 .int 4000003 (Or.inr (by decide)))
      (And.intro rfl (And.intro rfl (install_term original highRequest 4000001 _ (by decide)))))

theorem encode_abi (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (clauses : List (Clause size)) (request : Request size) (first : Nat) :
    encode input graph queries points clauses request first =
      TypedJointPredicateEncoding.Witness.encode (input ++ constraints request first) graph
        (ConfigurationReaderEncoding.queries request first ++ queries) points clauses := rfl

theorem render_abi (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (clauses : List (Clause size)) (request : Request size) (first : Nat) :
    render input graph queries points clauses request first =
      TypedJointPredicateEncoding.Witness.render (input ++ constraints request first) graph
        (ConfigurationReaderEncoding.queries request first ++ queries) points clauses := rfl

end Regression

end CCFRaft.Sparse.ConfigurationReaderComposition

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.ConfigurationReaderComposition).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit ConfigurationReaderComposition axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"ConfigurationReaderComposition: {checked} declarations passed the transitive axiom gate."
