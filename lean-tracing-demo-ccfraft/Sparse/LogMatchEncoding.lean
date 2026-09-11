import Sparse.LogMatchSummary
import Sparse.TypedJointPredicateEncoding

set_option autoImplicit false

namespace CCFRaft.Sparse.LogMatchEncoding

open Smt (Assignment Term Ty)
open IntervalEncoding (natTerm natValue)
open EntryPredicate (Predicate Operand Query)
open TypedIntervalEncoding (SymbolicGraph Observation interpret)
open TypedJointPredicateEncoding (localQueries Concrete Domains)
open TypedJointPredicateEncoding.Witness (Clause Existentials)
open VersionedIntervals (RootArrays)

variable {size roots : Nat}

structure Spec (size : Nat) where
  version : Fin size
  length : Nat
  index : Nat
  threshold : Nat
  best : Nat

def Spec.maximum (spec : Spec size) : Nat :=
  max spec.length (max spec.index (max spec.threshold spec.best))

def Source (assignment : Assignment) (spec : Spec size) : Prop :=
  0 <= assignment.constant .int spec.length /\
  0 <= assignment.constant .int spec.index /\
  0 <= assignment.constant .int spec.threshold /\
  0 <= assignment.constant .int spec.best

def clipTerm (spec : Spec size) : Term .int :=
  .ite (.le (natTerm spec.index) (natTerm spec.length)) (natTerm spec.index) (natTerm spec.length)

def anchorTerm (spec : Spec size) : Term .int :=
  .ite (.le (natTerm spec.best) (.integer 0)) (.integer 0) (.sub (natTerm spec.best) (.integer 1))

def constraints (spec : Spec size) (first : Nat) : SmtScript.Formula :=
  TypedIntervalReadBlock.domainFormula [spec.length, spec.index, spec.threshold, spec.best] ++
    [.le (.integer 0) (natTerm first),
     .le (.integer 0) (natTerm (first + 1)),
     .le (natTerm spec.best) (natTerm first),
     .equal (natTerm first) (clipTerm spec),
     .equal (natTerm (first + 1)) (anchorTerm spec)]

structure Scalars (assignment : Assignment) (spec : Spec size) (first : Nat) : Prop where
  source : Source assignment spec
  clip : assignment.constant .int first =
    ((min (natValue assignment spec.index) (natValue assignment spec.length) : Nat) : Int)
  anchor : assignment.constant .int (first + 1) = ((natValue assignment spec.best - 1 : Nat) : Int)
  bound : natValue assignment spec.best <= min (natValue assignment spec.index) (natValue assignment spec.length)

theorem clip_eval (assignment : Assignment) (spec : Spec size) (source : Source assignment spec) :
    (clipTerm spec).eval assignment =
      ((min (natValue assignment spec.index) (natValue assignment spec.length) : Nat) : Int) := by
  have arithmetic (index length : Int) (hi : 0 <= index) (hl : 0 <= length) :
      (if index <= length then index else length) = ((min index.toNat length.toNat : Nat) : Int) := by
    split <;> omega
  simpa only [clipTerm, Term.eval, natTerm, natValue, decide_eq_true_eq] using
    arithmetic _ _ source.2.1 source.1

theorem anchor_eval (assignment : Assignment) (spec : Spec size) (source : Source assignment spec) :
    (anchorTerm spec).eval assignment = ((natValue assignment spec.best - 1 : Nat) : Int) := by
  have arithmetic (best : Int) (nonnegative : 0 <= best) :
      (if best <= 0 then 0 else best - 1) = ((best.toNat - 1 : Nat) : Int) := by
    split <;> omega
  simpa only [anchorTerm, Term.eval, natTerm, natValue, decide_eq_true_eq] using
    arithmetic _ source.2.2.2

theorem constraints_raw (assignment : Assignment) (spec : Spec size) (first : Nat) :
    SmtScript.Holds assignment (constraints spec first) <->
      Source assignment spec /\
      0 <= assignment.constant .int first /\
      0 <= assignment.constant .int (first + 1) /\
      assignment.constant .int spec.best <= assignment.constant .int first /\
      assignment.constant .int first = (clipTerm spec).eval assignment /\
      assignment.constant .int (first + 1) = (anchorTerm spec).eval assignment := by
  have domains : SmtScript.Holds assignment
      (TypedIntervalReadBlock.domainFormula [spec.length, spec.index, spec.threshold, spec.best]) <->
        Source assignment spec := by
    simp only [TypedIntervalReadBlock.domainFormula, SmtScript.Holds,
      List.forall_mem_map, List.mem_dedup, natTerm, Term.eval, decide_eq_true_eq]
    simp [Source]
  simp only [constraints, QueueEncoding.holds_append, domains]
  simp [SmtScript.Holds, natTerm, Term.eval]

theorem constraints_correct (assignment : Assignment) (spec : Spec size) (first : Nat) :
    SmtScript.Holds assignment (constraints spec first) <-> Scalars assignment spec first := by
  rw [constraints_raw]
  constructor
  next =>
    intro facts
    have clip := facts.2.2.2.2.1.trans (clip_eval assignment spec facts.1)
    have anchor := facts.2.2.2.2.2.trans (anchor_eval assignment spec facts.1)
    refine { source := facts.1, clip, anchor, bound := ?_ }
    apply Int.ofNat_le.mp
    rw [show (natValue assignment spec.best : Int) = assignment.constant .int spec.best from
      Int.toNat_of_nonneg facts.1.2.2.2, <- clip]
    exact facts.2.2.2.1
  next =>
    intro facts
    refine And.intro facts.source (And.intro ?_ (And.intro ?_ (And.intro ?_
      (And.intro (facts.clip.trans (clip_eval assignment spec facts.source).symm)
        (facts.anchor.trans (anchor_eval assignment spec facts.source).symm)))))
    next => rw [facts.clip]; exact Int.natCast_nonneg _
    next => rw [facts.anchor]; exact Int.natCast_nonneg _
    next =>
      rw [facts.clip]
      have bound := Int.ofNat_le.mpr facts.bound
      simpa only [natValue, Int.toNat_of_nonneg facts.source.2.2.2] using bound

def eligible (spec : Spec size) : Predicate size :=
  .le (.decodedTerm (.cell spec.version)) (.input (natTerm spec.threshold))

def suffix (spec : Spec size) (first : Nat) : Query size :=
  { lower := spec.best, upper := first, predicate := .not (eligible spec) }

def anchorQuery (spec : Spec size) (first : Nat) : Query size :=
  { lower := first + 1, upper := spec.best, predicate := eligible spec }

def cells (assignment : Assignment) (graph : SymbolicGraph roots .entry size)
    (arrays : RootArrays roots EntryValue.Entry) (spec : Spec size) (position : Nat) : EntryValue.Entry :=
  VersionedIntervals.evaluate (interpret assignment graph) arrays position spec.version

-- Finite-prefix decoding is confined to the semantic proposition.
def Result (assignment : Assignment) (graph : SymbolicGraph roots .entry size)
    (arrays : RootArrays roots EntryValue.Entry) (spec : Spec size) : Prop :=
  findHighestPossibleMatch
    ({ length := natValue assignment spec.length, entries := fun position =>
        EntryValue.decodeEntry (cells assignment graph arrays spec position) } : ArrayLog.ArrayLog).decode
    (natValue assignment spec.index) (natValue assignment spec.threshold) = natValue assignment spec.best

theorem eligible_eval (assignment : Assignment) (spec : Spec size) (values : Fin size -> EntryValue.Entry) :
    (eligible spec).eval assignment values =
      decide (BijectiveIntegerLog.smtDecode (values spec.version).term <= assignment.constant .int spec.threshold) := by
  simp only [eligible, Predicate.eval, Operand.eval, natTerm, Term.eval, BijectiveIntegerLog.decode_formula]

def Meaning (assignment : Assignment) (graph : SymbolicGraph roots .entry size)
    (arrays : RootArrays roots EntryValue.Entry) (spec : Spec size) (first : Nat) : Prop :=
  SmtScript.Holds assignment (constraints spec first) /\
    VersionedIntervals.Realizes (interpret assignment graph)
      (IntervalQueries.schemas (localQueries assignment [suffix spec first, anchorQuery spec first])) arrays

theorem suffix_correct (assignment : Assignment) (graph : SymbolicGraph roots .entry size)
    (arrays : RootArrays roots EntryValue.Entry) (spec : Spec size) (first : Nat) :
    VersionedIntervals.Realizes (interpret assignment graph)
      (IntervalQueries.schemas (localQueries assignment [suffix spec first])) arrays <->
      forall position, natValue assignment spec.best <= position ->
        position < natValue assignment first ->
        Not (BijectiveIntegerLog.smtDecode (cells assignment graph arrays spec position).term <=
          assignment.constant .int spec.threshold) := by
  simp [VersionedIntervals.Realizes, IntervalQueries.schemas, localQueries, suffix,
    Query.toLocalQuery, VersionedIntervals.Query.Inside, Predicate.eval, eligible_eval, cells]

theorem anchor_correct (assignment : Assignment) (graph : SymbolicGraph roots .entry size)
    (arrays : RootArrays roots EntryValue.Entry) (spec : Spec size) (first : Nat)
    (facts : Scalars assignment spec first) :
    VersionedIntervals.Realizes (interpret assignment graph)
      (IntervalQueries.schemas (localQueries assignment [anchorQuery spec first])) arrays <->
      (0 < natValue assignment spec.best ->
        BijectiveIntegerLog.smtDecode
          (cells assignment graph arrays spec (natValue assignment spec.best - 1)).term <=
            assignment.constant .int spec.threshold) := by
  have anchor_value : natValue assignment (first + 1) = natValue assignment spec.best - 1 := by
    simp only [natValue, facts.anchor, Int.toNat_natCast]
  have interval :
      VersionedIntervals.Realizes (interpret assignment graph)
        (IntervalQueries.schemas (localQueries assignment [anchorQuery spec first])) arrays <->
      forall position, natValue assignment spec.best - 1 <= position ->
        position < natValue assignment spec.best ->
        BijectiveIntegerLog.smtDecode (cells assignment graph arrays spec position).term <=
          assignment.constant .int spec.threshold := by
    simp [VersionedIntervals.Realizes, IntervalQueries.schemas, localQueries, anchorQuery,
      Query.toLocalQuery, VersionedIntervals.Query.Inside, eligible_eval, cells, anchor_value]
  rw [interval]
  constructor
  next =>
    intro all positive
    exact all (natValue assignment spec.best - 1) (Nat.le_refl _) (by omega)
  next =>
    intro hit position lower upper
    have same : position = natValue assignment spec.best - 1 := by omega
    rw [same]
    exact hit (by omega)

theorem meaning_correct (assignment : Assignment) (graph : SymbolicGraph roots .entry size)
    (arrays : RootArrays roots EntryValue.Entry) (spec : Spec size) (first : Nat) :
    Meaning assignment graph arrays spec first <->
      Scalars assignment spec first /\ Result assignment graph arrays spec := by
  rw [Meaning, constraints_correct]
  apply and_congr_right
  intro facts
  have queries :
      VersionedIntervals.Realizes (interpret assignment graph)
        (IntervalQueries.schemas (localQueries assignment [suffix spec first, anchorQuery spec first])) arrays <->
      VersionedIntervals.Realizes (interpret assignment graph)
        (IntervalQueries.schemas (localQueries assignment [suffix spec first])) arrays /\
      VersionedIntervals.Realizes (interpret assignment graph)
        (IntervalQueries.schemas (localQueries assignment [anchorQuery spec first])) arrays := by
    simp [VersionedIntervals.Realizes, IntervalQueries.schemas, localQueries]
  rw [queries]
  rw [suffix_correct, anchor_correct assignment graph arrays spec first facts]
  have clip_value : natValue assignment first =
      min (natValue assignment spec.index) (natValue assignment spec.length) := by
    simp only [natValue, facts.clip, Int.toNat_natCast]
  have threshold : assignment.constant .int spec.threshold = (natValue assignment spec.threshold : Int) :=
    (Int.toNat_of_nonneg facts.source.2.2.1).symm
  rw [Result, LogMatchSummary.entry_value_result_iff]
  simp only [LogMatchSummary.StorageSummary, facts.bound, true_and, clip_value, threshold]
  exact and_comm

def install (original : Assignment) (spec : Spec size) (first : Nat) : Assignment :=
  ScalarExtension.install original first (Fin.cases
    (((min (natValue original spec.index) (natValue original spec.length)) : Nat) : Int)
    (fun _ : Fin 1 => ((natValue original spec.best - 1 : Nat) : Int)))

theorem install_outside (original : Assignment) (spec : Spec size) (first : Nat)
    (sort : Ty) (id : Nat) (outside : id < first \/ first + 2 <= id) :
    (install original spec first).constant sort id = original.constant sort id :=
  ScalarExtension.outside original first _ sort id outside

theorem install_unary (original : Assignment) (spec : Spec size) (first : Nat) :
    (install original spec first).unary = original.unary := rfl

theorem install_selectors (original : Assignment) (spec : Spec size) (first : Nat) :
    (install original spec first).selectors = original.selectors := rfl

theorem install_term (original : Assignment) (spec : Spec size) (first : Nat)
    {sort : Ty} (term : Term sort) (below : SymbolBounds.termMax term < first) :
    term.eval (install original spec first) = term.eval original :=
  ScalarExtension.eval_below original first _ term below

theorem install_graph (original : Assignment) (spec : Spec size) (first : Nat)
    (graph : SymbolicGraph roots .entry size) (below : TypedIntervalEncoding.graphMax graph < first) :
    interpret (install original spec first) graph = interpret original graph :=
  TypedJointPredicateEncoding.graph_congr _ _ first graph below (install_term original spec first)

theorem source_ids (spec : Spec size) (first : Nat) (below : spec.maximum < first) :
    spec.length < first /\ spec.index < first /\ spec.threshold < first /\ spec.best < first := by
  simpa only [Spec.maximum, max_lt_iff] using below

theorem install_values (original : Assignment) (spec : Spec size) (first : Nat) :
    (install original spec first).constant .int first =
      ((min (natValue original spec.index) (natValue original spec.length) : Nat) : Int) /\
    (install original spec first).constant .int (first + 1) =
      ((natValue original spec.best - 1 : Nat) : Int) :=
  And.intro (ScalarExtension.at_index original first _ (0 : Fin 2))
    (ScalarExtension.at_index original first _ (1 : Fin 2))

theorem install_source (original : Assignment) (spec : Spec size) (first : Nat)
    (below : spec.maximum < first) :
    Source (install original spec first) spec <-> Source original spec := by
  have bounds := source_ids spec first below
  simp only [Source, install_outside original spec first .int _ (Or.inl bounds.1),
    install_outside original spec first .int _ (Or.inl bounds.2.1),
    install_outside original spec first .int _ (Or.inl bounds.2.2.1),
    install_outside original spec first .int _ (Or.inl bounds.2.2.2)]

theorem install_result (original : Assignment) (spec : Spec size) (first : Nat)
    (graph : SymbolicGraph roots .entry size) (arrays : RootArrays roots EntryValue.Entry)
    (below : spec.maximum < first) (graph_below : TypedIntervalEncoding.graphMax graph < first) :
    Result (install original spec first) graph arrays spec <-> Result original graph arrays spec := by
  have bounds := source_ids spec first below
  simp only [Result, cells, install_graph original spec first graph graph_below, natValue,
    install_outside original spec first .int _ (Or.inl bounds.1),
    install_outside original spec first .int _ (Or.inl bounds.2.1),
    install_outside original spec first .int _ (Or.inl bounds.2.2.1),
    install_outside original spec first .int _ (Or.inl bounds.2.2.2)]

theorem installed_meaning_iff (original : Assignment) (spec : Spec size) (first : Nat)
    (graph : SymbolicGraph roots .entry size) (arrays : RootArrays roots EntryValue.Entry)
    (below : spec.maximum < first) (graph_below : TypedIntervalEncoding.graphMax graph < first) :
    Meaning (install original spec first) graph arrays spec first <->
      Source original spec /\ Result original graph arrays spec := by
  rw [meaning_correct, install_result original spec first graph arrays below graph_below]
  constructor
  next =>
    intro facts
    exact And.intro ((install_source original spec first below).mp facts.1.source) facts.2
  next =>
    intro facts
    have bounds := source_ids spec first below
    have length := install_outside original spec first .int _ (Or.inl bounds.1)
    have index := install_outside original spec first .int _ (Or.inl bounds.2.1)
    have best := install_outside original spec first .int _ (Or.inl bounds.2.2.2)
    refine And.intro ?_ facts.2
    refine
      { source := (install_source original spec first below).mpr facts.1
        clip := ?_
        anchor := ?_
        bound := ?_ }
    next => simpa only [natValue, length, index] using (install_values original spec first).1
    next => simpa only [natValue, best] using (install_values original spec first).2
    next =>
      have summary := (LogMatchSummary.entry_value_result_iff _ _ _ _ _).mp facts.2
      simpa only [natValue, length, index, best] using summary.1

def Context (assignment : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (clauses : List (Clause size))
    (arrays : RootArrays roots EntryValue.Entry) : Prop :=
  SmtScript.Holds assignment input /\ Domains assignment graph queries points /\
    Concrete assignment graph queries points arrays /\ Existentials assignment graph clauses arrays

-- The old compiler's zero boundary is above every caller symbol and metadata ID.
-- It is a reservation bound here, not an allocated or independently installed zero.
theorem install_context (original : Assignment) (spec : Spec size) (first : Nat)
    (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (clauses : List (Clause size)) (arrays : RootArrays roots EntryValue.Entry)
    (reserved : TypedJointPredicateEncoding.Witness.zero input graph queries points clauses <= first) :
    Context (install original spec first) input graph queries points clauses arrays <->
      Context original input graph queries points clauses arrays := by
  have bounds := TypedJointPredicateEncoding.allocation_bounds input graph queries points
  have old := Nat.le_trans (TypedJointPredicateEncoding.Witness.old_bound input graph queries points clauses) reserved
  have lift (id : Nat) (small : id < TypedJointPredicateEncoding.zeroId input graph queries points) :
      id < first := Nat.lt_of_lt_of_le small old
  have terms := fun {sort : Ty} (term : Term sort) below => install_term original spec first term below
  have graph_eq := install_graph original spec first graph (lift _ bounds.2.1)
  have query_eq : localQueries (install original spec first) queries = localQueries original queries := by
    apply List.map_congr_left
    intro query member
    exact TypedJointPredicateEncoding.query_congr _ _ first query
      (lift _ (Nat.lt_of_le_of_lt (TypedJointPredicateEncoding.query_bound queries query member) bounds.2.2.1)) terms
  have domains_eq : Domains (install original spec first) graph queries points <->
      Domains original graph queries points := by
    apply forall_congr'
    intro id
    apply forall_congr'
    intro member
    rw [install_outside original spec first .int id (Or.inl
      (lift id (TypedJointPredicateEncoding.metadata_bound input graph queries points id member)))]
  have points_eq :
      TypedIntervalEncoding.ObservationsHold (install original spec first)
        (IntervalReadback.actual (interpret original graph) arrays) points <->
      TypedIntervalEncoding.ObservationsHold original
        (IntervalReadback.actual (interpret original graph) arrays) points := by
    apply forall_congr'
    intro point
    apply forall_congr'
    intro member
    have small := lift _ (Nat.lt_of_le_of_lt (TypedIntervalEncoding.observation_bound points point member) bounds.2.2.2)
    have position := install_outside original spec first .int point.position
      (Or.inl (Nat.lt_of_le_of_lt (Nat.le_max_left _ _) small))
    have expected := terms point.expected (Nat.lt_of_le_of_lt (Nat.le_max_right _ _) small)
    simp only [natValue, position, expected]
  have witnesses_eq : Existentials (install original spec first) graph clauses arrays <->
      Existentials original graph clauses arrays := by
    apply forall_congr'
    intro index
    have small := TypedJointPredicateEncoding.Witness.new_bound input graph queries points clauses index
    have query_below := Nat.lt_of_lt_of_le small.1 reserved
    have same_query := TypedJointPredicateEncoding.query_congr _ _ first clauses[index.val].toQuery query_below terms
    have lower := install_outside original spec first .int clauses[index.val].lower
      (Or.inl (Nat.lt_of_le_of_lt clauses[index.val].toQuery.bounds.1 query_below))
    have upper := install_outside original spec first .int clauses[index.val].upper
      (Or.inl (Nat.lt_of_le_of_lt clauses[index.val].toQuery.bounds.2.1 query_below))
    have enable := terms clauses[index.val].enable (Nat.lt_of_lt_of_le small.2 reserved)
    have predicate := fun values => TypedJointPredicateEncoding.predicate_congr _ _ first clauses[index.val].predicate
      (Nat.lt_of_le_of_lt clauses[index.val].toQuery.bounds.2.2 query_below) values terms
    dsimp only
    rw [lower, upper, enable, same_query, graph_eq]
    simp only [predicate]
  have input_eq : SmtScript.Holds (install original spec first) input <-> SmtScript.Holds original input :=
    ScalarExtension.formula_below original first _ input (lift _ bounds.1)
  simp only [Context, Concrete, graph_eq, query_eq, input_eq, domains_eq, points_eq, witnesses_eq]

-- These are precisely the semantic arguments to one outer Witness invocation.
def Assembled (assignment : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (clauses : List (Clause size))
    (arrays : RootArrays roots EntryValue.Entry) (spec : Spec size) (first : Nat) : Prop :=
  Context assignment (input ++ constraints spec first) graph
    (suffix spec first :: anchorQuery spec first :: queries) points clauses arrays

theorem assembled_correct (assignment : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (clauses : List (Clause size))
    (arrays : RootArrays roots EntryValue.Entry) (spec : Spec size) (first : Nat) :
    Assembled assignment input graph queries points clauses arrays spec first <->
      Context assignment input graph queries points clauses arrays /\ Meaning assignment graph arrays spec first := by
  have concrete :
      Concrete assignment graph (suffix spec first :: anchorQuery spec first :: queries) points arrays <->
      VersionedIntervals.Realizes (interpret assignment graph)
        (IntervalQueries.schemas (localQueries assignment [suffix spec first, anchorQuery spec first])) arrays /\
      Concrete assignment graph queries points arrays := by
    simp [Concrete, VersionedIntervals.Realizes, IntervalQueries.schemas, localQueries, and_assoc]
  have domains :
      Domains assignment graph (suffix spec first :: anchorQuery spec first :: queries) points <->
      Domains assignment graph queries points /\
        0 <= assignment.constant .int spec.best /\ 0 <= assignment.constant .int first /\
        0 <= assignment.constant .int (first + 1) := by
    simp only [Domains, TypedJointPredicateEncoding.boundIds, List.flatMap_cons, suffix, anchorQuery]
    simp [or_imp, forall_and, and_assoc, and_left_comm, and_comm]
  have derived (holds : SmtScript.Holds assignment (constraints spec first)) :
      0 <= assignment.constant .int spec.best /\ 0 <= assignment.constant .int first /\
        0 <= assignment.constant .int (first + 1) := by
    have facts := (constraints_correct assignment spec first).mp holds
    exact And.intro facts.source.2.2.2
      (And.intro (by rw [facts.clip]; exact Int.natCast_nonneg _)
        (by rw [facts.anchor]; exact Int.natCast_nonneg _))
  unfold Assembled
  rw [Context, QueueEncoding.holds_append, concrete, domains]
  unfold Context Meaning
  tauto

theorem installed_assembled_iff (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (clauses : List (Clause size))
    (arrays : RootArrays roots EntryValue.Entry) (spec : Spec size) (first : Nat)
    (source_below : spec.maximum < first)
    (reserved : TypedJointPredicateEncoding.Witness.zero input graph queries points clauses <= first) :
    Assembled (install original spec first) input graph queries points clauses arrays spec first <->
      Context original input graph queries points clauses arrays /\
        Source original spec /\ Result original graph arrays spec := by
  have graph_below := Nat.lt_of_lt_of_le
    (TypedJointPredicateEncoding.allocation_bounds input graph queries points).2.1
    (Nat.le_trans (TypedJointPredicateEncoding.Witness.old_bound input graph queries points clauses) reserved)
  rw [assembled_correct, install_context original spec first input graph queries points clauses arrays reserved,
    installed_meaning_iff original spec first graph arrays source_below graph_below]

theorem assembled_exists_iff (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (clauses : List (Clause size)) (spec : Spec size) (first : Nat)
    (source_below : spec.maximum < first)
    (reserved : TypedJointPredicateEncoding.Witness.zero input graph queries points clauses <= first) :
    (exists original : Assignment, exists arrays : RootArrays roots EntryValue.Entry,
      Assembled original input graph queries points clauses arrays spec first) <->
    exists original : Assignment, exists arrays : RootArrays roots EntryValue.Entry,
      Context original input graph queries points clauses arrays /\
        Source original spec /\ Result original graph arrays spec := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro original witness =>
      cases witness with
      | intro arrays assembled =>
        have parts := (assembled_correct original input graph queries points clauses arrays spec first).mp assembled
        have reader := (meaning_correct original graph arrays spec first).mp parts.2
        exact Exists.intro original (Exists.intro arrays
          (And.intro parts.1 (And.intro reader.1.source reader.2)))
  next =>
    intro witness
    cases witness with
    | intro original witness =>
      cases witness with
      | intro arrays facts =>
        exact Exists.intro (install original spec first) (Exists.intro arrays
          ((installed_assembled_iff original input graph queries points clauses arrays spec first
            source_below reserved).mpr facts))

def encode (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (clauses : List (Clause size)) (spec : Spec size) (first : Nat) : SmtScript.Formula :=
  TypedJointPredicateEncoding.Witness.encode (input ++ constraints spec first) graph
    (suffix spec first :: anchorQuery spec first :: queries) points clauses

def render (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (clauses : List (Clause size)) (spec : Spec size) (first : Nat) : String :=
  TypedJointPredicateEncoding.Witness.render (input ++ constraints spec first) graph
    (suffix spec first :: anchorQuery spec first :: queries) points clauses

theorem encode_exists_iff (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (clauses : List (Clause size)) (spec : Spec size) (first : Nat)
    (source_below : spec.maximum < first)
    (reserved : TypedJointPredicateEncoding.Witness.zero input graph queries points clauses <= first) :
    (exists assignment : Assignment, SmtScript.Holds assignment
      (encode input graph queries points clauses spec first)) <->
    exists original : Assignment, exists arrays : RootArrays roots EntryValue.Entry,
      Context original input graph queries points clauses arrays /\
        Source original spec /\ Result original graph arrays spec := by
  rw [encode, TypedJointPredicateEncoding.Witness.encode_exists_iff]
  exact assembled_exists_iff input graph queries points clauses spec first source_below reserved

theorem rendered_exists_iff (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (clauses : List (Clause size)) (spec : Spec size) (first : Nat)
    (source_below : spec.maximum < first)
    (reserved : TypedJointPredicateEncoding.Witness.zero input graph queries points clauses <= first) :
    (exists assignment : Assignment, SmtScriptText.runText assignment
      (render input graph queries points clauses spec first) = some true) <->
    exists original : Assignment, exists arrays : RootArrays roots EntryValue.Entry,
      Context original input graph queries points clauses arrays /\
        Source original spec /\ Result original graph arrays spec := by
  rw [render, TypedJointPredicateEncoding.Witness.rendered_exists_iff]
  exact assembled_exists_iff input graph queries points clauses spec first source_below reserved

namespace Regression

def spec : Spec 1 := { version := 0, length := 0, index := 1, threshold := 2, best := 3 }

def graph : SymbolicGraph 1 .entry 1 := .push .empty (.root 0)

def frame (original : Assignment) (length index threshold best : Int) : Assignment :=
  ScalarExtension.install original 0
    (Fin.cases length (Fin.cases index (Fin.cases threshold (fun _ : Fin 1 => best))))

def unsorted : RootArrays 1 EntryValue.Entry :=
  fun _ position => { term := if position = 0 then 1 else if position = 1 then -5 else if position = 2 then -1 else 4
                      content := .signature }

def check (original : Assignment) (length index threshold best : Int) : Prop :=
  Meaning (install (frame original length index threshold best) spec 4) graph unsorted spec 4

theorem controls (original : Assignment) :
    check original 4 4 2 3 /\
    check original 4 100 2 3 /\
    check original 4 2 2 1 /\
    check original 4 0 0 0 /\
    check original 0 100 0 0 /\
    check original 4 100 0 0 /\
    check original 4 100 100 4 /\
    Not (check original 4 4 2 1) /\
    Not (check original 4 4 2 2) /\
    Not (check original (-1) 0 0 0) := by
  simp only [check, installed_meaning_iff _ spec 4 graph unsorted (by decide) (by decide)]
  unfold Source Result
  exact of_decide_eq_true rfl

theorem zero_term (original : Assignment) :
    Meaning (install (frame original 1 100 0 1) spec 4) graph
      (fun _ _ => { term := 0, content := .signature }) spec 4 := by
  rw [installed_meaning_iff _ spec 4 graph _ (by decide) (by decide)]
  unfold Source Result
  exact of_decide_eq_true rfl

def aliased : Spec 1 := { version := 0, length := 0, index := 0, threshold := 0, best := 0 }

theorem source_alias (original : Assignment) :
    Meaning (install (frame original 3 99 99 99) aliased 4) graph
      (fun _ _ => { term := -1, content := .signature }) aliased 4 := by
  rw [installed_meaning_iff _ aliased 4 graph _ (by decide) (by decide)]
  unfold Source Result
  exact of_decide_eq_true rfl

theorem shape :
    (constraints spec 4).length = 9 /\
    (constraints aliased 4).length = 6 /\
    (eligible spec).references = [0] /\
    (eligible spec).externalSymbols = [Smt.Symbol.constant .int 2] /\
    (anchorQuery spec 4).lower = 5 /\ (anchorQuery spec 4).upper = 3 /\
    (anchorQuery spec 4).predicate.references = [0] := by
  decide +kernel

theorem reservation_edges (original : Assignment) :
    (install original spec 4).constant .int 3 = original.constant .int 3 /\
    (install original spec 4).constant .int 6 = original.constant .int 6 /\
    (install original spec 4).unary = original.unary /\
    (install original spec 4).selectors = original.selectors :=
  And.intro (install_outside original spec 4 .int 3 (Or.inl (by decide)))
    (And.intro (install_outside original spec 4 .int 6 (Or.inr (by decide)))
      (And.intro rfl rfl))

end Regression

end CCFRaft.Sparse.LogMatchEncoding

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.LogMatchEncoding).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit LogMatchEncoding axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"LogMatchEncoding: {checked} declarations passed the allowed-axiom gate."
