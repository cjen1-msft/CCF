import Sparse.IntervalPredicate
import Sparse.SmtScriptText

set_option autoImplicit false

namespace CCFRaft.Sparse.IntervalQueryEncoding

open Smt (Assignment Term)
open IntervalPredicate (Operand Predicate Query)
open IntervalEncoding (InputNat SymbolicGraph natTerm natValue)
open IntervalReadback (Address Demand Reads actual)
open VersionedIntervals (RootArrays)

variable {roots size : Nat}

def operandIds : Operand size -> List Nat
  | .cell _ | .input (.literal _) => []
  | .input (.symbolic id) => [id]

def predicateIds : Predicate size -> List Nat
  | .eq left right | .ne left right | .le left right | .lt left right =>
    operandIds left ++ operandIds right

def boundIds (graph : SymbolicGraph roots size) (queries : List (Query size)) : List Nat :=
  graph.endpoints ++ queries.flatMap (fun query => [query.lower, query.upper])

def metadataIds (graph : SymbolicGraph roots size) (queries : List (Query size)) : List Nat :=
  boundIds graph queries ++ queries.flatMap (fun query => predicateIds query.predicate)

def reservedIds (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) : List Nat :=
  (SmtScript.symbols input).map QueueEncoding.symbolId ++ metadataIds graph queries

def zeroId (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) : Nat :=
  (reservedIds input graph queries).toFinset.sup id + 1

theorem reserved_below_zero (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (id : Nat)
    (present : Membership.mem (reservedIds input graph queries) id) :
    id < zeroId input graph queries := by
  have bound := Finset.le_sup (f := fun n : Nat => n) (List.mem_toFinset.mpr present)
  exact Nat.lt_succ_of_le bound

def setZero (original : Assignment) (zeroID : Nat) : Assignment where
  constant ty id :=
    match ty with
    | .bool => original.constant .bool id
    | .int => if id = zeroID then 0 else original.constant .int id
  unary := original.unary

theorem setZero_other (original : Assignment) (zeroID id : Nat) (different : Not (id = zeroID)) :
    (setZero original zeroID).constant .int id = original.constant .int id := by
  simp [setZero, different]

theorem term_setZero (original : Assignment) (zeroID : Nat) {ty : Smt.Ty} (term : Term ty)
    (below : forall symbol, Membership.mem (SmtScript.termSymbols term) symbol ->
      QueueEncoding.symbolId symbol < zeroID) :
    term.eval (setZero original zeroID) = term.eval original := by
  induction term with
  | boolean _ | integer _ => rfl
  | unknown ty id =>
    have small := below (.constant ty id) (by simp [SmtScript.termSymbols])
    have different : Not (id = zeroID) := by change id < zeroID at small; omega
    cases ty <;> simp [Term.eval, setZero, different]
  | app domain result id argument ih =>
    exact congrArg (original.unary domain result id)
      (ih (fun symbol present => below symbol (by simp [SmtScript.termSymbols, present])))
  | add left right ihl ihr
  | sub left right ihl ihr
  | le left right ihl ihr
  | equal left right ihl ihr
  | and left right ihl ihr
  | implies left right ihl ihr =>
    have hl := ihl (fun symbol present => below symbol (by simp [SmtScript.termSymbols, present]))
    have hr := ihr (fun symbol present => below symbol (by simp [SmtScript.termSymbols, present]))
    simp only [Term.eval, hl, hr]
  | not value ih => exact congrArg Bool.not (ih below)
  | ite condition yes no ihc ihy ihn =>
    have hc := ihc (fun symbol present => below symbol (by simp [SmtScript.termSymbols, present]))
    have hy := ihy (fun symbol present => below symbol (by simp [SmtScript.termSymbols, present]))
    have hn := ihn (fun symbol present => below symbol (by simp [SmtScript.termSymbols, present]))
    simp only [Term.eval, hc, hy, hn]

theorem input_setZero (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots size) (queries : List (Query size)) :
    SmtScript.Holds (setZero original (zeroId input graph queries)) input <->
      SmtScript.Holds original input := by
  have term_eq (term : Term .bool) (present : Membership.mem input term) :
      term.eval (setZero original (zeroId input graph queries)) = term.eval original := by
    apply term_setZero
    intro symbol member
    apply reserved_below_zero input graph queries
    apply List.mem_append.mpr
    apply Or.inl
    apply List.mem_map.mpr
    refine Exists.intro symbol (And.intro ?_ rfl)
    exact (SmtScript.symbol_coverage input symbol).mpr (Exists.intro term
      (And.intro present (by simpa only [SmtScript.lower_symbols] using member)))
  constructor
  next =>
    intro holds term present
    rw [<- term_eq term present]
    exact holds term present
  next =>
    intro holds term present
    rw [term_eq term present]
    exact holds term present

theorem metadata_setZero (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots size) (queries : List (Query size))
    (id : Nat) (present : Membership.mem (metadataIds graph queries) id) :
    (setZero original (zeroId input graph queries)).constant .int id =
      original.constant .int id := by
  apply setZero_other
  have small := reserved_below_zero input graph queries id (List.mem_append.mpr (Or.inr present))
  omega

def interpretedQueries (assignment : Assignment) (queries : List (Query size)) :
    List (IntervalQueries.LocalQuery size Int) :=
  queries.map (Query.toLocalQuery assignment)

def Domains (assignment : Assignment) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) : Prop :=
  forall id, Membership.mem (boundIds graph queries) id -> 0 <= assignment.constant .int id

def Realizes (assignment : Assignment) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (arrays : RootArrays roots Int) : Prop :=
  VersionedIntervals.Realizes (IntervalEncoding.interpret assignment graph)
    (IntervalQueries.schemas (interpretedQueries assignment queries)) arrays

def augmented (input : SmtScript.Formula) (zeroID : Nat) : SmtScript.Formula :=
  input ++ [.equal (natTerm zeroID) (.integer 0)]

def seeds (zeroID : Nat) (graph : SymbolicGraph roots size) (queries : List (Query size)) :
    List (Demand roots size) :=
  IntervalPredicate.requests (IntervalPredicate.cutIds zeroID graph queries) (queries.map Query.predicate)

def planned (zeroID : Nat) (graph : SymbolicGraph roots size) (queries : List (Query size)) :
    List (Demand roots size) :=
  IntervalDemandPlan.plan graph (seeds zeroID graph queries)

def guardTerm (base : Nat) (query : Query size) (position : Nat) : Term .bool :=
  .implies (.and (.le (natTerm query.lower) (natTerm position))
    (.not (.le (natTerm query.upper) (natTerm position))))
      (query.predicate.lower roots base position)

def guardFormula (base zeroID : Nat) (graph : SymbolicGraph roots size) (queries : List (Query size)) :
    SmtScript.Formula :=
  queries.flatMap fun query =>
    (IntervalPredicate.cutIds zeroID graph queries).map (guardTerm (roots := roots) base query)

def readFormula (base zeroID : Nat) (graph : SymbolicGraph roots size) (queries : List (Query size)) :
    SmtScript.Formula :=
  (planned zeroID graph queries).map
    (IntervalEncoding.readEquation base (IntervalEncoding.templates base graph)
      (IntervalEncoding.templates_size base graph))

def encode (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) : SmtScript.Formula :=
  let zeroID := zeroId input graph queries
  let initial := augmented input zeroID
  let base := QueueEncoding.freshBase initial
  let cuts := IntervalPredicate.cutIds zeroID graph queries
  let requests := IntervalPredicate.requests cuts (queries.map Query.predicate)
  let table := IntervalEncoding.templates base graph
  initial ++ (boundIds graph queries).dedup.map (fun id => Term.le (.integer 0) (natTerm id)) ++
    (IntervalDemandPlan.plan graph requests).map
      (IntervalEncoding.readEquation base table (IntervalEncoding.templates_size base graph)) ++
    queries.flatMap (fun query => cuts.map (guardTerm (roots := roots) base query))

def render (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) : String :=
  SmtScript.render (encode input graph queries)

theorem augmented_correct (assignment : Assignment) (input : SmtScript.Formula) (zeroID : Nat) :
    SmtScript.Holds assignment (augmented input zeroID) <->
      SmtScript.Holds assignment input /\ assignment.constant .int zeroID = 0 := by
  rw [augmented, QueueEncoding.holds_append]
  simp [SmtScript.Holds, natTerm, Term.eval]

theorem bounds_correct (assignment : Assignment) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) :
    SmtScript.Holds assignment ((boundIds graph queries).dedup.map
      (fun id => Term.le (.integer 0) (natTerm id))) <-> Domains assignment graph queries := by
  simp [SmtScript.Holds, Domains, natTerm, Term.eval]

theorem cut_nonnegative (assignment : Assignment) (zeroID : Nat) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (zero_value : assignment.constant .int zeroID = 0)
    (domains : Domains assignment graph queries) (id : Nat)
    (present : Membership.mem (IntervalPredicate.cutIds zeroID graph queries) id) :
    0 <= assignment.constant .int id := by
  have member := (IntervalPredicate.cutIds_membership zeroID graph queries id).mp present
  cases List.mem_cons.mp member with
  | inl same => subst id; rw [zero_value]
  | inr bound => exact domains id bound

theorem operand_congr (left right : Assignment) (operand : Operand size) (values : Fin size -> Int)
    (agree : forall id, Membership.mem (operandIds operand) id ->
      left.constant .int id = right.constant .int id) :
    operand.eval left values = operand.eval right values := by
  cases operand with
  | cell _ => rfl
  | input value =>
    cases value with
    | literal _ => rfl
    | symbolic id => exact agree id (by simp [operandIds])

theorem predicate_congr (left right : Assignment) (predicate : Predicate size)
    (agree : forall id, Membership.mem (predicateIds predicate) id ->
      left.constant .int id = right.constant .int id) :
    predicate.eval left = predicate.eval right := by
  funext values
  cases predicate <;> rename_i first second
  all_goals
    have h1 := operand_congr left right first values
      (fun id present => agree id (List.mem_append.mpr (Or.inl present)))
    have h2 := operand_congr left right second values
      (fun id present => agree id (List.mem_append.mpr (Or.inr present)))
    simp only [Predicate.eval, h1, h2]

theorem interpret_congr (left right : Assignment) (graph : SymbolicGraph roots size)
    (agree : forall id, Membership.mem graph.endpoints id ->
      left.constant .int id = right.constant .int id) :
    IntervalEncoding.interpret left graph = IntervalEncoding.interpret right graph := by
  induction graph with
  | empty => rfl
  | push previous node ih =>
    have earlier := ih (fun id present => agree id (List.mem_append.mpr (Or.inl present)))
    cases node with
    | root _ => simp only [IntervalEncoding.interpret, IntervalEncoding.interpretNode, earlier]
    | constant _ => simp only [IntervalEncoding.interpret, IntervalEncoding.interpretNode, earlier]
    | splice lower upper inside outside =>
      have hl := agree lower (by simp [VersionedIntervals.Graph.endpoints, VersionedIntervals.Version.endpoints])
      have hu := agree upper (by simp [VersionedIntervals.Graph.endpoints, VersionedIntervals.Version.endpoints])
      simp only [IntervalEncoding.interpret, IntervalEncoding.interpretNode, earlier, natValue, hl, hu]

theorem queries_congr (left right : Assignment) (graph : SymbolicGraph roots size)
    (queries : List (Query size))
    (agree : forall id, Membership.mem (metadataIds graph queries) id ->
      left.constant .int id = right.constant .int id) :
    interpretedQueries left queries = interpretedQueries right queries := by
  apply List.map_congr_left
  intro query present
  have hl := agree query.lower (List.mem_append.mpr (Or.inl (List.mem_append.mpr (Or.inr
    (List.mem_flatMap.mpr (Exists.intro query (And.intro present (by simp))))))))
  have hu := agree query.upper (List.mem_append.mpr (Or.inl (List.mem_append.mpr (Or.inr
    (List.mem_flatMap.mpr (Exists.intro query (And.intro present (by simp))))))))
  have hp := predicate_congr left right query.predicate (fun id member => agree id
    (List.mem_append.mpr (Or.inr
      (List.mem_flatMap.mpr (Exists.intro query (And.intro present member))))))
  have point_eq (values : Fin size -> Int) := congrFun hp values
  simp only [Query.toLocalQuery, natValue, hl, hu, point_eq]

theorem domains_congr (left right : Assignment) (graph : SymbolicGraph roots size)
    (queries : List (Query size))
    (agree : forall id, Membership.mem (metadataIds graph queries) id ->
      left.constant .int id = right.constant .int id) :
    Domains left graph queries <-> Domains right graph queries := by
  unfold Domains
  apply forall_congr'
  intro id
  apply forall_congr'
  intro present
  rw [agree id (List.mem_append.mpr (Or.inl present))]

theorem realizes_congr (left right : Assignment) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (arrays : RootArrays roots Int)
    (agree : forall id, Membership.mem (metadataIds graph queries) id ->
      left.constant .int id = right.constant .int id) :
    Realizes left graph queries arrays <-> Realizes right graph queries arrays := by
  rw [Realizes, Realizes, queries_congr left right graph queries agree,
    interpret_congr left right graph (fun id present =>
      agree id (List.mem_append.mpr (Or.inl (List.mem_append.mpr (Or.inl present)))))]

theorem endpoints_interpret (assignment : Assignment) (graph : SymbolicGraph roots size) :
    (IntervalEncoding.interpret assignment graph).endpoints = graph.endpoints.map (natValue assignment) := by
  induction graph with
  | empty => rfl
  | push previous node ih =>
    cases node <;>
      simp [IntervalEncoding.interpret, IntervalEncoding.interpretNode, VersionedIntervals.Graph.endpoints,
        VersionedIntervals.Version.endpoints, ih]

theorem cutList_interpret (assignment : Assignment) (zeroID : Nat) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (zero_value : assignment.constant .int zeroID = 0) :
    IntervalQueries.cutList (IntervalEncoding.interpret assignment graph)
      (interpretedQueries assignment queries) =
    (zeroID :: boundIds graph queries).map (natValue assignment) := by
  simp [IntervalQueries.cutList, IntervalQueries.schemas, interpretedQueries,
    Query.toLocalQuery, boundIds, endpoints_interpret, List.map_flatMap, List.flatMap_map,
    Function.comp_def, natValue, zero_value]

theorem cut_image (assignment : Assignment) (zeroID : Nat) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (zero_value : assignment.constant .int zeroID = 0) (position : Nat) :
    Membership.mem (VersionedIntervals.cuts (IntervalEncoding.interpret assignment graph)
      (IntervalQueries.schemas (interpretedQueries assignment queries))) position <->
    exists id, Membership.mem (IntervalPredicate.cutIds zeroID graph queries) id /\
      natValue assignment id = position := by
  rw [<- IntervalQueries.mem_cutList, cutList_interpret assignment zeroID graph queries zero_value]
  simp only [List.mem_map, IntervalPredicate.cutIds, List.mem_dedup, boundIds]

theorem seed_requested (zeroID : Nat) (graph : SymbolicGraph roots size) (queries : List (Query size))
    (id : Nat) (cut : Membership.mem (IntervalPredicate.cutIds zeroID graph queries) id)
    (query : Query size) (present : Membership.mem queries query) (version : Fin size)
    (referenced : Membership.mem query.predicate.references version) :
    Membership.mem (seeds zeroID graph queries) (.version version, id) := by
  apply List.mem_map.mpr
  refine Exists.intro (id, version) (And.intro ?_ rfl)
  apply List.mem_product.mpr
  refine And.intro (List.mem_dedup.mpr cut) ?_
  apply (IntervalPredicate.references_membership _ version).mpr
  exact Exists.intro query.predicate (And.intro
    (List.mem_map.mpr (Exists.intro query (And.intro present rfl))) referenced)

theorem seed_position (zeroID : Nat) (graph : SymbolicGraph roots size) (queries : List (Query size))
    (demand : Demand roots size) (present : Membership.mem (seeds zeroID graph queries) demand) :
    Membership.mem (IntervalPredicate.cutIds zeroID graph queries) demand.2 := by
  cases List.mem_map.mp present with
  | intro pair spec =>
    cases spec.2
    exact List.mem_dedup.mp (List.mem_product.mp spec.1).1

theorem planned_position (zeroID : Nat) (graph : SymbolicGraph roots size) (queries : List (Query size))
    (demand : Demand roots size) (present : Membership.mem (planned zeroID graph queries) demand) :
    Membership.mem (IntervalPredicate.cutIds zeroID graph queries) demand.2 := by
  apply (IntervalDemandPlan.walk_spec (IntervalDemandPlan.table graph) [] (seeds zeroID graph queries)).minimal
    (fun cell => Membership.mem (IntervalPredicate.cutIds zeroID graph queries) cell.2) ?_ ?_
    (seed_position zeroID graph queries) demand present
  next =>
    intro cell member child dependency
    cases List.mem_map.mp dependency with
    | intro address spec => cases spec.2; exact member
  next => intro cell member; simp at member

def semanticDemands (assignment : Assignment) (zeroID : Nat) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) : Finset (Demand roots size) :=
  (planned zeroID graph queries).toFinset.image (fun cell => (cell.1, natValue assignment cell.2))

theorem semantic_closed (assignment : Assignment) (zeroID : Nat) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) :
    IntervalReadback.Closed (IntervalEncoding.interpret assignment graph)
      (semanticDemands assignment zeroID graph queries) := by
  intro address position present child dependency
  cases Finset.mem_image.mp present with
  | intro demand spec =>
    cases spec.2
    apply Finset.mem_image.mpr
    refine Exists.intro (child, demand.2) (And.intro ?_ rfl)
    exact IntervalDemandPlan.plan_closed graph (seeds zeroID graph queries) demand.1 demand.2 spec.1
      child (by simpa only [IntervalEncoding.dependencies_interpret] using dependency)

theorem request_covered (assignment : Assignment) (zeroID : Nat) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (zero_value : assignment.constant .int zeroID = 0)
    (demand : Demand roots size)
    (present : Membership.mem (IntervalQueries.requests (IntervalEncoding.interpret assignment graph)
      (interpretedQueries assignment queries)) demand) :
    Membership.mem (semanticDemands assignment zeroID graph queries) demand := by
  cases List.mem_flatMap.mp present with
  | intro position cut_spec =>
    cases List.mem_flatMap.mp cut_spec.2 with
    | intro localQuery query_spec =>
      cases List.mem_map.mp query_spec.1 with
      | intro query original =>
        cases original.2
        cases List.mem_map.mp query_spec.2 with
        | intro version reference_spec =>
          cases reference_spec.2
          have cut := (IntervalQueries.mem_cutList _ _ position).mp cut_spec.1
          cases (cut_image assignment zeroID graph queries zero_value position).mp cut with
          | intro id id_spec =>
            apply Finset.mem_image.mpr
            refine Exists.intro (.version version, id) (And.intro ?_ ?_)
            next =>
              apply List.mem_toFinset.mpr
              exact IntervalDemandPlan.plan_includes graph (seeds zeroID graph queries) _
                (seed_requested zeroID graph queries id id_spec.1 query original.1 version reference_spec.1)
            next => simp only [id_spec.2]

theorem equation_correct (assignment : Assignment) (base : Nat) (graph : SymbolicGraph roots size)
    (demand : Demand roots size) (nonnegative : 0 <= assignment.constant .int demand.2) :
    (IntervalEncoding.readEquation base (IntervalEncoding.templates base graph)
      (IntervalEncoding.templates_size base graph) demand).eval assignment = true <->
    IntervalReadback.Equation (IntervalEncoding.interpret assignment graph)
      (IntervalEncoding.reads assignment base) demand.1 (natValue assignment demand.2) := by
  cases demand with
  | mk address position =>
    cases address with
    | root _ => simp [IntervalEncoding.readEquation, IntervalReadback.Equation, Term.eval]
    | version version =>
      simp only [IntervalEncoding.readEquation, IntervalEncoding.templates_get, Term.eval, decide_eq_true_eq]
      rw [IntervalEncoding.readRef_eval assignment base _ position nonnegative,
        IntervalEncoding.nodeTerm_eval assignment graph base version position nonnegative]
      rfl

theorem read_correct (assignment : Assignment) (base zeroID : Nat) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (zero_value : assignment.constant .int zeroID = 0)
    (domains : Domains assignment graph queries) :
    SmtScript.Holds assignment (readFormula base zeroID graph queries) <->
    IntervalReadback.Equations (IntervalEncoding.interpret assignment graph)
      (semanticDemands assignment zeroID graph queries) (IntervalEncoding.reads assignment base) := by
  have point (demand : Demand roots size) (present : Membership.mem (planned zeroID graph queries) demand) :=
    equation_correct assignment base graph demand
      (cut_nonnegative assignment zeroID graph queries zero_value domains demand.2
        (planned_position zeroID graph queries demand present))
  constructor
  next =>
    intro holds address position present
    cases Finset.mem_image.mp present with
    | intro demand spec =>
      cases spec.2
      exact (point demand (List.mem_toFinset.mp spec.1)).mp (holds _
        (List.mem_map.mpr (Exists.intro demand (And.intro (List.mem_toFinset.mp spec.1) rfl))))
  next =>
    intro equations term present
    cases List.mem_map.mp present with
    | intro demand spec =>
      rw [<- spec.2]
      apply (point demand spec.1).mpr
      exact equations _ _ (Finset.mem_image.mpr
        (Exists.intro demand (And.intro (List.mem_toFinset.mpr spec.1) rfl)))

theorem guard_correct (assignment : Assignment) (base : Nat) (query : Query size) (id : Nat)
    (nonnegative : 0 <= assignment.constant .int id) :
    (guardTerm (roots := roots) base query id).eval assignment = true <->
      (query.toLocalQuery assignment).toQuery.Inside (natValue assignment id) ->
      query.predicate.eval assignment (fun version =>
        IntervalEncoding.reads assignment base (Address.version (roots := roots) version)
          (natValue assignment id)) = true := by
  simp [guardTerm, Term.eval, Predicate.lower_correct _ assignment roots base id nonnegative,
    Query.toLocalQuery, VersionedIntervals.Query.Inside, natTerm, natValue,
    Int.toNat_of_nonneg nonnegative]
  by_cases lower : assignment.constant .int query.lower <= assignment.constant .int id <;>
    by_cases upper : assignment.constant .int id < assignment.constant .int query.upper <;>
      simp_all

theorem guards_correct (assignment : Assignment) (base zeroID : Nat) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (zero_value : assignment.constant .int zeroID = 0)
    (domains : Domains assignment graph queries) :
    SmtScript.Holds assignment (guardFormula base zeroID graph queries) <->
    IntervalQueries.CutPredicates (IntervalEncoding.interpret assignment graph)
      (interpretedQueries assignment queries) (IntervalEncoding.reads assignment base) := by
  constructor
  next =>
    intro holds localQuery present cut active
    cases List.mem_map.mp present with
    | intro query spec =>
      cases spec.2
      cases (cut_image assignment zeroID graph queries zero_value cut.val).mp cut.property with
      | intro id id_spec =>
        have guarded := (guard_correct (roots := roots) assignment base query id
          (cut_nonnegative assignment zeroID graph queries zero_value domains id id_spec.1)).mp
            (holds _ (List.mem_flatMap.mpr (Exists.intro query (And.intro spec.1
              (List.mem_map.mpr (Exists.intro id (And.intro id_spec.1 rfl)))))))
        rw [id_spec.2] at guarded
        exact guarded active
  next =>
    intro valid term present
    cases List.mem_flatMap.mp present with
    | intro query query_spec =>
      cases List.mem_map.mp query_spec.2 with
      | intro id id_spec =>
        rw [<- id_spec.2]
        apply (guard_correct (roots := roots) assignment base query id
          (cut_nonnegative assignment zeroID graph queries zero_value domains id id_spec.1)).mpr
        exact valid (query.toLocalQuery assignment)
          (List.mem_map.mpr (Exists.intro query (And.intro query_spec.1 rfl)))
          (Subtype.mk (natValue assignment id)
            ((cut_image assignment zeroID graph queries zero_value _).mpr
              (Exists.intro id (And.intro id_spec.1 rfl))))

def Semantics (assignment : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) : Prop :=
  let zeroID := zeroId input graph queries
  let base := QueueEncoding.freshBase (augmented input zeroID)
  SmtScript.Holds assignment input /\ assignment.constant .int zeroID = 0 /\
    Domains assignment graph queries /\
    IntervalReadback.Equations (IntervalEncoding.interpret assignment graph)
      (semanticDemands assignment zeroID graph queries) (IntervalEncoding.reads assignment base) /\
    IntervalQueries.CutPredicates (IntervalEncoding.interpret assignment graph)
      (interpretedQueries assignment queries) (IntervalEncoding.reads assignment base)

theorem encode_correct (assignment : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots size) (queries : List (Query size)) :
    SmtScript.Holds assignment (encode input graph queries) <->
      Semantics assignment input graph queries := by
  let zeroID := zeroId input graph queries
  let base := QueueEncoding.freshBase (augmented input zeroID)
  change SmtScript.Holds assignment (augmented input zeroID ++
    (boundIds graph queries).dedup.map (fun id => Term.le (.integer 0) (natTerm id)) ++
    readFormula base zeroID graph queries ++ guardFormula base zeroID graph queries) <-> _
  simp only [QueueEncoding.holds_append, augmented_correct, bounds_correct]
  constructor
  next =>
    intro valid
    exact And.intro valid.1.1.1.1 (And.intro valid.1.1.1.2 (And.intro valid.1.1.2
      (And.intro
        ((read_correct assignment base zeroID graph queries valid.1.1.1.2 valid.1.1.2).mp valid.1.2)
        ((guards_correct assignment base zeroID graph queries valid.1.1.1.2 valid.1.1.2).mp valid.2))))
  next =>
    intro valid
    exact And.intro (And.intro (And.intro (And.intro valid.1 valid.2.1) valid.2.2.1)
      ((read_correct assignment base zeroID graph queries valid.2.1 valid.2.2.1).mpr valid.2.2.2.1))
      ((guards_correct assignment base zeroID graph queries valid.2.1 valid.2.2.1).mpr valid.2.2.2.2)

theorem encode_sound (assignment : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots size) (queries : List (Query size))
    (holds : SmtScript.Holds assignment (encode input graph queries)) :
    SmtScript.Holds assignment input /\ Domains assignment graph queries /\
      exists arrays : RootArrays roots Int, Realizes assignment graph queries arrays := by
  have valid := (encode_correct assignment input graph queries).mp holds
  refine And.intro valid.1 (And.intro valid.2.2.1 ?_)
  have compiled : IntervalQueries.Compiled (IntervalEncoding.interpret assignment graph)
      (interpretedQueries assignment queries)
      (IntervalEncoding.reads assignment (QueueEncoding.freshBase
        (augmented input (zeroId input graph queries)))) := by
    refine And.intro ?_ valid.2.2.2.2
    intro address position present
    apply valid.2.2.2.1 address position
    apply IntervalDemandPlan.plan_minimal (IntervalEncoding.interpret assignment graph) _ _
      (semantic_closed assignment (zeroId input graph queries) graph queries)
      (request_covered assignment (zeroId input graph queries) graph queries valid.2.1)
      (address, position) (List.mem_toFinset.mp present)
  cases IntervalQueries.compiled_realizes (IntervalEncoding.interpret assignment graph)
      (interpretedQueries assignment queries) _ compiled with
  | intro arrays spec => exact Exists.intro arrays spec.1

def install (original : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (arrays : RootArrays roots Int) : Assignment :=
  let zeroID := zeroId input graph queries
  IntervalEncoding.install (setZero original zeroID) (augmented input zeroID) graph arrays

-- This exclusive end includes the spare slot used by the existing UF installer.
def nextFunctionId (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) : Nat :=
  QueueEncoding.freshBase (augmented input (zeroId input graph queries)) + roots + size + 1

theorem install_metadata (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots size) (queries : List (Query size)) (arrays : RootArrays roots Int)
    (id : Nat) (present : Membership.mem (metadataIds graph queries) id) :
    (install original input graph queries arrays).constant .int id = original.constant .int id :=
  metadata_setZero original input graph queries id present

theorem install_input_preserved (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots size) (queries : List (Query size)) (arrays : RootArrays roots Int) :
    SmtScript.Holds (install original input graph queries arrays) input <->
      SmtScript.Holds original input := by
  have term_preserved (term : Term .bool) (present : Membership.mem input term) :
      term.eval (install original input graph queries arrays) =
        term.eval (setZero original (zeroId input graph queries)) := by
    apply QueueEncoding.eval_install
    intro symbol member
    apply QueueEncoding.input_symbol_bound (augmented input (zeroId input graph queries))
    apply (SmtScript.symbol_coverage _ _).mpr
    exact Exists.intro term (And.intro (List.mem_append.mpr (Or.inl present))
      (by simpa only [SmtScript.lower_symbols] using member))
  rw [<- input_setZero original input graph queries]
  constructor
  next =>
    intro holds term present
    rw [<- term_preserved term present]
    exact holds term present
  next =>
    intro holds term present
    rw [term_preserved term present]
    exact holds term present

theorem install_satisfies (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots size) (queries : List (Query size)) (arrays : RootArrays roots Int)
    (input_holds : SmtScript.Holds original input) (domains : Domains original graph queries)
    (realizes : Realizes original graph queries arrays) :
    SmtScript.Holds (install original input graph queries arrays) (encode input graph queries) := by
  let zeroID := zeroId input graph queries
  let initialized := setZero original zeroID
  let finished := install original input graph queries arrays
  have agree := install_metadata original input graph queries arrays
  have new_domains := (domains_congr finished original graph queries agree).mpr domains
  have new_realizes := (realizes_congr finished original graph queries arrays agree).mpr realizes
  have read_exact :
      IntervalEncoding.reads finished (QueueEncoding.freshBase (augmented input zeroID)) =
        actual (IntervalEncoding.interpret finished graph) arrays := by
    change IntervalEncoding.reads
      (IntervalEncoding.install initialized (augmented input zeroID) graph arrays) _ = _
    rw [IntervalEncoding.reads_install]
    simp only [finished, install, IntervalEncoding.install, IntervalEncoding.interpret_install]
    rfl
  apply (encode_correct finished input graph queries).mpr
  refine And.intro ((install_input_preserved original input graph queries arrays).mpr input_holds)
    (And.intro (by simp [finished, install, IntervalEncoding.install, QueueEncoding.installCounts, setZero])
      (And.intro new_domains (And.intro ?_ ?_)))
  next =>
    rw [read_exact]
    intro address position _
    exact IntervalReadback.actual_equation (IntervalEncoding.interpret finished graph) arrays address position
  next =>
    rw [read_exact]
    exact (IntervalQueries.realizes_compiled (IntervalEncoding.interpret finished graph)
      (interpretedQueries finished queries) arrays new_realizes).2

theorem encode_exists_iff (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) :
    (exists assignment : Assignment, SmtScript.Holds assignment (encode input graph queries)) <->
    (exists original : Assignment, exists arrays : RootArrays roots Int,
      SmtScript.Holds original input /\ Domains original graph queries /\
        Realizes original graph queries arrays) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro assignment holds =>
      have sound := encode_sound assignment input graph queries holds
      cases sound.2.2 with
      | intro arrays valid =>
        exact Exists.intro assignment (Exists.intro arrays
          (And.intro sound.1 (And.intro sound.2.1 valid)))
  next =>
    intro witness
    cases witness with
    | intro original witness =>
      cases witness with
      | intro arrays spec =>
        exact Exists.intro (install original input graph queries arrays)
          (install_satisfies original input graph queries arrays spec.1 spec.2.1 spec.2.2)

theorem rendered_exists_iff (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) :
    (exists assignment : Assignment,
      SmtScriptText.runText assignment (render input graph queries) = some true) <->
    (exists original : Assignment, exists arrays : RootArrays roots Int,
      SmtScript.Holds original input /\ Domains original graph queries /\
        Realizes original graph queries arrays) := by
  simp only [render, <- SmtScriptText.formula_text_iff]
  exact encode_exists_iff input graph queries

private def regressionAssignment (lower upper : Nat) : Assignment where
  constant ty id :=
    match ty with
    | .bool => false
    | .int => if id = 2 then (lower : Int) else if id = 3 then (upper : Int) else 0
  unary _ result _ _ := match result with | .bool => false | .int => 0

private def falseQuery : Query 0 :=
  { lower := 2, upper := 3, predicate := .eq (.input (.literal 0)) (.input (.literal 1)) }

theorem empty_or_reversed_regression (lower upper : Nat) (reversed : upper <= lower) :
    exists assignment : Assignment,
      SmtScriptText.runText assignment
        (render [] (VersionedIntervals.Graph.empty : SymbolicGraph 0 0) [falseQuery]) = some true := by
  apply (rendered_exists_iff _ _ _).mpr
  refine Exists.intro (regressionAssignment lower upper) (Exists.intro (fun root => Fin.elim0 root)
    (And.intro (by simp [SmtScript.Holds]) (And.intro ?_ ?_)))
  next =>
    intro id present
    simp [boundIds, VersionedIntervals.Graph.endpoints, falseQuery] at present
    cases present with
    | inl same => subst id; simp [regressionAssignment]
    | inr same => subst id; simp [regressionAssignment]
  next =>
    intro query present index active
    have same : query = (falseQuery.toLocalQuery (regressionAssignment lower upper)).toQuery := by
      simpa [IntervalQueries.schemas, interpretedQueries] using present
    subst query
    simp [Query.toLocalQuery, falseQuery, VersionedIntervals.Query.Inside, natValue,
      regressionAssignment] at active
    omega

theorem aliased_bounds_regression :
    exists assignment : Assignment,
      SmtScriptText.runText assignment
        (render [.equal (natTerm 2) (natTerm 3)]
          (VersionedIntervals.Graph.empty : SymbolicGraph 0 0) [falseQuery]) = some true := by
  apply (rendered_exists_iff _ _ _).mpr
  refine Exists.intro (regressionAssignment 7 7) (Exists.intro (fun root => Fin.elim0 root)
    (And.intro ?_ (And.intro ?_ ?_)))
  next => simp [SmtScript.Holds, natTerm, Term.eval, regressionAssignment]
  next =>
    intro id present
    simp [boundIds, VersionedIntervals.Graph.endpoints, falseQuery] at present
    cases present with
    | inl same => subst id; simp [regressionAssignment]
    | inr same => subst id; simp [regressionAssignment]
  next =>
    intro query present index active
    have same : query = (falseQuery.toLocalQuery (regressionAssignment 7 7)).toQuery := by
      simpa [IntervalQueries.schemas, interpretedQueries] using present
    subst query
    simp [Query.toLocalQuery, falseQuery, VersionedIntervals.Query.Inside, natValue,
      regressionAssignment] at active
    omega

theorem metadata_reservation_regression :
    zeroId [] (VersionedIntervals.Graph.empty : SymbolicGraph 0 0)
      [{ lower := 2, upper := 3,
         predicate := .eq (.input (.symbolic 70)) (.input (.literal 0)) }] = 71 := by
  decide

private def pointBound (id : Nat) (value : Int) : Term .bool :=
  .equal (natTerm id) (.integer value)

private theorem holds_pointBound (assignment : Assignment) (id : Nat) (value : Int)
    (holds : (pointBound id value).eval assignment = true) :
    assignment.constant .int id = value := by
  simpa [pointBound, natTerm, Term.eval] using holds

theorem nonempty_false_regression :
    Not (exists assignment : Assignment, SmtScriptText.runText assignment
      (render [pointBound 2 0, pointBound 3 1]
        (VersionedIntervals.Graph.empty : SymbolicGraph 0 0) [falseQuery]) = some true) := by
  intro witness
  cases (rendered_exists_iff _ _ _).mp witness with
  | intro assignment witness =>
    cases witness with
    | intro arrays spec =>
      have lower := holds_pointBound assignment 2 0 (spec.1 _ (by simp))
      have upper := holds_pointBound assignment 3 1 (spec.1 _ (by simp))
      have impossible := spec.2.2 (falseQuery.toLocalQuery assignment).toQuery
        (by simp [IntervalQueries.schemas, interpretedQueries]) 0
        (by simp [falseQuery, Query.toLocalQuery, VersionedIntervals.Query.Inside, natValue, lower, upper])
      change decide ((0 : Int) = 1) = true at impossible
      contradiction

private def sharedGraph : SymbolicGraph 1 2 :=
  .push (.push .empty (.root 0)) (.root 0)

private def outerQuery : Query 2 :=
  { lower := 2, upper := 3, predicate := .eq (.cell 0) (.input (.literal 0)) }

private def innerQuery : Query 2 :=
  { lower := 4, upper := 5, predicate := .eq (.cell 1) (.input (.literal 1)) }

theorem overlapping_shared_root_regression :
    Not (exists assignment : Assignment, SmtScriptText.runText assignment
      (render [pointBound 2 0, pointBound 3 10, pointBound 4 5, pointBound 5 6]
        sharedGraph [outerQuery, innerQuery]) = some true) := by
  intro witness
  cases (rendered_exists_iff _ _ _).mp witness with
  | intro assignment witness =>
    cases witness with
    | intro arrays spec =>
      have lower1 := holds_pointBound assignment 2 0 (spec.1 _ (by simp))
      have upper1 := holds_pointBound assignment 3 10 (spec.1 _ (by simp))
      have lower2 := holds_pointBound assignment 4 5 (spec.1 _ (by simp))
      have upper2 := holds_pointBound assignment 5 6 (spec.1 _ (by simp))
      have first := spec.2.2 (outerQuery.toLocalQuery assignment).toQuery
        (by simp [IntervalQueries.schemas, interpretedQueries]) 5
        (by simp [outerQuery, Query.toLocalQuery, VersionedIntervals.Query.Inside, natValue, lower1, upper1])
      have second := spec.2.2 (innerQuery.toLocalQuery assignment).toQuery
        (by simp [IntervalQueries.schemas, interpretedQueries]) 5
        (by simp [innerQuery, Query.toLocalQuery, VersionedIntervals.Query.Inside, natValue, lower2, upper2])
      have first_value : arrays 0 5 = 0 := of_decide_eq_true first
      have second_value : arrays 0 5 = 1 := of_decide_eq_true second
      omega

end CCFRaft.Sparse.IntervalQueryEncoding

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.IntervalQueryEncoding).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse.IntervalQueryEncoding: allowed-axiom gate passed for {checked} declarations."

#print axioms CCFRaft.Sparse.IntervalQueryEncoding.install_metadata
#print axioms CCFRaft.Sparse.IntervalQueryEncoding.install_input_preserved
#print axioms CCFRaft.Sparse.IntervalQueryEncoding.rendered_exists_iff
#print axioms CCFRaft.Sparse.IntervalQueryEncoding.overlapping_shared_root_regression
