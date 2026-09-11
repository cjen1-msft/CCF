import Sparse.EntryPredicate
import Sparse.TypedIntervalReadBlock
import Sparse.JointIntervalCompletion
import Sparse.IntervalQueryEncoding

set_option autoImplicit false

namespace CCFRaft.Sparse.TypedJointPredicateEncoding

open Smt (Assignment Term Ty)
open EntryPredicate (Operand Predicate Query)
open IntervalEncoding (InputNat natTerm natValue)
open IntervalReadback (Address Demand Reads actual)
open TypedIntervalEncoding (SymbolicGraph Observation interpret reads readRef)
open VersionedIntervals (RootArrays)

variable {roots size : Nat} {ty : Ty}

def queryMax : List (Query size) -> Nat
  | [] => 0
  | query :: rest => max query.externalMax (queryMax rest)

def zeroId (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry)) : Nat :=
  max (SymbolBounds.formulaMax input)
    (max (TypedIntervalEncoding.graphMax graph) (max (queryMax queries) (TypedIntervalEncoding.observationMax points))) + 1

def first (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry)) : Nat :=
  zeroId input graph queries points + 1

def nextFunctionId (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry)) : Nat :=
  first input graph queries points + roots + size

theorem allocation_bounds (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry)) :
    SymbolBounds.formulaMax input < zeroId input graph queries points /\
    TypedIntervalEncoding.graphMax graph < zeroId input graph queries points /\
    queryMax queries < zeroId input graph queries points /\
    TypedIntervalEncoding.observationMax points < zeroId input graph queries points := by
  unfold zeroId
  omega

theorem query_bound (queries : List (Query size)) (query : Query size) (member : Membership.mem queries query) :
    query.externalMax <= queryMax queries := by
  induction queries with
  | nil => simp at member
  | cons head rest ih =>
    cases List.mem_cons.mp member with
    | inl same => subst query; exact Nat.le_max_left _ _
    | inr present => exact Nat.le_trans (ih present) (Nat.le_max_right _ _)

def boundIds (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) : List Nat :=
  graph.endpoints ++ queries.flatMap (fun query => [query.lower, query.upper]) ++ points.map Observation.position

def Domains (assignment : Assignment) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry)) : Prop :=
  forall id, Membership.mem (boundIds graph queries points) id -> 0 <= assignment.constant .int id

def localQueries (assignment : Assignment) (queries : List (Query size)) :=
  queries.map (Query.toLocalQuery assignment)

def semanticPoints (assignment : Assignment) (points : List (Observation roots size .entry)) : List (Demand roots size) :=
  points.map (fun point => (point.address, natValue assignment point.position))

def cutIds (zeroID : Nat) (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) : List Nat :=
  (zeroID :: boundIds graph queries points).dedup

-- Extra point demands can use this builder without expected-value terms.
def requestsFrom (cuts : List Nat) (predicates : List (Predicate size))
    (points : List (Demand roots size)) : List (Demand roots size) :=
  ((cuts.product (EntryPredicate.references predicates)).map
    (fun pair : Prod Nat (Fin size) => (Address.version pair.2, pair.1)) ++ points).dedup

def seeds (zeroID : Nat) (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) : List (Demand roots size) :=
  requestsFrom (cutIds zeroID graph queries points) (queries.map Query.predicate) (TypedIntervalEncoding.requested points)

theorem cuts_nodup (zeroID : Nat) (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) : (cutIds zeroID graph queries points).Nodup :=
  List.nodup_dedup _

theorem requests_nodup (cuts : List Nat) (predicates : List (Predicate size)) (points : List (Demand roots size)) :
    (requestsFrom cuts predicates points).Nodup := List.nodup_dedup _

theorem endpoints_interpret (assignment : Assignment) (graph : SymbolicGraph roots .entry size) :
    (interpret assignment graph).endpoints = graph.endpoints.map (natValue assignment) := by
  induction graph with
  | empty => rfl
  | push previous node ih =>
    cases node <;> simp [interpret, TypedIntervalEncoding.interpretNode,
      VersionedIntervals.Graph.endpoints, VersionedIntervals.Version.endpoints, ih]

theorem cut_image (assignment : Assignment) (zeroID : Nat) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (zero : assignment.constant .int zeroID = 0) (position : Nat) :
    Membership.mem (JointIntervalCompletion.cuts (interpret assignment graph)
      (localQueries assignment queries) (semanticPoints assignment points)) position <->
      exists id, Membership.mem (cutIds zeroID graph queries points) id /\ natValue assignment id = position := by
  have raw : IntervalQueries.cutList (interpret assignment graph) (localQueries assignment queries) ++
      (semanticPoints assignment points).map Prod.snd =
      (zeroID :: boundIds graph queries points).map (natValue assignment) := by
    simp only [IntervalQueries.cutList]
    simp [IntervalQueries.schemas, localQueries, Query.toLocalQuery, semanticPoints,
      boundIds, List.map_flatMap, List.flatMap_map, Function.comp_def, natValue, zero, List.append_assoc]
    exact endpoints_interpret assignment graph
  simp only [JointIntervalCompletion.cuts, List.mem_toFinset, JointIntervalCompletion.cutList,
    List.mem_dedup, raw, List.mem_map, cutIds]

theorem cut_nonnegative (assignment : Assignment) (zeroID : Nat) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (zero : assignment.constant .int zeroID = 0) (domains : Domains assignment graph queries points)
    (id : Nat) (member : Membership.mem (cutIds zeroID graph queries points) id) :
    0 <= assignment.constant .int id := by
  cases List.mem_cons.mp (List.mem_dedup.mp member) with
  | inl same => subst id; rw [zero]
  | inr present => exact domains id present

theorem point_nonnegative (assignment : Assignment) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (domains : Domains assignment graph queries points) (point : Observation roots size .entry)
    (member : Membership.mem points point) : 0 <= assignment.constant .int point.position :=
  domains _ (List.mem_append.mpr (Or.inr (List.mem_map.mpr (Exists.intro point (And.intro member rfl)))))

theorem query_nonnegative (assignment : Assignment) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (domains : Domains assignment graph queries points) (query : Query size) (member : Membership.mem queries query) :
    0 <= assignment.constant .int query.lower /\ 0 <= assignment.constant .int query.upper := by
  have bound (id : Nat) (present : Membership.mem [query.lower, query.upper] id) :=
    domains id (List.mem_append.mpr (Or.inl (List.mem_append.mpr (Or.inr
      (List.mem_flatMap.mpr (Exists.intro query (And.intro member present)))))))
  exact And.intro (bound _ (by simp)) (bound _ (by simp))

theorem point_seed (zeroID : Nat) (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (point : Observation roots size .entry)
    (member : Membership.mem points point) :
    Membership.mem (seeds zeroID graph queries points) (point.address, point.position) :=
  List.mem_dedup.mpr (List.mem_append.mpr (Or.inr
    (List.mem_map.mpr (Exists.intro point (And.intro member rfl)))))

theorem reference_seed (zeroID : Nat) (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (id : Nat)
    (cut : Membership.mem (cutIds zeroID graph queries points) id) (query : Query size)
    (member : Membership.mem queries query) (version : Fin size)
    (referenced : Membership.mem query.predicate.references version) :
    Membership.mem (seeds zeroID graph queries points) (.version version, id) := by
  apply List.mem_dedup.mpr
  apply List.mem_append.mpr
  apply Or.inl
  exact List.mem_map.mpr (Exists.intro (id, version) (And.intro
    (List.mem_product.mpr (And.intro cut ((EntryPredicate.references_mem _ _).mpr
      (Exists.intro query.predicate (And.intro
        (List.mem_map.mpr (Exists.intro query (And.intro member rfl))) referenced))))) rfl))

theorem seed_position (zeroID : Nat) (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (demand : Demand roots size)
    (member : Membership.mem (seeds zeroID graph queries points) demand) :
    Membership.mem (cutIds zeroID graph queries points) demand.2 := by
  cases List.mem_append.mp (List.mem_dedup.mp member) with
  | inl product =>
    cases List.mem_map.mp product with
    | intro pair spec => cases spec.2; exact (List.mem_product.mp spec.1).1
  | inr pointMember =>
    cases List.mem_map.mp pointMember with
    | intro point spec =>
      cases spec.2
      exact List.mem_dedup.mpr (List.mem_cons_of_mem _ (List.mem_append.mpr
        (Or.inr (List.mem_map.mpr (Exists.intro point (And.intro spec.1 rfl))))))

theorem plan_positions (graph : SymbolicGraph roots .entry size) (requests : List (Demand roots size))
    (property : Nat -> Prop) (initial : forall demand, Membership.mem requests demand -> property demand.2)
    (demand : Demand roots size) (member : Membership.mem (TypedIntervalReadBlock.planned graph requests) demand) :
    property demand.2 := by
  apply (IntervalDemandPlan.walk_spec (IntervalDemandPlan.table graph) [] requests).minimal
    (fun cell => property cell.2) ?_ ?_ initial demand member
  next =>
    intro cell present child dependency
    cases List.mem_map.mp dependency with
    | intro address spec => cases spec.2; exact present
  next => intro cell present; simp at present

def guardTerm (base : Nat) (query : Query size) (position : InputNat) : Term .bool :=
  .implies (.and (.le (natTerm query.lower) (natTerm position))
    (.not (.le (natTerm query.upper) (natTerm position)))) (query.predicate.lower roots base position)

theorem guard_correct (assignment : Assignment) (base : Nat) (query : Query size) (position : InputNat)
    (lower : 0 <= assignment.constant .int query.lower) (upper : 0 <= assignment.constant .int query.upper)
    (nonnegative : 0 <= assignment.constant .int position) :
    (guardTerm (roots := roots) base query position).eval assignment = true <->
      (query.toLocalQuery assignment).toQuery.Inside (natValue assignment position) ->
        query.predicate.eval assignment (fun version =>
          reads (ty := .entry) assignment base (Address.version (roots := roots) version) (natValue assignment position)) = true := by
  rw [query.inside_iff assignment position lower upper nonnegative]
  simp [guardTerm, Term.eval, query.predicate.lower_correct assignment roots base position nonnegative, natTerm]
  simp only [<- not_le]
  tauto

def guardFormula (base zeroID : Nat) (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) : SmtScript.Formula :=
  queries.flatMap (fun query => (cutIds zeroID graph queries points).map (guardTerm (roots := roots) base query))

theorem guards_correct (assignment : Assignment) (base zeroID : Nat) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (zero : assignment.constant .int zeroID = 0) (domains : Domains assignment graph queries points) :
    SmtScript.Holds assignment (guardFormula base zeroID graph queries points) <->
      JointIntervalCompletion.CutPredicates (interpret assignment graph) (localQueries assignment queries)
        (semanticPoints assignment points) (reads assignment base) := by
  constructor
  next =>
    intro holds localQuery present cut active
    cases List.mem_map.mp present with
    | intro query selected =>
      cases selected.2
      cases (cut_image assignment zeroID graph queries points zero cut.val).mp cut.property with
      | intro id spec =>
        have bounds := query_nonnegative assignment graph queries points domains query selected.1
        have guarded := (guard_correct assignment base query id bounds.1 bounds.2
          (cut_nonnegative assignment zeroID graph queries points zero domains id spec.1)).mp
          (holds _ (List.mem_flatMap.mpr (Exists.intro query (And.intro selected.1
            (List.mem_map.mpr (Exists.intro id (And.intro spec.1 rfl)))))))
        rw [spec.2] at guarded
        exact guarded active
  next =>
    intro valid term present
    cases List.mem_flatMap.mp present with
    | intro query selected =>
      cases List.mem_map.mp selected.2 with
      | intro id spec =>
        rw [<- spec.2]
        have bounds := query_nonnegative assignment graph queries points domains query selected.1
        apply (guard_correct assignment base query id bounds.1 bounds.2
          (cut_nonnegative assignment zeroID graph queries points zero domains id spec.1)).mpr
        exact valid (query.toLocalQuery assignment)
          (List.mem_map.mpr (Exists.intro query (And.intro selected.1 rfl)))
          (Subtype.mk (natValue assignment id) ((cut_image assignment zeroID graph queries points zero _).mpr
            (Exists.intro id (And.intro spec.1 rfl))))

def pointFormula (base : Nat) (points : List (Observation roots size .entry)) : SmtScript.Formula :=
  points.map (fun point => .equal (readRef base point.address point.position) point.expected)

theorem points_correct (assignment : Assignment) (base : Nat) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (domains : Domains assignment graph queries points) :
    SmtScript.Holds assignment (pointFormula base points) <->
      TypedIntervalEncoding.ObservationsHold assignment (reads assignment base) points := by
  simp only [pointFormula, SmtScript.Holds, List.forall_mem_map, Term.eval, decide_eq_true_eq,
    TypedIntervalEncoding.ObservationsHold]
  exact forall_congr' (fun point => forall_congr' (fun member => by
    rw [TypedIntervalEncoding.readRef_eval _ _ _ _ (point_nonnegative assignment graph queries points domains point member)]))

def encode (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry)) : SmtScript.Formula :=
  let zeroID := zeroId input graph queries points
  let base := first input graph queries points
  let cuts := cutIds zeroID graph queries points
  let requests := requestsFrom cuts (queries.map Query.predicate) (TypedIntervalEncoding.requested points)
  input ++ [.equal (natTerm zeroID) (.integer 0)] ++
    TypedIntervalReadBlock.domainFormula (boundIds graph queries points) ++
    TypedIntervalReadBlock.equations base graph requests ++
    queries.flatMap (fun query => cuts.map (guardTerm (roots := roots) base query)) ++ pointFormula base points

def render (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry)) : String :=
  SmtScript.render (encode input graph queries points)

def Semantics (assignment : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry)) : Prop :=
  let zeroID := zeroId input graph queries points
  let base := first input graph queries points
  SmtScript.Holds assignment input /\ assignment.constant .int zeroID = 0 /\
    Domains assignment graph queries points /\
    (exists arrays : RootArrays roots EntryValue.Entry,
      TypedIntervalReadBlock.Agrees assignment graph
        (TypedIntervalReadBlock.planned graph (seeds zeroID graph queries points)) (reads assignment base) arrays) /\
    JointIntervalCompletion.CutPredicates (interpret assignment graph) (localQueries assignment queries)
      (semanticPoints assignment points) (reads assignment base) /\
    TypedIntervalEncoding.ObservationsHold assignment (reads assignment base) points

theorem encode_correct (assignment : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry)) :
    SmtScript.Holds assignment (encode input graph queries points) <-> Semantics assignment input graph queries points := by
  let zeroID := zeroId input graph queries points
  let base := first input graph queries points
  have domains_iff : SmtScript.Holds assignment (TypedIntervalReadBlock.domainFormula (boundIds graph queries points)) <->
      Domains assignment graph queries points := by
    simp [TypedIntervalReadBlock.domainFormula, SmtScript.Holds, Domains, natTerm, Term.eval]
  have read_iff (zero : assignment.constant .int zeroID = 0) (domains : Domains assignment graph queries points) :=
    TypedIntervalReadBlock.equations_readback_iff assignment base graph (seeds zeroID graph queries points)
      (plan_positions graph _ (fun id => 0 <= assignment.constant .int id) (fun demand member =>
        cut_nonnegative assignment zeroID graph queries points zero domains demand.2
          (seed_position zeroID graph queries points demand member)))
  change SmtScript.Holds assignment (((((input ++ [.equal (natTerm zeroID) (.integer 0)]) ++
    TypedIntervalReadBlock.domainFormula (boundIds graph queries points)) ++
    TypedIntervalReadBlock.equations base graph (seeds zeroID graph queries points)) ++
    guardFormula base zeroID graph queries points) ++ pointFormula base points) <-> _
  simp only [QueueEncoding.holds_append, domains_iff]
  have zero_iff : SmtScript.Holds assignment [.equal (natTerm zeroID) (.integer 0)] <->
      assignment.constant .int zeroID = 0 := by simp [SmtScript.Holds, Term.eval, natTerm]
  rw [zero_iff]
  constructor
  next =>
    intro spec
    have domains := spec.1.1.1.2
    have zero := spec.1.1.1.1.2
    exact And.intro spec.1.1.1.1.1 (And.intro zero (And.intro domains
      (And.intro ((read_iff zero domains).mp spec.1.1.2)
        (And.intro ((guards_correct assignment base zeroID graph queries points zero domains).mp spec.1.2)
          ((points_correct assignment base graph queries points domains).mp spec.2)))))
  next =>
    intro spec
    have domains := spec.2.2.1
    exact And.intro (And.intro (And.intro (And.intro (And.intro spec.1 spec.2.1) domains)
      ((read_iff spec.2.1 domains).mpr spec.2.2.2.1))
      ((guards_correct assignment base zeroID graph queries points spec.2.1 domains).mpr spec.2.2.2.2.1))
      ((points_correct assignment base graph queries points domains).mpr spec.2.2.2.2.2)

def Concrete (assignment : Assignment) (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (arrays : RootArrays roots EntryValue.Entry) : Prop :=
  VersionedIntervals.Realizes (interpret assignment graph) (IntervalQueries.schemas (localQueries assignment queries)) arrays /\
    TypedIntervalEncoding.ObservationsHold assignment (actual (interpret assignment graph) arrays) points

theorem encode_sound (assignment : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (holds : SmtScript.Holds assignment (encode input graph queries points)) :
    SmtScript.Holds assignment input /\ Domains assignment graph queries points /\
      exists arrays : RootArrays roots EntryValue.Entry, Concrete assignment graph queries points arrays := by
  have spec := (encode_correct assignment input graph queries points).mp holds
  let zeroID := zeroId input graph queries points
  let base := first input graph queries points
  cases spec.2.2.2.1 with
  | intro sampled agree =>
    have cut_predicates : JointIntervalCompletion.CutPredicates (interpret assignment graph)
        (localQueries assignment queries) (semanticPoints assignment points) (actual (interpret assignment graph) sampled) := by
      intro localQuery present cut active
      cases List.mem_map.mp present with
      | intro query selected =>
        cases selected.2
        cases (cut_image assignment zeroID graph queries points spec.2.1 cut.val).mp cut.property with
        | intro id cut_spec =>
          have same := query.predicate.locality assignment
            (fun version => actual (interpret assignment graph) sampled (.version version) cut.val)
            (fun version => reads (ty := .entry) assignment base (.version version) cut.val)
            (fun version referenced => by
              rw [<- cut_spec.2]
              exact agree _ (TypedIntervalReadBlock.requested_mem graph _ _
                (reference_seed zeroID graph queries points id cut_spec.1 query selected.1 version referenced)))
          change query.predicate.eval assignment _ = true
          rw [same]
          exact spec.2.2.2.2.1 _ (List.mem_map.mpr (Exists.intro query (And.intro selected.1 rfl))) cut active
    let completed := JointIntervalCompletion.complete (interpret assignment graph)
      (localQueries assignment queries) (semanticPoints assignment points) sampled
    refine And.intro spec.1 (And.intro spec.2.2.1 (Exists.intro completed (And.intro ?_ ?_)))
    next => exact JointIntervalCompletion.completion_realizes _ _ _ sampled cut_predicates
    next =>
      intro point present
      have cut := JointIntervalCompletion.point_cut (interpret assignment graph) (localQueries assignment queries)
        (semanticPoints assignment points) _ (List.mem_map.mpr (Exists.intro point (And.intro present rfl)))
      exact (JointIntervalCompletion.actual_complete_at_cut _ _ _ sampled point.address
        (Subtype.mk (natValue assignment point.position) cut)).trans
        ((agree _ (TypedIntervalReadBlock.requested_mem graph _ _ (point_seed zeroID graph queries points point present))).trans
          (spec.2.2.2.2.2 point present))

theorem endpoint_bound (graph : SymbolicGraph roots .entry size) (id : Nat)
    (member : Membership.mem graph.endpoints id) : id <= TypedIntervalEncoding.graphMax graph := by
  induction graph with
  | empty => simp [VersionedIntervals.Graph.endpoints] at member
  | push previous node ih =>
    cases List.mem_append.mp member with
    | inl present => exact Nat.le_trans (ih present) (Nat.le_max_left _ _)
    | inr present =>
      apply Nat.le_trans (m := TypedIntervalEncoding.nodeMax node) ?_ (Nat.le_max_right _ _)
      cases node <;> simp_all [VersionedIntervals.Version.endpoints, TypedIntervalEncoding.nodeMax]
      omega

theorem metadata_bound (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry)) (id : Nat)
    (member : Membership.mem (boundIds graph queries points) id) : id < zeroId input graph queries points := by
  have bounds := allocation_bounds input graph queries points
  cases List.mem_append.mp member with
  | inl earlier =>
    cases List.mem_append.mp earlier with
    | inl endpoint => exact Nat.lt_of_le_of_lt (endpoint_bound graph id endpoint) bounds.2.1
    | inr bound =>
      cases List.mem_flatMap.mp bound with
      | intro query spec =>
        have small := Nat.lt_of_le_of_lt (query_bound queries query spec.1) bounds.2.2.1
        simp only [List.mem_cons, List.not_mem_nil, or_false] at spec
        cases spec.2 with
        | inl same => rw [same]; exact Nat.lt_of_le_of_lt query.bounds.1 small
        | inr same => rw [same]; exact Nat.lt_of_le_of_lt query.bounds.2.1 small
  | inr point =>
    cases List.mem_map.mp point with
    | intro observation spec =>
      rw [<- spec.2]
      exact Nat.lt_of_le_of_lt (Nat.le_trans (Nat.le_max_left _ _)
        (TypedIntervalEncoding.observation_bound points observation spec.1)) bounds.2.2.2

theorem term_symbol_bound (term : Term ty) (limit : Nat) (below : SymbolBounds.termMax term < limit)
    (symbol : Smt.Symbol) (member : Membership.mem (SmtScript.termSymbols term) symbol) :
    QueueEncoding.symbolId symbol < limit := by
  rw [SymbolBounds.termMax_correct] at below
  exact Nat.lt_of_le_of_lt (Finset.le_sup (f := SymbolBounds.symbolId) (List.mem_toFinset.mpr member)) below

theorem operand_congr (left right : Assignment) (limit : Nat) (operand : Operand size ty)
    (below : operand.externalMax < limit) (cells : Fin size -> EntryValue.Entry)
    (terms : forall {sort : Ty}, forall term : Term sort, SymbolBounds.termMax term < limit ->
      term.eval left = term.eval right) : operand.eval left cells = operand.eval right cells := by
  induction operand with
  | cell _ => rfl
  | input term => exact terms term below
  | decodedInput term => simp only [Operand.eval, terms term below]
  | entryTerm operand ih | entryContent operand ih | decodedTerm operand ih =>
    simp only [Operand.eval, ih below]

theorem predicate_congr (left right : Assignment) (limit : Nat) (predicate : Predicate size)
    (below : predicate.externalMax < limit) (cells : Fin size -> EntryValue.Entry)
    (terms : forall {sort : Ty}, forall term : Term sort, SymbolBounds.termMax term < limit ->
      term.eval left = term.eval right) : predicate.eval left cells = predicate.eval right cells := by
  induction predicate with
  | eq a b | ne a b | le a b | lt a b =>
    have bounds : a.externalMax < limit /\ b.externalMax < limit := max_lt_iff.mp below
    simp only [Predicate.eval, operand_congr left right limit a bounds.1 cells terms,
      operand_congr left right limit b bounds.2 cells terms]
  | input term => exact terms term below
  | not value ih => simp only [Predicate.eval, ih below]
  | and a b ihl ihr | implies a b ihl ihr =>
    have bounds : a.externalMax < limit /\ b.externalMax < limit := max_lt_iff.mp below
    simp only [Predicate.eval, ihl bounds.1, ihr bounds.2]

theorem graph_congr (left right : Assignment) (limit : Nat) (graph : SymbolicGraph roots .entry size)
    (below : TypedIntervalEncoding.graphMax graph < limit)
    (terms : forall {sort : Ty}, forall term : Term sort, SymbolBounds.termMax term < limit ->
      term.eval left = term.eval right) : interpret left graph = interpret right graph := by
  induction graph with
  | empty => rfl
  | push previous node ih =>
    have bounds : TypedIntervalEncoding.graphMax previous < limit /\ TypedIntervalEncoding.nodeMax node < limit :=
      max_lt_iff.mp below
    simp only [interpret, ih bounds.1]
    cases node with
    | root _ => rfl
    | constant term => simp only [TypedIntervalEncoding.interpretNode, terms term bounds.2]
    | splice lower upper inside outside =>
      have small : lower < limit /\ upper < limit := max_lt_iff.mp bounds.2
      have hl := terms (natTerm lower) small.1
      have hu := terms (natTerm upper) small.2
      simp only [natTerm, Term.eval] at hl hu
      simp only [TypedIntervalEncoding.interpretNode, natValue, hl, hu]

theorem query_congr (left right : Assignment) (limit : Nat) (query : Query size)
    (below : query.externalMax < limit)
    (terms : forall {sort : Ty}, forall term : Term sort, SymbolBounds.termMax term < limit ->
      term.eval left = term.eval right) : query.toLocalQuery left = query.toLocalQuery right := by
  have bounds := query.bounds
  have hl := terms (natTerm query.lower) (Nat.lt_of_le_of_lt bounds.1 below)
  have hu := terms (natTerm query.upper) (Nat.lt_of_le_of_lt bounds.2.1 below)
  simp only [natTerm, Term.eval] at hl hu
  simp only [Query.toLocalQuery, natValue, hl, hu,
    predicate_congr left right limit query.predicate (Nat.lt_of_le_of_lt bounds.2.2 below) _ terms]

def install (original : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry))
    (arrays : RootArrays roots EntryValue.Entry) : Assignment :=
  TypedIntervalReadBlock.install (IntervalQueryEncoding.setZero original (zeroId input graph queries points))
    (first input graph queries points) graph arrays

theorem install_constant_other (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (arrays : RootArrays roots EntryValue.Entry)
    (sort : Ty) (id : Nat) (different : Not (id = zeroId input graph queries points)) :
    (install original input graph queries points arrays).constant sort id = original.constant sort id := by
  cases sort with
  | int => exact IntervalQueryEncoding.setZero_other original _ id different
  | bool | nodes | content | entry => rfl

theorem install_selectors (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (arrays : RootArrays roots EntryValue.Entry) :
    (install original input graph queries points arrays).selectors = original.selectors := rfl

theorem install_external (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (arrays : RootArrays roots EntryValue.Entry)
    (domain result : Ty) (id : Nat)
    (outside : id < first input graph queries points \/ nextFunctionId input graph queries points <= id) :
    (install original input graph queries points arrays).unary domain result id = original.unary domain result id :=
  TypedIntervalReadBlock.install_external _ _ graph arrays domain result id outside

theorem install_source_term (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (arrays : RootArrays roots EntryValue.Entry)
    (term : Term ty) (below : SymbolBounds.termMax term < zeroId input graph queries points) :
    term.eval (install original input graph queries points arrays) = term.eval original := by
  exact ((TypedIntervalReadBlock.install_source_term _ _ graph arrays term
    (Nat.lt_trans below (Nat.lt_succ_self _))).1).trans
    (IntervalQueryEncoding.term_setZero original _ term (term_symbol_bound term _ below))

theorem install_source_functions (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (arrays : RootArrays roots EntryValue.Entry)
    (term : Term ty) (below : SymbolBounds.termMax term < zeroId input graph queries points)
    (domain result : Ty) (id : Nat) (member : Membership.mem (SmtScript.termSymbols term) (.unary domain result id)) :
    (install original input graph queries points arrays).unary domain result id = original.unary domain result id := by
  apply install_external
  exact Or.inl (Nat.lt_trans (term_symbol_bound term _ below _ member) (Nat.lt_succ_self _))

theorem install_query_functions (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (arrays : RootArrays roots EntryValue.Entry)
    (query : Query size) (selected : Membership.mem queries query) (domain result : Ty) (id : Nat)
    (member : Membership.mem query.predicate.externalSymbols (.unary domain result id)) :
    (install original input graph queries points arrays).unary domain result id = original.unary domain result id := by
  apply install_external
  apply Or.inl
  exact Nat.lt_trans (Nat.lt_of_le_of_lt
    (Nat.le_trans (query.predicate.external_symbol_bound _ member) query.bounds.2.2)
    (Nat.lt_of_le_of_lt (query_bound queries query selected) (allocation_bounds input graph queries points).2.2.1))
    (Nat.lt_succ_self _)

theorem install_graph (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (arrays : RootArrays roots EntryValue.Entry) :
    interpret (install original input graph queries points arrays) graph = interpret original graph :=
  graph_congr _ _ _ graph (allocation_bounds input graph queries points).2.1
    (fun term below => install_source_term original input graph queries points arrays term below)

theorem install_queries (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (arrays : RootArrays roots EntryValue.Entry) :
    localQueries (install original input graph queries points arrays) queries = localQueries original queries := by
  apply List.map_congr_left
  intro query member
  exact query_congr _ _ _ query
    (Nat.lt_of_le_of_lt (query_bound queries query member) (allocation_bounds input graph queries points).2.2.1)
    (fun term below => install_source_term original input graph queries points arrays term below)

theorem install_metadata (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (arrays : RootArrays roots EntryValue.Entry)
    (id : Nat) (member : Membership.mem (boundIds graph queries points) id) :
    (install original input graph queries points arrays).constant .int id = original.constant .int id := by
  apply install_constant_other
  have bound := metadata_bound input graph queries points id member
  omega

theorem install_input_iff (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (arrays : RootArrays roots EntryValue.Entry) :
    SmtScript.Holds (install original input graph queries points arrays) input <-> SmtScript.Holds original input := by
  apply forall_congr'
  intro term
  apply forall_congr'
  intro member
  rw [install_source_term original input graph queries points arrays term
    (Nat.lt_of_le_of_lt (TypedIntervalEncoding.formula_term_bound input term member)
      (allocation_bounds input graph queries points).1)]

theorem install_concrete (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (arrays : RootArrays roots EntryValue.Entry)
    (concrete : Concrete original graph queries points arrays) :
    Concrete (install original input graph queries points arrays) graph queries points arrays := by
  refine And.intro ?_ ?_
  next =>
    change VersionedIntervals.Realizes _ (IntervalQueries.schemas _) arrays
    rw [install_graph, install_queries]
    exact concrete.1
  next =>
    intro point member
    have pb := Nat.lt_of_le_of_lt (TypedIntervalEncoding.observation_bound points point member)
      (allocation_bounds input graph queries points).2.2.2
    have expected := install_source_term original input graph queries points arrays point.expected
      (Nat.lt_of_le_of_lt (Nat.le_max_right _ _) pb)
    have position := install_constant_other original input graph queries points arrays .int point.position
      (Nat.ne_of_lt (Nat.lt_of_le_of_lt (Nat.le_max_left _ _) pb))
    change actual _ arrays point.address (natValue _ point.position) = _
    rw [install_graph, expected]
    simp only [natValue, position]
    exact concrete.2 point member

theorem install_reads (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (arrays : RootArrays roots EntryValue.Entry) :
    reads (install original input graph queries points arrays) (first input graph queries points) =
      actual (interpret (install original input graph queries points arrays) graph) arrays := by
  have below := Nat.lt_trans (allocation_bounds input graph queries points).2.1 (Nat.lt_succ_self _)
  rw [show interpret (install original input graph queries points arrays) graph =
    interpret (IntervalQueryEncoding.setZero original (zeroId input graph queries points)) graph from
      TypedIntervalReadBlock.install_graph _ _ graph arrays below]
  exact TypedIntervalReadBlock.install_reads _ _ graph arrays

theorem install_satisfies (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (arrays : RootArrays roots EntryValue.Entry)
    (input_holds : SmtScript.Holds original input) (domains : Domains original graph queries points)
    (concrete : Concrete original graph queries points arrays) :
    SmtScript.Holds (install original input graph queries points arrays) (encode input graph queries points) := by
  apply (encode_correct _ input graph queries points).mpr
  have installed := install_concrete original input graph queries points arrays concrete
  refine And.intro ((install_input_iff original input graph queries points arrays).mpr input_holds)
    (And.intro ?_ (And.intro ?_ (And.intro ?_ (And.intro ?_ ?_))))
  next => simp [install, TypedIntervalReadBlock.install, TypedIntervalEncoding.installUF, IntervalQueryEncoding.setZero]
  next =>
    intro id member
    rw [install_metadata original input graph queries points arrays id member]
    exact domains id member
  next =>
    refine Exists.intro arrays ?_
    intro demand _
    rw [install_reads]
  next =>
    rw [install_reads]
    exact (JointIntervalCompletion.realizes_compiled _ _ _ arrays installed.1).2
  next =>
    rw [install_reads]
    exact installed.2

theorem encode_exists_iff (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry)) :
    (exists assignment : Assignment, SmtScript.Holds assignment (encode input graph queries points)) <->
      exists original : Assignment, exists arrays : RootArrays roots EntryValue.Entry,
        SmtScript.Holds original input /\ Domains original graph queries points /\ Concrete original graph queries points arrays := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro assignment holds =>
      have spec := encode_sound assignment input graph queries points holds
      cases spec.2.2 with
      | intro arrays concrete =>
        exact Exists.intro assignment (Exists.intro arrays (And.intro spec.1 (And.intro spec.2.1 concrete)))
  next =>
    intro witness
    cases witness with
    | intro original witness =>
      cases witness with
      | intro arrays spec =>
        exact Exists.intro (install original input graph queries points arrays)
          (install_satisfies original input graph queries points arrays spec.1 spec.2.1 spec.2.2)

theorem rendered_exists_iff (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (queries : List (Query size)) (points : List (Observation roots size .entry)) :
    (exists assignment : Assignment, SmtScriptText.runText assignment (render input graph queries points) = some true) <->
      exists original : Assignment, exists arrays : RootArrays roots EntryValue.Entry,
        SmtScript.Holds original input /\ Domains original graph queries points /\ Concrete original graph queries points arrays := by
  simp only [render, <- SmtScriptText.formula_text_iff, encode_exists_iff]

namespace Regression

def signature : Term .entry := .entry (.integer (-1)) .signature
def transaction : Term .entry := .entry (.integer 0) (.transaction (.integer 7))
def rootGraph : SymbolicGraph 1 .entry 1 := .push .empty (.root 0)
def signatureArrays : RootArrays 1 EntryValue.Entry := fun _ _ => { term := -1, content := .signature }

def point (position : Nat) (expected : Term .entry) : Observation 1 1 .entry :=
  { address := .root 0, position := position, expected := expected }

def bound (id : Nat) (value : Int) : Term .bool := .equal (natTerm id) (.integer value)

theorem bound_value (assignment : Assignment) (id : Nat) (value : Int)
    (holds : (bound id value).eval assignment = true) : assignment.constant .int id = value := by
  simpa [bound, Term.eval, natTerm] using holds

theorem contradictory_duplicates :
    Not (exists assignment : Assignment, SmtScriptText.runText assignment
      (render [] rootGraph [] [point 2 signature, point 2 transaction]) = some true) := by
  intro witness
  cases (rendered_exists_iff _ _ _ _).mp witness with
  | intro assignment witness =>
    cases witness with
    | intro arrays spec =>
      have a := spec.2.2.2 (point 2 signature) (by simp)
      have b := spec.2.2.2 (point 2 transaction) (by simp)
      have different := congrArg EntryValue.Entry.term (a.symm.trans b)
      norm_num [signature, transaction, point, Term.eval] at different

theorem aliased_positions_conflict :
    Not (exists assignment : Assignment, SmtScriptText.runText assignment
      (render [.equal (natTerm 2) (natTerm 3)] rootGraph []
        [point 2 signature, point 3 transaction]) = some true) := by
  intro witness
  cases (rendered_exists_iff _ _ _ _).mp witness with
  | intro assignment witness =>
    cases witness with
    | intro arrays spec =>
      have same : assignment.constant .int 2 = assignment.constant .int 3 := by
        simpa [Term.eval, natTerm] using spec.1 (.equal (natTerm 2) (natTerm 3)) (by simp)
      have a := spec.2.2.2 (point 2 signature) (by simp)
      have b := spec.2.2.2 (point 3 transaction) (by simp)
      simp only [point, natValue, same] at a b
      have different := congrArg EntryValue.Entry.term (a.symm.trans b)
      norm_num [signature, transaction, Term.eval] at different

def equalSignature : Query 1 :=
  { lower := 0, upper := 1, predicate := .eq (.cell 0) (.input signature) }

theorem universal_point_conflict :
    Not (exists assignment : Assignment, SmtScriptText.runText assignment
      (render [bound 0 0, bound 1 2, bound 2 1] rootGraph [equalSignature] [point 2 transaction]) = some true) := by
  intro witness
  cases (rendered_exists_iff _ _ _ _).mp witness with
  | intro assignment witness =>
    cases witness with
    | intro arrays spec =>
      have lower := bound_value assignment 0 0 (spec.1 _ (by simp))
      have upper := bound_value assignment 1 2 (spec.1 _ (by simp))
      have position := bound_value assignment 2 1 (spec.1 _ (by simp))
      have uniform := spec.2.2.1 (equalSignature.toLocalQuery assignment).toQuery
        (by simp [IntervalQueries.schemas, localQueries]) 1
        (by simp [equalSignature, Query.toLocalQuery, VersionedIntervals.Query.Inside, natValue, lower, upper])
      have a : arrays 0 1 = signature.eval assignment := of_decide_eq_true uniform
      have b := spec.2.2.2 (point 2 transaction) (by simp)
      change arrays 0 (natValue assignment 2) = transaction.eval assignment at b
      simp only [natValue, position] at b
      have different := congrArg EntryValue.Entry.term (a.symm.trans b)
      norm_num [signature, transaction, Term.eval] at different

theorem point_outside_and_inside_controls :
    let original := TypedIntervalEncoding.Regression.fixtureAssignment 0 2 3
    let arrays : RootArrays 1 EntryValue.Entry := fun _ position =>
      if position = 3 then { term := 0, content := .transaction 7 } else { term := -1, content := .signature }
    TypedIntervalReadBlock.Regression.check
      (install original [] rootGraph [equalSignature] [point 2 transaction] arrays)
      (encode [] rootGraph [equalSignature] [point 2 transaction]) = true /\
    TypedIntervalReadBlock.Regression.check
      (install (TypedIntervalEncoding.Regression.fixtureAssignment 0 2 1) []
        rootGraph [equalSignature] [point 2 signature] signatureArrays)
      (encode [] rootGraph [equalSignature] [point 2 signature]) = true := by
  decide +kernel

def closedQuery (value : Bool) : Query 0 :=
  { lower := 0, upper := 1, predicate := .input (.boolean value) }

def closedCheck (lower upper : Nat) (value : Bool) : Bool :=
  let graph : SymbolicGraph 0 .entry 0 := .empty
  let queries := [closedQuery value]
  let original := TypedIntervalEncoding.Regression.fixtureAssignment lower upper 0
  TypedIntervalReadBlock.Regression.check (install original [] graph queries [] (fun root => Fin.elim0 root))
    (encode [] graph queries [])

theorem empty_reversed_and_no_references :
    closedCheck 2 2 false = true /\ closedCheck 3 1 false = true /\
    closedCheck 0 1 false = false /\ closedCheck 0 1 true = true /\
    seeds 10 (.empty : SymbolicGraph 0 .entry 0) [closedQuery false] [] = [] := by
  decide +kernel

theorem nonempty_no_reference_false :
    Not (exists assignment : Assignment, SmtScriptText.runText assignment
      (render [bound 0 0, bound 1 1] (.empty : SymbolicGraph 0 .entry 0) [closedQuery false] []) = some true) := by
  intro witness
  cases (rendered_exists_iff _ _ _ _).mp witness with
  | intro assignment witness =>
    cases witness with
    | intro arrays spec =>
      have lower := bound_value assignment 0 0 (spec.1 _ (by simp))
      have upper := bound_value assignment 1 1 (spec.1 _ (by simp))
      have impossible := spec.2.2.1 ((closedQuery false).toLocalQuery assignment).toQuery
        (by simp [IntervalQueries.schemas, localQueries]) 0
        (by simp [closedQuery, Query.toLocalQuery, VersionedIntervals.Query.Inside, natValue, lower, upper])
      contradiction

def disabled : Query 1 :=
  { lower := 0, upper := 1,
    predicate := .implies (.input (.boolean false))
      (.eq (.cell 0) (.input (.app .nodes .entry 9000 (.unknown .nodes 2)))) }

def highPoint : Observation 1 1 .entry := point 10000 (.app .int .entry 11000 (natTerm 8))

def unusedGraph : SymbolicGraph 1 .entry 1 :=
  .push .empty (.constant (.app .int .entry 15000 (natTerm 20000)))

theorem false_query_and_unused_metadata :
    zeroId [] rootGraph [disabled] [] = 9001 /\
    (seeds 9001 rootGraph [disabled] []).length = 3 /\
    zeroId [] rootGraph [] [highPoint] = 11001 /\
    zeroId [] unusedGraph [] [] = 20001 /\
    zeroId [.unknown .bool 30000] unusedGraph [disabled] [highPoint] = 30001 /\
    nextFunctionId [] rootGraph [disabled] [] = 9004 := by
  decide +kernel

theorem unused_function_preserved (original : Assignment) :
    (install original [] unusedGraph [] [] signatureArrays).unary .int .entry 15000 =
      original.unary .int .entry 15000 := by
  apply install_external
  exact Or.inl (by decide +kernel)

theorem disabled_function_preserved (original : Assignment) :
    (install original [] rootGraph [disabled] [] signatureArrays).unary .nodes .entry 9000 =
      original.unary .nodes .entry 9000 := by
  apply install_query_functions original [] rootGraph [disabled] [] signatureArrays disabled (by simp)
  simp [disabled, Predicate.externalSymbols, Operand.externalSymbols, SmtScript.termSymbols]

def negativeBounds : Assignment :=
  { TypedIntervalEncoding.Regression.fixtureAssignment 0 1 0 with
    constant := fun sort id =>
      match sort with
      | .int => if id = 0 then -1 else 1
      | sort => (TypedIntervalEncoding.Regression.fixtureAssignment 0 1 0).constant sort id }

theorem disabled_domains_remain :
    TypedIntervalReadBlock.Regression.check (install negativeBounds [] rootGraph [disabled] [] signatureArrays)
      (encode [] rootGraph [disabled] []) = false /\
    TypedIntervalReadBlock.Regression.check
      (install (TypedIntervalEncoding.Regression.fixtureAssignment 0 1 0) [] rootGraph [disabled] [] signatureArrays)
      (encode [] rootGraph [disabled] []) = true := by
  decide +kernel

theorem repeated_cuts_and_references :
    (cutIds 4 rootGraph [equalSignature, equalSignature] [point 2 signature, point 2 signature]).length = 4 /\
    (seeds 4 rootGraph [equalSignature, equalSignature] [point 2 signature, point 2 signature]).length = 5 /\
    (pointFormula 10 [point 2 signature, point 2 signature]).length = 2 := by
  decide +kernel

theorem empty_mode :
    closedCheck 0 0 true = true /\
    TypedIntervalReadBlock.Regression.check
      (install (TypedIntervalEncoding.Regression.fixtureAssignment 0 0 0) []
        (.empty : SymbolicGraph 0 .entry 0) [] [] (fun root => Fin.elim0 root))
      (encode [] (.empty : SymbolicGraph 0 .entry 0) [] []) = true := by
  decide +kernel

end Regression

end CCFRaft.Sparse.TypedJointPredicateEncoding

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.TypedJointPredicateEncoding).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse.TypedJointPredicateEncoding: allowed-axiom gate passed for {checked} declarations."

#print axioms CCFRaft.Sparse.TypedJointPredicateEncoding.rendered_exists_iff
#print axioms CCFRaft.Sparse.TypedJointPredicateEncoding.install_query_functions
