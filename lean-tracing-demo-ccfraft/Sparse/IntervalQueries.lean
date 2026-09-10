import Sparse.IntervalDemandPlan

set_option autoImplicit false

namespace CCFRaft.Sparse.IntervalQueries

open VersionedIntervals
open IntervalReadback

structure LocalQuery (size : Nat) (A : Type) extends Query size A where
  references : List (Fin size)
  locality : forall left right : Fin size -> A,
    (forall version, Membership.mem references version -> left version = right version) ->
    (accepts left <-> accepts right)

variable {roots size : Nat} {A : Type}

def schemas (queries : List (LocalQuery size A)) : List (Query size A) :=
  queries.map LocalQuery.toQuery

-- Keep endpoint occurrences as a list; the memoized planner removes duplicate demands.
def cutList (graph : Graph roots A size) (queries : List (LocalQuery size A)) : List Nat :=
  0 :: (graph.endpoints ++ (schemas queries).flatMap (fun query => [query.lower, query.upper]))

theorem mem_cutList (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (position : Nat) :
    Membership.mem (cutList graph queries) position <->
      Membership.mem (cuts graph (schemas queries)) position := by
  simp [cutList, cuts]

-- No interval guard is evaluated while constructing requests.
def requests (graph : Graph roots A size) (queries : List (LocalQuery size A)) :
    List (Demand roots size) :=
  (cutList graph queries).flatMap fun position =>
    queries.flatMap fun query =>
      query.references.map fun version => (Address.version version, position)

theorem reference_requested (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (query : LocalQuery size A) (present : Membership.mem queries query)
    (cut : Cut graph (schemas queries)) (version : Fin size)
    (referenced : Membership.mem query.references version) :
    Membership.mem (requests graph queries) (.version version, cut.val) :=
  List.mem_flatMap.mpr (Exists.intro cut.val (And.intro
    ((mem_cutList graph queries cut.val).mpr cut.property)
    (List.mem_flatMap.mpr (Exists.intro query (And.intro present
      (List.mem_map.mpr (Exists.intro version (And.intro referenced rfl))))))))

theorem request_at_cut (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (address : Address roots size) (position : Nat)
    (present : Membership.mem (requests graph queries) (address, position)) :
    Membership.mem (cuts graph (schemas queries)) position := by
  cases List.mem_flatMap.mp present with
  | intro cut cut_spec =>
    cases List.mem_flatMap.mp cut_spec.2 with
    | intro query query_spec =>
      cases List.mem_map.mp query_spec.2 with
      | intro version version_spec =>
        cases version_spec.2
        exact (mem_cutList graph queries _).mp cut_spec.1

def CutPredicates (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (reads : Reads roots size A) : Prop :=
  forall query, Membership.mem queries query -> forall cut : Cut graph (schemas queries),
    query.toQuery.Inside cut.val ->
      query.accepts (fun version => reads (.version version) cut.val)

def Compiled (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (reads : Reads roots size A) : Prop :=
  Equations graph (IntervalDemandPlan.plan graph (requests graph queries)).toFinset reads /\
    CutPredicates graph queries reads

def Agrees (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (left right : Reads roots size A) : Prop :=
  forall address position, Membership.mem (requests graph queries) (address, position) ->
    left address position = right address position

theorem finiteConditions_of_agrees (graph : Graph roots A size)
    (queries : List (LocalQuery size A)) (reads : Reads roots size A)
    (arrays : RootArrays roots A) (agree : Agrees graph queries (actual graph arrays) reads)
    (valid : CutPredicates graph queries reads) :
    FiniteConditions graph (schemas queries) (fun arrayID cut => arrays arrayID cut.val) := by
  intro query present cut active
  cases List.mem_map.mp present with
  | intro localQuery spec =>
    cases spec.2
    apply (localQuery.locality _ _ ?_).mp (valid localQuery spec.1 cut active)
    intro version referenced
    exact (agree (.version version) cut.val
      (reference_requested graph queries localQuery spec.1 cut version referenced)).symm

theorem actual_complete_at_cut (graph : Graph roots A size)
    (queries : List (LocalQuery size A)) (arrays : RootArrays roots A)
    (address : Address roots size) (cut : Cut graph (schemas queries)) :
    actual graph (complete graph (schemas queries) (fun arrayID cut => arrays arrayID cut.val))
      address cut.val = actual graph arrays address cut.val := by
  cases address with
  | root arrayID =>
    exact complete_at_cut graph (schemas queries) (fun arrayID cut => arrays arrayID cut.val)
      arrayID cut
  | version version =>
    change evaluate graph (complete graph (schemas queries) _) cut.val version =
      evaluate graph arrays cut.val version
    rw [completion_values, sampleIndex_self]
    rfl

theorem compiled_realizes (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (reads : Reads roots size A) (compiled : Compiled graph queries reads) :
    exists arrays : RootArrays roots A,
      Realizes graph (schemas queries) arrays /\
        Agrees graph queries (actual graph arrays) reads := by
  cases (IntervalDemandPlan.planned_readback_iff graph (requests graph queries) reads).mp
      compiled.1 with
  | intro sampledArrays planned_agree =>
    have agree : Agrees graph queries (actual graph sampledArrays) reads := by
      intro address position present
      exact planned_agree address position
        (IntervalDemandPlan.plan_includes graph (requests graph queries) _ present)
    let samples : Samples graph (schemas queries) :=
      fun arrayID cut => sampledArrays arrayID cut.val
    refine Exists.intro (complete graph (schemas queries) samples) (And.intro ?_ ?_)
    next =>
      exact completion_realizes graph (schemas queries) samples
        (finiteConditions_of_agrees graph queries reads sampledArrays agree compiled.2)
    next =>
      intro address position present
      exact (actual_complete_at_cut graph queries sampledArrays address
        (Subtype.mk position (request_at_cut graph queries address position present))).trans
          (agree address position present)

theorem realizes_compiled (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (arrays : RootArrays roots A) (valid : Realizes graph (schemas queries) arrays) :
    Compiled graph queries (actual graph arrays) := by
  constructor
  next =>
    intro address position _
    exact actual_equation graph arrays address position
  next =>
    intro query present cut active
    exact valid query.toQuery (List.mem_map.mpr (Exists.intro query (And.intro present rfl)))
      cut.val active

theorem requested_completion_iff (graph : Graph roots A size)
    (queries : List (LocalQuery size A)) (requested : Reads roots size A) :
    (exists reads : Reads roots size A,
      Agrees graph queries reads requested /\ Compiled graph queries reads) <->
    (exists arrays : RootArrays roots A,
      Realizes graph (schemas queries) arrays /\
        Agrees graph queries (actual graph arrays) requested) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro reads spec =>
      cases compiled_realizes graph queries reads spec.2 with
      | intro arrays completed =>
        refine Exists.intro arrays (And.intro completed.1 ?_)
        intro address position present
        exact (completed.2 address position present).trans (spec.1 address position present)
  next =>
    intro witness
    cases witness with
    | intro arrays spec =>
      exact Exists.intro (actual graph arrays)
        (And.intro spec.2 (realizes_compiled graph queries arrays spec.1))

theorem compiled_exists_iff (graph : Graph roots A size) (queries : List (LocalQuery size A)) :
    (exists reads : Reads roots size A, Compiled graph queries reads) <->
    (exists arrays : RootArrays roots A, Realizes graph (schemas queries) arrays) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro reads compiled =>
      cases compiled_realizes graph queries reads compiled with
      | intro arrays spec => exact Exists.intro arrays spec.1
  next =>
    intro witness
    cases witness with
    | intro arrays valid =>
      exact Exists.intro (actual graph arrays) (realizes_compiled graph queries arrays valid)

theorem cuts_card_bound (graph : Graph roots A size) (queries : List (LocalQuery size A)) :
    (cuts graph (schemas queries)).card <= 1 + 2 * graph.spliceCount + 2 * queries.length := by
  simpa only [schemas, List.length_map] using cuts_card_le graph (schemas queries)

private def sharedRootGraph : Graph 1 Nat 2 :=
  .push (.push .empty (.root 0)) (.root 0)

private def cellQuery (version : Fin 2) (expected : Nat) : LocalQuery 2 Nat where
  lower := 1
  upper := 2
  accepts values := values version = expected
  references := [version]
  locality left right agree := by
    rw [agree version (by simp)]

theorem shared_root_conflict :
    Not (exists reads : Reads 1 2 Nat,
      Compiled sharedRootGraph [cellQuery 0 3, cellQuery 1 4] reads) := by
  intro witness
  cases (compiled_exists_iff sharedRootGraph [cellQuery 0 3, cellQuery 1 4]).mp witness with
  | intro arrays valid =>
    have left := valid (cellQuery 0 3).toQuery (by simp [schemas]) 1 (by
      simp [Query.Inside, cellQuery])
    have right := valid (cellQuery 1 4).toQuery (by simp [schemas]) 1 (by
      simp [Query.Inside, cellQuery])
    change arrays 0 1 = 3 at left
    change arrays 0 1 = 4 at right
    omega

theorem unreferenced_version_not_requested :
    Not (Membership.mem (requests sharedRootGraph [cellQuery 0 3])
      (.version 1, 1)) := by
  decide +kernel

private def emptyFalseQuery : LocalQuery 2 Nat where
  lower := 7
  upper := 7
  accepts _ := False
  references := []
  locality _ _ _ := Iff.rfl

theorem empty_interval_false_predicate :
    exists reads : Reads 1 2 Nat, Compiled sharedRootGraph [emptyFalseQuery] reads := by
  apply (compiled_exists_iff sharedRootGraph [emptyFalseQuery]).mpr
  refine Exists.intro (fun _ _ => 0) ?_
  intro query member position active
  have same : query = emptyFalseQuery.toQuery := by simpa [schemas] using member
  subst query
  simp [Query.Inside, emptyFalseQuery] at active
  omega

end CCFRaft.Sparse.IntervalQueries

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.IntervalQueries).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse.IntervalQueries: allowed-axiom gate passed for {checked} declarations."

#print axioms CCFRaft.Sparse.IntervalQueries.requested_completion_iff
#print axioms CCFRaft.Sparse.IntervalQueries.compiled_exists_iff
#print axioms CCFRaft.Sparse.IntervalQueries.cuts_card_bound
