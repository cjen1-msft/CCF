import Sparse.IntervalQueries
import Mathlib.Data.List.Nodup

set_option autoImplicit false

namespace CCFRaft.Sparse.JointIntervalCompletion

open VersionedIntervals (Graph RootArrays evaluate)
open IntervalQueries (LocalQuery schemas)
open IntervalReadback (Address Demand Reads actual Equations)

variable {roots size : Nat} {A : Type}

def cutList (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) : List Nat :=
  (IntervalQueries.cutList graph queries ++ points.map Prod.snd).dedup

def cuts (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) : Finset Nat :=
  (cutList graph queries points).toFinset

theorem cuts_membership (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) (position : Nat) :
    Membership.mem (cuts graph queries points) position <->
      Membership.mem (VersionedIntervals.cuts graph (schemas queries)) position \/
      Membership.mem (points.map Prod.snd) position := by
  simp only [cuts, List.mem_toFinset, cutList, List.mem_dedup, List.mem_append,
    IntervalQueries.mem_cutList]

theorem base_cut (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) (position : Nat)
    (present : Membership.mem (VersionedIntervals.cuts graph (schemas queries)) position) :
    Membership.mem (cuts graph queries points) position :=
  (cuts_membership graph queries points position).mpr (Or.inl present)

theorem zero_cut (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) : Membership.mem (cuts graph queries points) 0 :=
  base_cut graph queries points 0 (VersionedIntervals.zero_cut graph (schemas queries))

theorem point_cut (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) (point : Demand roots size) (present : Membership.mem points point) :
    Membership.mem (cuts graph queries points) point.2 :=
  (cuts_membership graph queries points point.2).mpr (Or.inr
    (List.mem_map.mpr (Exists.intro point (And.intro present rfl))))

def queryRequests (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) : List (Demand roots size) :=
  ((cutList graph queries points).product (queries.flatMap LocalQuery.references).dedup).map
    (fun pair => (Address.version pair.2, pair.1))

-- Point-only addresses do not enter the global cut/reference product.
def requests (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) : List (Demand roots size) :=
  (queryRequests graph queries points ++ points).dedup

def planned (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) : List (Demand roots size) :=
  IntervalDemandPlan.plan graph (requests graph queries points)

theorem queryRequests_nodup (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) : (queryRequests graph queries points).Nodup := by
  apply ((List.nodup_dedup _).product (List.nodup_dedup _)).map
  intro left right same
  cases left
  cases right
  simp only [Prod.mk.injEq, Address.version.injEq] at same
  exact Prod.ext same.2 same.1

theorem requests_nodup (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) : (requests graph queries points).Nodup :=
  List.nodup_dedup _

theorem planned_nodup (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) : (planned graph queries points).Nodup :=
  IntervalDemandPlan.plan_nodup graph _

theorem point_requested (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) (point : Demand roots size) (present : Membership.mem points point) :
    Membership.mem (requests graph queries points) point :=
  List.mem_dedup.mpr (List.mem_append.mpr (Or.inr present))

theorem reference_requested (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) (query : LocalQuery size A) (present : Membership.mem queries query)
    (position : Nat) (cut : Membership.mem (cuts graph queries points) position)
    (version : Fin size) (referenced : Membership.mem query.references version) :
    Membership.mem (requests graph queries points) (.version version, position) := by
  apply List.mem_dedup.mpr
  apply List.mem_append.mpr
  apply Or.inl
  apply List.mem_map.mpr
  refine Exists.intro (position, version) (And.intro ?_ rfl)
  exact List.mem_product.mpr (And.intro (List.mem_toFinset.mp cut)
    (List.mem_dedup.mpr (List.mem_flatMap.mpr (Exists.intro query (And.intro present referenced)))))

theorem request_at_cut (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) (demand : Demand roots size)
    (present : Membership.mem (requests graph queries points) demand) :
    Membership.mem (cuts graph queries points) demand.2 := by
  cases List.mem_append.mp (List.mem_dedup.mp present) with
  | inl query =>
    cases List.mem_map.mp query with
    | intro pair spec =>
      cases spec.2
      exact List.mem_toFinset.mpr (List.mem_product.mp spec.1).1
  | inr point => exact point_cut graph queries points demand point

abbrev Cut (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) :=
  { position : Nat // Membership.mem (cuts graph queries points) position }

def CutPredicates (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) (reads : Reads roots size A) : Prop :=
  forall query, Membership.mem queries query -> forall cut : Cut graph queries points,
    query.toQuery.Inside cut.val ->
      query.accepts (fun version => reads (.version version) cut.val)

def Compiled (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) (reads : Reads roots size A) : Prop :=
  Equations graph (planned graph queries points).toFinset reads /\
    CutPredicates graph queries points reads

def Agrees (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) (left right : Reads roots size A) : Prop :=
  forall address position, Membership.mem (requests graph queries points) (address, position) ->
    left address position = right address position

def complete (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) (arrays : RootArrays roots A) : RootArrays roots A :=
  fun root index => arrays root
    (IntervalCompletion.floor (cuts graph queries points) (zero_cut graph queries points) index)

theorem actual_complete_at_cut (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) (arrays : RootArrays roots A) (address : Address roots size)
    (cut : Cut graph queries points) :
    actual graph (complete graph queries points arrays) address cut.val =
      actual graph arrays address cut.val := by
  cases address <;>
    simp only [actual, evaluate, complete,
      IntervalCompletion.floor_self _ _ cut.val cut.property]

theorem completion_values (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) (arrays : RootArrays roots A) (index : Nat) :
    evaluate graph (complete graph queries points arrays) index =
      evaluate graph arrays
        (IntervalCompletion.floor (cuts graph queries points) (zero_cut graph queries points) index) :=
  VersionedIntervals.graph_values_floor graph (cuts graph queries points) (zero_cut graph queries points)
    (fun endpoint present => base_cut graph queries points endpoint
      (VersionedIntervals.graph_cuts graph (schemas queries) endpoint present)) _ index

theorem completion_realizes (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) (arrays : RootArrays roots A)
    (valid : CutPredicates graph queries points (actual graph arrays)) :
    VersionedIntervals.Realizes graph (schemas queries) (complete graph queries points arrays) := by
  intro query present index active
  cases List.mem_map.mp present with
  | intro localQuery spec =>
    cases spec.2
    let cut : Cut graph queries points :=
      Subtype.mk (IntervalCompletion.floor (cuts graph queries points) (zero_cut graph queries points) index)
        (IntervalCompletion.floor_spec _ _ index).1
    have endpoints := VersionedIntervals.query_cuts graph (schemas queries) localQuery.toQuery
      (List.mem_map.mpr (Exists.intro localQuery (And.intro spec.1 rfl)))
    have floor_active : localQuery.toQuery.Inside cut.val :=
      (VersionedIntervals.interval_floor (cuts graph queries points) (zero_cut graph queries points)
        localQuery.lower localQuery.upper
        (base_cut graph queries points _ endpoints.1) (base_cut graph queries points _ endpoints.2) index).mpr active
    rw [completion_values]
    exact valid localQuery spec.1 cut floor_active

theorem predicates_of_agrees (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) (left right : Reads roots size A)
    (agree : Agrees graph queries points left right) (valid : CutPredicates graph queries points right) :
    CutPredicates graph queries points left := by
  intro query present cut active
  apply (query.locality _ _ ?_).mp (valid query present cut active)
  intro version referenced
  exact (agree (.version version) cut.val
    (reference_requested graph queries points query present cut.val cut.property version referenced)).symm

theorem compiled_realizes (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) (reads : Reads roots size A) (compiled : Compiled graph queries points reads) :
    exists arrays : RootArrays roots A,
      VersionedIntervals.Realizes graph (schemas queries) arrays /\
        Agrees graph queries points (actual graph arrays) reads := by
  cases (IntervalDemandPlan.planned_readback_iff graph (requests graph queries points) reads).mp
      compiled.1 with
  | intro sampled agree_all =>
    have agree : Agrees graph queries points (actual graph sampled) reads := by
      intro address position present
      exact agree_all address position
        (IntervalDemandPlan.plan_includes graph (requests graph queries points) _ present)
    refine Exists.intro (complete graph queries points sampled) (And.intro ?_ ?_)
    next =>
      exact completion_realizes graph queries points sampled
        (predicates_of_agrees graph queries points _ _ agree compiled.2)
    next =>
      intro address position present
      exact (actual_complete_at_cut graph queries points sampled address
        (Subtype.mk position (request_at_cut graph queries points (address, position) present))).trans
          (agree address position present)

theorem realizes_compiled (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) (arrays : RootArrays roots A)
    (valid : VersionedIntervals.Realizes graph (schemas queries) arrays) :
    Compiled graph queries points (actual graph arrays) := by
  refine And.intro (fun address position _ => IntervalReadback.actual_equation graph arrays address position) ?_
  intro query present cut active
  exact valid query.toQuery (List.mem_map.mpr (Exists.intro query (And.intro present rfl))) cut.val active

theorem requested_completion_iff (graph : Graph roots A size) (queries : List (LocalQuery size A))
    (points : List (Demand roots size)) (wanted : Reads roots size A) :
    (exists reads : Reads roots size A,
      Agrees graph queries points reads wanted /\ Compiled graph queries points reads) <->
    (exists arrays : RootArrays roots A,
      VersionedIntervals.Realizes graph (schemas queries) arrays /\
        Agrees graph queries points (actual graph arrays) wanted) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro reads spec =>
      cases compiled_realizes graph queries points reads spec.2 with
      | intro arrays completed =>
        refine Exists.intro arrays (And.intro completed.1 ?_)
        intro address position present
        exact (completed.2 address position present).trans (spec.1 address position present)
  next =>
    intro witness
    cases witness with
    | intro arrays spec =>
      exact Exists.intro (actual graph arrays)
        (And.intro spec.2 (realizes_compiled graph queries points arrays spec.1))

private def singleGraph : Graph 1 Int 1 :=
  .push .empty (.root 0)

private def zeroQuery : LocalQuery 1 Int where
  lower := 0
  upper := 10
  accepts values := values 0 = 0
  references := [0]
  locality left right agree := by rw [agree 0 (by simp)]

private def markedArrays (marked : Nat) : RootArrays 1 Int :=
  fun _ position => if position = marked then 1 else 0

theorem conflicting_point_inside_regression :
    Not (exists reads : Reads 1 1 Int,
      Agrees singleGraph [zeroQuery] [(.root 0, 5)] reads (actual singleGraph (markedArrays 5)) /\
      Compiled singleGraph [zeroQuery] [(.root 0, 5)] reads) := by
  intro witness
  cases (requested_completion_iff _ _ _ _).mp witness with
  | intro arrays spec =>
    have matching := spec.1 zeroQuery.toQuery (by simp [schemas]) 5
      (by simp [zeroQuery, VersionedIntervals.Query.Inside])
    have point := spec.2 (.root 0) 5
      (point_requested singleGraph [zeroQuery] [(.root 0, 5)] _ (by simp))
    change arrays 0 5 = 0 at matching
    change arrays 0 5 = 1 at point
    omega

theorem point_outside_intervals_regression :
    exists reads : Reads 1 1 Int,
      Agrees singleGraph [zeroQuery] [(.root 0, 15)] reads (actual singleGraph (markedArrays 15)) /\
      Compiled singleGraph [zeroQuery] [(.root 0, 15)] reads := by
  apply (requested_completion_iff _ _ _ _).mpr
  refine Exists.intro (markedArrays 15) (And.intro ?_ (fun _ _ _ => rfl))
  intro query present position active
  have same : query = zeroQuery.toQuery := by simpa [schemas] using present
  subst query
  change (if position = 15 then (1 : Int) else 0) = 0
  have different : Not (position = 15) := by
    simp [zeroQuery, VersionedIntervals.Query.Inside] at active
    omega
  simp only [if_neg different]

private def conflictingAliases : Reads 1 1 Int
  | .root _, _ => 0
  | .version _, _ => 1

theorem root_version_alias_regression :
    Not (exists reads : Reads 1 1 Int,
      Agrees singleGraph [] [(.root 0, 3), (.version 0, 3)] reads conflictingAliases /\
      Compiled singleGraph [] [(.root 0, 3), (.version 0, 3)] reads) := by
  intro witness
  cases (requested_completion_iff _ _ _ _).mp witness with
  | intro arrays spec =>
    have root_value := spec.2 (.root 0) 3
      (point_requested singleGraph [] [(.root 0, 3), (.version 0, 3)] _ (by simp))
    have version_value := spec.2 (.version 0) 3
      (point_requested singleGraph [] [(.root 0, 3), (.version 0, 3)] _ (by simp))
    change arrays 0 3 = 0 at root_value
    change arrays 0 3 = 1 at version_value
    omega

theorem point_only_sparse_regression :
    planned (.push (.push .empty (.root 0)) (.root 1) : Graph 2 Int 2) [] [(.version 1, 7)] =
      [(.root 1, 7), (.version 1, 7)] := by
  decide +kernel

theorem empty_points_regression :
    requests singleGraph [zeroQuery] [] = [(.version 0, 0), (.version 0, 10)] := by
  decide

theorem empty_inputs_regression :
    requests (.empty : Graph 0 Int 0) [] [] = [] /\
      planned (.empty : Graph 0 Int 0) [] [] = [] := by
  decide +kernel

end CCFRaft.Sparse.JointIntervalCompletion

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.JointIntervalCompletion).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse.JointIntervalCompletion: allowed-axiom gate passed for {checked} declarations."

#print axioms CCFRaft.Sparse.JointIntervalCompletion.requested_completion_iff
#print axioms CCFRaft.Sparse.JointIntervalCompletion.actual_complete_at_cut
#print axioms CCFRaft.Sparse.JointIntervalCompletion.conflicting_point_inside_regression
#print axioms CCFRaft.Sparse.JointIntervalCompletion.point_outside_intervals_regression
#print axioms CCFRaft.Sparse.JointIntervalCompletion.root_version_alias_regression
