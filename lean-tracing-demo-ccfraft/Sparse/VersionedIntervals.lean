import Sparse.IntervalCompletion

set_option autoImplicit false

namespace CCFRaft.Sparse.VersionedIntervals

inductive Version (roots : Nat) (A : Type) (prior : Nat) where
  | root (arrayID : Fin roots)
  | constant (value : A)
  | splice (lower upper : Nat) (insideVersion outsideVersion : Fin prior)

inductive Graph (roots : Nat) (A : Type) : Nat -> Type where
  | empty : Graph roots A 0
  | push {prior : Nat} (previous : Graph roots A prior) (version : Version roots A prior) :
    Graph roots A (prior + 1)

variable {roots size : Nat} {A : Type}

def Version.value (version : Version roots A size) (rootValues : Fin roots -> A)
    (previousValues : Fin size -> A) (index : Nat) : A :=
  match version with
  | .root arrayID => rootValues arrayID
  | .constant value => value
  | .splice lower upper insideVersion outsideVersion =>
    if lower <= index /\ index < upper then previousValues insideVersion
    else previousValues outsideVersion

def Graph.values : {size : Nat} -> Graph roots A size -> (Fin roots -> A) ->
    Nat -> (Fin size -> A)
  | _, .empty, _, _ => Fin.elim0
  | _, .push previous version, rootValues, index =>
    Fin.snoc (previous.values rootValues index)
      (version.value rootValues (previous.values rootValues index) index)

abbrev RootArrays (roots : Nat) (A : Type) := Fin roots -> Nat -> A

def evaluate (graph : Graph roots A size) (arrays : RootArrays roots A) (index : Nat) :
    Fin size -> A :=
  graph.values (fun arrayID => arrays arrayID index) index

structure Query (size : Nat) (A : Type) where
  lower : Nat
  upper : Nat
  accepts : (Fin size -> A) -> Prop

def Query.Inside (query : Query size A) (index : Nat) : Prop :=
  query.lower <= index /\ index < query.upper

def Version.endpoints : Version roots A size -> List Nat
  | .root _ | .constant _ => []
  | .splice lower upper _ _ => [lower, upper]

def Version.spliceCount : Version roots A size -> Nat
  | .root _ | .constant _ => 0
  | .splice _ _ _ _ => 1

def Graph.endpoints : {size : Nat} -> Graph roots A size -> List Nat
  | _, .empty => []
  | _, .push previous version => previous.endpoints ++ version.endpoints

def Graph.spliceCount : {size : Nat} -> Graph roots A size -> Nat
  | _, .empty => 0
  | _, .push previous version => previous.spliceCount + version.spliceCount

def cuts (graph : Graph roots A size) (queries : List (Query size A)) : Finset Nat :=
  insert 0 ((graph.endpoints ++
    queries.flatMap (fun query => [query.lower, query.upper])).toFinset)

theorem zero_cut (graph : Graph roots A size) (queries : List (Query size A)) :
    Membership.mem (cuts graph queries) 0 := by
  simp [cuts]

theorem graph_cuts (graph : Graph roots A size) (queries : List (Query size A))
    (endpoint : Nat) (present : Membership.mem graph.endpoints endpoint) :
    Membership.mem (cuts graph queries) endpoint := by
  simp only [cuts, Finset.mem_insert, List.mem_toFinset, List.mem_append]
  exact Or.inr (Or.inl present)

theorem query_cuts (graph : Graph roots A size) (queries : List (Query size A))
    (query : Query size A) (present : Membership.mem queries query) :
    Membership.mem (cuts graph queries) query.lower /\
      Membership.mem (cuts graph queries) query.upper := by
  have lower : Membership.mem
      (queries.flatMap (fun query => [query.lower, query.upper])) query.lower :=
    List.mem_flatMap.mpr (Exists.intro query (And.intro present (by simp)))
  have upper : Membership.mem
      (queries.flatMap (fun query => [query.lower, query.upper])) query.upper :=
    List.mem_flatMap.mpr (Exists.intro query (And.intro present (by simp)))
  simp only [cuts, Finset.mem_insert, List.mem_toFinset, List.mem_append]
  exact And.intro (Or.inr (Or.inr lower)) (Or.inr (Or.inr upper))

theorem graph_endpoints_length (graph : Graph roots A size) :
    graph.endpoints.length = 2 * graph.spliceCount := by
  induction graph with
  | empty => rfl
  | push previous version ih =>
    cases version <;>
      simp [Graph.endpoints, Graph.spliceCount, Version.endpoints, Version.spliceCount,
        ih, Nat.mul_add]

theorem cuts_card_le (graph : Graph roots A size) (queries : List (Query size A)) :
    (cuts graph queries).card <= 1 + 2 * graph.spliceCount + 2 * queries.length := by
  have query_endpoints :
      (queries.flatMap (fun query => [query.lower, query.upper])).length =
        2 * queries.length := by
    induction queries with
    | nil => rfl
    | cons query rest ih => simp [ih, Nat.mul_add]
  calc
    (cuts graph queries).card <= (graph.endpoints ++
        queries.flatMap (fun query => [query.lower, query.upper])).toFinset.card + 1 :=
      Finset.card_insert_le _ _
    _ <= (graph.endpoints ++
        queries.flatMap (fun query => [query.lower, query.upper])).length + 1 :=
      Nat.add_le_add_right (List.toFinset_card_le _) 1
    _ = 1 + 2 * graph.spliceCount + 2 * queries.length := by
      rw [List.length_append, graph_endpoints_length, query_endpoints]
      omega

theorem interval_floor (boundaries : Finset Nat) (zero : Membership.mem boundaries 0)
    (lower upper : Nat) (lower_cut : Membership.mem boundaries lower)
    (upper_cut : Membership.mem boundaries upper) (index : Nat) :
    (lower <= IntervalCompletion.floor boundaries zero index /\
      IntervalCompletion.floor boundaries zero index < upper) <->
    (lower <= index /\ index < upper) := by
  have spec := IntervalCompletion.floor_spec boundaries zero index
  constructor
  next =>
    intro active
    refine And.intro (by omega) ?_
    by_contra outside
    have past : upper <= index := by omega
    have upper_below := spec.2.2 upper upper_cut past
    omega
  next =>
    intro active
    exact And.intro (spec.2.2 lower lower_cut active.1) (by omega)

theorem version_value_floor (version : Version roots A size)
    (boundaries : Finset Nat) (zero : Membership.mem boundaries 0)
    (covered : forall endpoint, Membership.mem version.endpoints endpoint ->
      Membership.mem boundaries endpoint)
    (rootValues : Fin roots -> A) (previousValues : Fin size -> A) (index : Nat) :
    version.value rootValues previousValues index =
      version.value rootValues previousValues (IntervalCompletion.floor boundaries zero index) := by
  cases version with
  | root _ => rfl
  | constant _ => rfl
  | splice lower upper insideVersion outsideVersion =>
    have lower_cut := covered lower (by simp [Version.endpoints])
    have upper_cut := covered upper (by simp [Version.endpoints])
    simp only [Version.value,
      interval_floor boundaries zero lower upper lower_cut upper_cut index]

theorem graph_values_floor (graph : Graph roots A size)
    (boundaries : Finset Nat) (zero : Membership.mem boundaries 0)
    (covered : forall endpoint, Membership.mem graph.endpoints endpoint ->
      Membership.mem boundaries endpoint)
    (rootValues : Fin roots -> A) (index : Nat) :
    graph.values rootValues index =
      graph.values rootValues (IntervalCompletion.floor boundaries zero index) := by
  induction graph with
  | empty => rfl
  | push previous version ih =>
    have previous_covered : forall endpoint, Membership.mem previous.endpoints endpoint ->
        Membership.mem boundaries endpoint := by
      intro endpoint present
      exact covered endpoint (List.mem_append.mpr (Or.inl present))
    have version_covered : forall endpoint, Membership.mem version.endpoints endpoint ->
        Membership.mem boundaries endpoint := by
      intro endpoint present
      exact covered endpoint (List.mem_append.mpr (Or.inr present))
    simp only [Graph.values]
    rw [ih previous_covered]
    rw [version_value_floor version boundaries zero version_covered]

abbrev Cut (graph : Graph roots A size) (queries : List (Query size A)) :=
  { index : Nat // Membership.mem (cuts graph queries) index }

abbrev Samples (graph : Graph roots A size) (queries : List (Query size A)) :=
  Fin roots -> Cut graph queries -> A

def sampleIndex (graph : Graph roots A size) (queries : List (Query size A))
    (index : Nat) : Cut graph queries :=
  Subtype.mk (IntervalCompletion.floor (cuts graph queries) (zero_cut graph queries) index)
    (IntervalCompletion.floor_spec (cuts graph queries) (zero_cut graph queries) index).1

theorem sampleIndex_self (graph : Graph roots A size) (queries : List (Query size A))
    (cut : Cut graph queries) : sampleIndex graph queries cut.val = cut :=
  Subtype.ext (IntervalCompletion.floor_self (cuts graph queries) (zero_cut graph queries)
    cut.val cut.property)

def complete (graph : Graph roots A size) (queries : List (Query size A))
    (samples : Samples graph queries) : RootArrays roots A :=
  fun arrayID index => samples arrayID (sampleIndex graph queries index)

theorem complete_at_cut (graph : Graph roots A size) (queries : List (Query size A))
    (samples : Samples graph queries) (arrayID : Fin roots) (cut : Cut graph queries) :
    complete graph queries samples arrayID cut.val = samples arrayID cut := by
  simp only [complete, sampleIndex_self]

-- Every version is evaluated at the same absolute position; no edge shifts it.
theorem completion_values (graph : Graph roots A size) (queries : List (Query size A))
    (samples : Samples graph queries) (index : Nat) :
    evaluate graph (complete graph queries samples) index =
      graph.values (fun arrayID => samples arrayID (sampleIndex graph queries index))
        (sampleIndex graph queries index).val :=
  graph_values_floor graph (cuts graph queries) (zero_cut graph queries)
    (graph_cuts graph queries) _ index

def FiniteConditions (graph : Graph roots A size) (queries : List (Query size A))
    (samples : Samples graph queries) : Prop :=
  forall query, Membership.mem queries query -> forall cut : Cut graph queries,
    query.Inside cut.val ->
    query.accepts (graph.values (fun arrayID => samples arrayID cut) cut.val)

def Realizes (graph : Graph roots A size) (queries : List (Query size A))
    (arrays : RootArrays roots A) : Prop :=
  forall query, Membership.mem queries query -> forall index,
    query.Inside index -> query.accepts (evaluate graph arrays index)

theorem completion_realizes (graph : Graph roots A size) (queries : List (Query size A))
    (samples : Samples graph queries) (valid : FiniteConditions graph queries samples) :
    Realizes graph queries (complete graph queries samples) := by
  intro query present index active
  have endpoints := query_cuts graph queries query present
  have floor_active : query.Inside (sampleIndex graph queries index).val :=
    (interval_floor (cuts graph queries) (zero_cut graph queries) query.lower query.upper
      endpoints.1 endpoints.2 index).mpr active
  rw [completion_values]
  exact valid query present (sampleIndex graph queries index) floor_active

theorem realizes_finite (graph : Graph roots A size) (queries : List (Query size A))
    (arrays : RootArrays roots A) (valid : Realizes graph queries arrays) :
    FiniteConditions graph queries (fun arrayID cut => arrays arrayID cut.val) := by
  intro query present cut active
  exact valid query present cut.val active

theorem finite_completion_iff (graph : Graph roots A size) (queries : List (Query size A)) :
    (exists samples : Samples graph queries, FiniteConditions graph queries samples) <->
    (exists arrays : RootArrays roots A, Realizes graph queries arrays) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro samples valid =>
      exact Exists.intro (complete graph queries samples)
        (completion_realizes graph queries samples valid)
  next =>
    intro witness
    cases witness with
    | intro arrays valid =>
      exact Exists.intro (fun arrayID cut => arrays arrayID cut.val)
        (realizes_finite graph queries arrays valid)

end CCFRaft.Sparse.VersionedIntervals

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.VersionedIntervals).isPrefixOf name then
      let axioms <- Lean.collectAxioms name
      for axiomName in axioms do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Versioned interval audit passed: {checked} declarations."

#print axioms CCFRaft.Sparse.VersionedIntervals.completion_values
#print axioms CCFRaft.Sparse.VersionedIntervals.finite_completion_iff
#print axioms CCFRaft.Sparse.VersionedIntervals.cuts_card_le
