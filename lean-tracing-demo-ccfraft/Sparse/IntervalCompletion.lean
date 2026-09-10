import Model
import Mathlib.Data.List.OfFn
import Mathlib.Data.Finset.Max

set_option autoImplicit false

namespace CCFRaft.Sparse.IntervalCompletion

variable {A : Type}

structure Interval (A : Type) where
  lower : Nat
  upper : Nat
  accepts : A -> Prop

def Inside (interval : Interval A) (index : Nat) : Prop :=
  interval.lower <= index /\ index < interval.upper

def cuts (points : List (Prod Nat A)) (intervals : List (Interval A)) : Finset Nat :=
  insert 0 ((points.map Prod.fst ++ intervals.flatMap (fun interval =>
    [interval.lower, interval.upper])).toFinset)

theorem zero_cut (points : List (Prod Nat A)) (intervals : List (Interval A)) :
    Membership.mem (cuts points intervals) 0 := by simp [cuts]

theorem point_cut (points : List (Prod Nat A)) (intervals : List (Interval A))
    (point : Prod Nat A) (present : Membership.mem points point) :
    Membership.mem (cuts points intervals) point.1 := by
  simp only [cuts, Finset.mem_insert, List.mem_toFinset, List.mem_append]
  exact Or.inr (Or.inl (List.mem_map.mpr (Exists.intro point (And.intro present rfl))))

theorem interval_cuts (points : List (Prod Nat A)) (intervals : List (Interval A))
    (interval : Interval A) (present : Membership.mem intervals interval) :
    Membership.mem (cuts points intervals) interval.lower /\
      Membership.mem (cuts points intervals) interval.upper := by
  have lower : Membership.mem
      (intervals.flatMap (fun interval => [interval.lower, interval.upper])) interval.lower := by
    apply List.mem_flatMap.mpr
    exact Exists.intro interval (And.intro present (by simp))
  have upper : Membership.mem
      (intervals.flatMap (fun interval => [interval.lower, interval.upper])) interval.upper := by
    apply List.mem_flatMap.mpr
    exact Exists.intro interval (And.intro present (by simp))
  simp only [cuts, Finset.mem_insert, List.mem_toFinset, List.mem_append]
  exact And.intro (Or.inr (Or.inr lower)) (Or.inr (Or.inr upper))

theorem cuts_card_le (points : List (Prod Nat A)) (intervals : List (Interval A)) :
    (cuts points intervals).card <= points.length + 2 * intervals.length + 1 := by
  have endpoints :
      (intervals.flatMap (fun interval => [interval.lower, interval.upper])).length =
        2 * intervals.length := by
    induction intervals with
    | nil => simp
    | cons interval rest ih => simp [ih, Nat.mul_add, Nat.add_comm]; omega
  calc
    (cuts points intervals).card <=
        (points.map Prod.fst ++ intervals.flatMap (fun interval =>
          [interval.lower, interval.upper])).toFinset.card + 1 :=
      Finset.card_insert_le _ _
    _ <= (points.map Prod.fst ++ intervals.flatMap (fun interval =>
          [interval.lower, interval.upper])).length + 1 :=
      Nat.add_le_add_right (List.toFinset_card_le _) 1
    _ = points.length + 2 * intervals.length + 1 := by simp [endpoints]

def floor (boundaries : Finset Nat) (zero : Membership.mem boundaries 0) (index : Nat) : Nat :=
  (boundaries.filter (fun boundary => boundary <= index)).max'
    (Exists.intro 0 (by simp [zero]))

theorem floor_spec (boundaries : Finset Nat) (zero : Membership.mem boundaries 0) (index : Nat) :
    Membership.mem boundaries (floor boundaries zero index) /\
      floor boundaries zero index <= index /\
      (forall boundary, Membership.mem boundaries boundary -> boundary <= index ->
        boundary <= floor boundaries zero index) := by
  have present := Finset.max'_mem (boundaries.filter (fun boundary => boundary <= index))
    (Exists.intro 0 (by simp [zero]))
  have parts := Finset.mem_filter.mp present
  refine And.intro parts.1 (And.intro parts.2 ?_)
  intro boundary member below
  exact Finset.le_max' _ boundary (Finset.mem_filter.mpr (And.intro member below))

theorem floor_self (boundaries : Finset Nat) (zero : Membership.mem boundaries 0) (index : Nat)
    (present : Membership.mem boundaries index) : floor boundaries zero index = index := by
  have h := floor_spec boundaries zero index
  exact Nat.le_antisymm h.2.1 (h.2.2 index present (Nat.le_refl index))

theorem inside_floor (points : List (Prod Nat A)) (intervals : List (Interval A))
    (interval : Interval A) (present : Membership.mem intervals interval) (index : Nat) :
    Inside interval (floor (cuts points intervals) (zero_cut points intervals) index) <->
      Inside interval index := by
  have bounds := interval_cuts points intervals interval present
  have f := floor_spec (cuts points intervals) (zero_cut points intervals) index
  unfold Inside
  constructor
  next =>
    intro active
    refine And.intro (by omega) ?_
    by_contra outside
    have lower : interval.upper <= index := by omega
    have contradiction := f.2.2 interval.upper bounds.2 lower
    omega
  next =>
    intro active
    exact And.intro (f.2.2 interval.lower bounds.1 active.1) (by omega)

def Requirements (points : List (Prod Nat A)) (intervals : List (Interval A))
    (index : Nat) (value : A) : Prop :=
  (forall point, Membership.mem points point -> point.1 = index -> value = point.2) /\
    (forall interval, Membership.mem intervals interval -> Inside interval index ->
      interval.accepts value)

def FiniteConditions (length : Nat) (points : List (Prod Nat A)) (intervals : List (Interval A))
    (samples : Nat -> A) : Prop :=
  (forall point, Membership.mem points point -> point.1 < length) /\
    (forall boundary, Membership.mem (cuts points intervals) boundary -> boundary < length ->
      Requirements points intervals boundary (samples boundary))

def Realizes (log : List A) (length : Nat) (points : List (Prod Nat A))
    (intervals : List (Interval A)) : Prop :=
  log.length = length /\
    (forall point, Membership.mem points point -> log[point.1]? = some point.2) /\
    (forall interval, Membership.mem intervals interval -> forall index,
      forall bounded : index < log.length, Inside interval index ->
        interval.accepts (log.get (Fin.mk index bounded)))

def complete (length : Nat) (points : List (Prod Nat A)) (intervals : List (Interval A))
    (samples : Nat -> A) : List A :=
  List.ofFn (fun index : Fin length =>
    samples (floor (cuts points intervals) (zero_cut points intervals) index.val))

theorem completion_realizes (length : Nat) (points : List (Prod Nat A))
    (intervals : List (Interval A)) (samples : Nat -> A)
    (valid : FiniteConditions length points intervals samples) :
    Realizes (complete length points intervals samples) length points intervals := by
  refine And.intro (by simp [complete]) (And.intro ?_ ?_)
  next =>
    intro point member
    have bounded := valid.1 point member
    have cut := point_cut points intervals point member
    have same := floor_self (cuts points intervals) (zero_cut points intervals) point.1 cut
    have value := (valid.2 point.1 cut bounded).1 point member rfl
    simp [complete, bounded, same, value]
  next =>
    intro interval member index bounded active
    have index_bound : index < length := by simpa [complete] using bounded
    have f := floor_spec (cuts points intervals) (zero_cut points intervals) index
    have floor_bound : floor (cuts points intervals) (zero_cut points intervals) index < length := by
      omega
    have value := (valid.2 _ f.1 floor_bound).2 interval member
      ((inside_floor points intervals interval member index).mpr active)
    simpa [complete] using value

theorem realizes_finite (log : List A) (length : Nat) (points : List (Prod Nat A))
    (intervals : List (Interval A)) (fallback : A)
    (valid : Realizes log length points intervals) :
    FiniteConditions length points intervals (fun index => log[index]?.getD fallback) := by
  have size := valid.1
  constructor
  next =>
    intro point member
    have present := valid.2.1 point member
    have bound := (List.getElem?_eq_some_iff.mp present).1
    omega
  next =>
    intro boundary _ below
    have inside : boundary < log.length := by omega
    constructor
    next =>
      intro point member same
      have present := valid.2.1 point member
      rw [same] at present
      simp [present]
    next =>
      intro interval member active
      have accepted := valid.2.2 interval member boundary inside active
      simpa [inside] using accepted

theorem finite_completion_iff (length : Nat) (points : List (Prod Nat A))
    (intervals : List (Interval A)) (fallback : A) :
    (exists samples : Nat -> A, FiniteConditions length points intervals samples) <->
      (exists log : List A, Realizes log length points intervals) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro samples valid =>
      exact Exists.intro (complete length points intervals samples)
        (completion_realizes length points intervals samples valid)
  next =>
    intro witness
    cases witness with
    | intro log valid =>
      exact Exists.intro (fun index => log[index]?.getD fallback)
        (realizes_finite log length points intervals fallback valid)

private def atLeastSeven : Interval Nat :=
  { lower := 0, upper := 1000000, accepts := fun value => 7 <= value }

theorem million_example :
    exists log : List Nat, Realizes log 1000000 [(999999, 9)] [atLeastSeven] := by
  apply (finite_completion_iff 1000000 [(999999, 9)] [atLeastSeven] 0).mp
  refine Exists.intro (fun _ => 9) ?_
  constructor
  next => simp
  next =>
    intro boundary _ _
    constructor
    next =>
      intro point member _
      have same : point = (999999, 9) := by simpa using member
      simp [same]
    next =>
      intro interval member _
      have same : interval = atLeastSeven := by simpa using member
      simp [same, atLeastSeven]

private def belowThree : Interval Nat :=
  { lower := 0, upper := 10, accepts := fun value => value < 3 }

private def atLeastThree : Interval Nat :=
  { lower := 5, upper := 9, accepts := fun value => 3 <= value }

theorem overlapping_gap_conflict :
    Not (exists log : List Nat, Realizes log 1000000 [] [belowThree, atLeastThree]) := by
  intro witness
  have condition := (finite_completion_iff 1000000 [] [belowThree, atLeastThree] 0).mpr witness
  cases condition with
  | intro samples valid =>
    have boundary : Membership.mem (cuts [] [belowThree, atLeastThree]) 5 := by
      simp [cuts, belowThree, atLeastThree]
    have constraints := (valid.2 5 boundary (by omega)).2
    have below := constraints belowThree (by simp) (by simp [Inside, belowThree])
    have above := constraints atLeastThree (by simp) (by simp [Inside, atLeastThree])
    change samples 5 < 3 at below
    change 3 <= samples 5 at above
    omega

end CCFRaft.Sparse.IntervalCompletion

run_cmd do
  for theoremName in [
      ``CCFRaft.Sparse.IntervalCompletion.inside_floor,
      ``CCFRaft.Sparse.IntervalCompletion.cuts_card_le,
      ``CCFRaft.Sparse.IntervalCompletion.completion_realizes,
      ``CCFRaft.Sparse.IntervalCompletion.finite_completion_iff,
      ``CCFRaft.Sparse.IntervalCompletion.million_example,
      ``CCFRaft.Sparse.IntervalCompletion.overlapping_gap_conflict] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom: {name}"
