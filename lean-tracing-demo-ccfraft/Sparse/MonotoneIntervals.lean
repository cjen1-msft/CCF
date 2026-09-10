import Sparse.IntervalCompletion

set_option autoImplicit false

-- Local log completion only. List witnesses stay in proofs, not runtime encoding.
namespace CCFRaft.Sparse.MonotoneIntervals

open IntervalCompletion

variable {A : Type}

def OrderedCutTerms (term : A -> Nat) (length current : Nat)
    (boundaries : Finset Nat) (samples : Nat -> A) : Prop :=
  (forall earlier, Membership.mem boundaries earlier ->
    forall later, Membership.mem boundaries later ->
      earlier <= later -> later < length ->
        term (samples earlier) <= term (samples later)) /\
  (forall boundary, Membership.mem boundaries boundary -> boundary < length ->
    term (samples boundary) <= current)

theorem floor_monotone (boundaries : Finset Nat)
    (zero : Membership.mem boundaries 0) :
    Monotone (floor boundaries zero) := by
  intro earlier later ordered
  have left := floor_spec boundaries zero earlier
  have right := floor_spec boundaries zero later
  exact right.2.2 _ left.1 (Nat.le_trans left.2.1 ordered)

theorem completion_terms (term : A -> Nat) (length current : Nat)
    (points : List (Prod Nat A)) (intervals : List (Interval A)) (samples : Nat -> A)
    (ordered : OrderedCutTerms term length current (cuts points intervals) samples) :
    Monotone (fun index : Fin (complete length points intervals samples).length =>
      term ((complete length points intervals samples).get index)) /\
    (forall entry, Membership.mem (complete length points intervals samples) entry ->
      term entry <= current) := by
  constructor
  next =>
    intro earlier later increasing
    have live : later.val < length := by simpa [complete] using later.isLt
    have left := floor_spec (cuts points intervals) (zero_cut points intervals) earlier.val
    have right := floor_spec (cuts points intervals) (zero_cut points intervals) later.val
    have comparison := ordered.1 _ left.1 _ right.1
      (floor_monotone _ _ increasing) (Nat.lt_of_le_of_lt right.2.1 live)
    simpa [complete] using comparison
  next =>
    intro entry present
    simp only [complete, List.mem_ofFn] at present
    cases present with
    | intro index same =>
      subst entry
      have boundary := floor_spec (cuts points intervals) (zero_cut points intervals) index.val
      exact ordered.2 _ boundary.1 (Nat.lt_of_le_of_lt boundary.2.1 index.isLt)

theorem log_terms_finite (term : A -> Nat) (log : List A) (current : Nat)
    (boundaries : Finset Nat) (fallback : A)
    (ordered : Monotone (fun index : Fin log.length => term (log.get index)))
    (bounded : forall entry, Membership.mem log entry -> term entry <= current) :
    OrderedCutTerms term log.length current boundaries
      (fun index => log[index]?.getD fallback) := by
  constructor
  next =>
    intro earlier _ later _ increasing live
    have earlier_live : earlier < log.length := Nat.lt_of_le_of_lt increasing live
    have comparison := ordered
      (show (Fin.mk earlier earlier_live : Fin log.length) <= Fin.mk later live from increasing)
    simpa [earlier_live, live] using comparison
  next =>
    intro boundary _ live
    have bound := bounded (log.get (Fin.mk boundary live)) (List.get_mem _ _)
    simpa [live] using bound

theorem finite_completion_iff (term : A -> Nat) (length current : Nat)
    (points : List (Prod Nat A)) (intervals : List (Interval A)) (fallback : A) :
    (exists samples : Nat -> A,
      FiniteConditions length points intervals samples /\
        OrderedCutTerms term length current (cuts points intervals) samples) <->
    (exists log : List A,
      Realizes log length points intervals /\
        Monotone (fun index : Fin log.length => term (log.get index)) /\
        (forall entry, Membership.mem log entry -> term entry <= current)) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro samples valid =>
      exact Exists.intro (complete length points intervals samples)
        (And.intro (completion_realizes length points intervals samples valid.1)
          (completion_terms term length current points intervals samples valid.2))
  next =>
    intro witness
    cases witness with
    | intro log valid =>
      refine Exists.intro (fun index => log[index]?.getD fallback)
        (And.intro (realizes_finite log length points intervals fallback valid.1) ?_)
      have finite := log_terms_finite term log current (cuts points intervals) fallback
        valid.2.1 valid.2.2
      simpa only [valid.1.1] using finite

theorem entryAt_monotone_iff {N T : Type} (log : List (Entry N T)) :
    Monotone (fun index : Fin log.length => (log.get index).term) <->
      (forall earlier later earlierEntry laterEntry,
        earlier < later ->
          entryAt? log earlier = some earlierEntry ->
            entryAt? log later = some laterEntry ->
              earlierEntry.term <= laterEntry.term) := by
  constructor
  next =>
    intro ordered earlier later earlierEntry laterEntry increasing left right
    have earlier_nonzero : Not (earlier = 0) := by
      intro zero
      simp [entryAt?, zero] at left
    have later_nonzero : Not (later = 0) := by omega
    have left_read : log[earlier - 1]? = some earlierEntry := by
      simpa [entryAt?, earlier_nonzero] using left
    have right_read : log[later - 1]? = some laterEntry := by
      simpa [entryAt?, later_nonzero] using right
    have left_live := (List.getElem?_eq_some_iff.mp left_read).1
    have right_live := (List.getElem?_eq_some_iff.mp right_read).1
    have left_value : log.get (Fin.mk (earlier - 1) left_live) = earlierEntry := by
      simpa [left_live] using left_read
    have right_value : log.get (Fin.mk (later - 1) right_live) = laterEntry := by
      simpa [right_live] using right_read
    have comparison := ordered
      (show (Fin.mk (earlier - 1) left_live : Fin log.length) <=
          Fin.mk (later - 1) right_live from Nat.sub_le_sub_right (Nat.le_of_lt increasing) 1)
    simpa only [left_value, right_value] using comparison
  next =>
    intro ordered earlier later increasing
    cases lt_or_eq_of_le increasing with
    | inl strict =>
      exact ordered (earlier.val + 1) (later.val + 1) (log.get earlier) (log.get later)
        (Nat.add_lt_add_right strict 1)
        (by simp [entryAt?, earlier.isLt])
        (by simp [entryAt?, later.isLt])
    | inr same =>
      rw [same]

-- The reader proposition is the defining body of CCFRaft.MonoHistory.
theorem entryAt_completion_iff {N T : Type} (length current : Nat)
    (points : List (Prod Nat (Entry N T))) (intervals : List (Interval (Entry N T)))
    (fallback : Entry N T) :
    (exists samples : Nat -> Entry N T,
      FiniteConditions length points intervals samples /\
        OrderedCutTerms Entry.term length current (cuts points intervals) samples) <->
    (exists log : List (Entry N T),
      Realizes log length points intervals /\
        (forall earlier later earlierEntry laterEntry,
          earlier < later ->
            entryAt? log earlier = some earlierEntry ->
              entryAt? log later = some laterEntry ->
                earlierEntry.term <= laterEntry.term) /\
        (forall entry, Membership.mem log entry -> entry.term <= current)) := by
  simpa only [entryAt_monotone_iff] using
    (finite_completion_iff Entry.term length current points intervals fallback)

theorem empty_completion (term : A -> Nat) (current : Nat)
    (intervals : List (Interval A)) (fallback : A) :
    exists log : List A, Realizes log 0 [] intervals /\
      Monotone (fun index : Fin log.length => term (log.get index)) /\
      (forall entry, Membership.mem log entry -> term entry <= current) := by
  apply (finite_completion_iff term 0 current [] intervals fallback).mp
  refine Exists.intro (fun _ => fallback) ?_
  simp [FiniteConditions, OrderedCutTerms]

theorem million_completion :
    exists log : List Nat,
      Realizes log 1000000 [(999999, 9)]
        [{ lower := 0, upper := 1000000, accepts := fun value => 7 <= value }] /\
      Monotone (fun index : Fin log.length => log.get index) /\
      (forall entry, Membership.mem log entry -> entry <= 9) := by
  apply (finite_completion_iff id 1000000 9 _ _ 0).mp
  refine Exists.intro (fun _ => 9) (And.intro ?_ ?_)
  next =>
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
        have same : interval =
            { lower := 0, upper := 1000000, accepts := fun value : Nat => 7 <= value } := by
          simpa using member
        simp [same]
  next => simp [OrderedCutTerms]

theorem decreasing_points_rejected :
    Not (exists log : List Nat,
      Realizes log 3 [(0, 9), (2, 3)] [] /\
      Monotone (fun index : Fin log.length => log.get index) /\
      (forall entry, Membership.mem log entry -> entry <= 100)) := by
  intro witness
  have finite := (finite_completion_iff id 3 100 [(0, 9), (2, 3)] [] 0).mpr witness
  cases finite with
  | intro samples valid =>
    have left_cut := point_cut [(0, 9), (2, 3)] [] (0, 9) (by simp)
    have right_cut := point_cut [(0, 9), (2, 3)] [] (2, 3) (by simp)
    have left := (valid.1.2 0 left_cut (by omega)).1 (0, 9) (by simp) rfl
    have right := (valid.1.2 2 right_cut (by omega)).1 (2, 3) (by simp) rfl
    have comparison := valid.2.1 0 left_cut 2 right_cut (by omega) (by omega)
    change samples 0 <= samples 2 at comparison
    simp only [left, right] at comparison
    omega

theorem point_above_current_rejected :
    Not (exists log : List Nat,
      Realizes log 1 [(0, 4)] [] /\
      Monotone (fun index : Fin log.length => log.get index) /\
      (forall entry, Membership.mem log entry -> entry <= 3)) := by
  intro witness
  have finite := (finite_completion_iff id 1 3 [(0, 4)] [] 0).mpr witness
  cases finite with
  | intro samples valid =>
    have boundary := point_cut [(0, 4)] [] (0, 4) (by simp)
    have value := (valid.1.2 0 boundary (by omega)).1 (0, 4) (by simp) rfl
    have bounded := valid.2.2 0 boundary (by omega)
    change samples 0 <= 3 at bounded
    simp only [value] at bounded
    omega

theorem separated_term_intervals_rejected :
    Not (exists log : List Nat,
      Realizes log 3 []
        [{ lower := 0, upper := 1, accepts := fun value => value = 9 },
         { lower := 2, upper := 3, accepts := fun value => value = 3 }] /\
      Monotone (fun index : Fin log.length => log.get index) /\
      (forall entry, Membership.mem log entry -> entry <= 100)) := by
  let left : IntervalCompletion.Interval Nat :=
    { lower := 0, upper := 1, accepts := fun value => value = 9 }
  let right : IntervalCompletion.Interval Nat :=
    { lower := 2, upper := 3, accepts := fun value => value = 3 }
  intro witness
  have finite := (finite_completion_iff id 3 100 [] [left, right] 0).mpr witness
  cases finite with
  | intro samples valid =>
    have left_cut := (interval_cuts [] [left, right] left (by simp)).1
    have right_cut := (interval_cuts [] [left, right] right (by simp)).1
    have left_value := (valid.1.2 0 left_cut (by omega)).2 left (by simp)
      (by simp [Inside, left])
    have right_value := (valid.1.2 2 right_cut (by omega)).2 right (by simp)
      (by simp [Inside, right])
    have comparison := valid.2.1 0 left_cut 2 right_cut (by omega) (by omega)
    change samples 0 = 9 at left_value
    change samples 2 = 3 at right_value
    change samples 0 <= samples 2 at comparison
    omega

theorem equal_terms_distinct_payloads :
    exists log : List (Prod Nat Nat),
      Realizes log 3 [(0, (1, 10)), (2, (1, 20))] [] /\
      Monotone (fun index : Fin log.length => (log.get index).1) /\
      (forall entry, Membership.mem log entry -> entry.1 <= 1) := by
  apply (finite_completion_iff Prod.fst 3 1 _ _ (0, 0)).mp
  refine Exists.intro (fun index => (1, if index < 2 then 10 else 20)) (And.intro ?_ ?_)
  next =>
    constructor
    next => simp
    next =>
      intro boundary _ _
      constructor
      next =>
        intro point member same
        simp only [List.mem_cons, List.not_mem_nil, or_false] at member
        cases member with
        | inl equal =>
          subst point
          subst boundary
          rfl
        | inr equal =>
          subst point
          subst boundary
          rfl
      next => simp
  next => simp [OrderedCutTerms]

theorem dead_cuts_unconstrained :
    FiniteConditions 1 [(0, 7), (0, 7)]
      [{ lower := 1, upper := 10, accepts := fun _ => False },
       { lower := 3, upper := 2, accepts := fun _ => False }]
      (fun index => if index = 0 then 7 else 100) /\
    OrderedCutTerms id 1 7
      (cuts [(0, 7), (0, 7)]
        [{ lower := 1, upper := 10, accepts := fun _ => False },
         { lower := 3, upper := 2, accepts := fun _ => False }])
      (fun index => if index = 0 then 7 else 100) := by
  simp [FiniteConditions, Requirements, OrderedCutTerms, cuts, Inside]

end CCFRaft.Sparse.MonotoneIntervals

run_cmd do
  let namespaceName := `CCFRaft.Sparse.MonotoneIntervals
  let mut count := 0
  let environment <- Lean.getEnv
  for (name, _) in environment.constants.toList do
    if namespaceName.isPrefixOf name then
      count := count + 1
      let axioms <- Lean.collectAxioms name
      for axiomName in axioms do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"MonotoneIntervals: audited {count} declarations; only propext, Classical.choice, Quot.sound"
