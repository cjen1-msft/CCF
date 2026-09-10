import Sparse.QueueClause

set_option autoImplicit false

namespace CCFRaft.Sparse.QueueCountBounds

open Sparse.QueueStream (Event concreteFollows)
open Sparse.CountedQueue (Uses)
open Sparse.IntegerQueue (ValidCounts RawInitialFacts initial_valid valid_update)
open Sparse.SignedQueue (SignedWindow)
open Sparse.QueueClause

variable {A : Type} [DecidableEq A]

def PointBound (cursor : Cursor A) (message : A) : Prop :=
  0 <= cursor.counts message /\
    cursor.counts message <= cursor.window.tail - cursor.window.head

def QueryBounds (cursor : Cursor A) : Event A -> Prop
  | .send message | .pop message => PointBound cursor message
  | .peek _ | .length _ => True

-- Only the event's packet key is constrained, at its source and target states.
def Bounds (heap : Heap A) : List (Clause A) -> Prop
  | [] => True
  | clause :: rest =>
    QueryBounds (heap clause.source) clause.event /\
    QueryBounds (heap clause.target) clause.event /\ Bounds heap rest

def BoundedHolds (order : Int -> A) (heap : Heap A) (clauses : List (Clause A)) : Prop :=
  Holds order heap clauses /\ Bounds heap clauses

-- This finite invariant is proved from RawInitialFacts, not added to the compiler.
def Budget (keys : Finset A) (cursor : Cursor A) : Prop :=
  ValidCounts keys cursor.counts /\
    keys.sum cursor.counts <= cursor.window.tail - cursor.window.head

theorem sum_update (keys : Finset A) (counts : A -> Int) (message : A) (value : Int)
    (tracked : Membership.mem keys message) :
    keys.sum (Function.update counts message value) =
      keys.sum counts - counts message + value := by
  have old := Finset.add_sum_erase keys counts tracked
  change counts message + (keys.erase message).sum counts = keys.sum counts at old
  rw [Finset.sum_update_of_mem tracked, Finset.sdiff_singleton_eq_erase]
  change value + (keys.erase message).sum counts = keys.sum counts - counts message + value
  omega

omit [DecidableEq A] in
theorem budget_point (keys : Finset A) (cursor : Cursor A) (message : A)
    (budget : Budget keys cursor) (tracked : Membership.mem keys message) :
    PointBound cursor message := by
  exact And.intro (budget.1 message tracked)
    ((Finset.single_le_sum budget.1 tracked).trans budget.2)

omit [DecidableEq A] in
theorem uses_split (keys : Finset A) (event : Event A) (rest : List (Event A)) :
    Uses keys (event :: rest) <-> Uses keys [event] /\ Uses keys rest := by
  cases event <;> simp [Uses]

omit [DecidableEq A] in
theorem budget_query (keys : Finset A) (cursor : Cursor A) (event : Event A)
    (budget : Budget keys cursor) (used : Uses keys [event]) :
    QueryBounds cursor event := by
  cases event with
  | send message => exact budget_point keys cursor message budget used.1
  | pop message => exact budget_point keys cursor message budget used.1
  | peek _ => trivial
  | length _ => trivial

theorem budget_advance (keys : Finset A) (order : Int -> A) (cursor : Cursor A)
    (event : Event A) (budget : Budget keys cursor) (used : Uses keys [event])
    (allowed : guard order cursor event) :
    Budget keys (advance cursor event) := by
  cases event with
  | send message =>
    by_cases zero : cursor.counts message = 0
    next =>
      simp only [advance, zero, if_true]
      change ValidCounts keys (Function.update cursor.counts message 1) /\
        keys.sum (Function.update cursor.counts message 1) <=
          cursor.window.tail + 1 - cursor.window.head
      refine And.intro (valid_update keys cursor.counts message 1 budget.1 (by omega)) ?_
      rw [sum_update keys cursor.counts message 1 used.1, zero]
      have total := budget.2
      omega
    next => simpa only [advance, zero, if_false] using budget
  | pop message =>
    have positive : 0 < cursor.counts message := allowed.2.2
    change ValidCounts keys
        (Function.update cursor.counts message (cursor.counts message - 1)) /\
      keys.sum (Function.update cursor.counts message (cursor.counts message - 1)) <=
        cursor.window.tail - (cursor.window.head + 1)
    refine And.intro (valid_update keys cursor.counts message
      (cursor.counts message - 1) budget.1 (by omega)) ?_
    rw [sum_update keys cursor.counts message (cursor.counts message - 1) used.1]
    have total := budget.2
    omega
  | peek _ => exact budget
  | length _ => exact budget

theorem compile_bounds (keys : Finset A) (order : Int -> A) (heap : Heap A)
    (trace : List (Event A)) (current fresh : Nat) (uses : Uses keys trace)
    (budget : Budget keys (heap current))
    (holds : Holds order heap (compile current fresh trace)) :
    Bounds heap (compile current fresh trace) := by
  induction trace generalizing current fresh with
  | nil => trivial
  | cons event rest ih =>
    have used := (uses_split keys event rest).mp uses
    have before := budget_query keys (heap current) event budget used.1
    by_cases writing : writes event = true
    next =>
      simp only [compile, writing, if_true, Holds, Clause.Holds] at holds
      have after : Budget keys (heap fresh) := by
        rw [holds.1.2]
        exact budget_advance keys order (heap current) event budget used.1 holds.1.1
      simp only [compile, writing, if_true, Bounds]
      exact And.intro before (And.intro
        (budget_query keys (heap fresh) event after used.1)
        (ih fresh (fresh + 1) used.2 after holds.2))
    next =>
      simp only [compile, writing] at holds
      simp only [compile, writing]
      exact And.intro before (And.intro before
        (ih current fresh used.2 budget holds.2))

variable [BEq A] [LawfulBEq A]

omit [DecidableEq A] [LawfulBEq A] in
theorem initial_budget (keys : Finset A) (cursor : Cursor A) (length : Int)
    (nonnegative : 0 <= length) (trace : List (Event A))
    (window : cursor.window = { head := 0, tail := length })
    (facts : RawInitialFacts keys cursor.counts length.toNat trace) :
    Budget keys cursor := by
  refine And.intro (initial_valid keys cursor.counts length.toNat trace facts) ?_
  have total := facts.2
  rw [window]
  change keys.sum cursor.counts <= length - 0
  omega

omit [LawfulBEq A] in
theorem bounded_holds_iff (keys : Finset A) (order : Int -> A) (heap : Heap A)
    (length : Int) (nonnegative : 0 <= length) (trace : List (Event A))
    (uses : Uses keys trace)
    (window : (heap 0).window = { head := 0, tail := length })
    (facts : RawInitialFacts keys (heap 0).counts length.toNat trace) :
    BoundedHolds order heap (compile 0 1 trace) <-> Holds order heap (compile 0 1 trace) := by
  constructor
  next => exact fun holds => holds.1
  next =>
    intro holds
    exact And.intro holds (compile_bounds keys order heap trace 0 1 uses
      (initial_budget keys (heap 0) length nonnegative trace window facts) holds)

theorem bounded_compiled_exists_iff (keys : Finset A) (length : Int)
    (nonnegative : 0 <= length) (trace : List (Event A)) (uses : Uses keys trace)
    (filler : A) (fresh : Not (Membership.mem keys filler)) :
    (exists order : Int -> A, exists heap : Heap A,
      (heap 0).window = { head := 0, tail := length } /\
      RawInitialFacts keys (heap 0).counts length.toNat trace /\
      BoundedHolds order heap (compile 0 1 trace)) <->
    (exists queue : List A, (queue.length : Int) = length /\ concreteFollows queue trace) := by
  rw [<- Sparse.QueueClause.compiled_exists_iff keys length nonnegative trace
    uses filler fresh]
  constructor
  next =>
    intro witness
    cases witness with
    | intro order witness =>
      cases witness with
      | intro heap spec =>
        exact Exists.intro order (Exists.intro heap
          (And.intro spec.1 (And.intro spec.2.1 spec.2.2.1)))
  next =>
    intro witness
    cases witness with
    | intro order witness =>
      cases witness with
      | intro heap spec =>
        exact Exists.intro order (Exists.intro heap
          (And.intro spec.1 (And.intro spec.2.1
            ((bounded_holds_iff keys order heap length nonnegative trace uses
              spec.1 spec.2.1).mpr spec.2.2))))

end CCFRaft.Sparse.QueueCountBounds

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.QueueCountBounds).isPrefixOf name then
      let axioms <- Lean.collectAxioms name
      for axiomName in axioms do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse queue count bounds audit passed: {checked} declarations."
