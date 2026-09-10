import Sparse.SignedQueue

set_option autoImplicit false

namespace CCFRaft.Sparse.QueueClause

open Sparse.QueueStream (Event concreteFollows)
open Sparse.CountedQueue (Uses)
open Sparse.IntegerQueue (RawInitialFacts)
open Sparse.SignedQueue

variable {A : Type} [DecidableEq A]

structure Cursor (A : Type) where
  counts : A -> Int
  window : SignedWindow

def advance (cursor : Cursor A) : Event A -> Cursor A
  | .send message =>
    if cursor.counts message = 0 then
      { counts := Function.update cursor.counts message 1, window := cursor.window.append }
    else cursor
  | .pop message =>
    { counts := Function.update cursor.counts message (cursor.counts message - 1)
      window := cursor.window.pop }
  | .peek _
  | .length _ => cursor

def guard (order : Int -> A) (cursor : Cursor A) : Event A -> Prop
  | .send message => cursor.counts message = 0 -> order cursor.window.tail = message
  | .pop message =>
    cursor.window.head < cursor.window.tail /\ order cursor.window.head = message /\
      0 < cursor.counts message
  | .peek message =>
    cursor.window.head < cursor.window.tail /\ order cursor.window.head = message
  | .length length => cursor.window.tail - cursor.window.head = (length : Int)

def cursorFollows (order : Int -> A) : Cursor A -> List (Event A) -> Prop
  | _, [] => True
  | cursor, event :: rest =>
    guard order cursor event /\ cursorFollows order (advance cursor event) rest

theorem cursor_iff_signed (order : Int -> A) (cursor : Cursor A) (trace : List (Event A)) :
    cursorFollows order cursor trace <->
      signedFollows order cursor.counts cursor.window trace := by
  induction trace generalizing cursor with
  | nil => rfl
  | cons event rest ih =>
    cases event with
    | send message =>
      by_cases zero : cursor.counts message = 0 <;>
        simp [cursorFollows, guard, advance, signedFollows, zero, ih]
    | pop message =>
      simp only [cursorFollows, guard, advance, signedFollows, ih, and_assoc]
    | peek message =>
      simp only [cursorFollows, guard, advance, signedFollows, ih, and_assoc]
    | length length =>
      exact and_congr Iff.rfl (ih cursor)

structure Clause (A : Type) where
  event : Event A
  source : Nat
  target : Nat

abbrev Heap (A : Type) := Nat -> Cursor A

def Clause.Holds (order : Int -> A) (heap : Heap A) (clause : Clause A) : Prop :=
  guard order (heap clause.source) clause.event /\
    heap clause.target = advance (heap clause.source) clause.event

def Holds (order : Int -> A) (heap : Heap A) : List (Clause A) -> Prop
  | [] => True
  | clause :: rest => clause.Holds order heap /\ Holds order heap rest

def writes : Event A -> Bool
  | .send _ | .pop _ => true
  | .peek _ | .length _ => false

def compile (current fresh : Nat) : List (Event A) -> List (Clause A)
  | [] => []
  | event :: rest =>
    if writes event then
      { event := event, source := current, target := fresh } ::
        compile fresh (fresh + 1) rest
    else
      { event := event, source := current, target := current } ::
        compile current fresh rest

theorem advance_readonly (cursor : Cursor A) (event : Event A) (readonly : writes event = false) :
    advance cursor event = cursor := by
  cases event <;> simp_all [writes, advance]

def fieldEquations (source target : Cursor A) : Event A -> Prop
  | .send message =>
    target.window.head = source.window.head /\
    target.window.tail = source.window.tail + (if source.counts message = 0 then 1 else 0) /\
    target.counts = Function.update source.counts message
      (if source.counts message = 0 then 1 else source.counts message)
  | .pop message =>
    target.window.head = source.window.head + 1 /\
    target.window.tail = source.window.tail /\
    target.counts = Function.update source.counts message (source.counts message - 1)
  | .peek _
  | .length _ =>
    target.window.head = source.window.head /\
    target.window.tail = source.window.tail /\
    target.counts = source.counts

omit [DecidableEq A] in
theorem cursor_eq_iff (left right : Cursor A) :
    left = right <->
      left.window.head = right.window.head /\
      left.window.tail = right.window.tail /\ left.counts = right.counts := by
  cases left with
  | mk counts window =>
    cases right with
    | mk counts' window' =>
      cases window
      cases window'
      simp only [Cursor.mk.injEq, SignedWindow.mk.injEq]
      tauto

theorem field_equations_iff (source target : Cursor A) (event : Event A) :
    fieldEquations source target event <-> target = advance source event := by
  rw [cursor_eq_iff]
  cases event with
  | send message =>
    by_cases empty : source.counts message = 0
    next => simp [fieldEquations, advance, empty, SignedWindow.append]
    next => simp [fieldEquations, advance, empty, Function.update_eq_self]
  | pop message => rfl
  | peek message => rfl
  | length length => rfl

theorem clause_fields_iff (order : Int -> A) (heap : Heap A) (clause : Clause A) :
    (guard order (heap clause.source) clause.event /\
      fieldEquations (heap clause.source) (heap clause.target) clause.event) <->
    clause.Holds order heap := by
  exact and_congr Iff.rfl (field_equations_iff _ _ _)

omit [DecidableEq A] in
theorem compile_length (trace : List (Event A)) (current fresh : Nat) :
    (compile current fresh trace).length = trace.length := by
  induction trace generalizing current fresh with
  | nil => rfl
  | cons event rest ih =>
    simp only [compile]
    split <;> simp [ih]

theorem compile_sound (trace : List (Event A)) (order : Int -> A)
    (heap : Heap A) (current fresh : Nat)
    (holds : Holds order heap (compile current fresh trace)) :
    cursorFollows order (heap current) trace := by
  induction trace generalizing current fresh with
  | nil => trivial
  | cons event rest ih =>
    unfold compile at holds
    split at holds
    next =>
      have next := ih _ _ holds.2
      have link := holds.1.2
      change heap fresh = advance (heap current) event at link
      exact And.intro holds.1.1 (by simpa only [link] using next)
    next =>
      have next := ih _ _ holds.2
      have link := holds.1.2
      change heap current = advance (heap current) event at link
      exact And.intro holds.1.1 (by simpa only [Eq.symm link] using next)

theorem compile_complete (trace : List (Event A)) (order : Int -> A)
    (heap : Heap A) (current fresh : Nat) (unused : current < fresh)
    (follows : cursorFollows order (heap current) trace) :
    exists extended : Heap A,
      (forall index, index < fresh -> extended index = heap index) /\
        Holds order extended (compile current fresh trace) := by
  induction trace generalizing heap current fresh with
  | nil => exact Exists.intro heap (And.intro (fun _ _ => rfl) True.intro)
  | cons event rest ih =>
    by_cases writing : writes event = true
    next =>
      let updated := Function.update heap fresh (advance (heap current) event)
      have next : cursorFollows order (updated fresh) rest := by
        simpa [updated] using follows.2
      cases ih updated fresh (fresh + 1) (by omega) next with
      | intro extended spec =>
        have old : extended current = heap current := by
          rw [spec.1 current (by omega)]
          simp [updated, Function.update_of_ne (Nat.ne_of_lt unused)]
        have new : extended fresh = advance (heap current) event := by
          rw [spec.1 fresh (by omega)]
          simp [updated]
        refine Exists.intro extended (And.intro ?_ ?_)
        next =>
          intro index below
          rw [spec.1 index (by omega)]
          simp [updated, Function.update_of_ne (Nat.ne_of_lt below)]
        next =>
          simp only [compile, writing, if_true, Holds, Clause.Holds, old, new]
          exact And.intro (And.intro follows.1 True.intro) spec.2
    next =>
      have readonly : writes event = false := Bool.eq_false_iff.mpr writing
      have stable := advance_readonly (heap current) event readonly
      have next : cursorFollows order (heap current) rest := by
        simpa only [stable] using follows.2
      cases ih heap current fresh unused next with
      | intro extended spec =>
        refine Exists.intro extended (And.intro spec.1 ?_)
        have old := spec.1 current unused
        simp only [compile, readonly, Bool.false_eq_true, if_false, Holds, Clause.Holds, old, stable]
        exact And.intro (And.intro follows.1 True.intro) spec.2

variable [BEq A] [LawfulBEq A]

theorem compiled_exists_iff (keys : Finset A) (length : Int) (nonnegative : 0 <= length)
    (trace : List (Event A)) (uses : Uses keys trace)
    (filler : A) (fresh : Not (Membership.mem keys filler)) :
    (exists order : Int -> A, exists heap : Heap A,
      (heap 0).window = { head := 0, tail := length } /\
      RawInitialFacts keys (heap 0).counts length.toNat trace /\
      Holds order heap (compile 0 1 trace)) <->
    (exists queue : List A, (queue.length : Int) = length /\ concreteFollows queue trace) := by
  rw [(signed_exists_iff keys length nonnegative trace uses filler fresh).symm]
  constructor
  next =>
    intro witness
    cases witness with
    | intro order witness =>
      cases witness with
      | intro heap spec =>
        have execution := (cursor_iff_signed order (heap 0) trace).mp
          (compile_sound trace order heap 0 1 spec.2.2)
        exact Exists.intro order (Exists.intro (heap 0).counts (And.intro spec.2.1
          (by simpa only [spec.1] using execution)))
  next =>
    intro witness
    cases witness with
    | intro order witness =>
      cases witness with
      | intro counts spec =>
        let initial : Cursor A :=
          { counts := counts, window := { head := 0, tail := length } }
        have execution : cursorFollows order initial trace :=
          (cursor_iff_signed order initial trace).mpr spec.2
        cases compile_complete trace order (fun _ => initial) 0 1 (by omega) execution with
        | intro heap complete =>
          have first := complete.1 0 (by omega)
          refine Exists.intro order (Exists.intro heap (And.intro ?_ (And.intro ?_ complete.2)))
          next => rw [first]
          next => simpa only [first] using spec.1

end CCFRaft.Sparse.QueueClause

run_cmd do
  for theoremName in [
      ``CCFRaft.Sparse.QueueClause.cursor_iff_signed,
      ``CCFRaft.Sparse.QueueClause.clause_fields_iff,
      ``CCFRaft.Sparse.QueueClause.compile_length,
      ``CCFRaft.Sparse.QueueClause.compile_sound,
      ``CCFRaft.Sparse.QueueClause.compile_complete,
      ``CCFRaft.Sparse.QueueClause.compiled_exists_iff] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom: {name}"
