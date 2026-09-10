import Sparse.QueueClause

set_option autoImplicit false

namespace CCFRaft.Sparse.QueueObservationBounds

open QueueStream (Event)
open QueueClause
open SignedQueue (SignedWindow)

variable {A : Type}

def popCount : List (Event A) -> Nat
  | [] => 0
  | .pop _ :: rest => 1 + popCount rest
  | _ :: rest => popCount rest

def sentKeys : List (Event A) -> List A
  | [] => []
  | .send message :: rest => message :: sentKeys rest
  | _ :: rest => sentKeys rest

structure Facts (order : Int -> A) (initialLength : Int) (pops : Nat)
    (sent : List A) (cursor : Cursor A) : Prop where
  head : cursor.window.head = (pops : Int)
  tail_lower : initialLength <= cursor.window.tail
  tail_upper : cursor.window.tail <= initialLength + (sent.length : Int)
  produced : forall index, initialLength <= index -> index < cursor.window.tail ->
    Membership.mem sent (order index)

theorem initial_facts (order : Int -> A) (initial : Cursor A) (initialLength : Int)
    (window : initial.window = { head := 0, tail := initialLength }) :
    Facts order initialLength 0 [] initial := by
  constructor
  next => simp [window]
  next => simp [window]
  next => simp [window]
  next =>
    intro index lower upper
    simp only [window] at upper
    omega

theorem window_bounds (order : Int -> A) (initialLength : Int) (pops : Nat)
    (sent : List A) (cursor : Cursor A) (facts : Facts order initialLength pops sent cursor) :
    initialLength - (pops : Int) <= cursor.window.tail - cursor.window.head /\
      cursor.window.tail - cursor.window.head <=
        initialLength + (sent.length : Int) - (pops : Int) := by
  have head := facts.head
  have lower := facts.tail_lower
  have upper := facts.tail_upper
  omega

variable [DecidableEq A]

def after : Cursor A -> List (Event A) -> Cursor A
  | cursor, [] => cursor
  | cursor, event :: rest => after (advance cursor event) rest

theorem facts_advance (order : Int -> A) (initialLength : Int) (pops : Nat)
    (sent : List A) (cursor : Cursor A) (event : Event A)
    (facts : Facts order initialLength pops sent cursor) (allowed : guard order cursor event) :
    Facts order initialLength (pops + popCount [event]) (sent ++ sentKeys [event])
      (advance cursor event) := by
  have head := facts.head
  have lower := facts.tail_lower
  have upper := facts.tail_upper
  cases event with
  | send message =>
    by_cases fresh : cursor.counts message = 0
    next =>
      simp only [popCount, sentKeys, Nat.add_zero, advance, fresh, if_true]
      constructor
      next => exact head
      next =>
        change initialLength <= cursor.window.tail + 1
        omega
      next =>
        change cursor.window.tail + 1 <= initialLength + ((sent ++ [message]).length : Int)
        simp only [List.length_append, List.length_singleton, Nat.cast_add, Nat.cast_one]
        omega
      next =>
        intro index from_initial below
        change index < cursor.window.tail + 1 at below
        by_cases old : index < cursor.window.tail
        next => exact List.mem_append.mpr (Or.inl (facts.produced index from_initial old))
        next =>
          have same : index = cursor.window.tail := by omega
          have stored := allowed fresh
          rw [same, stored]
          exact List.mem_append.mpr (Or.inr (by simp))
    next =>
      simp only [popCount, sentKeys, Nat.add_zero, advance, fresh, if_false]
      constructor
      next => exact head
      next => exact lower
      next =>
        simp only [List.length_append, List.length_singleton, Nat.cast_add, Nat.cast_one]
        omega
      next =>
        intro index from_initial below
        exact List.mem_append.mpr (Or.inl (facts.produced index from_initial below))
  | pop message =>
    simp only [popCount, sentKeys, Nat.add_zero, List.append_nil, advance]
    constructor
    next =>
      change cursor.window.head + 1 = ((pops + 1 : Nat) : Int)
      simp only [Nat.cast_add, Nat.cast_one]
      omega
    next => exact lower
    next => exact upper
    next => exact facts.produced
  | peek _ => simpa only [popCount, sentKeys, Nat.add_zero, List.append_nil, advance] using facts
  | length _ => simpa only [popCount, sentKeys, Nat.add_zero, List.append_nil, advance] using facts

theorem facts_after (order : Int -> A) (initialLength : Int) (pops : Nat)
    (sent : List A) (cursor : Cursor A) (history : List (Event A))
    (facts : Facts order initialLength pops sent cursor) (follows : cursorFollows order cursor history) :
    Facts order initialLength (pops + popCount history) (sent ++ sentKeys history)
      (after cursor history) := by
  induction history generalizing pops sent cursor with
  | nil => simpa only [popCount, sentKeys, Nat.add_zero, List.append_nil, after] using facts
  | cons event rest ih =>
    have next := facts_advance order initialLength pops sent cursor event facts follows.1
    have result := ih (pops + popCount [event]) (sent ++ sentKeys [event])
      (advance cursor event) next follows.2
    cases event <;>
      simpa only [popCount, sentKeys, after, Nat.add_zero, Nat.add_assoc,
        List.append_nil, List.append_assoc, List.singleton_append] using result

theorem follows_append (order : Int -> A) (cursor : Cursor A)
    (history rest : List (Event A)) :
    cursorFollows order cursor (history ++ rest) <->
      cursorFollows order cursor history /\ cursorFollows order (after cursor history) rest := by
  induction history generalizing cursor with
  | nil => simp only [List.nil_append, cursorFollows, after, true_and]
  | cons event history ih =>
    simp only [List.cons_append, cursorFollows, after, ih, and_assoc]

omit [DecidableEq A] in
theorem length_observation (order : Int -> A) (initialLength : Int) (pops : Nat)
    (sent : List A) (cursor : Cursor A) (length : Nat)
    (facts : Facts order initialLength pops sent cursor)
    (observed : guard order cursor (.length length)) :
    (length : Int) + (pops : Int) - (sent.length : Int) <= initialLength /\
      initialLength <= (length : Int) + (pops : Int) := by
  have bounds := window_bounds order initialLength pops sent cursor facts
  change cursor.window.tail - cursor.window.head = (length : Int) at observed
  omega

omit [DecidableEq A] in
theorem unseen_observation (order : Int -> A) (initialLength : Int) (pops : Nat)
    (sent : List A) (cursor : Cursor A) (message : A)
    (facts : Facts order initialLength pops sent cursor)
    (available : cursor.window.head < cursor.window.tail)
    (selected : order cursor.window.head = message)
    (different : forall key, Membership.mem sent key -> Not (message = key)) :
    cursor.window.head < initialLength /\ (pops : Int) + 1 <= initialLength := by
  have in_initial : cursor.window.head < initialLength := by
    by_contra outside
    have from_initial : initialLength <= cursor.window.head := by omega
    have sent_message := facts.produced cursor.window.head from_initial available
    rw [selected] at sent_message
    exact different message sent_message rfl
  have head := facts.head
  exact And.intro in_initial (by omega)

def ObservationFacts (initialLength : Int) (pops : Nat) (sent : List A)
    (cursor : Cursor A) : Event A -> Prop
  | .length length =>
    (length : Int) + (pops : Int) - (sent.length : Int) <= initialLength /\
      initialLength <= (length : Int) + (pops : Int)
  | .peek message | .pop message =>
    (forall key, Membership.mem sent key -> Not (message = key)) ->
      cursor.window.head < initialLength /\ (pops : Int) + 1 <= initialLength
  | .send _ => True

omit [DecidableEq A] in
theorem observation_facts (order : Int -> A) (initialLength : Int) (pops : Nat)
    (sent : List A) (cursor : Cursor A) (event : Event A)
    (facts : Facts order initialLength pops sent cursor) (allowed : guard order cursor event) :
    ObservationFacts initialLength pops sent cursor event := by
  cases event with
  | send _ => trivial
  | length length => exact length_observation order initialLength pops sent cursor length facts allowed
  | peek message =>
    exact unseen_observation order initialLength pops sent cursor message facts
      allowed.1 allowed.2
  | pop message =>
    exact unseen_observation order initialLength pops sent cursor message facts
      allowed.1 allowed.2.1

def AllPrefixFacts (order : Int -> A) (initial : Cursor A) (initialLength : Int)
    (trace : List (Event A)) : Prop :=
  forall history rest, trace = history ++ rest ->
    Facts order initialLength (popCount history) (sentKeys history) (after initial history) /\
    (forall event suffix, rest = event :: suffix ->
      ObservationFacts initialLength (popCount history) (sentKeys history)
        (after initial history) event)

theorem all_prefix_facts (order : Int -> A) (initial : Cursor A) (initialLength : Int)
    (trace : List (Event A))
    (window : initial.window = { head := 0, tail := initialLength })
    (follows : cursorFollows order initial trace) :
    AllPrefixFacts order initial initialLength trace := by
  intro history rest split
  have execution := (follows_append order initial history rest).mp
    (by simpa only [split] using follows)
  have facts : Facts order initialLength (popCount history) (sentKeys history)
      (after initial history) := by
    simpa only [Nat.zero_add, List.nil_append] using
      facts_after order initialLength 0 [] initial history
        (initial_facts order initial initialLength window) execution.1
  refine And.intro facts ?_
  intro event suffix next
  have tail_execution : cursorFollows order (after initial history) (event :: suffix) := by
    simpa only [next] using execution.2
  exact observation_facts order initialLength (popCount history) (sentKeys history)
    (after initial history) event facts tail_execution.1

theorem compiled_all_prefix_facts (order : Int -> A) (heap : Heap A)
    (initialLength : Int) (trace : List (Event A))
    (window : (heap 0).window = { head := 0, tail := initialLength })
    (holds : Holds order heap (compile 0 1 trace)) :
    AllPrefixFacts order (heap 0) initialLength trace :=
  all_prefix_facts order (heap 0) initialLength trace window
    (compile_sound trace order heap 0 1 holds)

end CCFRaft.Sparse.QueueObservationBounds

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.QueueObservationBounds).isPrefixOf name then
      let axioms <- Lean.collectAxioms name
      for axiomName in axioms do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Queue observation bounds audit passed: {checked} declarations."

#print axioms CCFRaft.Sparse.QueueObservationBounds.facts_after
#print axioms CCFRaft.Sparse.QueueObservationBounds.length_observation
#print axioms CCFRaft.Sparse.QueueObservationBounds.unseen_observation
#print axioms CCFRaft.Sparse.QueueObservationBounds.compiled_all_prefix_facts
