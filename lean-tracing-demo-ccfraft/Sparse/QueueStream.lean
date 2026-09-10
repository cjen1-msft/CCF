import Model
import Mathlib.Data.List.OfFn

set_option autoImplicit false

namespace CCFRaft.Sparse.QueueStream

variable {A : Type}

def segment (order : Nat -> A) (start length : Nat) : List A :=
  List.ofFn (fun i : Fin length => order (start + i.val))

@[simp] theorem segment_length (order : Nat -> A) (start length : Nat) :
    (segment order start length).length = length := by
  simp [segment]

@[simp] theorem segment_zero (order : Nat -> A) (start : Nat) :
    segment order start 0 = [] := rfl

theorem segment_cons (order : Nat -> A) (start length : Nat) :
    segment order start (length + 1) =
      order start :: segment order (start + 1) length := by
  simp [segment, List.ofFn_succ, Nat.add_comm, Nat.add_left_comm]

theorem segment_append (order : Nat -> A) (start length : Nat) :
    segment order start (length + 1) =
      segment order start length ++ [order (start + length)] := by
  induction length generalizing start with
  | zero => simp [segment_cons]
  | succ length ih =>
    rw [segment_cons order start (length + 1), ih (start + 1),
      segment_cons order start length]
    simp [Nat.add_comm, Nat.add_left_comm]

structure Window where
  head : Nat
  tail : Nat

def Window.Valid (window : Window) : Prop := window.head <= window.tail

def Window.decode (window : Window) (order : Nat -> A) : List A :=
  segment order window.head (window.tail - window.head)

def Window.append (window : Window) : Window :=
  { window with tail := window.tail + 1 }

def Window.pop (window : Window) : Window :=
  { window with head := window.head + 1 }

def AgreeBelow (left right : Nat -> A) (bound : Nat) : Prop :=
  forall index, index < bound -> left index = right index

theorem decode_agrees (window : Window) (left right : Nat -> A)
    (agree : AgreeBelow left right window.tail) :
    window.decode left = window.decode right := by
  unfold Window.decode segment
  congr 1
  funext i
  apply agree
  have h := i.isLt
  omega

theorem decode_append (window : Window) (valid : window.Valid) (order : Nat -> A) :
    window.append.decode order = window.decode order ++ [order window.tail] := by
  have h : window.tail + 1 - window.head = (window.tail - window.head) + 1 := by
    unfold Window.Valid at valid
    omega
  have sum : window.head + (window.tail - window.head) = window.tail := by
    unfold Window.Valid at valid
    omega
  simp only [Window.append, Window.decode, h, segment_append, sum]

theorem decode_cons (window : Window) (present : window.head < window.tail)
    (order : Nat -> A) :
    window.decode order = order window.head :: window.pop.decode order := by
  have h : window.tail - window.head = (window.tail - (window.head + 1)) + 1 := by
    omega
  simp only [Window.decode, h, segment_cons, Window.pop]

theorem decode_head (window : Window) (order : Nat -> A) (message : A)
    (observed : (window.decode order).head? = some message) :
    window.head < window.tail /\ order window.head = message := by
  by_cases present : window.head < window.tail
  next =>
    rw [decode_cons window present order] at observed
    exact And.intro present (Option.some.inj observed)
  next =>
    have zero : window.tail - window.head = 0 := by omega
    simp [Window.decode, zero] at observed

inductive Event (A : Type) where
  | send (message : A)
  | pop (message : A)
  | peek (message : A)
  | length (length : Nat)

variable [DecidableEq A]

def concreteFollows : List A -> List (Event A) -> Prop
  | _, [] => True
  | queue, .send message :: rest =>
    concreteFollows
      (if Membership.mem queue message then queue else queue ++ [message]) rest
  | queue, .pop message :: rest =>
    queue.head? = some message /\ concreteFollows queue.tail rest
  | queue, .peek message :: rest =>
    queue.head? = some message /\ concreteFollows queue rest
  | queue, .length length :: rest =>
    queue.length = length /\ concreteFollows queue rest

def streamFollows (order : Nat -> A) : Window -> List (Event A) -> Prop
  | _, [] => True
  | window, .send message :: rest =>
    if Membership.mem (window.decode order) message then streamFollows order window rest
    else order window.tail = message /\ streamFollows order window.append rest
  | window, .pop message :: rest =>
    window.head < window.tail /\ order window.head = message /\
      streamFollows order window.pop rest
  | window, .peek message :: rest =>
    window.head < window.tail /\ order window.head = message /\
      streamFollows order window rest
  | window, .length length :: rest =>
    window.tail - window.head = length /\ streamFollows order window rest

theorem stream_sound (order : Nat -> A) (window : Window) (valid : window.Valid)
    (trace : List (Event A)) (follows : streamFollows order window trace) :
    concreteFollows (window.decode order) trace := by
  induction trace generalizing window with
  | nil => trivial
  | cons event rest ih =>
    cases event with
    | send message =>
      unfold streamFollows at follows
      unfold concreteFollows
      by_cases present : Membership.mem (window.decode order) message
      next =>
        simp only [present, if_true] at follows
        simp only [present, if_true]
        exact ih window valid follows
      next =>
        simp only [present, if_false] at follows
        simp only [present, if_false]
        have next_valid : window.append.Valid := by
          change window.head <= window.tail + 1
          unfold Window.Valid at valid
          omega
        have next := ih window.append next_valid follows.2
        simpa only [decode_append window valid order, follows.1] using next
    | pop message =>
      have present := follows.1
      have first := follows.2.1
      have next_valid : window.pop.Valid := by
        change window.head + 1 <= window.tail
        omega
      have next := ih window.pop next_valid follows.2.2
      simp only [concreteFollows, decode_cons window present order, first,
        List.head?_cons, List.tail_cons]
      exact And.intro True.intro next
    | peek message =>
      have present := follows.1
      have first := follows.2.1
      refine And.intro ?_ (ih window valid follows.2.2)
      simp only [decode_cons window present order, first, List.head?_cons]
    | length length =>
      exact And.intro (by simpa [Window.decode] using follows.1)
        (ih window valid follows.2)

theorem stream_complete (order : Nat -> A) (window : Window) (valid : window.Valid)
    (trace : List (Event A)) (follows : concreteFollows (window.decode order) trace) :
    exists future : Nat -> A,
      AgreeBelow future order window.tail /\ streamFollows future window trace := by
  induction trace generalizing order window with
  | nil =>
    exact Exists.intro order (And.intro (fun _ _ => rfl) True.intro)
  | cons event rest ih =>
    cases event with
    | send message =>
      unfold concreteFollows at follows
      by_cases present : Membership.mem (window.decode order) message
      next =>
        simp only [present, if_true] at follows
        cases ih order window valid follows with
        | intro future spec =>
          refine Exists.intro future (And.intro spec.1 ?_)
          have same := decode_agrees window future order spec.1
          simpa only [streamFollows, same, present, if_true] using spec.2
      next =>
        simp only [present, if_false] at follows
        let updated := Function.update order window.tail message
        have preserved : AgreeBelow updated order window.tail := by
          intro index below
          have distinct : Not (index = window.tail) := by omega
          simp [updated, Function.update_of_ne distinct]
        have same := decode_agrees window updated order preserved
        have stored : updated window.tail = message := by simp [updated]
        have next_valid : window.append.Valid := by
          change window.head <= window.tail + 1
          unfold Window.Valid at valid
          omega
        have next_follows : concreteFollows (window.append.decode updated) rest := by
          simpa only [decode_append window valid updated, same, stored] using follows
        cases ih updated window.append next_valid next_follows with
        | intro future spec =>
          have old_agree : AgreeBelow future order window.tail := by
            intro index below
            have newer : index < window.append.tail := by
              change index < window.tail + 1
              omega
            exact (spec.1 index newer).trans (preserved index below)
          have latest : future window.tail = message := by
            have within : window.tail < window.append.tail := by
              change window.tail < window.tail + 1
              omega
            exact (spec.1 window.tail within).trans stored
          have old_same := decode_agrees window future order old_agree
          refine Exists.intro future (And.intro old_agree ?_)
          simp only [streamFollows, old_same, present, if_false]
          exact And.intro latest spec.2
    | pop message =>
      have selected := decode_head window order message follows.1
      have next_valid : window.pop.Valid := by
        change window.head + 1 <= window.tail
        have h := selected.1
        omega
      have next_follows : concreteFollows (window.pop.decode order) rest := by
        simpa only [decode_cons window selected.1 order, List.tail_cons] using follows.2
      cases ih order window.pop next_valid next_follows with
      | intro future spec =>
        exact Exists.intro future (And.intro spec.1
          (And.intro selected.1 (And.intro
            ((spec.1 window.head selected.1).trans selected.2) spec.2)))
    | peek message =>
      have selected := decode_head window order message follows.1
      cases ih order window valid follows.2 with
      | intro future spec =>
        exact Exists.intro future (And.intro spec.1
          (And.intro selected.1 (And.intro
            ((spec.1 window.head selected.1).trans selected.2) spec.2)))
    | length length =>
      cases ih order window valid follows.2 with
      | intro future spec =>
        refine Exists.intro future (And.intro spec.1 (And.intro ?_ spec.2))
        simpa only [Window.decode, segment_length] using follows.1

theorem stream_exists_iff (length : Nat) (trace : List (Event A)) (fallback : A) :
    (exists order : Nat -> A,
      streamFollows order { head := 0, tail := length } trace) <->
    (exists queue : List A, queue.length = length /\ concreteFollows queue trace) := by
  let window : Window := { head := 0, tail := length }
  have valid : window.Valid := Nat.zero_le length
  constructor
  next =>
    intro witness
    cases witness with
    | intro order follows =>
      refine Exists.intro (window.decode order) (And.intro ?_ ?_)
      next => simp [window, Window.decode]
      next => exact stream_sound order window valid trace follows
  next =>
    intro witness
    cases witness with
    | intro queue spec =>
      let order : Nat -> A := fun index => queue[index]?.getD fallback
      have initial : window.decode order = queue := by
        change segment order 0 length = queue
        rw [Eq.symm spec.1]
        simp [segment, order, List.ofFn_getElem]
      have follows : concreteFollows (window.decode order) trace := by
        rw [initial]
        exact spec.2
      cases stream_complete order window valid trace follows with
      | intro future complete =>
        exact Exists.intro future complete.2

end CCFRaft.Sparse.QueueStream

run_cmd do
  for theoremName in [
      ``CCFRaft.Sparse.QueueStream.decode_agrees,
      ``CCFRaft.Sparse.QueueStream.decode_append,
      ``CCFRaft.Sparse.QueueStream.decode_cons,
      ``CCFRaft.Sparse.QueueStream.stream_sound,
      ``CCFRaft.Sparse.QueueStream.stream_complete,
      ``CCFRaft.Sparse.QueueStream.stream_exists_iff] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom: {name}"
