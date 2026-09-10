import Sparse.QueueCounts
import Sparse.QueueStream

set_option autoImplicit false

namespace CCFRaft.Sparse.CountedQueue

open Sparse.QueueStream

variable {A : Type} [DecidableEq A] [BEq A] [LawfulBEq A]

def Correct (keys : Finset A) (counts : A -> Nat) (queue : List A) : Prop :=
  forall message, Membership.mem keys message -> counts message = queue.count message

theorem correct_append (keys : Finset A) (counts : A -> Nat) (queue : List A)
    (message : A) (correct : Correct keys counts queue)
    (tracked : Membership.mem keys message) (zero : counts message = 0) :
    Correct keys (Function.update counts message 1) (queue ++ [message]) := by
  intro key member
  have old := correct key member
  by_cases same : key = message
  next =>
    subst key
    have empty_count := (correct message tracked).symm.trans zero
    simp [Function.update_self, List.count_append, empty_count]
  next =>
    simp [List.count_append, same, Ne.symm same, old]

theorem correct_pop (keys : Finset A) (counts : A -> Nat) (message : A)
    (tail : List A) (correct : Correct keys counts (message :: tail)) :
    Correct keys (Function.update counts message (counts message - 1)) tail := by
  intro key member
  have old := correct key member
  by_cases same : key = message
  next =>
    subst key
    simp only [Function.update_self, old, List.count_cons_self, Nat.add_sub_cancel]
  next =>
    simpa [Function.update_of_ne same, List.count_cons, same, Ne.symm same] using old

def Uses (keys : Finset A) : List (Event A) -> Prop
  | [] => True
  | .send message :: rest
  | .pop message :: rest
  | .peek message :: rest => Membership.mem keys message /\ Uses keys rest
  | .length _ :: rest => Uses keys rest

def countedFollows (order : Nat -> A) : (A -> Nat) -> Window -> List (Event A) -> Prop
  | _, _, [] => True
  | counts, window, .send message :: rest =>
    if counts message = 0 then
      order window.tail = message /\
        countedFollows order (Function.update counts message 1) window.append rest
    else countedFollows order counts window rest
  | counts, window, .pop message :: rest =>
    window.head < window.tail /\ order window.head = message /\ 0 < counts message /\
      countedFollows order (Function.update counts message (counts message - 1))
        window.pop rest
  | counts, window, .peek message :: rest =>
    window.head < window.tail /\ order window.head = message /\
      countedFollows order counts window rest
  | counts, window, .length length :: rest =>
    window.tail - window.head = length /\ countedFollows order counts window rest

def readHeads : List (Event A) -> List A
  | [] => []
  | .pop message :: rest => message :: readHeads rest
  | .peek message :: rest =>
    match readHeads rest with
    | [] => [message]
    | head :: tail => head :: tail
  | .send _ :: rest
  | .length _ :: rest => readHeads rest

omit [DecidableEq A] [BEq A] [LawfulBEq A] in
theorem read_heads_length_le (trace : List (Event A)) :
    (readHeads trace).length <= trace.length := by
  induction trace with
  | nil => simp [readHeads]
  | cons event rest ih =>
    cases event <;> cases heads : readHeads rest <;> simp_all [readHeads] <;> omega

omit [BEq A] [LawfulBEq A] in
theorem counted_read_heads (order : Nat -> A) (counts : A -> Nat) (window : Window)
    (trace : List (Event A)) (follows : countedFollows order counts window trace) :
    segment order window.head (readHeads trace).length = readHeads trace := by
  induction trace generalizing counts window with
  | nil => rfl
  | cons event rest ih =>
    cases event with
    | send message =>
      by_cases zero : counts message = 0
      next =>
        simp only [countedFollows, zero, if_true] at follows
        exact ih _ window.append follows.2
      next =>
        simp only [countedFollows, zero, if_false] at follows
        exact ih counts window follows
    | pop message =>
      simp only [readHeads, List.length_cons, segment_cons, follows.2.1]
      exact congrArg (List.cons message) (ih _ window.pop follows.2.2.2)
    | peek message =>
      have future := ih counts window follows.2.2
      cases heads : readHeads rest with
      | nil => simp [readHeads, heads, segment_cons, follows.2.1]
      | cons head tail => simpa only [readHeads, heads] using future
    | length length =>
      exact ih counts window follows.2

omit [BEq A] [LawfulBEq A] in
theorem counted_order_transfer (left right : Nat -> A) (counts : A -> Nat)
    (window : Window) (trace : List (Event A))
    (before : AgreeBelow left right (window.head + (readHeads trace).length))
    (after : forall index, window.tail <= index -> left index = right index)
    (follows : countedFollows left counts window trace) :
    countedFollows right counts window trace := by
  induction trace generalizing counts window with
  | nil => trivial
  | cons event rest ih =>
    cases event with
    | send message =>
      by_cases zero : counts message = 0
      next =>
        simp only [countedFollows, zero, if_true] at follows
        simp only [countedFollows, zero, if_true]
        refine And.intro
          ((after window.tail (Nat.le_refl _)).symm.trans follows.1) ?_
        apply ih _ window.append before ?_ follows.2
        intro index lower
        apply after
        change window.tail + 1 <= index at lower
        omega
      next =>
        simp only [countedFollows, zero, if_false] at follows
        simp only [countedFollows, zero, if_false]
        exact ih counts window before after follows
    | pop message =>
      have selected : right window.head = message := by
        have inside : window.head < window.head + (readHeads (.pop message :: rest)).length := by
          simp only [readHeads, List.length_cons]
          omega
        exact (before window.head inside).symm.trans follows.2.1
      have next_before :
          AgreeBelow left right (window.pop.head + (readHeads rest).length) := by
        intro index below
        apply before
        change index < window.head + ((readHeads rest).length + 1)
        change index < window.head + 1 + (readHeads rest).length at below
        omega
      exact And.intro follows.1 (And.intro selected (And.intro follows.2.2.1
        (ih _ window.pop next_before after follows.2.2.2)))
    | peek message =>
      have positive : 0 < (readHeads (.peek message :: rest)).length := by
        cases heads : readHeads rest <;> simp [readHeads, heads]
      have size :
          (readHeads rest).length <= (readHeads (.peek message :: rest)).length := by
        cases heads : readHeads rest <;> simp [readHeads, heads]
      have selected : right window.head = message := by
        have inside :
            window.head < window.head + (readHeads (.peek message :: rest)).length := by
          omega
        exact (before window.head inside).symm.trans follows.2.1
      have next_before : AgreeBelow left right (window.head + (readHeads rest).length) := by
        intro index below
        exact before index (lt_of_lt_of_le below (Nat.add_le_add_left size window.head))
      exact And.intro follows.1 (And.intro selected
        (ih counts window next_before after follows.2.2))
    | length length =>
      exact And.intro follows.1 (ih counts window before after follows.2)

theorem counted_iff_stream (keys : Finset A) (order : Nat -> A) (counts : A -> Nat)
    (window : Window) (valid : window.Valid) (trace : List (Event A))
    (uses : Uses keys trace) (correct : Correct keys counts (window.decode order)) :
    countedFollows order counts window trace <-> streamFollows order window trace := by
  induction trace generalizing counts window with
  | nil => rfl
  | cons event rest ih =>
    cases event with
    | send message =>
      have tracked := uses.1
      by_cases zero : counts message = 0
      next =>
        have absent : Not (Membership.mem (window.decode order) message) := by
          apply List.count_eq_zero.mp
          exact (correct message tracked).symm.trans zero
        simp only [countedFollows, streamFollows, zero, if_true, absent, if_false]
        apply and_congr_right
        intro stored
        have next_valid : window.append.Valid := by
          change window.head <= window.tail + 1
          unfold Window.Valid at valid
          omega
        have next_correct :
            Correct keys (Function.update counts message 1) (window.append.decode order) := by
          rw [decode_append window valid order, stored]
          exact correct_append keys counts (window.decode order) message correct tracked zero
        exact ih _ _ next_valid uses.2 next_correct
      next =>
        have present : Membership.mem (window.decode order) message := by
          apply List.count_pos_iff.mp
          have old := correct message tracked
          omega
        simp only [countedFollows, streamFollows, zero, if_false, present, if_true]
        exact ih counts window valid uses.2 correct
    | pop message =>
      simp only [countedFollows, streamFollows]
      apply and_congr_right
      intro present
      apply and_congr_right
      intro first
      have queue_eq :
          window.decode order = message :: window.pop.decode order := by
        rw [decode_cons window present order, first]
      have positive : 0 < counts message := by
        have old := correct message uses.1
        rw [queue_eq, List.count_cons_self] at old
        omega
      have next_valid : window.pop.Valid := by
        change window.head + 1 <= window.tail
        omega
      have next_correct :
          Correct keys (Function.update counts message (counts message - 1))
            (window.pop.decode order) := by
        apply correct_pop
        rw [Eq.symm queue_eq]
        exact correct
      simp only [positive, true_and]
      exact ih _ _ next_valid uses.2 next_correct
    | peek message =>
      simp only [countedFollows, streamFollows]
      apply and_congr_right
      intro _
      apply and_congr_right
      intro _
      exact ih counts window valid uses.2 correct
    | length length =>
      simp only [countedFollows, streamFollows]
      apply and_congr_right
      intro _
      exact ih counts window valid uses correct

omit [DecidableEq A] [BEq A] [LawfulBEq A] in
theorem segment_take (order : Nat -> A) (start length take : Nat) :
    (segment order start length).take take = segment order start (min take length) := by
  apply List.ext_getElem
  next => simp [Sparse.QueueStream.segment]
  next =>
    intro index left right
    simp [Sparse.QueueStream.segment]

def InitialFacts (keys : Finset A) (counts : A -> Nat) (length : Nat)
    (trace : List (Event A)) : Prop :=
  let front := (readHeads trace).take length
  front.length <= length /\
    (forall message, Membership.mem keys message -> front.count message <= counts message) /\
    keys.sum (fun message => counts message - front.count message) <= length - front.length

theorem supported_counts_sum (keys : Finset A) (queue : List A)
    (supported : forall message, Membership.mem queue message -> Membership.mem keys message) :
    keys.sum (fun message => queue.count message) = queue.length := by
  induction queue with
  | nil => simp
  | cons head tail ih =>
    have tracked : Membership.mem keys head := supported head (by simp)
    have tail_supported : forall message,
        Membership.mem tail message -> Membership.mem keys message := by
      intro message member
      exact supported message (List.mem_cons_of_mem head member)
    have step (message : A) :
        (head :: tail).count message =
          tail.count message + if head = message then 1 else 0 := by
      by_cases same : head = message <;> simp [same]
    simp_rw [step]
    rw [Finset.sum_add_distrib, ih tail_supported]
    simp [tracked]

omit [DecidableEq A] [BEq A] [LawfulBEq A] in
theorem read_heads_tracked (keys : Finset A) (trace : List (Event A)) (uses : Uses keys trace) :
    forall message, Membership.mem (readHeads trace) message -> Membership.mem keys message := by
  induction trace with
  | nil => simp [readHeads]
  | cons event rest ih =>
    cases event with
    | send message => exact ih uses.2
    | pop message =>
      intro key member
      cases List.mem_cons.mp member with
      | inl same => simpa only [same] using uses.1
      | inr member => exact ih uses.2 key member
    | peek message =>
      cases heads : readHeads rest with
      | nil =>
        intro key member
        have same : key = message := by simpa [readHeads, heads] using member
        simpa only [same] using uses.1
      | cons head tail => simpa only [readHeads, heads] using ih uses.2
    | length length => exact ih uses

theorem residual_bounds_iff (front : List A) (keys : Finset A) (counts : A -> Nat)
    (length : Nat)
    (supported : forall message, Membership.mem front message -> Membership.mem keys message) :
    (front.length <= length /\
      (forall message, Membership.mem keys message -> front.count message <= counts message) /\
      keys.sum (fun message => counts message - front.count message) <= length - front.length) <->
    ((forall message, Membership.mem keys message -> front.count message <= counts message) /\
      keys.sum counts <= length) := by
  have total := supported_counts_sum keys front supported
  have balance
      (lower : forall message, Membership.mem keys message -> front.count message <= counts message) :
      keys.sum (fun message => counts message - front.count message) + front.length =
        keys.sum counts := by
    rw [Eq.symm total, Eq.symm (Finset.sum_add_distrib)]
    exact Finset.sum_congr rfl fun message member => Nat.sub_add_cancel (lower message member)
  constructor
  next =>
    intro bounds
    have equal := balance bounds.2.1
    exact And.intro bounds.2.1 (by omega)
  next =>
    intro bounds
    have equal := balance bounds.1
    have prefix_bound : front.length <= length := by
      have h := Finset.sum_le_sum bounds.1
      omega
    exact And.intro prefix_bound (And.intro bounds.1 (by omega))

theorem initial_facts_iff (keys : Finset A) (counts : A -> Nat) (length : Nat)
    (trace : List (Event A)) (uses : Uses keys trace) :
    InitialFacts keys counts length trace <->
      (forall message, Membership.mem keys message ->
        ((readHeads trace).take length).count message <= counts message) /\
      keys.sum counts <= length := by
  apply residual_bounds_iff
  intro message member
  exact read_heads_tracked keys trace uses message (List.mem_of_mem_take member)

theorem finite_counted_exists_iff (keys : Finset A) (length : Nat)
    (trace : List (Event A)) (uses : Uses keys trace)
    (filler : A) (fresh : Not (Membership.mem keys filler)) :
    (exists order : Nat -> A, exists counts : A -> Nat,
      InitialFacts keys counts length trace /\
        countedFollows order counts { head := 0, tail := length } trace) <->
    (exists queue : List A, queue.length = length /\ concreteFollows queue trace) := by
  let window : Window := { head := 0, tail := length }
  let front := (readHeads trace).take length
  have valid : window.Valid := Nat.zero_le length
  constructor
  next =>
    intro witness
    cases witness with
    | intro order witness =>
      cases witness with
      | intro counts spec =>
        have completion :=
          (Sparse.QueueCounts.prefix_counts_exact front keys counts length filler fresh).mpr
            spec.1
        cases completion with
        | intro suffix completed =>
          let queue := front ++ suffix
          have queue_length : queue.length = length := completed.1
          let updated : Nat -> A :=
            fun index => if index < length then queue[index]?.getD filler else order index
          have decoded : window.decode updated = queue := by
            simp [window, Window.decode, Sparse.QueueStream.segment, updated, Eq.symm queue_length,
              List.ofFn_getElem]
          have heads_read := counted_read_heads order counts window trace spec.2
          have before : AgreeBelow order updated (window.head + (readHeads trace).length) := by
            intro index below
            have inside : index < (readHeads trace).length := by simpa [window] using below
            by_cases initial : index < length
            next =>
              have read : (readHeads trace)[index]?.getD filler = order index := by
                rw [Eq.symm heads_read]
                simp [Sparse.QueueStream.segment, window, inside]
              simpa [updated, queue, List.getElem?_append, front,
                List.getElem?_take, initial, inside] using read.symm
            next => simp [updated, initial]
          have after : forall index, window.tail <= index -> order index = updated index := by
            intro index lower
            have outside : Not (index < length) := by change length <= index at lower; omega
            simp [updated, outside]
          have moved := counted_order_transfer order updated counts window trace before after spec.2
          have correct : Correct keys counts (window.decode updated) := by
            intro message tracked
            rw [decoded]
            exact (completed.2 message tracked).symm
          have stream := (counted_iff_stream keys updated counts window valid trace uses correct).mp moved
          refine Exists.intro queue (And.intro queue_length ?_)
          simpa only [decoded] using stream_sound updated window valid trace stream
  next =>
    intro witness
    cases witness with
    | intro queue spec =>
      let order : Nat -> A := fun index => queue[index]?.getD filler
      have decoded : window.decode order = queue := by
        change segment order 0 length = queue
        rw [Eq.symm spec.1]
        simp [Sparse.QueueStream.segment, order, List.ofFn_getElem]
      have follows : concreteFollows (window.decode order) trace := by
        rw [decoded]
        exact spec.2
      cases stream_complete order window valid trace follows with
      | intro future complete =>
        have future_decoded : window.decode future = queue :=
          (decode_agrees window future order complete.1).trans decoded
        let counts : A -> Nat := fun message => queue.count message
        have correct : Correct keys counts (window.decode future) := by
          intro message _
          rw [future_decoded]
        have counted :=
          (counted_iff_stream keys future counts window valid trace uses correct).mpr complete.2
        have heads_read := counted_read_heads future counts window trace counted
        have head_take := congrArg (fun list : List A => list.take length) heads_read
        have queue_take :=
          congrArg (fun list : List A => list.take (readHeads trace).length) future_decoded
        have left : segment future 0 (min length (readHeads trace).length) = front := by
          simpa [window, front, segment_take] using head_take
        have right : segment future 0 (min length (readHeads trace).length) =
            queue.take (readHeads trace).length := by
          simpa [window, Window.decode, segment_take, Nat.min_comm] using queue_take
        have front_eq := left.symm.trans right
        have rebuilt : front ++ queue.drop (readHeads trace).length = queue := by
          rw [front_eq, List.take_append_drop]
        refine Exists.intro future (Exists.intro counts (And.intro ?_ counted))
        apply (Sparse.QueueCounts.prefix_counts_exact front keys counts length filler fresh).mp
        refine Exists.intro (queue.drop (readHeads trace).length) (And.intro ?_ ?_)
        next => rw [rebuilt]; exact spec.1
        next =>
          intro message _
          rw [rebuilt]

theorem source_counted_exists_iff (source : Node)
    (keys : Finset (Sparse.QueueCounts.PacketFrom source)) (length : Nat)
    (trace : List (Event (Sparse.QueueCounts.PacketFrom source)))
    (uses : Uses keys trace) :
    (exists order : Nat -> Sparse.QueueCounts.PacketFrom source,
      exists counts : Sparse.QueueCounts.PacketFrom source -> Nat,
        InitialFacts keys counts length trace /\
          countedFollows order counts { head := 0, tail := length } trace) <->
    (exists queue : List (Sparse.QueueCounts.PacketFrom source),
      queue.length = length /\ concreteFollows queue trace) := by
  cases Sparse.QueueCounts.fresh_source_packet source source keys with
  | intro filler fresh =>
    exact finite_counted_exists_iff keys length trace uses filler fresh

end CCFRaft.Sparse.CountedQueue

run_cmd do
  for theoremName in [
      ``CCFRaft.Sparse.CountedQueue.correct_append,
      ``CCFRaft.Sparse.CountedQueue.correct_pop,
      ``CCFRaft.Sparse.CountedQueue.read_heads_length_le,
      ``CCFRaft.Sparse.CountedQueue.counted_read_heads,
      ``CCFRaft.Sparse.CountedQueue.counted_order_transfer,
      ``CCFRaft.Sparse.CountedQueue.counted_iff_stream,
      ``CCFRaft.Sparse.CountedQueue.initial_facts_iff,
      ``CCFRaft.Sparse.CountedQueue.finite_counted_exists_iff,
      ``CCFRaft.Sparse.CountedQueue.source_counted_exists_iff] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom: {name}"
