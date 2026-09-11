-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.Queue

set_option autoImplicit false

/-!
Native FIFO storage semantics. List reconstruction is proof-only; the encoder
uses named SMT arrays and scalar head/length versions.
-/

namespace CCFRaft.NativeArrayQueue

variable {M : Type}

structure Queue (M : Type) where
  head : Nat
  length : Nat
  cells : Nat -> M

def Queue.decode (queue : Queue M) : List M :=
  List.ofFn fun i : Fin queue.length => queue.cells (queue.head + i.val)

def Queue.ofList (filler : M) (values : List M) : Queue M :=
  { head := 0, length := values.length, cells := fun i => values[i]?.getD filler }

@[simp] theorem Queue.decode_length (queue : Queue M) :
    queue.decode.length = queue.length := by
  simp [Queue.decode]

@[simp] theorem Queue.decode_ofList (filler : M) (values : List M) :
    (Queue.ofList filler values).decode = values := by
  simp [Queue.decode, Queue.ofList, List.ofFn_getElem]

def Queue.push (queue : Queue M) (message : M) : Queue M :=
  { queue with
    length := queue.length + 1
    cells := Function.update queue.cells (queue.head + queue.length) message }

def Queue.pop (queue : Queue M) : Queue M :=
  { queue with head := queue.head + 1, length := queue.length - 1 }

theorem Queue.push_correct (queue : Queue M) (message : M) :
    (queue.push message).decode = queue.decode ++ [message] := by
  simp only [Queue.decode, Queue.push]
  rw [List.ofFn_succ']
  simp only [Fin.val_last, Function.update_self, List.concat_eq_append]
  congr 1
  apply congrArg List.ofFn
  funext index
  have different : index.val ≠ queue.length := Nat.ne_of_lt index.isLt
  simp [Function.update_apply, different]

theorem Queue.head_tail (queue : Queue M) (nonempty : 0 < queue.length) :
    queue.decode = queue.cells queue.head :: queue.pop.decode := by
  cases size : queue.length with
  | zero => omega
  | succ length =>
    simp only [Queue.decode, Queue.pop, size, Nat.add_sub_cancel, List.ofFn_succ]
    congr 1
    apply congrArg List.ofFn
    funext index
    congr 1
    simp [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm]

theorem Queue.point_correct (queue : Queue M) (index : Nat) (expected : M) :
    (index < queue.length /\ queue.cells (queue.head + index) = expected) <->
      queue.decode[index]? = some expected := by
  by_cases live : index < queue.length <;> simp [Queue.decode, live]

theorem Queue.pop_correct (queue : Queue M) :
    queue.pop.decode = queue.decode.tail := by
  by_cases nonempty : 0 < queue.length
  · rw [queue.head_tail nonempty]
    rfl
  · have zero : queue.length = 0 := by omega
    simp [Queue.decode, Queue.pop, zero]

theorem Queue.head_correct (queue : Queue M) (expected : M) :
    (0 < queue.length /\ queue.cells queue.head = expected) <->
      queue.decode.head? = some expected := by
  simpa [List.head?_eq_getElem?] using queue.point_correct 0 expected

def Queue.peek (queue : Queue M) : Option M :=
  if 0 < queue.length then some (queue.cells queue.head) else none

theorem Queue.peek_correct (queue : Queue M) : queue.peek = queue.decode.head? := by
  by_cases live : 0 < queue.length
  · rw [Queue.peek, if_pos live, queue.head_tail live]
    rfl
  · have empty : queue.length = 0 := by omega
    simp [Queue.peek, Queue.decode, empty]

inductive Instruction (M : Type) where
  | length (expected : Nat)
  | point (index : Nat) (expected : M)
  | send (message : M)
  | receive (expected : M)

def follows (queue : Queue M) : List (Instruction M) -> Prop
  | [] => True
  | .length expected :: rest => queue.length = expected /\ follows queue rest
  | .point index expected :: rest =>
      (index < queue.length /\ queue.cells (queue.head + index) = expected) /\
        follows queue rest
  | .send message :: rest => follows (queue.push message) rest
  | .receive expected :: rest =>
      (0 < queue.length /\ queue.cells queue.head = expected) /\ follows queue.pop rest

def listFollows (queue : List M) : List (Instruction M) -> Prop
  | [] => True
  | .length expected :: rest => queue.length = expected /\ listFollows queue rest
  | .point index expected :: rest => queue[index]? = some expected /\ listFollows queue rest
  | .send message :: rest => listFollows (queue ++ [message]) rest
  | .receive expected :: rest => queue.head? = some expected /\ listFollows queue.tail rest

theorem follows_correct (queue : Queue M) (trace : List (Instruction M)) :
    follows queue trace <-> listFollows queue.decode trace := by
  induction trace generalizing queue with
  | nil => rfl
  | cons instruction rest ih =>
    cases instruction <;>
      simp only [follows, listFollows, Queue.decode_length, Queue.point_correct,
        Queue.head_correct, ih, Queue.push_correct, Queue.pop_correct]

theorem exists_iff (filler : M) (trace : List (Instruction M)) :
    (exists queue, follows queue trace) <-> exists queue, listFollows queue trace := by
  constructor
  · rintro ⟨queue, holds⟩
    exact ⟨queue.decode, (follows_correct queue trace).mp holds⟩
  · rintro ⟨queue, holds⟩
    exact ⟨Queue.ofList filler queue, (follows_correct _ trace).mpr (by simpa using holds)⟩

section Model

variable {N T : Type} [DecidableEq N] [DecidableEq T]

abbrev Network (N T : Type) := N -> N -> Queue (Message N T)

def decodeNetwork (network : Network N T) : Sparse.Queue.Sparse N T :=
  fun destination source => (network destination source).decode

def send (network : Network N T) (message : Message N T) : Network N T :=
  Function.update network message.destination
    (Function.update (network message.destination) message.source
      ((network message.destination message.source).push message))

def popSource (network : Network N T) (destination source : N) : Network N T :=
  Function.update network destination
    (Function.update (network destination) source ((network destination source).pop))

theorem pop_source_correct (network : Network N T) (destination source : N) :
    decodeNetwork (popSource network destination source) =
      Sparse.Queue.replaceSource (decodeNetwork network) destination source
        ((decodeNetwork network destination source).tail) := by
  funext d s
  by_cases target : d = destination
  · subst d
    by_cases origin : s = source
    · subst s
      simp [popSource, decodeNetwork, Sparse.Queue.replaceSource, Queue.pop_correct]
    · simp [popSource, decodeNetwork, Sparse.Queue.replaceSource, origin]
  · simp [popSource, decodeNetwork, Sparse.Queue.replaceSource, target]

theorem send_correct (network : Network N T) (message : Message N T) :
    decodeNetwork (send network message) =
      Sparse.Queue.sparseEnqueue (decodeNetwork network) message := by
  funext destination source
  by_cases target : destination = message.destination
  · subst destination
    by_cases origin : source = message.source
    · subst source
      simp [send, decodeNetwork, Sparse.Queue.sparseEnqueue, Sparse.Queue.replaceSource,
        Queue.push_correct]
    · simp [send, decodeNetwork, Sparse.Queue.sparseEnqueue, Sparse.Queue.replaceSource, origin]
  · simp [send, decodeNetwork, Sparse.Queue.sparseEnqueue, Sparse.Queue.replaceSource, target]

theorem model_send_correct (network : Network N T) (model : Sparse.Queue.Network N T)
    (same : decodeNetwork network = Sparse.Queue.abstractNetwork model) (message : Message N T) :
    decodeNetwork (send network message) = Sparse.Queue.abstractNetwork (CCFRaft.enqueue model message) := by
  rw [send_correct, same, Sparse.Queue.enqueue_correct]

theorem model_pop_correct (network : Network N T) (model : Sparse.Queue.Network N T)
    (same : decodeNetwork network = Sparse.Queue.abstractNetwork model)
    (source destination : N) (message : Message N T) (rest : List (Message N T))
    (taken : takeFirstFrom source (model destination) = some (message, rest)) :
    decodeNetwork (popSource network destination source) =
      Sparse.Queue.abstractNetwork (updateQueue model destination rest) := by
  have spec := Sparse.Queue.take_some_spec source (model destination) message rest taken
  have tail :
      (Sparse.Queue.abstractNetwork model destination source).tail =
        Sparse.Queue.partition source rest := by
    simp [Sparse.Queue.abstractNetwork, spec.2.1]
  rw [pop_source_correct, same, Sparse.Queue.dequeue_correct model destination source message rest taken, tail]

theorem model_peek_correct (network : Network N T) (model : Sparse.Queue.Network N T)
    (same : decodeNetwork network = Sparse.Queue.abstractNetwork model)
    (source destination : N) :
    (network destination source).peek =
      (takeFirstFrom source (model destination)).map Prod.fst := by
  rw [Queue.peek_correct]
  have partition := congrFun (congrFun same destination) source
  change (network destination source).decode = Sparse.Queue.partition source (model destination) at partition
  rw [partition]
  cases taken : takeFirstFrom source (model destination) with
  | none =>
    rw [(Sparse.Queue.take_none_iff source (model destination)).mp taken]
    rfl
  | some pair =>
    rcases pair with ⟨message, rest⟩
    rw [(Sparse.Queue.take_some_spec source (model destination) message rest taken).2.1]
    rfl

theorem model_initial_exists [Fintype N] (network : Network N T)
    (wellFormed : forall destination, Sparse.Queue.WellFormed (decodeNetwork network destination)) :
    exists model, Sparse.Queue.abstractNetwork model = decodeNetwork network := by
  exact ⟨Sparse.Queue.realizeNetwork (decodeNetwork network),
    Sparse.Queue.network_realizability _ wellFormed⟩

end Model

end CCFRaft.NativeArrayQueue

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayQueue).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
