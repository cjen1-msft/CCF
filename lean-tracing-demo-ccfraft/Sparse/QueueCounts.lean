import Model
import Mathlib.Algebra.BigOperators.Group.Finset.Basic

set_option autoImplicit false

namespace CCFRaft.Sparse.QueueCounts

variable {A : Type} [DecidableEq A] [BEq A] [LawfulBEq A]

theorem counts_sum_le_length (keys : Finset A) (queue : List A) :
    keys.sum (fun m => queue.count m) <= queue.length := by
  induction queue with
  | nil => simp
  | cons head tail ih =>
    have step (m : A) :
        (head :: tail).count m = tail.count m + if m = head then 1 else 0 := by
      by_cases h : m = head
      next => simp [h]
      next => simp [h, Ne.symm h]
    simp_rw [step]
    rw [Finset.sum_add_distrib]
    have extra : keys.sum (fun m => if m = head then 1 else 0) <= 1 := by
      by_cases h : Membership.mem keys head <;> simp [h]
    simpa using Nat.add_le_add ih extra

theorem counted_list_exists (keys : Finset A) (counts : A -> Nat) :
    exists queue : List A,
      queue.length = keys.sum counts /\
      forall m, queue.count m = if Membership.mem keys m then counts m else 0 := by
  induction keys using Finset.induction_on with
  | empty =>
    exact Exists.intro [] (And.intro (by simp) (by simp))
  | @insert key keys absent ih =>
    cases ih with
    | intro queue spec =>
      refine Exists.intro (List.replicate (counts key) key ++ queue) (And.intro ?_ ?_)
      next => simp [spec.1, Finset.sum_insert, absent]
      next =>
        intro m
        by_cases same : m = key
        next => subst m; simp [List.count_append, spec.2, absent]
        next =>
          simp [List.count_append, List.count_replicate, spec.2, same, Ne.symm same]

theorem counts_exact (keys : Finset A) (counts : A -> Nat)
    (length : Nat) (filler : A) (fresh : Not (Membership.mem keys filler)) :
    (exists queue : List A, queue.length = length /\
      forall m, Membership.mem keys m -> queue.count m = counts m) <->
    keys.sum counts <= length := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro queue spec =>
      calc
        keys.sum counts = keys.sum (fun m => queue.count m) :=
          Finset.sum_congr rfl fun m hm => (spec.2 m hm).symm
        _ <= queue.length := counts_sum_le_length keys queue
        _ = length := spec.1
  next =>
    intro bound
    cases counted_list_exists keys counts with
    | intro queue spec =>
      refine Exists.intro (queue ++ List.replicate (length - keys.sum counts) filler)
        (And.intro ?_ ?_)
      next =>
        simp only [List.length_append, List.length_replicate, spec.1]
        omega
      next =>
        intro m hm
        have distinct : Not (m = filler) := by
          intro same
          subst m
          exact fresh hm
        simp [List.count_append, List.count_replicate, spec.2, hm, Ne.symm distinct]

theorem prefix_counts_exact (front : List A) (keys : Finset A)
    (counts : A -> Nat) (length : Nat) (filler : A)
    (fresh : Not (Membership.mem keys filler)) :
    (exists suffix : List A, (front ++ suffix).length = length /\
      forall m, Membership.mem keys m -> (front ++ suffix).count m = counts m) <->
    front.length <= length /\
      (forall m, Membership.mem keys m -> front.count m <= counts m) /\
      keys.sum (fun m => counts m - front.count m) <= length - front.length := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro suffix spec =>
      have lengths : front.length + suffix.length = length := by simpa using spec.1
      have residual (m : A) (hm : Membership.mem keys m) :
          counts m - front.count m = suffix.count m := by
        have h := spec.2 m hm
        simp only [List.count_append] at h
        omega
      refine And.intro (by omega) (And.intro ?_ ?_)
      next =>
        intro m hm
        have h := spec.2 m hm
        simp only [List.count_append] at h
        omega
      next =>
        have heq := Finset.sum_congr rfl residual
        rw [heq]
        have h := counts_sum_le_length keys suffix
        omega
  next =>
    intro bounds
    have witness := (counts_exact keys (fun m => counts m - front.count m)
      (length - front.length) filler fresh).mpr bounds.2.2
    cases witness with
    | intro suffix spec =>
      refine Exists.intro suffix (And.intro ?_ ?_)
      next =>
        simp only [List.length_append, spec.1]
        have h := bounds.1
        omega
      next =>
        intro m hm
        have h := spec.2 m hm
        have hb := bounds.2.1 m hm
        simp only [List.count_append]
        omega

omit [BEq A] [LawfulBEq A] in
theorem insert_accounting (keys : Finset A) (counts : A -> Nat) (m : A) :
    (insert m keys).sum counts =
      keys.sum counts + if Membership.mem keys m then 0 else counts m := by
  by_cases h : Membership.mem keys m
  next => simp [h, Finset.insert_eq_of_mem h]
  next => simp [h, Finset.sum_insert, Nat.add_comm]

abbrev PacketFrom (source : Node) :=
  { message : Message Node Nat // message.source = source }

theorem fresh_source_packet (source destination : Node)
    (keys : Finset (PacketFrom source)) :
    exists filler : PacketFrom source, Not (Membership.mem keys filler) := by
  let filler : PacketFrom source := Subtype.mk
    (.proposeVoteRequest {
      term := keys.sup (fun m => m.val.term) + 1
      source := source
      destination := destination }) rfl
  refine Exists.intro filler ?_
  intro present
  have bound := Finset.le_sup (f := fun m : PacketFrom source => m.val.term) present
  change keys.sup (fun m => m.val.term) + 1 <= keys.sup (fun m => m.val.term) at bound
  omega

theorem source_prefix_counts_exact (source : Node)
    (front : List (PacketFrom source)) (keys : Finset (PacketFrom source))
    (counts : PacketFrom source -> Nat) (length : Nat) :
    (exists suffix : List (PacketFrom source), (front ++ suffix).length = length /\
      forall m, Membership.mem keys m -> (front ++ suffix).count m = counts m) <->
    front.length <= length /\
      (forall m, Membership.mem keys m -> front.count m <= counts m) /\
      keys.sum (fun m => counts m - front.count m) <= length - front.length := by
  cases fresh_source_packet source source keys with
  | intro filler fresh =>
    exact prefix_counts_exact front keys counts length filler fresh

end CCFRaft.Sparse.QueueCounts

run_cmd do
  for theoremName in [
      ``CCFRaft.Sparse.QueueCounts.counts_sum_le_length,
      ``CCFRaft.Sparse.QueueCounts.counted_list_exists,
      ``CCFRaft.Sparse.QueueCounts.counts_exact,
      ``CCFRaft.Sparse.QueueCounts.prefix_counts_exact,
      ``CCFRaft.Sparse.QueueCounts.insert_accounting,
      ``CCFRaft.Sparse.QueueCounts.fresh_source_packet,
      ``CCFRaft.Sparse.QueueCounts.source_prefix_counts_exact] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom: {name}"
