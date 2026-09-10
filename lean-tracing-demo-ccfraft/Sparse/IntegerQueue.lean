import Sparse.CountedQueue

set_option autoImplicit false

namespace CCFRaft.Sparse.IntegerQueue

open Sparse.QueueStream (Window Event concreteFollows)
open Sparse.CountedQueue

variable {A : Type} [DecidableEq A] [BEq A] [LawfulBEq A]

def decodeCounts (counts : A -> Int) : A -> Nat :=
  fun message => (counts message).toNat

def encodeCounts (counts : A -> Nat) : A -> Int :=
  fun message => (counts message : Int)

def ValidCounts (keys : Finset A) (counts : A -> Int) : Prop :=
  forall message, Membership.mem keys message -> 0 <= counts message

omit [BEq A] [LawfulBEq A] in
theorem decode_update (counts : A -> Int) (message : A) (value : Int) :
    decodeCounts (Function.update counts message value) =
      Function.update (decodeCounts counts) message value.toNat := by
  funext key
  by_cases same : key = message <;> simp [decodeCounts, Function.update, same]

omit [BEq A] [LawfulBEq A] in
theorem valid_update (keys : Finset A) (counts : A -> Int) (message : A) (value : Int)
    (valid : ValidCounts keys counts) (nonnegative : 0 <= value) :
    ValidCounts keys (Function.update counts message value) := by
  intro key tracked
  by_cases same : key = message
  next =>
    subst key
    simpa only [Function.update_self] using nonnegative
  next => simpa [Function.update_of_ne same] using valid key tracked

def rawFollows (order : Nat -> A) : (A -> Int) -> Window -> List (Event A) -> Prop
  | _, _, [] => True
  | counts, window, .send message :: rest =>
    if counts message = 0 then
      order window.tail = message /\
        rawFollows order (Function.update counts message 1) window.append rest
    else rawFollows order counts window rest
  | counts, window, .pop message :: rest =>
    window.head < window.tail /\ order window.head = message /\ 0 < counts message /\
      rawFollows order (Function.update counts message (counts message - 1)) window.pop rest
  | counts, window, .peek message :: rest =>
    window.head < window.tail /\ order window.head = message /\
      rawFollows order counts window rest
  | counts, window, .length length :: rest =>
    window.tail - window.head = length /\ rawFollows order counts window rest

omit [BEq A] [LawfulBEq A] in
theorem raw_iff_counted (keys : Finset A) (order : Nat -> A) (counts : A -> Int)
    (window : Window) (trace : List (Event A)) (uses : Uses keys trace)
    (valid : ValidCounts keys counts) :
    rawFollows order counts window trace <->
      countedFollows order (decodeCounts counts) window trace := by
  induction trace generalizing counts window with
  | nil => rfl
  | cons event rest ih =>
    cases event with
    | send message =>
      have nonnegative := valid message uses.1
      have zero : counts message = 0 <-> decodeCounts counts message = 0 := by
        simp only [decodeCounts]
        omega
      by_cases empty : counts message = 0
      next =>
        have empty' := zero.mp empty
        simp only [rawFollows, countedFollows, empty, empty', if_true]
        apply and_congr_right
        intro _
        have next_valid := valid_update keys counts message 1 valid (by omega)
        have next := ih _ window.append uses.2 next_valid
        simpa only [decode_update, Int.toNat_one] using next
      next =>
        have nonempty : Not (decodeCounts counts message = 0) :=
          fun h => empty (zero.mpr h)
        simp only [rawFollows, countedFollows, empty, nonempty, if_false]
        exact ih counts window uses.2 valid
    | pop message =>
      have positive : (0 < counts message) <-> 0 < decodeCounts counts message := by
        simp only [decodeCounts]
        omega
      simp only [rawFollows, countedFollows]
      apply and_congr_right
      intro _
      apply and_congr_right
      intro _
      rw [Eq.symm (propext positive)]
      apply and_congr_right
      intro present
      have next_valid :=
        valid_update keys counts message (counts message - 1) valid (by omega)
      have next := ih _ window.pop uses.2 next_valid
      have subtract : (counts message - 1).toNat = decodeCounts counts message - 1 := by
        simp only [decodeCounts]
        omega
      simpa only [decode_update, subtract] using next
    | peek message =>
      simp only [rawFollows, countedFollows]
      apply and_congr_right
      intro _
      apply and_congr_right
      intro _
      exact ih counts window uses.2 valid
    | length length =>
      simp only [rawFollows, countedFollows]
      apply and_congr_right
      intro _
      exact ih counts window uses valid

def RawInitialFacts (keys : Finset A) (counts : A -> Int) (length : Nat)
    (trace : List (Event A)) : Prop :=
  (forall message, Membership.mem keys message ->
    (((readHeads trace).take length).count message : Int) <= counts message) /\
    keys.sum counts <= (length : Int)

omit [DecidableEq A] [LawfulBEq A] in
theorem initial_valid (keys : Finset A) (counts : A -> Int) (length : Nat)
    (trace : List (Event A)) (facts : RawInitialFacts keys counts length trace) :
    ValidCounts keys counts := by
  intro message tracked
  have h := facts.1 message tracked
  omega

theorem initial_iff (keys : Finset A) (counts : A -> Int) (length : Nat)
    (trace : List (Event A)) (uses : Uses keys trace) (valid : ValidCounts keys counts) :
    RawInitialFacts keys counts length trace <->
      InitialFacts keys (decodeCounts counts) length trace := by
  have sum_equal : ((keys.sum (decodeCounts counts) : Nat) : Int) = keys.sum counts := by
    push_cast
    apply Finset.sum_congr rfl
    intro message tracked
    have h := valid message tracked
    change ((counts message).toNat : Int) = counts message
    omega
  rw [initial_facts_iff keys (decodeCounts counts) length trace uses]
  constructor
  next =>
    intro facts
    refine And.intro ?_ ?_
    next =>
      intro message tracked
      have nonnegative := valid message tracked
      have bound := facts.1 message tracked
      simp only [decodeCounts]
      omega
    next =>
      have bound := facts.2
      omega
  next =>
    intro facts
    refine And.intro ?_ ?_
    next =>
      intro message tracked
      have nonnegative := valid message tracked
      have bound := facts.1 message tracked
      simp only [decodeCounts] at bound
      omega
    next =>
      have bound := facts.2
      omega

theorem raw_exists_iff (keys : Finset A) (length : Nat) (trace : List (Event A))
    (uses : Uses keys trace) (filler : A) (fresh : Not (Membership.mem keys filler)) :
    (exists order : Nat -> A, exists counts : A -> Int,
      RawInitialFacts keys counts length trace /\
        rawFollows order counts { head := 0, tail := length } trace) <->
    (exists queue : List A, queue.length = length /\ concreteFollows queue trace) := by
  rw [(finite_counted_exists_iff keys length trace uses filler fresh).symm]
  constructor
  next =>
    intro witness
    cases witness with
    | intro order witness =>
      cases witness with
      | intro counts spec =>
        have valid := initial_valid keys counts length trace spec.1
        exact Exists.intro order (Exists.intro (decodeCounts counts) (And.intro
          ((initial_iff keys counts length trace uses valid).mp spec.1)
          ((raw_iff_counted keys order counts _ trace uses valid).mp spec.2)))
  next =>
    intro witness
    cases witness with
    | intro order witness =>
      cases witness with
      | intro counts spec =>
        have valid : ValidCounts keys (encodeCounts counts) := by
          intro message _
          simp [encodeCounts]
        have inverse : decodeCounts (encodeCounts counts) = counts := by
          funext message
          simp [decodeCounts, encodeCounts]
        refine Exists.intro order (Exists.intro (encodeCounts counts) (And.intro ?_ ?_))
        next =>
          apply (initial_iff keys (encodeCounts counts) length trace uses valid).mpr
          simpa only [inverse] using spec.1
        next =>
          apply (raw_iff_counted keys order (encodeCounts counts) _ trace uses valid).mpr
          simpa only [inverse] using spec.2

def exampleCounts (message : Nat) : Int :=
  if message = 1 then 1 else -7

theorem negative_unqueried_counts :
    RawInitialFacts {1} exampleCounts 1 [.peek 1] /\
      rawFollows (fun _ => 1) exampleCounts { head := 0, tail := 1 } [.peek 1] /\
      exampleCounts 2 < 0 := by
  norm_num [RawInitialFacts, readHeads, exampleCounts, rawFollows]

end CCFRaft.Sparse.IntegerQueue

run_cmd do
  for theoremName in [
      ``CCFRaft.Sparse.IntegerQueue.raw_iff_counted,
      ``CCFRaft.Sparse.IntegerQueue.initial_iff,
      ``CCFRaft.Sparse.IntegerQueue.raw_exists_iff,
      ``CCFRaft.Sparse.IntegerQueue.negative_unqueried_counts] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom: {name}"
