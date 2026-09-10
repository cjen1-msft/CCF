import Sparse.IntegerQueue

set_option autoImplicit false

namespace CCFRaft.Sparse.SignedQueue

open Sparse.QueueStream (Window Event concreteFollows)
open Sparse.CountedQueue (Uses)
open Sparse.IntegerQueue

variable {A : Type} [DecidableEq A]

structure SignedWindow where
  head : Int
  tail : Int

def SignedWindow.Valid (window : SignedWindow) : Prop :=
  0 <= window.head /\ window.head <= window.tail

def SignedWindow.decode (window : SignedWindow) : Window :=
  { head := window.head.toNat, tail := window.tail.toNat }

def SignedWindow.append (window : SignedWindow) : SignedWindow :=
  { window with tail := window.tail + 1 }

def SignedWindow.pop (window : SignedWindow) : SignedWindow :=
  { window with head := window.head + 1 }

omit [DecidableEq A] in
theorem decode_append (window : SignedWindow) (valid : window.Valid) :
    window.append.decode = window.decode.append := by
  have tail_nonnegative : 0 <= window.tail := by have h := valid; unfold SignedWindow.Valid at h; omega
  have changed : (window.tail + 1).toNat = window.tail.toNat + 1 := by omega
  simp only [SignedWindow.append, SignedWindow.decode, Window.append, changed]

omit [DecidableEq A] in
theorem decode_pop (window : SignedWindow) (valid : window.Valid) :
    window.pop.decode = window.decode.pop := by
  have head_nonnegative := valid.1
  have changed : (window.head + 1).toNat = window.head.toNat + 1 := by omega
  simp only [SignedWindow.pop, SignedWindow.decode, Window.pop, changed]

def signedFollows (order : Int -> A) : (A -> Int) -> SignedWindow -> List (Event A) -> Prop
  | _, _, [] => True
  | counts, window, .send message :: rest =>
    if counts message = 0 then
      order window.tail = message /\
        signedFollows order (Function.update counts message 1) window.append rest
    else signedFollows order counts window rest
  | counts, window, .pop message :: rest =>
    window.head < window.tail /\ order window.head = message /\ 0 < counts message /\
      signedFollows order (Function.update counts message (counts message - 1)) window.pop rest
  | counts, window, .peek message :: rest =>
    window.head < window.tail /\ order window.head = message /\
      signedFollows order counts window rest
  | counts, window, .length length :: rest =>
    window.tail - window.head = (length : Int) /\ signedFollows order counts window rest

def decodeOrder (order : Int -> A) : Nat -> A := fun index => order (index : Int)

theorem signed_iff_raw (order : Int -> A) (counts : A -> Int) (window : SignedWindow)
    (valid : window.Valid) (trace : List (Event A)) :
    signedFollows order counts window trace <->
      rawFollows (decodeOrder order) counts window.decode trace := by
  induction trace generalizing counts window with
  | nil => rfl
  | cons event rest ih =>
    have hn : 0 <= window.head := valid.1
    have ht : 0 <= window.tail := by have h := valid.2; omega
    have order_head : decodeOrder order window.decode.head = order window.head := by
      simp [decodeOrder, SignedWindow.decode, Int.toNat_of_nonneg hn]
    have order_tail : decodeOrder order window.decode.tail = order window.tail := by
      simp [decodeOrder, SignedWindow.decode, Int.toNat_of_nonneg ht]
    have less : window.head < window.tail <-> window.decode.head < window.decode.tail := by
      simp only [SignedWindow.decode]
      omega
    cases event with
    | send message =>
      by_cases zero : counts message = 0
      next =>
        simp only [signedFollows, rawFollows, zero, if_true, order_tail]
        apply and_congr_right
        intro _
        have next_valid : window.append.Valid := by
          change 0 <= window.head /\ window.head <= window.tail + 1
          have h := valid.2
          omega
        simpa only [decode_append window valid] using ih _ window.append next_valid
      next =>
        simp only [signedFollows, rawFollows, zero, if_false]
        exact ih counts window valid
    | pop message =>
      simp only [signedFollows, rawFollows, order_head]
      rw [Eq.symm (propext less)]
      apply and_congr_right
      intro present
      apply and_congr_right
      intro _
      apply and_congr_right
      intro _
      have next_valid : window.pop.Valid := by
        change 0 <= window.head + 1 /\ window.head + 1 <= window.tail
        omega
      simpa only [decode_pop window valid] using ih _ window.pop next_valid
    | peek message =>
      simp only [signedFollows, rawFollows, order_head]
      rw [Eq.symm (propext less)]
      apply and_congr_right
      intro _
      apply and_congr_right
      intro _
      exact ih counts window valid
    | length length =>
      have subtract : window.tail - window.head = (length : Int) <->
          window.decode.tail - window.decode.head = length := by
        simp only [SignedWindow.decode]
        have h := valid.2
        omega
      simp only [signedFollows, rawFollows]
      exact and_congr subtract (ih counts window valid)

variable [BEq A] [LawfulBEq A]

theorem signed_exists_iff (keys : Finset A) (length : Int) (nonnegative : 0 <= length)
    (trace : List (Event A)) (uses : Uses keys trace)
    (filler : A) (fresh : Not (Membership.mem keys filler)) :
    (exists order : Int -> A, exists counts : A -> Int,
      RawInitialFacts keys counts length.toNat trace /\
        signedFollows order counts { head := 0, tail := length } trace) <->
    (exists queue : List A, (queue.length : Int) = length /\ concreteFollows queue trace) := by
  have length_cast : (length.toNat : Int) = length := by omega
  have length_eq (queue : List A) :
      (queue.length : Int) = length <-> queue.length = length.toNat := by omega
  simp_rw [length_eq]
  rw [(raw_exists_iff keys length.toNat trace uses filler fresh).symm]
  have valid : SignedWindow.Valid { head := 0, tail := length } :=
    And.intro (Int.le_refl 0) nonnegative
  constructor
  next =>
    intro witness
    cases witness with
    | intro order witness =>
      cases witness with
      | intro counts spec =>
        refine Exists.intro (decodeOrder order) (Exists.intro counts (And.intro spec.1 ?_))
        exact (signed_iff_raw order counts _ valid trace).mp spec.2
  next =>
    intro witness
    cases witness with
    | intro order witness =>
      cases witness with
      | intro counts spec =>
        let encoded : Int -> A := fun index => order index.toNat
        have inverse : decodeOrder encoded = order := by
          funext index
          simp [decodeOrder, encoded]
        refine Exists.intro encoded (Exists.intro counts (And.intro spec.1 ?_))
        apply (signed_iff_raw encoded counts _ valid trace).mpr
        simpa only [inverse, SignedWindow.decode, Int.toNat_zero] using spec.2

end CCFRaft.Sparse.SignedQueue

run_cmd do
  for theoremName in [
      ``CCFRaft.Sparse.SignedQueue.signed_iff_raw,
      ``CCFRaft.Sparse.SignedQueue.signed_exists_iff] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom: {name}"
