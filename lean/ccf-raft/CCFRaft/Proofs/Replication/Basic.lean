module

public import CCFRaft.Proofs.Safety.Lists

@[expose] public section

/-!
# Sequences and logs for replication progress

Facts about index sequences that hold infinitely often or are eventually
constant, the length of the agreeing prefix of two logs, and the retry index a
rejection selects.
-/

namespace CCFRaft.Proofs.Replication

open Model.Node

/-! ## Infinitely often -/

/-- `P` holds at arbitrarily late indices. -/
def Often (P : Nat -> Prop) : Prop :=
  forall cutoff, exists index, cutoff <= index /\ P index

theorem Often.mono {P Q : Nat -> Prop} (often : Often P) (imp : forall d, P d -> Q d)
    : Often Q :=
  fun cutoff =>
    let ⟨d, le, holds⟩ := often cutoff
    ⟨d, le, imp d holds⟩

theorem Often.after {P : Nat -> Prop} (often : Often P) (start : Nat)
    : Often fun d => start <= d /\ P d :=
  fun cutoff =>
    let ⟨d, le, holds⟩ := often (max cutoff start)
    ⟨d, le_trans (Nat.le_max_left _ _) le, le_trans (Nat.le_max_right _ _) le, holds⟩

/-- Without infinitely many exceptions, a property eventually holds forever. -/
theorem eventually_of_not_often {P : Nat -> Prop} (rare : Not (Often P))
    : exists start, forall d, start <= d -> Not (P d) := by
  simp only [Often, not_forall, not_exists, not_and] at rare
  exact rare

theorem mono_of_step {f : Nat -> Nat} {start : Nat}
    (step : forall d, start <= d -> f d <= f (d + 1)) {d e : Nat} (began : start <= d)
    (le : d <= e)
    : f d <= f e := by
  induction e, le using Nat.le_induction with
  | base => exact le_rfl
  | succ e le ih => exact ih.trans (step e (began.trans le))

/-- A bounded sequence that never decreases is eventually constant. -/
theorem eventually_const {f : Nat -> Nat} {start bound : Nat}
    (step : forall d, start <= d -> f d <= f (d + 1))
    (bounded : forall d, start <= d -> f d <= bound)
    : exists stop, start <= stop /\ forall d, stop <= d -> f d = f stop := by
  suffices
      forall gap start,
        bound - f start <= gap
        -> (forall d, start <= d -> f d <= f (d + 1))
        -> (forall d, start <= d -> f d <= bound)
        -> exists stop, start <= stop /\ forall d, stop <= d -> f d = f stop from
    this _ start le_rfl step bounded
  intro gap
  induction gap with
  | zero =>
      intro start gap step bounded
      refine ⟨start, le_rfl, fun d le => ?_⟩
      have := mono_of_step step le_rfl le
      have := bounded d le
      have := bounded start le_rfl
      omega
  | succ gap ih =>
      intro start bigger step bounded
      by_cases stays : forall d, start <= d -> f d = f start
      · exact ⟨start, le_rfl, stays⟩
      · simp only [not_forall] at stays
        obtain ⟨d, le, moved⟩ := stays
        have grows := mono_of_step step le_rfl le
        obtain ⟨stop, later, holds⟩ :=
          ih d (by have := bounded d le; omega) (fun e h => step e (le.trans h))
            (fun e h => bounded e (le.trans h))
        exact ⟨stop, le.trans later, holds⟩

/-- Infinitely many indices with a bounded label repeat some label infinitely often. -/
theorem Often.bucket {P : Nat -> Prop} {label : Nat -> Nat} {bound : Nat}
    (often : Often P) (bounded : forall d, P d -> label d <= bound)
    : exists k, k <= bound /\ Often fun d => P d /\ label d = k := by
  induction bound generalizing P with
  | zero =>
      exact ⟨
        0,
        le_rfl,
        often.mono fun d holds => ⟨holds, by have := bounded d holds; omega⟩
      ⟩
  | succ bound ih =>
      by_cases top : Often fun d => P d /\ label d = bound + 1
      · exact ⟨bound + 1, le_rfl, top⟩
      · obtain ⟨cutoff, below⟩ := eventually_of_not_often top
        obtain ⟨k, le, often'⟩ :=
          ih (P := fun d => cutoff <= d /\ P d) (often.after cutoff)
            fun d ⟨after, holds⟩ => by
              have := bounded d holds
              have ne : label d ≠ bound + 1 := fun eq => below d after ⟨holds, eq⟩
              omega
        exact ⟨k, by omega, often'.mono fun _ ⟨⟨_, holds⟩, eq⟩ => ⟨holds, eq⟩⟩

/-- The least label that repeats infinitely often. -/
theorem Often.least_bucket {P : Nat -> Prop} {label : Nat -> Nat} {bound : Nat}
    (often : Often P) (bounded : forall d, P d -> label d <= bound)
    : exists k,
        (Often fun d => P d /\ label d = k)
        /\ forall j, j < k -> Not (Often fun d => P d /\ label d = j) := by
  classical
  obtain ⟨k, _, repeats⟩ := often.bucket bounded
  have some : exists k, Often fun d => P d /\ label d = k := ⟨k, repeats⟩
  exact ⟨Nat.find some, Nat.find_spec some, fun _ lt => Nat.find_min some lt⟩

/-- A sequence infinitely often below and infinitely often at or above `c`
crosses up to `c` infinitely often. -/
theorem Often.crossing {f : Nat -> Nat} {c : Nat} (low : Often fun d => f d < c)
    (high : Often fun d => c <= f d)
    : Often fun d => f d < c /\ c <= f (d + 1) := by
  intro cutoff
  obtain ⟨first, le, below⟩ := low cutoff
  obtain ⟨second, le', above⟩ := high first
  suffices
      forall e, first <= e -> c <= f e -> exists d, first <= d /\ f d < c /\ c <= f (d + 1) by
    obtain ⟨d, after, crossed⟩ := this second le' above
    exact ⟨d, le.trans after, crossed⟩
  intro e after
  induction e, after using Nat.le_induction with
  | base => intro reached; omega
  | succ e after ih =>
      intro reached
      by_cases lt : f e < c
      · exact ⟨e, after, lt, reached⟩
      · obtain ⟨d, after', crossed⟩ := ih (by omega)
        exact ⟨d, after', crossed⟩

/-! ## Agreeing prefixes -/

/-- The length of the longest common prefix. -/
def agree {α : Type} [DecidableEq α] : List α -> List α -> Nat
  | x :: xs, y :: ys => if x = y then agree xs ys + 1 else 0
  | _, _ => 0

section Agree

variable {α : Type} [DecidableEq α]

theorem take_agree
    : forall (xs ys : List α), xs.take (agree xs ys) = ys.take (agree xs ys)
  | x :: xs, y :: ys => by
      simp only [agree]
      split
      · rename_i same
        subst same
        simp [take_agree xs ys]
      · simp
  | [], _ => by simp [agree]
  | _ :: _, [] => by simp [agree]

theorem agree_le_left : forall (xs ys : List α), agree xs ys <= xs.length
  | x :: xs, y :: ys => by
      simp only [agree]
      split
      · have := agree_le_left xs ys
        simp
        omega
      · exact Nat.zero_le _
  | [], _ => by simp [agree]
  | _ :: _, [] => by simp [agree]

theorem agree_le_right : forall (xs ys : List α), agree xs ys <= ys.length
  | x :: xs, y :: ys => by
      simp only [agree]
      split
      · have := agree_le_right xs ys
        simp
        omega
      · exact Nat.zero_le _
  | [], _ => by simp [agree]
  | _ :: _, [] => by simp [agree]

theorem le_agree
    : forall (xs ys : List α) (n : Nat),
        n <= xs.length -> n <= ys.length -> xs.take n = ys.take n -> n <= agree xs ys
  | _, _, 0, _, _, _ => Nat.zero_le _
  | x :: xs, y :: ys, n + 1, left, right, same => by
      simp only [List.take_succ_cons, List.cons.injEq] at same
      simp only [agree, same.1, ↓reduceIte]
      have := le_agree xs ys n (by simpa using left) (by simpa using right) same.2
      omega
  | [], _, n + 1, left, _, _ => by simp at left
  | _ :: _, [], n + 1, _, right, _ => by simp at right

theorem agree_mono {xs ys zs : List α} (sub : ys <+: zs)
    : agree xs ys <= agree xs zs := by
  have bound := agree_le_right xs ys
  refine le_agree _ _ _ (agree_le_left xs ys) (bound.trans sub.length_le) ?_
  rw [take_agree, CCFRaft.Proofs.Safety.take_eq_of_prefix sub bound]

theorem agree_of_prefix {xs ys : List α} (sub : xs <+: ys) : agree xs ys = xs.length :=
  le_antisymm (agree_le_left xs ys)
    (le_agree _ _ _ le_rfl sub.length_le
      (by rw [CCFRaft.Proofs.Safety.take_eq_of_prefix sub le_rfl]))

end Agree

/-! ## Retry indices -/

/-- The largest item satisfying `Q`, or `init` if larger. -/
def maxWhere (Q : Nat -> Prop) [DecidablePred Q] (items : List Nat) (init : Nat) : Nat :=
  items.foldl (fun best c => if Q c then max best c else best) init

theorem maxWhere_spec (Q : Nat -> Prop) [DecidablePred Q]
    : forall (items : List Nat) (init : Nat),
        init <= maxWhere Q items init
        /\ (forall c, c ∈ items -> Q c -> c <= maxWhere Q items init)
        /\ (maxWhere Q items init = init
            \/ (maxWhere Q items init ∈ items /\ Q (maxWhere Q items init)))
  | [], init => by simp [maxWhere]
  | item :: items, init => by
      have unfold : maxWhere Q (item :: items) init
          = maxWhere Q items (if Q item then max init item else init) := rfl
      rw [unfold]
      by_cases holds : Q item
      · rw [ite_eq_left holds]
        obtain ⟨grows, covers, chosen⟩ := maxWhere_spec Q items (max init item)
        refine ⟨by omega, fun c member holds' => ?_, ?_⟩
        · rcases List.mem_cons.mp member with rfl | member
          · omega
          · exact covers c member holds'
        · rcases chosen with same | ⟨member, holds'⟩
          · rcases Nat.le_total init item with le | le
            · have picked : maxWhere Q items (max init item) = item := by omega
              rw [picked]
              exact Or.inr ⟨List.mem_cons.mpr (Or.inl rfl), holds⟩
            · exact Or.inl (by omega)
          · exact Or.inr ⟨List.mem_cons_of_mem _ member, holds'⟩
      · rw [ite_eq_right holds]
        obtain ⟨grows, covers, chosen⟩ := maxWhere_spec Q items init
        refine ⟨grows, fun c member holds' => ?_, ?_⟩
        · rcases List.mem_cons.mp member with rfl | member
          · exact absurd holds' holds
          · exact covers c member holds'
        · rcases chosen with same | ⟨member, holds'⟩
          · exact Or.inl same
          · exact Or.inr ⟨List.mem_cons_of_mem _ member, holds'⟩

section Retry

variable {log : List Entry} {index term : Nat}

theorem fhpm_eq
    : findHighestPossibleMatch log index term
      = maxWhere (fun c => 0 < c /\ termAt log c <= term)
          (List.range (min index log.length + 1)) 0 :=
  rfl

theorem fhpm_le : findHighestPossibleMatch log index term <= min index log.length := by
  rw [fhpm_eq]
  rcases (maxWhere_spec (fun c => 0 < c /\ termAt log c <= term)
      (List.range (min index log.length + 1)) 0).2.2 with same | ⟨member, _⟩
  · rw [same]
    exact Nat.zero_le _
  · exact Nat.lt_succ_iff.mp (List.mem_range.mp member)

theorem le_fhpm {c : Nat} (positive : 0 < c) (le : c <= index) (bound : c <= log.length)
    (holds : termAt log c <= term)
    : c <= findHighestPossibleMatch log index term := by
  rw [fhpm_eq]
  exact (maxWhere_spec (fun c => 0 < c /\ termAt log c <= term)
          (List.range (min index log.length + 1)) 0).2.1
    c (List.mem_range.mpr (by omega)) ⟨positive, holds⟩

theorem fhpm_chosen
    : findHighestPossibleMatch log index term = 0
      \/ (0 < findHighestPossibleMatch log index term
          /\ termAt log (findHighestPossibleMatch log index term) <= term) := by
  rw [fhpm_eq]
  rcases (maxWhere_spec (fun c => 0 < c /\ termAt log c <= term)
      (List.range (min index log.length + 1)) 0).2.2 with same | ⟨_, holds⟩
  · exact Or.inl same
  · exact Or.inr holds

end Retry

end CCFRaft.Proofs.Replication
