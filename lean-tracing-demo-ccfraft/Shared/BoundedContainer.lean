-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.Symbolic

set_option autoImplicit false

namespace Symbolic.Container

abbrev Seq (a : Ty) := Expr (.seq a)

theorem select_correct {a : Ty} (ρ : Assignment) (xs : Seq a) (index : Expr .nat) :
    (Expr.get? xs index).eval ρ =
      match (xs.eval ρ)[index.eval ρ]? with
      | none => Sum.inl ()
      | some v => Sum.inr v := rfl

theorem store_correct {a : Ty} (ρ : Assignment)
    (xs : Seq a) (index : Expr .nat) (value : Expr a) :
    (Expr.set xs index value).eval ρ = (xs.eval ρ).set (index.eval ρ) (value.eval ρ) := rfl

theorem take_correct {a : Ty} (ρ : Assignment) (n : Expr .nat) (xs : Seq a) :
    (Expr.take n xs).eval ρ = (xs.eval ρ).take (n.eval ρ) := rfl

theorem drop_correct {a : Ty} (ρ : Assignment) (n : Expr .nat) (xs : Seq a) :
    (Expr.drop n xs).eval ρ = (xs.eval ρ).drop (n.eval ρ) := rfl

theorem append_correct {a : Ty} (ρ : Assignment) (xs ys : Seq a) :
    (Expr.append xs ys).eval ρ = xs.eval ρ ++ ys.eval ρ := rfl

theorem membership_correct {a : Ty} (ρ : Assignment) (xs : Seq a) (x : Expr a) :
    (Expr.contains xs x).eval ρ = true ↔ x.eval ρ ∈ xs.eval ρ := by
  simp [Expr.eval]

def within {a : Ty} (capacity : Nat) (xs : Seq a) : Expr .bool :=
  xs.length.le (.nat capacity)

def input {a : Ty} {capacity : Nat}
    (length : Expr .nat) (slots : Vector (Expr a) capacity) : Seq a :=
  .take length (.ofList slots.toList)

def inputDomain (capacity : Nat) (length : Expr .nat) : Expr .bool :=
  length.le (.nat capacity)

@[simp] theorem within_correct {a : Ty} (ρ : Assignment) (capacity : Nat) (xs : Seq a) :
    (within capacity xs).eval ρ = true ↔ (xs.eval ρ).length ≤ capacity := by
  simp [within, Expr.eval]

theorem input_correct {a : Ty} {capacity : Nat} (ρ : Assignment)
    (length : Expr .nat) (slots : Vector (Expr a) capacity) :
    (input length slots).eval ρ = (slots.toList.map (Expr.eval ρ)).take (length.eval ρ) := by
  simp [input, Expr.eval]

theorem input_length {a : Ty} {capacity : Nat} (ρ : Assignment)
    (length : Expr .nat) (slots : Vector (Expr a) capacity)
    (domain : (inputDomain capacity length).eval ρ = true) :
    ((input length slots).eval ρ).length = length.eval ρ := by
  have h : length.eval ρ ≤ capacity := by simpa [inputDomain, Expr.eval] using domain
  simp [input_correct, List.length_take, Nat.min_eq_left h]

def head {a : Ty} (xs : Seq a) : Expr a :=
  .rightD (.get? xs (.nat 0)) (defaultExpr a)

-- Fuel is a declared capacity, not a guessed bound on concrete input.
def foldr {a b : Ty} (step : Expr a → Expr b → Expr b) (base : Expr b) :
    Nat → Seq a → Expr b
  | 0, _ => base
  | n + 1, xs =>
      .ite (.eq xs.length (.nat 0)) base
        (step (head xs) (foldr step base n (.drop (.nat 1) xs)))

theorem foldr_correct {a b : Ty} (ρ : Assignment)
    (step : Expr a → Expr b → Expr b) (base : Expr b)
    (f : a.Value → b.Value → b.Value)
    (step_correct : ∀ x acc, (step x acc).eval ρ = f (x.eval ρ) (acc.eval ρ))
    (capacity : Nat) (xs : Seq a) (bound : (xs.eval ρ).length ≤ capacity) :
    (foldr step base capacity xs).eval ρ = (xs.eval ρ).foldr f (base.eval ρ) := by
  induction capacity generalizing xs with
  | zero =>
      have empty : xs.eval ρ = [] := List.length_eq_zero_iff.mp (by omega)
      simp [foldr, empty]
  | succ n ih =>
      cases hx : xs.eval ρ with
      | nil => simp [foldr, Expr.eval, hx]
      | cons x tail =>
          have hb : ((Expr.drop (.nat 1) xs).eval ρ).length ≤ n := by
            simp [Expr.eval, hx] at bound ⊢
            omega
          have ht := ih (.drop (.nat 1) xs) hb
          simp [foldr, Expr.eval, hx, step_correct, head, ht]

def map {a b : Ty} (capacity : Nat) (f : Expr a → Expr b) (xs : Seq a) : Seq b :=
  foldr (fun x acc => .cons (f x) acc) .nil capacity xs

theorem map_correct {a b : Ty} (ρ : Assignment)
    (capacity : Nat) (f : Expr a → Expr b) (g : a.Value → b.Value)
    (correct : ∀ x, (f x).eval ρ = g (x.eval ρ))
    (xs : Seq a) (bound : (xs.eval ρ).length ≤ capacity) :
    (map capacity f xs).eval ρ = (xs.eval ρ).map g := by
  rw [map, foldr_correct ρ _ _ (fun x acc => g x :: acc)]
  · simp [Expr.eval]
  · intro x acc; simp [Expr.eval, correct]
  · exact bound

def all {a : Ty} (capacity : Nat) (p : Expr a → Expr .bool) (xs : Seq a) : Expr .bool :=
  foldr (fun x acc => .and (p x) acc) (.bool true) capacity xs

theorem all_correct {a : Ty} (ρ : Assignment)
    (capacity : Nat) (p : Expr a → Expr .bool) (q : a.Value → Bool)
    (correct : ∀ x, (p x).eval ρ = q (x.eval ρ))
    (xs : Seq a) (bound : (xs.eval ρ).length ≤ capacity) :
    (all capacity p xs).eval ρ = (xs.eval ρ).all q := by
  rw [all, foldr_correct ρ _ _ (fun x acc => q x && acc)]
  · induction xs.eval ρ <;> simp_all [Expr.eval]
  · intro x acc; simp [Expr.eval, correct]
  · exact bound

def boundedAll {a : Ty} (capacity : Nat) (p : Expr a → Expr .bool) (xs : Seq a) :
    Expr .bool := .and (within capacity xs) (all capacity p xs)

theorem boundedAll_correct {a : Ty} (ρ : Assignment)
    (capacity : Nat) (p : Expr a → Expr .bool) (q : a.Value → Bool)
    (correct : ∀ x, (p x).eval ρ = q (x.eval ρ)) (xs : Seq a) :
    (boundedAll capacity p xs).eval ρ = true ↔
      (xs.eval ρ).length ≤ capacity ∧ ∀ x ∈ xs.eval ρ, q x = true := by
  by_cases h : (xs.eval ρ).length ≤ capacity
  · simp [boundedAll, within, Expr.eval, h, all_correct ρ capacity p q correct xs h]
  · simp [boundedAll, within, Expr.eval, h]

def filter {a : Ty} (capacity : Nat) (p : Expr a → Expr .bool) (xs : Seq a) : Seq a :=
  foldr (fun x acc => .ite (p x) (.cons x acc) acc) .nil capacity xs

theorem filter_correct {a : Ty} (ρ : Assignment)
    (capacity : Nat) (p : Expr a → Expr .bool) (q : a.Value → Bool)
    (correct : ∀ x, (p x).eval ρ = q (x.eval ρ))
    (xs : Seq a) (bound : (xs.eval ρ).length ≤ capacity) :
    (filter capacity p xs).eval ρ = (xs.eval ρ).filter q := by
  rw [filter, foldr_correct ρ _ _ (fun x acc => if q x then x :: acc else acc)]
  · induction xs.eval ρ <;> simp_all [Expr.eval, List.filter_cons]
  · intro x acc; simp [Expr.eval, correct]
  · exact bound

def enqueueNoDup {a : Ty} (xs : Seq a) (value : Expr a) : Seq a :=
  .ite (.contains xs value) xs (.append xs (.cons value .nil))

theorem enqueueNoDup_correct {a : Ty} (ρ : Assignment) (xs : Seq a) (value : Expr a) :
    (enqueueNoDup xs value).eval ρ =
      if value.eval ρ ∈ xs.eval ρ then xs.eval ρ else xs.eval ρ ++ [value.eval ρ] := by
  simp [enqueueNoDup, Expr.eval]

def prefixEqual {a : Ty} (n : Expr .nat) (xs ys : Seq a) : Expr .bool :=
  .eq (.take n xs) (.take n ys)

theorem prefixEqual_correct {a : Ty} (ρ : Assignment)
    (n : Expr .nat) (xs ys : Seq a) :
    (prefixEqual n xs ys).eval ρ = true ↔
      (xs.eval ρ).take (n.eval ρ) = (ys.eval ρ).take (n.eval ρ) := by
  simp [prefixEqual, Expr.eval]

def removeFirst {a : Ty} (p : Expr a → Expr .bool) : Nat → Seq a → Seq a
  | 0, xs => xs
  | n + 1, xs =>
      .ite (.eq xs.length (.nat 0)) xs
        (.ite (p (head xs)) (.drop (.nat 1) xs)
          (.cons (head xs) (removeFirst p n (.drop (.nat 1) xs))))

theorem removeFirst_correct {a : Ty} (ρ : Assignment)
    (p : Expr a → Expr .bool) (q : a.Value → Bool)
    (correct : ∀ x, (p x).eval ρ = q (x.eval ρ))
    (capacity : Nat) (xs : Seq a) (bound : (xs.eval ρ).length ≤ capacity) :
    (removeFirst p capacity xs).eval ρ = (xs.eval ρ).eraseP q := by
  induction capacity generalizing xs with
  | zero =>
      have empty : xs.eval ρ = [] := List.length_eq_zero_iff.mp (by omega)
      simp [removeFirst, empty]
  | succ n ih =>
      cases hx : xs.eval ρ with
      | nil => simp [removeFirst, Expr.eval, hx]
      | cons x tail =>
          have hb : ((Expr.drop (.nat 1) xs).eval ρ).length ≤ n := by
            simp [Expr.eval, hx] at bound ⊢
            omega
          have ht := ih (.drop (.nat 1) xs) hb
          simp [removeFirst, Expr.eval, hx, correct, head, ht, List.eraseP_cons]

def noDup {a : Ty} : Nat → Seq a → Expr .bool
  | 0, _ => .bool true
  | n + 1, xs =>
      .ite (.eq xs.length (.nat 0)) (.bool true)
        (.and (.not (.contains (.drop (.nat 1) xs) (head xs)))
          (noDup n (.drop (.nat 1) xs)))

theorem noDup_correct {a : Ty} (ρ : Assignment)
    (capacity : Nat) (xs : Seq a) (bound : (xs.eval ρ).length ≤ capacity) :
    (noDup capacity xs).eval ρ = true ↔ (xs.eval ρ).Nodup := by
  induction capacity generalizing xs with
  | zero =>
      have empty : xs.eval ρ = [] := List.length_eq_zero_iff.mp (by omega)
      simp [noDup, Expr.eval, empty]
  | succ n ih =>
      cases hx : xs.eval ρ with
      | nil => simp [noDup, Expr.eval, hx]
      | cons x tail =>
          have hb : ((Expr.drop (.nat 1) xs).eval ρ).length ≤ n := by
            simp [Expr.eval, hx] at bound ⊢
            omega
          have ht := ih (.drop (.nat 1) xs) hb
          simp [Expr.eval, hx] at ht
          simp [noDup, Expr.eval, hx, head, ht]

def takeFirstList {α : Type} (p : α → Bool) :
    List α → Sum Unit (α × List α)
  | [] => .inl ()
  | x :: xs =>
      if p x then .inr (x, xs) else
        match takeFirstList p xs with
        | .inl _ => .inl ()
        | .inr (selected, rest) => .inr (selected, x :: rest)

private def takeFirstScan {a : Ty} (p : Expr a → Expr .bool) :
    Nat → Seq a → Seq a → Expr (.sum .unit (.pair a (.seq a)))
  | 0, _, _ => .inl .unit
  | n + 1, skipped, xs =>
      let tail := Expr.drop (.nat 1) xs
      .ite (.eq xs.length (.nat 0)) (.inl .unit)
        (.ite (p (head xs)) (.inr (.pair (head xs) (.append skipped tail)))
          (takeFirstScan p n (.append skipped (.cons (head xs) .nil)) tail))

private theorem takeFirstScan_correct {a : Ty} (ρ : Assignment)
    (p : Expr a → Expr .bool) (q : a.Value → Bool)
    (correct : ∀ x, (p x).eval ρ = q (x.eval ρ))
    (capacity : Nat) (skipped xs : Seq a) (bound : (xs.eval ρ).length ≤ capacity) :
    (takeFirstScan p capacity skipped xs).eval ρ =
      match takeFirstList q (xs.eval ρ) with
      | .inl _ => .inl ()
      | .inr (selected, rest) => .inr (selected, skipped.eval ρ ++ rest) := by
  induction capacity generalizing skipped xs with
  | zero =>
      have empty : xs.eval ρ = [] := List.length_eq_zero_iff.mp (by omega)
      simp [takeFirstScan, Expr.eval, takeFirstList, empty]
  | succ n ih =>
      cases hx : xs.eval ρ with
      | nil => simp [takeFirstScan, Expr.eval, hx, takeFirstList]
      | cons x tail =>
          have hb : ((Expr.drop (.nat 1) xs).eval ρ).length ≤ n := by
            simp [Expr.eval, hx] at bound ⊢
            omega
          have ht := ih (.append skipped (.cons (head xs) .nil)) (.drop (.nat 1) xs) hb
          simp only [head] at ht
          cases hr : takeFirstList q tail <;> cases hp : q x <;>
            simp [takeFirstScan, Expr.eval, hx, correct, head, ht, takeFirstList,
              hr, hp, List.append_assoc]

def takeFirst {a : Ty} (p : Expr a → Expr .bool)
    (capacity : Nat) (xs : Seq a) : Expr (.sum .unit (.pair a (.seq a))) :=
  takeFirstScan p capacity .nil xs

theorem takeFirst_correct {a : Ty} (ρ : Assignment)
    (p : Expr a → Expr .bool) (q : a.Value → Bool)
    (correct : ∀ x, (p x).eval ρ = q (x.eval ρ))
    (capacity : Nat) (xs : Seq a) (bound : (xs.eval ρ).length ≤ capacity) :
    (takeFirst p capacity xs).eval ρ = takeFirstList q (xs.eval ρ) := by
  have h := takeFirstScan_correct ρ p q correct capacity .nil xs bound
  cases result : takeFirstList q (xs.eval ρ) <;>
    simpa [takeFirst, Expr.eval, result] using h

end Symbolic.Container
