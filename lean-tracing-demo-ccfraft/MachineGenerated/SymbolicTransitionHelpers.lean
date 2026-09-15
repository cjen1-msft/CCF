-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicOperations
import Shared.SymbolicFinite

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

theorem decode_choose {α : Type} (c : Codec α) (ρ : Assignment)
    (condition : Expr .bool) (yes no : Expr c.ty) :
    c.decode ρ (.ite condition yes no) =
      if condition.eval ρ then c.decode ρ yes else c.decode ρ no := by
  by_cases h : condition.eval ρ = true <;> simp [Codec.decode, Expr.eval, h]

def setUnion {n : Nat} (a b : Expr (Codec.finset n).ty) : Expr (Codec.finset n).ty :=
  tableExpr fun i => (tableGet a i).or (tableGet b i)

def setIntersection {n : Nat} (a b : Expr (Codec.finset n).ty) : Expr (Codec.finset n).ty :=
  tableExpr fun i => .and (tableGet a i) (tableGet b i)

def setDifference {n : Nat} (a b : Expr (Codec.finset n).ty) : Expr (Codec.finset n).ty :=
  tableExpr fun i => .and (tableGet a i) (.not (tableGet b i))

theorem setUnion_correct {n : Nat} (ρ : Assignment) (a b : Expr (Codec.finset n).ty) :
    (Codec.finset n).decode ρ (setUnion a b) =
      (Codec.finset n).decode ρ a ∪ (Codec.finset n).decode ρ b := by
  ext i
  simp [setUnion, Codec.decode, Codec.finset, Codec.transport, Codec.table, Codec.bool]

theorem setIntersection_correct {n : Nat} (ρ : Assignment) (a b : Expr (Codec.finset n).ty) :
    (Codec.finset n).decode ρ (setIntersection a b) =
      (Codec.finset n).decode ρ a ∩ (Codec.finset n).decode ρ b := by
  ext i
  simp [setIntersection, Codec.decode, Codec.finset, Codec.transport, Codec.table, Codec.bool,
    Expr.eval]

theorem setDifference_correct {n : Nat} (ρ : Assignment) (a b : Expr (Codec.finset n).ty) :
    (Codec.finset n).decode ρ (setDifference a b) =
      (Codec.finset n).decode ρ a \ (Codec.finset n).decode ρ b := by
  ext i
  simp [setDifference, Codec.decode, Codec.finset, Codec.transport, Codec.table, Codec.bool,
    Expr.eval]

def setCard {n : Nat} (bits : Expr (Codec.finset n).ty) : Expr .nat :=
  (List.finRange n).foldr
    (fun i acc => .add (.ite (tableGet bits i) (.nat 1) (.nat 0)) acc) (.nat 0)

theorem setCard_correct {n : Nat} (ρ : Assignment) (bits : Expr (Codec.finset n).ty) :
    (setCard bits).eval ρ = ((Codec.finset n).decode ρ bits).card := by
  have count (xs : List (Fin n)) :
      ((xs.foldr (fun i acc => Expr.add
        (.ite (tableGet bits i) (.nat 1) (.nat 0)) acc) (.nat 0)).eval ρ) =
        (xs.filter (fun i => vectorGet (bits.eval ρ) i)).length := by
    induction xs with
    | nil => rfl
    | cons x xs ih =>
        cases hx : vectorGet (bits.eval ρ) x <;> simp [Expr.eval, ih, hx, Nat.add_comm]
  rw [setCard, count]
  simp [Codec.decode, Codec.finset, Codec.transport, Codec.table, Codec.bool,
    ← List.toFinset_card_of_nodup (List.nodup_finRange n |>.filter _)]

def majority (support configuration : Expr nodeSetCodec.ty) : Expr .bool :=
  let supported := setCard (setIntersection support configuration)
  .lt (setCard configuration) (.add supported supported)

theorem majority_correct (ρ : Assignment) (support configuration : Expr nodeSetCodec.ty) :
    (majority support configuration).eval ρ = true ↔
      (nodeSetCodec.decode ρ support ∩ nodeSetCodec.decode ρ configuration).card * 2 >
        (nodeSetCodec.decode ρ configuration).card := by
  simp [majority, Expr.eval, setCard_correct, setIntersection_correct, Nat.mul_two]

def foldl {a b : Ty} (step : Expr b → Expr a → Expr b) :
    Nat → Expr b → Expr (.seq a) → Expr b
  | 0, base, _ => base
  | n + 1, base, xs =>
      .ite (.eq xs.length (.nat 0)) base
        (foldl step n (step base (Container.head xs)) (.drop (.nat 1) xs))

theorem foldl_correct {a b : Ty} {A B : Type} (ρ : Assignment)
    (decodeA : a.Value → A) (decodeB : b.Value → B)
    (step : Expr b → Expr a → Expr b) (f : B → A → B)
    (correct : ∀ acc x, decodeB ((step acc x).eval ρ) =
      f (decodeB (acc.eval ρ)) (decodeA (x.eval ρ)))
    (capacity : Nat) (base : Expr b) (xs : Expr (.seq a))
    (bound : (xs.eval ρ).length ≤ capacity) :
    decodeB ((foldl step capacity base xs).eval ρ) =
      (xs.eval ρ |>.map decodeA).foldl f (decodeB (base.eval ρ)) := by
  induction capacity generalizing xs base with
  | zero =>
      have empty : xs.eval ρ = [] := List.length_eq_zero_iff.mp (by omega)
      simp [foldl, empty]
  | succ n ih =>
      cases hx : xs.eval ρ with
      | nil => simp [foldl, Expr.eval, hx]
      | cons x tail =>
          have hb : ((Expr.drop (.nat 1) xs).eval ρ).length ≤ n := by
            simp [Expr.eval, hx] at bound ⊢
            omega
          have ht := ih (step base (Container.head xs)) (.drop (.nat 1) xs) hb
          simp only [Container.head] at ht
          simp [foldl, Expr.eval, hx, ht, correct, Container.head]

def indexedFold {A B : Type} (step : Nat → A → B → B) (base : B) :
    Nat → List A → B
  | _, [] => base
  | index, x :: xs => step index x (indexedFold step base (index + 1) xs)

def foldrFrom {a b : Ty} (step : Expr .nat → Expr a → Expr b → Expr b)
    (base : Expr b) : Nat → Expr .nat → Expr (.seq a) → Expr b
  | 0, _, _ => base
  | n + 1, index, xs =>
      .ite (.eq xs.length (.nat 0)) base
        (step index (Container.head xs)
          (foldrFrom step base n (.add index (.nat 1)) (.drop (.nat 1) xs)))

theorem foldrFrom_correct {a b : Ty} {A B : Type} (ρ : Assignment)
    (decodeA : a.Value → A) (decodeB : b.Value → B)
    (step : Expr .nat → Expr a → Expr b → Expr b) (base : Expr b)
    (f : Nat → A → B → B)
    (correct : ∀ i x acc, decodeB ((step i x acc).eval ρ) =
      f (i.eval ρ) (decodeA (x.eval ρ)) (decodeB (acc.eval ρ)))
    (capacity : Nat) (index : Expr .nat) (xs : Expr (.seq a))
    (bound : (xs.eval ρ).length ≤ capacity) :
    decodeB ((foldrFrom step base capacity index xs).eval ρ) =
      indexedFold f (decodeB (base.eval ρ)) (index.eval ρ) (xs.eval ρ |>.map decodeA) := by
  induction capacity generalizing xs index with
  | zero =>
      have empty : xs.eval ρ = [] := List.length_eq_zero_iff.mp (by omega)
      simp [foldrFrom, empty, indexedFold]
  | succ n ih =>
      cases hx : xs.eval ρ with
      | nil => simp [foldrFrom, Expr.eval, hx, indexedFold]
      | cons x tail =>
          have hb : ((Expr.drop (.nat 1) xs).eval ρ).length ≤ n := by
            simp [Expr.eval, hx] at bound ⊢
            omega
          have ht := ih (.add index (.nat 1)) (.drop (.nat 1) xs) hb
          simp [foldrFrom, Expr.eval, hx, ht, correct, Container.head, indexedFold]

end CCFRaft.SymbolicTransition
