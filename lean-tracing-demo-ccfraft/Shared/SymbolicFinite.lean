-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicData

set_option autoImplicit false

namespace Symbolic

def finValue : {n : Nat} → Expr (enumTy n) → Expr .nat
  | 0, _ => .nat 0
  | _ + 1, index =>
      matchSum index (fun _ => .nat 0)
        (fun rest => .add (.nat 1) (finValue rest))

theorem finValue_correct {n : Nat} (ρ : Assignment) (index : Expr (enumTy n)) :
    (finValue index).eval ρ = (enumDecode n (index.eval ρ)).val := by
  induction n with
  | zero => rfl
  | succ n ih =>
      cases hi : index.eval ρ <;>
        simp [finValue, matchSum, Expr.eval, ih, hi, enumDecode, Nat.add_comm]

def tableSelect {a : Ty} : {n : Nat} →
    Expr (vectorTy (n + 1) a) → Expr (enumTy n) → Expr a
  | 0, values, _ => values.fst
  | _ + 1, values, index =>
      matchSum index (fun _ => values.fst) (fun rest => tableSelect values.snd rest)

theorem tableSelect_correct {a : Ty} {n : Nat} (ρ : Assignment)
    (values : Expr (vectorTy (n + 1) a)) (index : Expr (enumTy n)) :
    (tableSelect values index).eval ρ =
      vectorGet (values.eval ρ) (enumDecode n (index.eval ρ)) := by
  induction n with
  | zero => rfl
  | succ n ih =>
      cases hi : index.eval ρ <;>
        simp [tableSelect, matchSum, Expr.eval, ih, hi, enumDecode, vectorGet]

theorem Codec.tableSelect_correct {α : Type} (c : Codec α) {n : Nat}
    (ρ : Assignment) (values : Expr (c.table (n + 1)).ty)
    (index : Expr (Codec.fin n).ty) :
    c.decode ρ (tableSelect values index) =
      (c.table (n + 1)).decode ρ values ((Codec.fin n).decode ρ index) := by
  exact congrArg c.equiv (Symbolic.tableSelect_correct ρ values index)

def setMember {n : Nat} (bits : Expr (Codec.finset n).ty) (index : Expr .nat) : Expr .bool :=
  tableMember bits index

theorem setMember_correct {n : Nat} (ρ : Assignment)
    (bits : Expr (Codec.finset n).ty) (index : Expr .nat) :
    (setMember bits index).eval ρ = true ↔
      index.eval ρ ∈ ((Codec.finset n).decode ρ bits).image Fin.val := by
  simp only [setMember, tableMember_correct ρ]
  change (∃ i, index.eval ρ = i.val ∧ vectorGet (bits.eval ρ) i = true) ↔ _
  simp [Codec.decode, Codec.finset, Codec.transport,
    Codec.table, Codec.bool, Finset.mem_image, and_comm]
  constructor <;> rintro ⟨i, hi, heq⟩ <;> exact ⟨i, hi, heq.symm⟩

def setInsert {n : Nat} (bits : Expr (Codec.finset n).ty) (index : Expr .nat) :
    Expr (Codec.finset n).ty :=
  tableStore bits index (.bool true)

def setErase {n : Nat} (bits : Expr (Codec.finset n).ty) (index : Expr .nat) :
    Expr (Codec.finset n).ty :=
  tableStore bits index (.bool false)

theorem setInsert_correct {n : Nat} (ρ : Assignment)
    (bits : Expr (Codec.finset n).ty) (index : Expr .nat) (i : Fin n) :
    i ∈ (Codec.finset n).decode ρ (setInsert bits index) ↔
      index.eval ρ = i.val ∨ i ∈ (Codec.finset n).decode ρ bits := by
  simp [setInsert, Codec.decode, Codec.finset, Codec.transport, Codec.table, Codec.bool,
    tableStore_correct, Expr.eval]

theorem setErase_correct {n : Nat} (ρ : Assignment)
    (bits : Expr (Codec.finset n).ty) (index : Expr .nat) (i : Fin n) :
    i ∈ (Codec.finset n).decode ρ (setErase bits index) ↔
      index.eval ρ ≠ i.val ∧ i ∈ (Codec.finset n).decode ρ bits := by
  simp [setErase, Codec.decode, Codec.finset, Codec.transport, Codec.table, Codec.bool,
    tableStore_correct, Expr.eval]

def optionalTest {a : Ty} (value : Expr (.sum .unit a))
    (predicate : Expr a → Expr .bool) : Expr .bool :=
  matchSum value (fun _ => .bool false) predicate

theorem optionalTest_correct {α : Type} (c : Codec α) (ρ : Assignment)
    (value : Expr c.option.ty) (predicate : Expr c.ty → Expr .bool) (p : α → Prop)
    (correct : ∀ x, (predicate x).eval ρ = true ↔ p (c.decode ρ x)) :
    (optionalTest value predicate).eval ρ = true ↔
      ∃ x, c.option.decode ρ value = some x ∧ p x := by
  cases hv : value.eval ρ <;>
    simp [optionalTest, matchSum, Expr.eval, correct, Codec.decode, Codec.option, hv]

end Symbolic
