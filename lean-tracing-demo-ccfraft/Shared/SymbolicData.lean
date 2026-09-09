-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.Symbolic

set_option autoImplicit false

namespace Symbolic

def quote : (s : Ty) → s.Value → Expr s
  | .nat, n => .nat n
  | .bool, b => .bool b
  | .unit, _ => .unit
  | .pair a b, (x, y) => .pair (quote a x) (quote b y)
  | .sum a _, .inl x => .inl (quote a x)
  | .sum _ b, .inr y => .inr (quote b y)
  | .seq a, xs => .ofList (xs.map (quote a))

@[simp] theorem eval_quote (ρ : Assignment) (s : Ty) (v : s.Value) :
    (quote s v).eval ρ = v := by
  induction s with
  | nat | bool | unit => cases v <;> rfl
  | pair a b ha hb => cases v; simp [quote, Expr.eval, ha, hb]
  | sum a b ha hb => cases v <;> simp [quote, Expr.eval, ha, hb]
  | seq a ha => simp [quote, List.map_map, Function.comp_def, ha]

structure Codec (α : Type) where
  ty : Ty
  equiv : ty.Value ≃ α

def Codec.decode {α : Type} (c : Codec α) (ρ : Assignment) (e : Expr c.ty) : α :=
  c.equiv (e.eval ρ)

def Codec.literal {α : Type} (c : Codec α) (v : α) : Expr c.ty :=
  quote c.ty (c.equiv.symm v)

@[simp] theorem Codec.decode_literal {α : Type} (c : Codec α) (ρ : Assignment) (v : α) :
    c.decode ρ (c.literal v) = v := by
  simp [Codec.decode, Codec.literal]

theorem Codec.equal_correct {α : Type} (c : Codec α) (ρ : Assignment) (a b : Expr c.ty) :
    (Expr.eq a b).eval ρ = true ↔ c.decode ρ a = c.decode ρ b := by
  simp [Expr.eval, Codec.decode]

def Codec.nat : Codec Nat := ⟨.nat, Equiv.refl _⟩
def Codec.bool : Codec Bool := ⟨.bool, Equiv.refl _⟩
def Codec.unit : Codec Unit := ⟨.unit, Equiv.refl _⟩

def Codec.prod {α β : Type} (a : Codec α) (b : Codec β) : Codec (α × β) :=
  ⟨.pair a.ty b.ty, Equiv.prodCongr a.equiv b.equiv⟩

def Codec.sum {α β : Type} (a : Codec α) (b : Codec β) : Codec (Sum α β) :=
  ⟨.sum a.ty b.ty, Equiv.sumCongr a.equiv b.equiv⟩

def Codec.list {α : Type} (a : Codec α) : Codec (List α) where
  ty := .seq a.ty
  equiv :=
    { toFun := List.map a.equiv
      invFun := List.map a.equiv.symm
      left_inv := by intro xs; simp [List.map_map]
      right_inv := by intro xs; simp [List.map_map] }

def Codec.option {α : Type} (a : Codec α) : Codec (Option α) where
  ty := .sum .unit a.ty
  equiv :=
    { toFun := fun v => match v with | .inl _ => none | .inr x => some (a.equiv x)
      invFun := fun v => match v with | none => .inl () | some x => .inr (a.equiv.symm x)
      left_inv := by intro v; cases v <;> simp
      right_inv := by intro v; cases v <;> simp }

def Codec.transport {α β : Type} (a : Codec α) (e : α ≃ β) : Codec β :=
  ⟨a.ty, a.equiv.trans e⟩

@[reducible] def enumTy : Nat → Ty
  | 0 => .unit
  | n + 1 => .sum .unit (enumTy n)

def enumDecode : (n : Nat) → (enumTy n).Value → Fin (n + 1)
  | 0, _ => 0
  | _ + 1, .inl _ => 0
  | n + 1, .inr v => (enumDecode n v).succ

def enumEncode : (n : Nat) → Fin (n + 1) → (enumTy n).Value
  | 0, _ => ()
  | n + 1, i => Fin.cases (.inl ()) (fun j => .inr (enumEncode n j)) i

theorem enumDecode_encode (n : Nat) (i : Fin (n + 1)) :
    enumDecode n (enumEncode n i) = i := by
  induction n with
  | zero => apply Fin.ext; omega
  | succ n ih => refine Fin.cases ?_ (fun j => ?_) i <;> simp [enumEncode, enumDecode, ih]

theorem enumEncode_decode (n : Nat) (v : (enumTy n).Value) :
    enumEncode n (enumDecode n v) = v := by
  induction n with
  | zero => exact Subsingleton.elim _ _
  | succ n ih => cases v <;> simp [enumEncode, enumDecode, ih]

def Codec.fin (n : Nat) : Codec (Fin (n + 1)) :=
  ⟨enumTy n, ⟨enumDecode n, enumEncode n, enumEncode_decode n, enumDecode_encode n⟩⟩

@[reducible] def vectorTy : Nat → Ty → Ty
  | 0, _ => .unit
  | n + 1, a => .pair a (vectorTy n a)

def vectorGet {a : Ty} : {n : Nat} → (vectorTy n a).Value → Fin n → a.Value
  | 0, _, i => Fin.elim0 i
  | _ + 1, (x, xs), i => Fin.cases x (vectorGet xs) i

def vectorOfFn {a : Ty} : {n : Nat} → (Fin n → a.Value) → (vectorTy n a).Value
  | 0, _ => ()
  | _ + 1, f => (f 0, vectorOfFn (fun i => f i.succ))

@[simp] theorem vectorGet_ofFn {a : Ty} {n : Nat} (f : Fin n → a.Value) (i : Fin n) :
    vectorGet (vectorOfFn f) i = f i := by
  induction n with
  | zero => exact Fin.elim0 i
  | succ n ih => refine Fin.cases ?_ (fun j => ?_) i <;> simp [vectorGet, vectorOfFn, ih]

@[simp] theorem vectorOfFn_get {a : Ty} {n : Nat} (v : (vectorTy n a).Value) :
    vectorOfFn (vectorGet v) = v := by
  induction n with
  | zero => exact Subsingleton.elim _ _
  | succ n ih =>
      cases v
      simp [vectorOfFn, vectorGet, ih]

def Codec.table {α : Type} (n : Nat) (c : Codec α) : Codec (Fin n → α) where
  ty := vectorTy n c.ty
  equiv :=
    { toFun := fun v i => c.equiv (vectorGet v i)
      invFun := fun f => vectorOfFn (fun i => c.equiv.symm (f i))
      left_inv := by intro v; simp
      right_inv := by intro f; funext i; simp }

def Codec.finset (n : Nat) : Codec (Finset (Fin n)) :=
  (Codec.table n Codec.bool).transport
    { toFun := fun f => Finset.univ.filter (fun i => f i)
      invFun := fun s i => decide (i ∈ s)
      left_inv := by intro f; funext i; simp
      right_inv := by intro s; ext i; simp }

def matchSum {a b c : Ty} (e : Expr (.sum a b))
    (left : Expr a → Expr c) (right : Expr b → Expr c) : Expr c :=
  .ite e.isLeft (left (.leftD e (defaultExpr a))) (right (.rightD e (defaultExpr b)))

theorem matchSum_correct {a b c : Ty} (ρ : Assignment) (e : Expr (.sum a b))
    (left : Expr a → Expr c) (right : Expr b → Expr c)
    (f : a.Value → c.Value) (g : b.Value → c.Value)
    (hl : ∀ x, (left x).eval ρ = f (x.eval ρ))
    (hr : ∀ x, (right x).eval ρ = g (x.eval ρ)) :
    (matchSum e left right).eval ρ =
      match e.eval ρ with | .inl x => f x | .inr y => g y := by
  cases he : e.eval ρ <;> simp [matchSum, Expr.eval, hl, hr, he]

def tableExpr {a : Ty} : {n : Nat} → (Fin n → Expr a) → Expr (vectorTy n a)
  | 0, _ => .unit
  | _ + 1, f => .pair (f 0) (tableExpr (fun i => f i.succ))

def tableGet {a : Ty} : {n : Nat} → Expr (vectorTy n a) → Fin n → Expr a
  | 0, _, i => Fin.elim0 i
  | _ + 1, e, i => Fin.cases e.fst (fun j => tableGet e.snd j) i

@[simp] theorem tableExpr_correct {a : Ty} {n : Nat} (ρ : Assignment)
    (f : Fin n → Expr a) :
    (tableExpr f).eval ρ = vectorOfFn (fun i => (f i).eval ρ) := by
  induction n with
  | zero => rfl
  | succ n ih => simp [tableExpr, Expr.eval, vectorOfFn, ih]

@[simp] theorem tableGet_correct {a : Ty} {n : Nat} (ρ : Assignment)
    (e : Expr (vectorTy n a)) (i : Fin n) :
    (tableGet e i).eval ρ = vectorGet (e.eval ρ) i := by
  induction n with
  | zero => exact Fin.elim0 i
  | succ n ih => refine Fin.cases ?_ (fun j => ?_) i <;> simp [tableGet, Expr.eval, vectorGet, ih]

def tableStore {a : Ty} {n : Nat}
    (e : Expr (vectorTy n a)) (index : Expr .nat) (value : Expr a) :
    Expr (vectorTy n a) :=
  tableExpr fun i => .ite (.eq index (.nat i.val)) value (tableGet e i)

theorem tableStore_correct {a : Ty} {n : Nat} (ρ : Assignment)
    (e : Expr (vectorTy n a)) (index : Expr .nat) (value : Expr a) (i : Fin n) :
    vectorGet ((tableStore e index value).eval ρ) i =
      if index.eval ρ = i.val then value.eval ρ else vectorGet (e.eval ρ) i := by
  simp [tableStore, Expr.eval]

def tableMember {n : Nat} (bits : Expr (vectorTy n .bool)) (index : Expr .nat) :
    Expr .bool :=
  (List.finRange n).foldr
    (fun i acc => (Expr.and (.eq index (.nat i.val)) (tableGet bits i)).or acc) (.bool false)

theorem tableMember_correct {n : Nat} (ρ : Assignment)
    (bits : Expr (vectorTy n .bool)) (index : Expr .nat) :
    (tableMember bits index).eval ρ = true ↔
      ∃ i : Fin n, index.eval ρ = i.val ∧ vectorGet (bits.eval ρ) i = true := by
  have aux (xs : List (Fin n)) :
      ((xs.foldr (fun i acc =>
        (Expr.and (.eq index (.nat i.val)) (tableGet bits i)).or acc) (.bool false)).eval ρ = true) ↔
        ∃ i ∈ xs, index.eval ρ = i.val ∧ vectorGet (bits.eval ρ) i = true := by
    induction xs with
    | nil => simp [Expr.eval]
    | cons x xs ih => simp [Expr.eval, ih]
  simpa [tableMember] using aux (List.finRange n)

def tableAll {a : Ty} {n : Nat} (p : Expr a → Expr .bool) (e : Expr (vectorTy n a)) :
    Expr .bool :=
  (List.finRange n).foldr (fun i acc => .and (p (tableGet e i)) acc) (.bool true)

theorem tableAll_correct {a : Ty} {n : Nat} (ρ : Assignment)
    (p : Expr a → Expr .bool) (q : a.Value → Prop) (e : Expr (vectorTy n a))
    (correct : ∀ x, (p x).eval ρ = true ↔ q (x.eval ρ)) :
    (tableAll p e).eval ρ = true ↔ ∀ i, q (vectorGet (e.eval ρ) i) := by
  have aux (xs : List (Fin n)) :
      ((xs.foldr (fun i acc => Expr.and (p (tableGet e i)) acc) (.bool true)).eval ρ = true) ↔
        ∀ i ∈ xs, q (vectorGet (e.eval ρ) i) := by
    induction xs <;> simp_all [Expr.eval]
  simpa [tableAll] using aux (List.finRange n)

end Symbolic
