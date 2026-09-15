-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionHelpers
import Shared.SymbolicNormalizeMemo

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

def appendSequence {a : Ty} : Expr (.seq a) → Expr (.seq a) → Expr (.seq a)
  | .nil, ys => ys
  | .cons x xs, ys => .cons x (appendSequence xs ys)
  | xs, ys => .append xs ys

theorem appendSequence_correct {a : Ty} (ρ : Assignment) (xs ys : Expr (.seq a)) :
    (appendSequence xs ys).eval ρ = xs.eval ρ ++ ys.eval ρ := by
  fun_induction appendSequence xs ys <;> simp_all [Expr.eval]

abbrev configurationCodec : Codec (Configuration Node) :=
  (Codec.nat.prod nodeSetCodec).transport
    { toFun := fun (index, nodes) => ⟨index, nodes⟩
      invFun := fun c => (c.index, c.nodes)
      left_inv := by rintro ⟨_, _⟩; rfl
      right_inv := by intro c; cases c; rfl }

def configurationStep (index : Expr .nat) (entry : Expr entryCodec.ty)
    (rest : Expr configurationCodec.list.ty) : Expr configurationCodec.list.ty :=
  -- Keep the recursive suffix outside content dispatch.
  appendSequence
    (matchSum entry.snd (fun _ => .nil) fun other =>
      matchSum other (fun _ => .nil) fun sets =>
        matchSum sets (fun nodes => .cons (.pair index nodes) .nil) (fun _ => .nil))
    rest

theorem configurationStep_correct (ρ : Assignment) (index : Expr .nat)
    (entry : Expr entryCodec.ty) (rest : Expr configurationCodec.list.ty) :
    configurationCodec.list.decode ρ (configurationStep index entry rest) =
      match (entryCodec.decode ρ entry).content with
      | .reconfiguration nodes =>
          ⟨index.eval ρ, nodes⟩ :: configurationCodec.list.decode ρ rest
      | _ => configurationCodec.list.decode ρ rest := by
  generalize he : entry.eval ρ = v
  rcases v with ⟨term, tx | (_ | (nodes | nodes))⟩ <;>
    simp [configurationStep, appendSequence_correct, matchSum, Expr.eval, Codec.decode, he,
      Codec.transport, Codec.prod, Codec.sum, Codec.list, Codec.nat]

def configurationsFrom (capacity : Nat) (index : Expr .nat) (log : Expr logCodec.ty) :
    Expr configurationCodec.list.ty :=
  (foldrFrom configurationStep .nil capacity index log).normalizeMemo

theorem configurationsFrom_correct (ρ : Assignment) (capacity : Nat)
    (index : Expr .nat) (log : Expr logCodec.ty)
    (bound : (logCodec.decode ρ log).length ≤ capacity) :
    configurationCodec.list.decode ρ (configurationsFrom capacity index log) =
      configurationsInLogFrom (index.eval ρ) (logCodec.decode ρ log) := by
  let f : Nat → Entry Node Nat → List (Configuration Node) → List (Configuration Node) :=
    fun i e acc =>
    match e.content with | .reconfiguration ns => ⟨i, ns⟩ :: acc | _ => acc
  have h := foldrFrom_correct ρ entryCodec.equiv configurationCodec.list.equiv
    configurationStep (.nil : Expr configurationCodec.list.ty) f
    (configurationStep_correct ρ) capacity index log
    (by simpa [Codec.decode, Codec.list] using bound)
  have scan (xs : List (Entry Node Nat)) (i : Nat) :
      indexedFold f [] i xs = configurationsInLogFrom i xs := by
    induction xs generalizing i with
    | nil => rfl
    | cons e xs ih =>
        cases hc : e.content <;> simp [indexedFold, f, configurationsInLogFrom, ih, hc]
  simpa [configurationsFrom, Codec.decode, Codec.list, Expr.normalizeMemo_correct, Expr.eval, scan] using h

def signatureAfterStep (retirement index : Expr .nat) (entry : Expr entryCodec.ty)
    (rest : Expr Codec.nat.option.ty) : Expr Codec.nat.option.ty :=
  .ite (.and (.lt retirement index) (.eq entry.snd (contentCodec.literal .signature)))
    (.inr index) rest

theorem signatureAfterStep_correct (ρ : Assignment)
    (retirement index : Expr .nat) (entry : Expr entryCodec.ty) (rest : Expr Codec.nat.option.ty) :
    Codec.nat.option.decode ρ (signatureAfterStep retirement index entry rest) =
      if retirement.eval ρ < index.eval ρ ∧ (entryCodec.decode ρ entry).content = .signature then
        some (index.eval ρ)
      else Codec.nat.option.decode ρ rest := by
  have he : (Expr.eq entry.snd (contentCodec.literal .signature)).eval ρ =
      decide ((entryCodec.decode ρ entry).content = .signature) := by
    apply Bool.eq_iff_iff.mpr
    rw [contentCodec.equal_correct, Codec.decode_literal, decide_eq_true_iff]
    rfl
  have hc : (Expr.and (.lt retirement index)
      (.eq entry.snd (contentCodec.literal .signature))).eval ρ =
      decide (retirement.eval ρ < index.eval ρ ∧
        (entryCodec.decode ρ entry).content = .signature) := by
    change (decide (retirement.eval ρ < index.eval ρ) &&
      (Expr.eq entry.snd (contentCodec.literal .signature)).eval ρ) = _
    rw [he]
    simp
  rw [signatureAfterStep, decode_choose, hc]
  simp [Codec.decode, Codec.option, Codec.nat, Expr.eval]

def signatureAfter (capacity : Nat) (retirement index : Expr .nat) (log : Expr logCodec.ty) :
    Expr Codec.nat.option.ty :=
  foldrFrom (signatureAfterStep retirement) (.inl .unit) capacity index log

theorem signatureAfter_correct (ρ : Assignment) (capacity : Nat)
    (retirement index : Expr .nat) (log : Expr logCodec.ty)
    (bound : (logCodec.decode ρ log).length ≤ capacity) :
    Codec.nat.option.decode ρ (signatureAfter capacity retirement index log) =
      signatureIndexAfterFrom (retirement.eval ρ) (index.eval ρ) (logCodec.decode ρ log) := by
  let f := fun i (e : Entry Node Nat) (rest : Option Nat) =>
    if retirement.eval ρ < i ∧ e.content = .signature then some i else rest
  have h := foldrFrom_correct ρ entryCodec.equiv Codec.nat.option.equiv
    (signatureAfterStep retirement) (.inl .unit) f (signatureAfterStep_correct ρ retirement)
    capacity index log (by simpa [Codec.decode, Codec.list] using bound)
  have scan (xs : List (Entry Node Nat)) (i : Nat) :
      indexedFold f none i xs = signatureIndexAfterFrom (retirement.eval ρ) i xs := by
    induction xs generalizing i <;> simp_all [indexedFold, f, signatureIndexAfterFrom]
  simpa [signatureAfter, Codec.decode, Codec.option, Expr.eval, scan] using h

def retiredIndexStep (node : Expr nodeCodec.ty) (index : Expr .nat) (entry : Expr entryCodec.ty)
    (rest : Expr Codec.nat.option.ty) : Expr Codec.nat.option.ty :=
  matchSum entry.snd (fun _ => rest) fun other =>
    matchSum other (fun _ => rest) fun sets =>
      matchSum sets (fun _ => rest) fun nodes =>
        .ite (tableSelect nodes node) (.inr index) rest

theorem retiredIndexStep_correct (ρ : Assignment) (node : Expr nodeCodec.ty)
    (index : Expr .nat) (entry : Expr entryCodec.ty) (rest : Expr Codec.nat.option.ty) :
    Codec.nat.option.decode ρ (retiredIndexStep node index entry rest) =
      match (entryCodec.decode ρ entry).content with
      | .retiredCommitted nodes =>
          if nodeCodec.decode ρ node ∈ nodes then some (index.eval ρ)
          else Codec.nat.option.decode ρ rest
      | _ => Codec.nat.option.decode ρ rest := by
  generalize he : entry.eval ρ = v
  rcases v with ⟨term, tx | (_ | (nodes | nodes))⟩ <;>
    simp [retiredIndexStep, matchSum, Expr.eval, tableSelect_correct, Codec.decode, he,
      Codec.transport, Codec.prod, Codec.sum, Codec.option, Codec.nat,
      Codec.finset, Codec.table, Codec.bool, Codec.fin]
  split_ifs <;> first | rfl | contradiction

def retiredIndex (capacity : Nat) (node : Expr nodeCodec.ty)
    (index : Expr .nat) (log : Expr logCodec.ty) : Expr Codec.nat.option.ty :=
  foldrFrom (retiredIndexStep node) (.inl .unit) capacity index log

theorem retiredIndex_correct (ρ : Assignment) (capacity : Nat) (node : Expr nodeCodec.ty)
    (index : Expr .nat) (log : Expr logCodec.ty)
    (bound : (logCodec.decode ρ log).length ≤ capacity) :
    Codec.nat.option.decode ρ (retiredIndex capacity node index log) =
      retiredCommittedIndexFrom (nodeCodec.decode ρ node) (index.eval ρ) (logCodec.decode ρ log) := by
  let f := fun i (e : Entry Node Nat) (rest : Option Nat) =>
    match e.content with
    | .retiredCommitted ns => if nodeCodec.decode ρ node ∈ ns then some i else rest
    | _ => rest
  have h := foldrFrom_correct ρ entryCodec.equiv Codec.nat.option.equiv
    (retiredIndexStep node) (.inl .unit) f (retiredIndexStep_correct ρ node)
    capacity index log (by simpa [Codec.decode, Codec.list] using bound)
  have scan (xs : List (Entry Node Nat)) (i : Nat) :
      indexedFold f none i xs = retiredCommittedIndexFrom (nodeCodec.decode ρ node) i xs := by
    induction xs generalizing i with
    | nil => rfl
    | cons e xs ih =>
        cases hc : e.content <;> simp [indexedFold, f, retiredCommittedIndexFrom, ih, hc]
  simpa [retiredIndex, Codec.decode, Codec.option, Expr.eval, scan] using h

end CCFRaft.SymbolicTransition
