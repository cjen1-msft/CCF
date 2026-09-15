-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionState
import MachineGenerated.SymbolicTransitionScans
import MachineGenerated.SymbolicBounds

set_option autoImplicit false

namespace CCFRaft.SymbolicReceive

open Symbolic SymbolicModel SymbolicTransition

def rawOptionCases {a b : Ty} (value : Expr (.sum .unit a))
    (onNone : Expr b) (onSome : Expr a → Expr b) : Expr b :=
  matchSum value (fun _ => onNone) onSome

theorem rawOptionCases_correct {α β : Type} (a : Codec α) (b : Codec β)
    (ρ : Assignment) (value : Expr a.option.ty) (onNone : Expr b.ty)
    (onSome : Expr a.ty → Expr b.ty) (f : α → β)
    (correct : ∀ x, b.decode ρ (onSome x) = f (a.decode ρ x)) :
    b.decode ρ (rawOptionCases value onNone onSome) =
      (a.option.decode ρ value).elim (b.decode ρ onNone) f := by
  cases hv : value.eval ρ <;>
    simp [rawOptionCases, matchSum, Codec.decode, Codec.option, Expr.eval, hv,
      show ∀ x, b.equiv ((onSome x).eval ρ) = f (a.equiv (x.eval ρ)) from correct]

private theorem encode_decode_local (value : BoundedState.LocalStateData) :
    BoundedState.encodeLocal (BoundedState.decodeLocal value) = value := by
  cases value
  simp only [BoundedState.encodeLocal, BoundedState.decodeLocal]
  congr 1 <;> ext i hi <;>
    simp [BoundedState.NodeTable.ofFunction, BoundedState.NodeTable.get, Vector.get]

abbrev nodeStateCodec : Codec (NodeState Node Nat) :=
  localCodec.transport
    { toFun := BoundedState.decodeLocal
      invFun := BoundedState.encodeLocal
      left_inv := encode_decode_local
      right_inv := BoundedState.decodeLocal_encodeLocal }

structure Local where
  role : Expr roleCodec.ty
  currentTerm : Expr .nat
  log : Expr logCodec.ty
  commitIndex : Expr .nat
  sentIndex : Expr (nodeTableCodec Codec.nat).ty
  matchIndex : Expr (nodeTableCodec Codec.nat).ty
  isNewFollower : Expr .bool
  votedFor : Expr nodeCodec.option.ty
  votesGranted : Expr nodeSetCodec.ty
  preVotesGranted : Expr nodeSetCodec.ty
  membershipState : Expr membershipCodec.ty
  retirementIndex : Expr Codec.nat.option.ty
  retirementCommittableIndex : Expr Codec.nat.option.ty
  retiredCommittedIndex : Expr Codec.nat.option.ty

def Local.unpack (value : Expr nodeStateCodec.ty) : Local :=
  let t1 := Expr.second value
  let t2 := Expr.second t1
  let t3 := Expr.second t2
  let t4 := Expr.second t3
  let t5 := Expr.second t4
  let t6 := Expr.second t5
  let t7 := Expr.second t6
  let t8 := Expr.second t7
  let t9 := Expr.second t8
  let t10 := Expr.second t9
  let t11 := Expr.second t10
  let t12 := Expr.second t11
  ⟨Expr.first value, Expr.first t1, Expr.first t2, Expr.first t3,
    Expr.first t4, Expr.first t5, Expr.first t6, Expr.first t7, Expr.first t8,
    Expr.first t9, Expr.first t10, Expr.first t11, Expr.first t12, Expr.second t12⟩

def Local.pack (value : Local) : Expr nodeStateCodec.ty :=
  .pair value.role <| .pair value.currentTerm <| .pair value.log <| .pair value.commitIndex <|
    .pair value.sentIndex <| .pair value.matchIndex <| .pair value.isNewFollower <|
    .pair value.votedFor <| .pair value.votesGranted <| .pair value.preVotesGranted <|
    .pair value.membershipState <| .pair value.retirementIndex <|
    .pair value.retirementCommittableIndex value.retiredCommittedIndex

def Local.eval (ρ : Assignment) (value : Local) : NodeState Node Nat :=
  { role := roleCodec.decode ρ value.role
    currentTerm := value.currentTerm.eval ρ
    log := logCodec.decode ρ value.log
    commitIndex := value.commitIndex.eval ρ
    sentIndex := ((nodeTableCodec Codec.nat).decode ρ value.sentIndex).get
    matchIndex := ((nodeTableCodec Codec.nat).decode ρ value.matchIndex).get
    isNewFollower := value.isNewFollower.eval ρ
    votedFor := nodeCodec.option.decode ρ value.votedFor
    votesGranted := nodeSetCodec.decode ρ value.votesGranted
    preVotesGranted := nodeSetCodec.decode ρ value.preVotesGranted
    membershipState := membershipCodec.decode ρ value.membershipState
    retirementIndex := Codec.nat.option.decode ρ value.retirementIndex
    retirementCommittableIndex := Codec.nat.option.decode ρ value.retirementCommittableIndex
    retiredCommittedIndex := Codec.nat.option.decode ρ value.retiredCommittedIndex }

@[simp] theorem Local.pack_correct (ρ : Assignment) (value : Local) :
    nodeStateCodec.decode ρ value.pack = value.eval ρ := rfl

@[simp] theorem Local.unpack_correct (ρ : Assignment) (value : Expr nodeStateCodec.ty) :
    (Local.unpack value).eval ρ = nodeStateCodec.decode ρ value := by
  simp only [Local.unpack, Local.eval, Codec.decode, Expr.first_correct, Expr.second_correct]
  rfl

def maximum (left right : Expr .nat) : Expr .nat :=
  .ite (.lt left right) right left

def minimum (left right : Expr .nat) : Expr .nat :=
  .ite (.lt left right) left right

@[simp] theorem maximum_correct (ρ : Assignment) (left right : Expr .nat) :
    (maximum left right).eval ρ = max (left.eval ρ) (right.eval ρ) := by
  have arithmetic (a b : Nat) : (if a < b then b else a) = max a b := by
    split_ifs with h
    · exact (Nat.max_eq_right (Nat.le_of_lt h)).symm
    · exact (Nat.max_eq_left (Nat.le_of_not_gt h)).symm
  simpa only [maximum, Expr.eval, decide_eq_true_eq] using arithmetic (left.eval ρ) (right.eval ρ)

@[simp] theorem minimum_correct (ρ : Assignment) (left right : Expr .nat) :
    (minimum left right).eval ρ = min (left.eval ρ) (right.eval ρ) := by
  have arithmetic (a b : Nat) : (if a < b then a else b) = min a b := by
    split_ifs with h
    · exact (Nat.min_eq_left (Nat.le_of_lt h)).symm
    · exact (Nat.min_eq_right (Nat.le_of_not_gt h)).symm
  simpa only [minimum, Expr.eval, decide_eq_true_eq] using arithmetic (left.eval ρ) (right.eval ρ)

def optionBind {α β : Type} (a : Codec α) (b : Codec β)
    (value : Expr a.option.ty) (f : Expr a.ty -> Expr b.option.ty) : Expr b.option.ty :=
  rawOptionCases value (.inl .unit) f

theorem optionBind_correct {α β : Type} (a : Codec α) (b : Codec β)
    (ρ : Assignment) (value : Expr a.option.ty) (f : Expr a.ty -> Expr b.option.ty)
    (g : α -> Option β) (correct : ∀ x, b.option.decode ρ (f x) = g (a.decode ρ x)) :
    b.option.decode ρ (optionBind a b value f) = (a.option.decode ρ value).bind g := by
  rw [optionBind, rawOptionCases_correct a b.option ρ _ _ f g correct]
  cases a.option.decode ρ value <;> rfl

def entryAt (log : Expr logCodec.ty) (index : Expr .nat) : Expr entryCodec.option.ty :=
  .ite (.eq index (.nat 0)) (.inl .unit) (.get? log (.sub index (.nat 1)))

@[simp] theorem entryAt_correct (ρ : Assignment) (log : Expr logCodec.ty) (index : Expr .nat) :
    entryCodec.option.decode ρ (entryAt log index) =
      entryAt? (logCodec.decode ρ log) (index.eval ρ) := by
  by_cases zero : index.eval ρ = 0
  · simp [entryAt, decode_choose, Expr.eval, zero, entryAt?, Codec.decode, Codec.option]
  · simp only [entryAt, decode_choose, Expr.eval, zero, decide_false, Bool.false_eq_true,
      if_false, entryAt?]
    let values : List entryCodec.ty.Value := log.eval ρ
    let i : Nat := index.eval ρ
    dsimp [Codec.decode, Codec.option, logCodec, Codec.list, Expr.eval]
    rw [List.getElem?_map]
    cases h : values[i - 1]? <;> simp_all [values, i]

def termAt (log : Expr logCodec.ty) (index : Expr .nat) : Expr .nat :=
  rawOptionCases (entryAt log index) (.nat 0) Expr.fst

@[simp] theorem termAt_correct (ρ : Assignment) (log : Expr logCodec.ty) (index : Expr .nat) :
    (termAt log index).eval ρ = CCFRaft.termAt (logCodec.decode ρ log) (index.eval ρ) := by
  have h := rawOptionCases_correct entryCodec Codec.nat ρ (entryAt log index) (.nat 0)
    Expr.fst Entry.term (fun _ => rfl)
  change (termAt log index).eval ρ = _
  rw [termAt, show (rawOptionCases (entryAt log index) (.nat 0) Expr.fst).eval ρ = _ from h,
    entryAt_correct]
  unfold CCFRaft.termAt
  cases entryAt? (logCodec.decode ρ log) (index.eval ρ) <;> rfl

def isSignature (log : Expr logCodec.ty) (index : Expr .nat) : Expr .bool :=
  rawOptionCases (entryAt log index) (.bool false)
    (fun entry => .eq entry.snd (contentCodec.literal .signature))

@[simp] theorem isSignature_correct (ρ : Assignment) (log : Expr logCodec.ty)
    (index : Expr .nat) :
    (isSignature log index).eval ρ =
      isSignatureAt (logCodec.decode ρ log) (index.eval ρ) := by
  have h := rawOptionCases_correct entryCodec Codec.bool ρ (entryAt log index) (.bool false)
    (fun entry => Expr.eq entry.snd (contentCodec.literal .signature))
    (fun entry => decide (entry.content = .signature)) (by
      intro entry
      apply Bool.eq_iff_iff.mpr
      simpa [Codec.decode, Codec.prod, Codec.transport] using
        contentCodec.equal_correct ρ entry.snd (contentCodec.literal .signature))
  change (isSignature log index).eval ρ = _
  rw [isSignature, show (rawOptionCases (entryAt log index) (.bool false)
    (fun entry => Expr.eq entry.snd (contentCodec.literal .signature))).eval ρ = _ from h,
    entryAt_correct]
  unfold isSignatureAt
  cases entryAt? (logCodec.decode ρ log) (index.eval ρ) <;> rfl

def rangeFold {a : Ty} (capacity : Nat) (length : Expr .nat)
    (step : Expr a -> Expr .nat -> Expr a) (base : Expr a) : Expr a :=
  foldl step capacity base (.take length (.ofList ((List.range capacity).map Expr.nat)))

theorem rangeFold_correct {A : Type} (a : Codec A) (ρ : Assignment)
    (capacity : Nat) (length : Expr .nat) (step : Expr a.ty -> Expr .nat -> Expr a.ty)
    (base : Expr a.ty) (f : A -> Nat -> A)
    (correct : ∀ acc index, a.decode ρ (step acc index) = f (a.decode ρ acc) (index.eval ρ))
    (bound : length.eval ρ ≤ capacity) :
    a.decode ρ (rangeFold capacity length step base) =
      (List.range (length.eval ρ)).foldl f (a.decode ρ base) := by
  have h := foldl_correct ρ id a.equiv step f correct capacity base
    (.take length (.ofList ((List.range capacity).map Expr.nat))) (by
      simp [Expr.eval, List.map_map, Function.comp_def])
  simpa [rangeFold, Codec.decode, Expr.eval, List.map_map, Function.comp_def,
    List.take_range, Nat.min_eq_left bound] using h

def maxCommittable (capacity : Nat) (log : Expr logCodec.ty) : Expr .nat :=
  rangeFold (capacity + 1) (.add log.length (.nat 1))
    (fun best index => .ite (isSignature log index) (maximum best index) best) (.nat 0)

@[simp] theorem maxCommittable_correct (ρ : Assignment) (capacity : Nat)
    (log : Expr logCodec.ty) (bound : (logCodec.decode ρ log).length ≤ capacity) :
    (maxCommittable capacity log).eval ρ = maxCommittableIndex (logCodec.decode ρ log) := by
  have h := rangeFold_correct Codec.nat ρ (capacity + 1) (.add log.length (.nat 1))
    (fun best index => .ite (isSignature log index) (maximum best index) best)
    (.nat 0) (fun best index =>
      if isSignatureAt (logCodec.decode ρ log) index then max best index else best) (by
      intro best index
      change (Expr.ite (isSignature log index) (maximum best index) best).eval ρ = _
      simp only [Expr.eval, isSignature_correct, maximum_correct]
      rfl) (by
      simp [Expr.eval, Codec.decode, Codec.list] at bound ⊢
      omega)
  simpa [maxCommittable, maxCommittableIndex, Codec.decode, Codec.nat,
    Codec.list, Expr.eval] using h

end CCFRaft.SymbolicReceive
