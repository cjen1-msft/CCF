-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionConfiguration

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

def entryAtExpr (log : Expr logCodec.ty) (index : Expr .nat) : Expr entryCodec.option.ty :=
  .ite (.eq index (.nat 0)) (.inl .unit) (.get? log (.sub index (.nat 1)))

theorem entryAtExpr_correct (ρ : Assignment) (log : Expr logCodec.ty) (index : Expr .nat) :
    entryCodec.option.decode ρ (entryAtExpr log index) =
      entryAt? (logCodec.decode ρ log) (index.eval ρ) := by
  rw [entryAtExpr, decode_choose]
  by_cases hzero : index.eval ρ = 0
  · simp [Expr.eval, hzero, entryAt?, Codec.decode, Codec.option]
  · simp [Expr.eval, hzero, entryAt?, Codec.decode, Codec.list, Codec.option,
      List.getElem?_map]
    split <;> split at * <;> simp_all

def signatureAtExpr (log : Expr logCodec.ty) (index : Expr .nat) : Expr .bool :=
  optionCases (entryAtExpr log index) (.bool false)
    (fun entry => .eq entry.snd (contentCodec.literal .signature))

theorem signatureAtExpr_correct (ρ : Assignment) (log : Expr logCodec.ty) (index : Expr .nat) :
    (signatureAtExpr log index).eval ρ = isSignatureAt (logCodec.decode ρ log) (index.eval ρ) := by
  have step (entry : Expr entryCodec.ty) :
      Codec.bool.decode ρ (.eq entry.snd (contentCodec.literal .signature)) =
        decide ((entryCodec.decode ρ entry).content = .signature) := by
    apply Bool.eq_iff_iff.mpr
    change (Expr.eq entry.snd (contentCodec.literal .signature)).eval ρ = true ↔ _
    rw [contentCodec.equal_correct, Codec.decode_literal, decide_eq_true_iff]
    rfl
  have h := optionCases_correct entryCodec Codec.bool ρ (entryAtExpr log index) (.bool false)
    (fun entry => .eq entry.snd (contentCodec.literal .signature))
    (fun entry => decide (entry.content = .signature)) step
  rw [entryAtExpr_correct] at h
  change (signatureAtExpr log index).eval ρ = _ at h
  rw [h]
  unfold isSignatureAt
  cases entryAt? (logCodec.decode ρ log) (index.eval ρ) <;> rfl

def termAtExpr (log : Expr logCodec.ty) (index : Expr .nat) : Expr .nat :=
  optionCases (entryAtExpr log index) (.nat 0) Expr.fst

theorem termAtExpr_correct (ρ : Assignment) (log : Expr logCodec.ty) (index : Expr .nat) :
    (termAtExpr log index).eval ρ = termAt (logCodec.decode ρ log) (index.eval ρ) := by
  have h := optionCases_correct entryCodec Codec.nat ρ (entryAtExpr log index) (.nat 0)
    Expr.fst Entry.term (fun _ => rfl)
  rw [entryAtExpr_correct] at h
  change (termAtExpr log index).eval ρ = _ at h
  rw [h]
  unfold termAt
  cases entryAt? (logCodec.decode ρ log) (index.eval ρ) <;> rfl

def rangeExpr (capacity : Nat) (length : Expr .nat) : Expr Codec.nat.list.ty :=
  .take length (.ofList ((List.range capacity).map Expr.nat))

theorem rangeExpr_correct (ρ : Assignment) (capacity : Nat) (length : Expr .nat)
    (bound : length.eval ρ ≤ capacity) :
    (rangeExpr capacity length).eval ρ = List.range (length.eval ρ) := by
  simp [rangeExpr, Expr.eval, List.map_map, Function.comp_def]
  exact List.take_range.trans (congrArg List.range (Nat.min_eq_left bound))

def maximumExpr (a b : Expr .nat) : Expr .nat := .ite (.lt a b) b a

theorem maximumExpr_correct (ρ : Assignment) (a b : Expr .nat) :
    (maximumExpr a b).eval ρ = max (a.eval ρ) (b.eval ρ) := by
  by_cases h : a.eval ρ < b.eval ρ
  · simp [maximumExpr, Expr.eval, h, Nat.max_eq_right (Nat.le_of_lt h)]
  · simp [maximumExpr, Expr.eval, h, Nat.max_eq_left (Nat.le_of_not_gt h)]

def committableStep (log : Expr logCodec.ty) (best index : Expr .nat) : Expr .nat :=
  (Expr.ite (signatureAtExpr log index) (maximumExpr best index) best).normalizeMemo

theorem committableStep_correct (ρ : Assignment) (log : Expr logCodec.ty)
    (best index : Expr .nat) :
    (committableStep log best index).eval ρ =
      if isSignatureAt (logCodec.decode ρ log) (index.eval ρ) then
        max (best.eval ρ) (index.eval ρ) else best.eval ρ := by
  simp only [committableStep, Expr.normalizeMemo_correct, Expr.eval, signatureAtExpr_correct,
    maximumExpr_correct]

def maxCommittableExpr (capacity : Nat) (log : Expr logCodec.ty) : Expr .nat :=
  foldl (committableStep log) (capacity + 1) (.nat 0)
    (rangeExpr (capacity + 1) (.add log.length (.nat 1)))

theorem maxCommittableExpr_correct (ρ : Assignment) (capacity : Nat)
    (log : Expr logCodec.ty) (bound : (logCodec.decode ρ log).length ≤ capacity) :
    (maxCommittableExpr capacity log).eval ρ = maxCommittableIndex (logCodec.decode ρ log) := by
  have hb : (log.eval ρ).length + 1 ≤ capacity + 1 := by
    simpa [Codec.decode, Codec.list] using Nat.succ_le_succ bound
  have hr := rangeExpr_correct ρ (capacity + 1) (.add log.length (.nat 1)) hb
  have h := foldl_correct ρ (fun n : Nat => n) (fun n : Nat => n)
    (committableStep log)
    (fun best index => if isSignatureAt (logCodec.decode ρ log) index then max best index else best)
    (committableStep_correct ρ log) (capacity + 1) (.nat 0)
    (rangeExpr (capacity + 1) (.add log.length (.nat 1)))
    (by simpa [hr, Expr.eval] using hb)
  simpa [maxCommittableExpr, hr, maxCommittableIndex, Codec.decode, Codec.list, Expr.eval] using h

def retiredEntryNodes (entry : Expr entryCodec.ty) : Expr nodeSetCodec.ty :=
  compactCase entry.snd (fun _ => nodeSetCodec.literal ∅) fun other =>
    compactCase other (fun _ => nodeSetCodec.literal ∅) fun sets =>
      compactCase sets (fun _ => nodeSetCodec.literal ∅) id

theorem retiredEntryNodes_correct (ρ : Assignment) (entry : Expr entryCodec.ty) :
    nodeSetCodec.decode ρ (retiredEntryNodes entry) =
      match (entryCodec.decode ρ entry).content with
      | .retiredCommitted nodes => nodes
      | _ => ∅ := by
  generalize he : entry.eval ρ = value
  rcases value with ⟨term, tx | (_ | (nodes | nodes))⟩ <;>
    simp [retiredEntryNodes, compactCase, matchSum, Expr.normalizeMemo_correct, Expr.eval,
      Codec.decode, Codec.transport, Codec.prod, Codec.sum, he]
  all_goals exact nodeSetCodec.decode_literal ρ ∅

def committedRetiredStep (commit index : Expr .nat) (entry : Expr entryCodec.ty)
    (remaining : Expr nodeSetCodec.ty) : Expr nodeSetCodec.ty :=
  (setUnion (.ite (index.le commit) (retiredEntryNodes entry) (nodeSetCodec.literal ∅))
    remaining).normalizeMemo

theorem committedRetiredStep_correct (ρ : Assignment) (commit index : Expr .nat)
    (entry : Expr entryCodec.ty) (remaining : Expr nodeSetCodec.ty) :
    nodeSetCodec.decode ρ (committedRetiredStep commit index entry remaining) =
      if index.eval ρ ≤ commit.eval ρ then
        match (entryCodec.decode ρ entry).content with
        | .retiredCommitted nodes => nodes ∪ nodeSetCodec.decode ρ remaining
        | _ => nodeSetCodec.decode ρ remaining
      else nodeSetCodec.decode ρ remaining := by
  rw [committedRetiredStep, decode_normalizeMemo, setUnion_correct, decode_choose,
    retiredEntryNodes_correct, Codec.decode_literal]
  simp only [eval_le, decide_eq_true_eq]
  by_cases h : index.eval ρ ≤ commit.eval ρ <;>
    cases (entryCodec.decode ρ entry).content <;> simp [h]

def committedRetiredNodesExpr (capacity : Nat) (commit index : Expr .nat) (log : Expr logCodec.ty) :
    Expr nodeSetCodec.ty :=
  foldrFrom (committedRetiredStep commit) (nodeSetCodec.literal ∅) capacity index log

theorem committedRetiredNodesExpr_correct (ρ : Assignment) (capacity : Nat)
    (commit index : Expr .nat) (log : Expr logCodec.ty)
    (bound : (logCodec.decode ρ log).length ≤ capacity) :
    nodeSetCodec.decode ρ (committedRetiredNodesExpr capacity commit index log) =
      retiredCommittedNodesUpToFrom (commit.eval ρ) (index.eval ρ) (logCodec.decode ρ log) := by
  let f := fun i (entry : Entry Node Nat) (remaining : Finset Node) =>
    if i ≤ commit.eval ρ then
      match entry.content with | .retiredCommitted nodes => nodes ∪ remaining | _ => remaining
    else remaining
  have h := foldrFrom_correct ρ entryCodec.equiv nodeSetCodec.equiv
    (committedRetiredStep commit) (nodeSetCodec.literal ∅) f
    (committedRetiredStep_correct ρ commit) capacity index log
    (by simpa [Codec.decode, Codec.list] using bound)
  have scan (entries : List (Entry Node Nat)) (i : Nat) :
      indexedFold f ∅ i entries =
        retiredCommittedNodesUpToFrom (commit.eval ρ) i entries := by
    induction entries generalizing i with
    | nil => rfl
    | cons entry entries ih =>
        simp only [indexedFold, f, retiredCommittedNodesUpToFrom, ih]
        by_cases hle : i ≤ commit.eval ρ <;>
          cases entry.content <;> simp [hle]
  change nodeSetCodec.decode ρ (committedRetiredNodesExpr capacity commit index log) =
    indexedFold f (nodeSetCodec.decode ρ (nodeSetCodec.literal ∅)) (index.eval ρ)
      (logCodec.decode ρ log) at h
  simpa only [Codec.decode_literal, scan] using h

end CCFRaft.SymbolicTransition
