-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicEntry

set_option autoImplicit false

namespace CCFRaft.SymbolicModel

open Symbolic

def entryWithin (bounds : BoundedState.Bounds) (e : Expr entryCodec.ty) : Expr .bool :=
  .and (.lt e.fst (.nat bounds.termCount))
    (matchSum e.snd (fun tx => .lt tx (.nat bounds.transactionCount)) (fun _ => .bool true))

theorem entryWithin_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (e : Expr entryCodec.ty) :
    (entryWithin bounds e).eval ρ = true ↔
      BoundedState.EntryWithin bounds (entryCodec.decode ρ e) := by
  generalize he : e.eval ρ = v
  rcases v with ⟨term, tx | (_ | (ns | ns))⟩ <;>
    simp [entryWithin, matchSum, Expr.eval, Codec.decode, he,
      Codec.transport, Codec.sum, Codec.prod, Codec.nat, BoundedState.EntryWithin]

def logWithin (bounds : BoundedState.Bounds) (log : Expr logCodec.ty) : Expr .bool :=
  Container.boundedAll bounds.logCapacity (entryWithin bounds) log

theorem logWithin_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (log : Expr logCodec.ty) :
    (logWithin bounds log).eval ρ = true ↔
      (logCodec.decode ρ log).length ≤ bounds.logCapacity ∧
        (logCodec.decode ρ log).Forall (BoundedState.EntryWithin bounds) := by
  have h (e : Expr entryCodec.ty) :
      (entryWithin bounds e).eval ρ =
        decide (BoundedState.EntryWithin bounds (entryCodec.equiv (e.eval ρ))) := by
    apply Bool.eq_iff_iff.mpr
    simpa [Codec.decode] using entryWithin_correct bounds ρ e
  simpa [logWithin, Codec.decode, Codec.list, List.forall_iff_forall_mem] using
    Container.boundedAll_correct ρ bounds.logCapacity (entryWithin bounds)
      (fun e => decide (BoundedState.EntryWithin bounds (entryCodec.equiv e))) h log

def messageWithin (bounds : BoundedState.Bounds) (e : Expr messageCodec.ty) : Expr .bool :=
  matchSum e (fun r =>
    .and (.lt r.fst (.nat bounds.termCount))
      (.and (.lt r.snd.fst (.nat bounds.indexCount))
        (.and (.lt r.snd.snd.fst (.nat bounds.termCount))
          (.and (logWithin bounds r.snd.snd.snd.fst)
            (.lt r.snd.snd.snd.snd.fst (.nat bounds.indexCount)))))) fun e =>
    matchSum e (fun r =>
      .and (.lt r.fst (.nat bounds.termCount))
        (.lt r.snd.snd.fst (.nat bounds.indexCount))) fun e =>
      matchSum e (fun r =>
        .and (.lt r.fst (.nat bounds.termCount))
          (.and (.lt r.snd.fst (.nat bounds.termCount))
            (.lt r.snd.snd.fst (.nat bounds.indexCount)))) fun e =>
        matchSum e (fun r => .lt r.fst (.nat bounds.termCount)) fun e =>
          matchSum e (fun r =>
            .and (.lt r.fst (.nat bounds.termCount))
              (.and (.lt r.snd.fst (.nat bounds.termCount))
                (.lt r.snd.snd.fst (.nat bounds.indexCount)))) fun e =>
            matchSum e (fun r => .lt r.fst (.nat bounds.termCount))
              (fun r => .lt r.fst (.nat bounds.termCount))

theorem messageWithin_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (e : Expr messageCodec.ty) :
    (messageWithin bounds e).eval ρ = true ↔
      BoundedState.MessageWithin bounds (messageCodec.decode ρ e) := by
  generalize he : e.eval ρ = v
  rcases v with r | (r | (r | (r | (r | (r | r))))) <;>
    simp [messageWithin, matchSum, Expr.eval, logWithin_correct bounds ρ, Codec.decode, he,
      Codec.transport, Codec.sum, Codec.prod, Codec.nat, Codec.list, BoundedState.MessageWithin,
      and_assoc]

def queueWithin (bounds : BoundedState.Bounds) (queue : Expr queueCodec.ty) : Expr .bool :=
  Container.boundedAll bounds.queueCapacity (messageWithin bounds) queue

theorem queueWithin_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (queue : Expr queueCodec.ty) :
    (queueWithin bounds queue).eval ρ = true ↔
      (queueCodec.decode ρ queue).length ≤ bounds.queueCapacity ∧
        (queueCodec.decode ρ queue).Forall (BoundedState.MessageWithin bounds) := by
  have h (e : Expr messageCodec.ty) :
      (messageWithin bounds e).eval ρ =
        decide (BoundedState.MessageWithin bounds (messageCodec.equiv (e.eval ρ))) := by
    apply Bool.eq_iff_iff.mpr
    simpa [Codec.decode] using messageWithin_correct bounds ρ e
  simpa [queueWithin, Codec.decode, Codec.list, List.forall_iff_forall_mem] using
    Container.boundedAll_correct ρ bounds.queueCapacity (messageWithin bounds)
      (fun e => decide (BoundedState.MessageWithin bounds (messageCodec.equiv e))) h queue

def optionalIndexWithin (bounds : BoundedState.Bounds) (e : Expr Codec.nat.option.ty) :
    Expr .bool :=
  matchSum e (fun _ => .bool true) (fun i => .lt i (.nat bounds.indexCount))

theorem optionalIndexWithin_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (e : Expr Codec.nat.option.ty) :
    (optionalIndexWithin bounds e).eval ρ = true ↔
      BoundedState.OptionalIndexWithin bounds (Codec.nat.option.decode ρ e) := by
  cases he : e.eval ρ <;>
    simp [optionalIndexWithin, matchSum, Expr.eval, he, Codec.decode, Codec.option,
      Codec.nat, BoundedState.OptionalIndexWithin]

def indicesWithin (bounds : BoundedState.Bounds)
    (e : Expr (nodeTableCodec Codec.nat).ty) : Expr .bool :=
  tableAll (fun i => .lt i (.nat bounds.indexCount)) e

theorem indicesWithin_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (e : Expr (nodeTableCodec Codec.nat).ty) :
    (indicesWithin bounds e).eval ρ = true ↔
      ∀ node, ((nodeTableCodec Codec.nat).decode ρ e).get node < bounds.indexCount := by
  have h := tableAll_correct ρ (fun i => Expr.lt i (.nat bounds.indexCount))
    (fun i => i < bounds.indexCount) e (by intro i; simp [Expr.eval])
  simpa [indicesWithin, Codec.decode, nodeTableCodec, Codec.table, Codec.transport,
    Codec.nat, BoundedState.NodeTable.get] using h

def localWithin (bounds : BoundedState.Bounds) (e : Expr localCodec.ty) : Expr .bool :=
  let retirement := e.snd.snd.snd.snd.snd.snd.snd.snd.snd.snd.snd
  .and (.lt e.snd.fst (.nat bounds.termCount))
    (.and (logWithin bounds e.snd.snd.fst)
      (.and (.lt e.snd.snd.snd.fst (.nat bounds.indexCount))
        (.and (indicesWithin bounds e.snd.snd.snd.snd.fst)
          (.and (indicesWithin bounds e.snd.snd.snd.snd.snd.fst)
            (.and (optionalIndexWithin bounds retirement.fst)
              (.and (optionalIndexWithin bounds retirement.snd.fst)
                (optionalIndexWithin bounds retirement.snd.snd)))))))

theorem localWithin_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (e : Expr localCodec.ty) :
    (localWithin bounds e).eval ρ = true ↔
      BoundedState.LocalDataWithin bounds (localCodec.decode ρ e) := by
  simp [localWithin, Expr.eval, logWithin_correct bounds ρ, indicesWithin_correct bounds ρ,
    optionalIndexWithin_correct bounds ρ, Codec.decode, Codec.transport, Codec.prod, Codec.nat,
    BoundedState.LocalDataWithin, and_assoc]

def optionalLocalWithin (bounds : BoundedState.Bounds) (e : Expr localCodec.option.ty) :
    Expr .bool :=
  matchSum e (fun _ => .bool true) (localWithin bounds)

theorem optionalLocalWithin_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (e : Expr localCodec.option.ty) :
    (optionalLocalWithin bounds e).eval ρ = true ↔
      BoundedState.OptionalLocalDataWithin bounds (localCodec.option.decode ρ e) := by
  cases he : e.eval ρ <;>
    simp [optionalLocalWithin, matchSum, Expr.eval, localWithin_correct bounds ρ,
      Codec.decode, Codec.option, he, BoundedState.OptionalLocalDataWithin]

theorem nodeTableAll_correct {α : Type} (c : Codec α) (ρ : Assignment)
    (p : Expr c.ty → Expr .bool) (q : α → Prop)
    (correct : ∀ x, (p x).eval ρ = true ↔ q (c.decode ρ x))
    (e : Expr (nodeTableCodec c).ty) :
    (tableAll p e).eval ρ = true ↔ ∀ node, q (((nodeTableCodec c).decode ρ e).get node) := by
  have h := tableAll_correct ρ p (fun x => q (c.equiv x)) e correct
  simpa [Codec.decode, nodeTableCodec, Codec.table, Codec.transport, BoundedState.NodeTable.get] using h

def stateWithin (bounds : BoundedState.Bounds)
    (e : Expr (stateCodec bounds.transactionCount).ty) : Expr .bool :=
  .and (tableAll (optionalLocalWithin bounds) e.fst)
    (tableAll (queueWithin bounds) e.snd.fst)

theorem stateWithin_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (e : Expr (stateCodec bounds.transactionCount).ty) :
    (stateWithin bounds e).eval ρ = true ↔
      BoundedState.WithinBounds bounds (evalEntry bounds ρ e) := by
  have hn := nodeTableAll_correct localCodec.option ρ (optionalLocalWithin bounds)
    (BoundedState.OptionalLocalDataWithin bounds) (optionalLocalWithin_correct bounds ρ) e.fst
  have hq := nodeTableAll_correct queueCodec ρ (queueWithin bounds)
    (fun q => q.length ≤ bounds.queueCapacity ∧ q.Forall (BoundedState.MessageWithin bounds))
    (queueWithin_correct bounds ρ) e.snd.fst
  have submitted : BoundedState.TransactionsWithin bounds
      ((stateCodec bounds.transactionCount).decode ρ e).toData.submittedTxIds := by
    intro tx htx
    obtain ⟨i, _, hi⟩ := Finset.mem_image.mp htx
    subst tx
    exact i.isLt
  rw [evalEntry_bounds_iff]
  simp only [stateWithin, Expr.eval, Bool.and_eq_true]
  rw [hn, hq]
  simp only [BoundedState.DataWithinBounds, submitted, and_true]
  rfl

end CCFRaft.SymbolicModel
