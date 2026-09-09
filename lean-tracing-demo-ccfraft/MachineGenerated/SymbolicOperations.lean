-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicModel

set_option autoImplicit false

namespace CCFRaft.SymbolicModel

open Symbolic

def messageSource (e : Expr messageCodec.ty) : Expr nodeCodec.ty :=
  matchSum e (fun r => r.snd.snd.snd.snd.snd.fst) fun e =>
    matchSum e (fun r => r.snd.snd.snd.fst) fun e =>
      matchSum e (fun r => r.snd.snd.snd.fst) fun e =>
        matchSum e (fun r => r.snd.snd.fst) fun e =>
          matchSum e (fun r => r.snd.snd.snd.fst) fun e =>
            matchSum e (fun r => r.snd.snd.fst) (fun r => r.snd.fst)

theorem messageSource_correct (ρ : Assignment) (e : Expr messageCodec.ty) :
    nodeCodec.decode ρ (messageSource e) = (messageCodec.decode ρ e).source := by
  generalize he : e.eval ρ = v
  rcases v with r | (r | (r | (r | (r | (r | r))))) <;>
    simp [messageSource, matchSum, Expr.eval, Codec.decode, he,
      Codec.transport, Codec.sum, Codec.prod, Message.source]

def logSlice (log : Expr logCodec.ty) (previous batchEnd : Expr .nat) : Expr logCodec.ty :=
  .take (.sub batchEnd previous) (.drop previous log)

theorem logSlice_correct (ρ : Assignment) (log : Expr logCodec.ty)
    (previous batchEnd : Expr .nat) :
    logCodec.decode ρ (logSlice log previous batchEnd) =
      messageEntries (logCodec.decode ρ log) (previous.eval ρ) (batchEnd.eval ρ) := by
  simp [logSlice, messageEntries, Codec.decode, Codec.list, Expr.eval,
    List.map_take, List.map_drop]

def queueEnqueue (queue : Expr queueCodec.ty) (message : Expr messageCodec.ty) :
    Expr queueCodec.ty := Container.enqueueNoDup queue message

theorem queueEnqueue_correct (ρ : Assignment) (queue : Expr queueCodec.ty)
    (message : Expr messageCodec.ty) :
    queueCodec.decode ρ (queueEnqueue queue message) =
      if messageCodec.decode ρ message ∈ queueCodec.decode ρ queue then
        queueCodec.decode ρ queue
      else queueCodec.decode ρ queue ++ [messageCodec.decode ρ message] := by
  simp [queueEnqueue, Container.enqueueNoDup, Expr.eval, Codec.decode, Codec.list]
  split <;> simp_all

def logPrefixEqual (n : Expr .nat) (a b : Expr logCodec.ty) : Expr .bool :=
  Container.prefixEqual n a b

theorem logPrefixEqual_correct (ρ : Assignment) (n : Expr .nat) (a b : Expr logCodec.ty) :
    (logPrefixEqual n a b).eval ρ = true ↔
      (logCodec.decode ρ a).take (n.eval ρ) = (logCodec.decode ρ b).take (n.eval ρ) := by
  have hinj : Function.Injective (List.map entryCodec.equiv) := logCodec.equiv.injective
  simp [logPrefixEqual, Container.prefixEqual, Expr.eval, Codec.decode, Codec.list,
    ← List.map_take, hinj.eq_iff]

private theorem takeFirstList_decode (source : Node) (xs : List messageCodec.ty.Value) :
    (match Container.takeFirstList
      (fun x => decide ((messageCodec.equiv x).source = source)) xs with
      | .inl _ => none
      | .inr (selected, rest) => some (messageCodec.equiv selected, rest.map messageCodec.equiv)) =
        takeFirstFrom source (xs.map messageCodec.equiv) := by
  induction xs with
  | nil => rfl
  | cons x xs ih =>
      by_cases h : (messageCodec.equiv x).source = source
      · simp [Container.takeFirstList, takeFirstFrom, h]
      · simp [Container.takeFirstList, takeFirstFrom, h]
        rw [← ih]
        cases Container.takeFirstList
          (fun x => decide ((messageCodec.equiv x).source = source)) xs <;> rfl

def queueTakeFirst (capacity : Nat) (source : Expr nodeCodec.ty) (queue : Expr queueCodec.ty) :
    Expr (messageCodec.prod queueCodec).option.ty :=
  Container.takeFirst (fun m => .eq (messageSource m) source) capacity queue

theorem queueTakeFirst_correct (ρ : Assignment) (capacity : Nat)
    (source : Expr nodeCodec.ty) (queue : Expr queueCodec.ty)
    (bound : (queueCodec.decode ρ queue).length ≤ capacity) :
    (messageCodec.prod queueCodec).option.decode ρ (queueTakeFirst capacity source queue) =
      takeFirstFrom (nodeCodec.decode ρ source) (queueCodec.decode ρ queue) := by
  have predicate (m : Expr messageCodec.ty) :
      (Expr.eq (messageSource m) source).eval ρ =
        decide ((messageCodec.equiv (m.eval ρ)).source = nodeCodec.decode ρ source) := by
    apply Bool.eq_iff_iff.mpr
    rw [nodeCodec.equal_correct, messageSource_correct, decide_eq_true_iff]
    rfl
  have hb : (queue.eval ρ : List messageCodec.ty.Value).length ≤ capacity := by
    simpa [Codec.decode, Codec.list] using bound
  have hc := Container.takeFirst_correct ρ
    (fun m => Expr.eq (messageSource m) source)
    (fun v => decide ((messageCodec.equiv v).source = nodeCodec.decode ρ source))
    predicate capacity queue hb
  simp only [queueTakeFirst, Codec.decode, Codec.option, Codec.prod, Codec.list]
  rw [hc]
  have hd := takeFirstList_decode (nodeCodec.decode ρ source) (queue.eval ρ)
  cases ht : Container.takeFirstList
    (fun v => decide ((messageCodec.equiv v).source = nodeCodec.decode ρ source)) (queue.eval ρ)
    with
  | inl _ =>
      rw [ht] at hd
      simpa only [Equiv.coe_fn_mk] using hd
  | inr pair =>
      rcases pair with ⟨selected, rest⟩
      rw [ht] at hd
      simpa only [Equiv.coe_fn_mk, Equiv.prodCongr_apply] using hd

end CCFRaft.SymbolicModel
