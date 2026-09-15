-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicReceiveProposal
import MachineGenerated.SymbolicReceiveNormalize

set_option autoImplicit false
set_option maxHeartbeats 200000

namespace CCFRaft.SymbolicReceive

open Symbolic SymbolicModel SymbolicTransition

theorem evalEntry_compact (bounds : BoundedState.Bounds) (ρ : Assignment)
    (value : Expr (stateCodec bounds.transactionCount).ty) :
    evalEntry bounds ρ (compact value) = evalEntry bounds ρ value := by
  simp only [evalEntry, decode_compact]

theorem local_log_bound (bounds : BoundedState.Bounds) (state : State Node Nat)
    (node : Node) (bound : BoundedState.WithinBounds bounds state) :
    (state.nodes node).log.length ≤ bounds.logCapacity := by
  have localBound := bound.1 node
  change ((state.node? node).getD freshNodeState).log.length ≤ _
  cases h : state.node? node with
  | none => simp [freshNodeState]
  | some value =>
    simp only [h, BoundedState.OptionalLocalWithin] at localBound
    exact localBound.2.1

theorem evalEntry_choose (bounds : BoundedState.Bounds) (ρ : Assignment) (c : Expr .bool)
    (yes no : Expr (stateCodec bounds.transactionCount).ty) :
    evalEntry bounds ρ (.ite c yes no) =
      if c.eval ρ then evalEntry bounds ρ yes else evalEntry bounds ρ no := by
  cases h : c.eval ρ <;> simp [evalEntry, Codec.decode, Expr.eval, h]

def writeQueue (transactions : Nat) (entry : Expr (stateCodec transactions).ty)
    (node : Expr nodeCodec.ty) (queue : Expr queueCodec.ty) : Expr (stateCodec transactions).ty :=
  .pair (Expr.first entry) (.pair
    (tableStore (Expr.first (Expr.second entry)) (finValue node) queue)
    (Expr.second (Expr.second entry)))

def writeQueueData {transactions : Nat} (entry : EntryData transactions)
    (node : Node) (queue : List (Message Node Nat)) : EntryData transactions :=
  (entry.1, Vector.ofFn (fun n => if node = n then queue else entry.2.1.get n), entry.2.2)

theorem writeQueue_decode (transactions : Nat) (ρ : Assignment)
    (entry : Expr (stateCodec transactions).ty) (node : Expr nodeCodec.ty) (queue : Expr queueCodec.ty) :
    (stateCodec transactions).decode ρ (writeQueue transactions entry node queue) =
      writeQueueData ((stateCodec transactions).decode ρ entry)
        (nodeCodec.decode ρ node) (queueCodec.decode ρ queue) := by
  apply Prod.ext
  · change (nodeTableCodec localCodec.option).decode ρ (Expr.first entry) = _
    simp only [Codec.decode, Expr.first_correct]
    rfl
  · apply Prod.ext
    · apply Vector.ext
      intro i hi
      have h := nodeTableStore_correct queueCodec ρ (Expr.first (Expr.second entry)) node queue ⟨i, hi⟩
      have before : (nodeTableCodec queueCodec).decode ρ (Expr.first (Expr.second entry)) =
          (nodeTableCodec queueCodec).decode ρ entry.snd.fst := by
        unfold Codec.decode
        congr 1
        simp [Expr.first_correct, Expr.second_correct, Expr.eval]
      rw [before] at h
      simpa only [writeQueueData, BoundedState.NodeTable.get, Vector.get, Vector.getElem_ofFn] using h
    · simp only [writeQueue, writeQueueData, Codec.decode, Expr.eval, Expr.second_correct]
      rfl

theorem writeQueueData_correct {transactions : Nat} (entry : EntryData transactions)
    (node : Node) (queue : List (Message Node Nat)) :
    BoundedState.decode (writeQueueData entry node queue).toData =
      { BoundedState.decode entry.toData with
        network := updateQueue (BoundedState.decode entry.toData).network node queue } := by
  apply state_ext
  · intro n
    simp only [State.node?, BoundedState.decode, BoundedState.Data.node?_decodeNodes]
    rfl
  · funext n
    change (Vector.ofFn (fun n => if node = n then queue else entry.2.1.get n)).get n = _
    simp [Vector.get_ofFn, updateQueue, Function.update_apply, eq_comm,
      BoundedState.decode, EntryData.toData]
  all_goals rfl

theorem writeQueue_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (queue : Expr queueCodec.ty) :
    evalEntry bounds ρ (writeQueue bounds.transactionCount entry node queue) =
      { evalEntry bounds ρ entry with
        network := updateQueue (evalEntry bounds ρ entry).network (nodeCodec.decode ρ node)
          (queueCodec.decode ρ queue) } := by
  unfold evalEntry
  rw [writeQueue_decode]
  exact writeQueueData_correct _ _ _

def writeCompleted (transactions : Nat) (entry : Expr (stateCodec transactions).ty)
    (node : Expr nodeCodec.ty) (nodes : Expr nodeSetCodec.ty) : Expr (stateCodec transactions).ty :=
  let tail1 := Expr.second entry
  let tail2 := Expr.second tail1
  let tail3 := Expr.second tail2
  let tail4 := Expr.second tail3
  .pair (Expr.first entry) (.pair (Expr.first tail1) (.pair (Expr.first tail2)
    (.pair (Expr.first tail3) (.pair (Expr.first tail4)
      (tableStore (Expr.second tail4) (finValue node) nodes)))))

def writeCompletedData {transactions : Nat} (entry : EntryData transactions)
    (node : Node) (nodes : Finset Node) : EntryData transactions :=
  (entry.1, entry.2.1, entry.2.2.1, entry.2.2.2.1, entry.2.2.2.2.1,
    Vector.ofFn (fun n => if node = n then nodes else entry.2.2.2.2.2.get n))

theorem writeCompleted_decode (transactions : Nat) (ρ : Assignment)
    (entry : Expr (stateCodec transactions).ty) (node : Expr nodeCodec.ty) (nodes : Expr nodeSetCodec.ty) :
    (stateCodec transactions).decode ρ (writeCompleted transactions entry node nodes) =
      writeCompletedData ((stateCodec transactions).decode ρ entry)
        (nodeCodec.decode ρ node) (nodeSetCodec.decode ρ nodes) := by
  apply Prod.ext
  · simp only [writeCompleted, writeCompletedData, Codec.decode, Expr.eval, Expr.first_correct]
    rfl
  · apply Prod.ext
    · simp only [writeCompleted, writeCompletedData, Codec.decode, Expr.eval, Expr.first_correct, Expr.second_correct]
      rfl
    · apply Prod.ext
      · simp only [writeCompleted, writeCompletedData, Codec.decode, Expr.eval, Expr.first_correct, Expr.second_correct]
        rfl
      · apply Prod.ext
        · simp only [writeCompleted, writeCompletedData, Codec.decode, Expr.eval, Expr.first_correct, Expr.second_correct]
          rfl
        · apply Prod.ext
          · simp only [writeCompleted, writeCompletedData, Codec.decode, Expr.eval, Expr.first_correct, Expr.second_correct]
            rfl
          · apply Vector.ext
            intro i hi
            have h := nodeTableStore_correct nodeSetCodec ρ
              (Expr.second (Expr.second (Expr.second (Expr.second (Expr.second entry))))) node nodes ⟨i, hi⟩
            have before : (nodeTableCodec nodeSetCodec).decode ρ
                (Expr.second (Expr.second (Expr.second (Expr.second (Expr.second entry))))) =
                (nodeTableCodec nodeSetCodec).decode ρ entry.snd.snd.snd.snd.snd := by
              unfold Codec.decode
              congr 1
              simp [Expr.second_correct, Expr.eval]
            rw [before] at h
            simpa only [writeCompletedData, BoundedState.NodeTable.get, Vector.get, Vector.getElem_ofFn] using h

theorem writeCompletedData_correct {transactions : Nat} (entry : EntryData transactions)
    (node : Node) (nodes : Finset Node) :
    BoundedState.decode (writeCompletedData entry node nodes).toData =
      { BoundedState.decode entry.toData with
        retirementCompleted := Function.update (BoundedState.decode entry.toData).retirementCompleted node nodes } := by
  apply state_ext
  · intro n
    simp only [State.node?, BoundedState.decode, BoundedState.Data.node?_decodeNodes]
    rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · funext n
    change (Vector.ofFn (fun n => if node = n then nodes else entry.2.2.2.2.2.get n)).get n = _
    simp [Vector.get_ofFn, Function.update_apply, eq_comm, BoundedState.decode, EntryData.toData]

theorem writeCompleted_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (nodes : Expr nodeSetCodec.ty) :
    evalEntry bounds ρ (writeCompleted bounds.transactionCount entry node nodes) =
      { evalEntry bounds ρ entry with
        retirementCompleted := Function.update (evalEntry bounds ρ entry).retirementCompleted
          (nodeCodec.decode ρ node) (nodeSetCodec.decode ρ nodes) } := by
  unfold evalEntry
  rw [writeCompleted_decode]
  exact writeCompletedData_correct _ _ _

def enqueue (transactions : Nat) (entry : Expr (stateCodec transactions).ty)
    (message : Expr messageCodec.ty) : Expr (stateCodec transactions).ty :=
  let destination := messageDestination message
  let queue := entryQueue transactions entry destination
  writeQueue transactions entry destination (.append queue (.cons message .nil))

theorem enqueue_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (message : Expr messageCodec.ty) :
    evalEntry bounds ρ (enqueue bounds.transactionCount entry message) =
      { evalEntry bounds ρ entry with
        network := CCFRaft.enqueue (evalEntry bounds ρ entry).network (messageCodec.decode ρ message) } := by
  have appended (queue : Expr queueCodec.ty) :
      queueCodec.decode ρ (.append queue (.cons message .nil)) =
        queueCodec.decode ρ queue ++ [messageCodec.decode ρ message] := by
    simp [Codec.decode, Codec.list, Expr.eval]
  simp only [enqueue, writeQueue_correct, appended,
    entryQueue_correct bounds ρ, messageDestination_correct]
  generalize evalEntry bounds ρ entry = state
  rfl

def evalOptional (bounds : BoundedState.Bounds) (ρ : Assignment)
    (value : Expr (stateCodec bounds.transactionCount).option.ty) : Option (State Node Nat) :=
  ((stateCodec bounds.transactionCount).option.decode ρ value).map
    (fun data => BoundedState.decode data.toData)

@[simp] theorem evalOptional_none (bounds : BoundedState.Bounds) (ρ : Assignment) :
    evalOptional bounds ρ (.inl .unit) = none := rfl

@[simp] theorem evalOptional_some (bounds : BoundedState.Bounds) (ρ : Assignment)
    (value : Expr (stateCodec bounds.transactionCount).ty) :
    evalOptional bounds ρ (.inr value) = some (evalEntry bounds ρ value) := rfl

theorem evalOptional_choose (bounds : BoundedState.Bounds) (ρ : Assignment) (condition : Expr .bool)
    (yes no : Expr (stateCodec bounds.transactionCount).option.ty) :
    evalOptional bounds ρ (.ite condition yes no) =
      if condition.eval ρ then evalOptional bounds ρ yes else evalOptional bounds ρ no := by
  cases h : condition.eval ρ <;> simp [evalOptional, Codec.decode, Expr.eval, h]

def chooseOptionRaw {A : Type} (c : Codec A) {b : Ty} (value : Expr c.option.ty)
    (onNone : Expr b) (onSome : Expr c.ty → Expr b) : Expr b :=
  rawOptionCases value onNone onSome

theorem chooseOptionRaw_correct {A B : Type} (c : Codec A) {b : Ty}
    (decode : b.Value → B) (ρ : Assignment) (value : Expr c.option.ty)
    (onNone : Expr b) (onSome : Expr c.ty → Expr b) (f : A → B)
    (correct : ∀ x, c.option.decode ρ value = some (c.decode ρ x) →
      decode ((onSome x).eval ρ) = f (c.decode ρ x)) :
    decode ((chooseOptionRaw c value onNone onSome).eval ρ) =
      (c.option.decode ρ value).elim (decode (onNone.eval ρ)) f := by
  cases hv : value.eval ρ with
  | inl unit =>
    simp [chooseOptionRaw, rawOptionCases, matchSum, Codec.decode, Codec.option, Expr.eval, hv]
  | inr x =>
    have hx : c.option.decode ρ value =
        some (c.decode ρ (Expr.rightD value (defaultExpr c.ty))) := by
      simp [Codec.decode, Codec.option, Expr.eval, hv]
    have h := correct (Expr.rightD value (defaultExpr c.ty)) hx
    simpa [chooseOptionRaw, rawOptionCases, matchSum, Codec.decode, Codec.option, Expr.eval, hv] using h

def chooseOption {A : Type} (c : Codec A) {b : Ty} (value : Expr c.option.ty)
    (onNone : Expr b) (onSome : Expr c.ty → Expr b) : Expr b :=
  match value with
  | .inl _ => onNone
  | .inr x => onSome x
  | value => chooseOptionRaw c value onNone onSome

theorem chooseOption_correct {A B : Type} (c : Codec A) {b : Ty}
    (decode : b.Value → B) (ρ : Assignment) (value : Expr c.option.ty)
    (onNone : Expr b) (onSome : Expr c.ty → Expr b) (f : A → B)
    (correct : ∀ x, c.option.decode ρ value = some (c.decode ρ x) →
      decode ((onSome x).eval ρ) = f (c.decode ρ x)) :
    decode ((chooseOption c value onNone onSome).eval ρ) =
      (c.option.decode ρ value).elim (decode (onNone.eval ρ)) f := by
  unfold chooseOption
  split
  · rfl
  · exact correct _ rfl
  · exact chooseOptionRaw_correct c decode ρ _ onNone onSome f correct

theorem evalOptional_cases {A : Type} (c : Codec A) (bounds : BoundedState.Bounds) (ρ : Assignment)
    (value : Expr c.option.ty) (onNone : Expr (stateCodec bounds.transactionCount).option.ty)
    (onSome : Expr c.ty → Expr (stateCodec bounds.transactionCount).option.ty)
    (f : A → Option (State Node Nat))
    (correct : ∀ x, c.option.decode ρ value = some (c.decode ρ x) →
      evalOptional bounds ρ (onSome x) = f (c.decode ρ x)) :
    evalOptional bounds ρ (chooseOption c value onNone onSome) =
      (c.option.decode ρ value).elim (evalOptional bounds ρ onNone) f :=
  chooseOption_correct c
    (fun raw => ((stateCodec bounds.transactionCount).option.equiv raw).map
      (fun data : EntryData bounds.transactionCount => BoundedState.decode data.toData))
    ρ value onNone onSome f correct

theorem evalEntry_cases {A : Type} (c : Codec A) (bounds : BoundedState.Bounds) (ρ : Assignment)
    (value : Expr c.option.ty) (onNone : Expr (stateCodec bounds.transactionCount).ty)
    (onSome : Expr c.ty → Expr (stateCodec bounds.transactionCount).ty)
    (f : A → State Node Nat)
    (correct : ∀ x, c.option.decode ρ value = some (c.decode ρ x) →
      evalEntry bounds ρ (onSome x) = f (c.decode ρ x)) :
    evalEntry bounds ρ (chooseOption c value onNone onSome) =
      (c.option.decode ρ value).elim (evalEntry bounds ρ onNone) f :=
  chooseOption_correct c
    (fun raw => BoundedState.decode ((stateCodec bounds.transactionCount).equiv raw).toData)
    ρ value onNone onSome f correct

end CCFRaft.SymbolicReceive
