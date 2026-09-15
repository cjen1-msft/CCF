-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import BoundedSymbolicTrace
import Shared.SymbolicEvalMemo

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel BoundedSymbolicTrace

def decodeMemo {A : Type} (codec : Codec A) (ρ : Assignment) (expression : Expr codec.ty) : A :=
  codec.equiv (expression.evalMemo ρ)

theorem decodeMemo_correct {A : Type} (codec : Codec A) (ρ : Assignment) (expression : Expr codec.ty) :
    decodeMemo codec ρ expression = codec.decode ρ expression := by
  simp only [decodeMemo, Expr.evalMemo_correct, Codec.decode]

def evalEntryMemoM (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) :
    StateM (Expr.EvaluationState ρ) (State Node Nat) := do
  let value ← entry.evalMemoM ρ
  return BoundedState.decode ((stateCodec bounds.transactionCount).equiv value).toData

theorem evalEntryMemoM_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (cache : Expr.EvaluationState ρ) :
    ((evalEntryMemoM bounds ρ entry).run cache).1 = evalEntry bounds ρ entry := by
  change BoundedState.decode ((stateCodec bounds.transactionCount).equiv
    ((entry.evalMemoM ρ).run cache).1).toData = _
  rw [Expr.evalMemoM_correct]
  rfl

def evalEntryMemo (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) : State Node Nat :=
  ((evalEntryMemoM bounds ρ entry).run {}).1

theorem evalEntryMemo_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) :
    evalEntryMemo bounds ρ entry = evalEntry bounds ρ entry :=
  evalEntryMemoM_correct bounds ρ entry {}

def evaluateActionMemo (ρ : Assignment) : SymbolicAction → Action Node Nat
  | .clientRequest node transaction => .clientRequest node (transaction.evalMemo ρ)
  | action => evaluateAction ρ action

theorem evaluateActionMemo_correct (ρ : Assignment) (action : SymbolicAction) :
    evaluateActionMemo ρ action = evaluateAction ρ action := by
  cases action <;> simp [evaluateActionMemo, evaluateAction, Expr.evalMemo_correct]

end CCFRaft.SymbolicTransition
