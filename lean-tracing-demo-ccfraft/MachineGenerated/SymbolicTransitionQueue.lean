-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionState

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

def queueTakeFirstById (capacity : Nat) (source : Expr nodeCodec.ty) (queue : Expr queueCodec.ty) :
    Expr (messageCodec.prod queueCodec).option.ty :=
  Container.takeFirst
    (fun message => .eq (finValue (messageSource message)) (finValue source)) capacity queue

theorem queueTakeFirstById_correct (ρ : Assignment) (capacity : Nat)
    (source : Expr nodeCodec.ty) (queue : Expr queueCodec.ty)
    (bound : (queueCodec.decode ρ queue).length ≤ capacity) :
    (messageCodec.prod queueCodec).option.decode ρ (queueTakeFirstById capacity source queue) =
      takeFirstFrom (nodeCodec.decode ρ source) (queueCodec.decode ρ queue) := by
  let p := fun v : messageCodec.ty.Value =>
    decide ((messageCodec.equiv v).source = nodeCodec.decode ρ source)
  have byId (message : Expr messageCodec.ty) :
      (Expr.eq (finValue (messageSource message)) (finValue source)).eval ρ = p (message.eval ρ) := by
    apply Bool.eq_iff_iff.mpr
    simp only [Expr.eval, finValue_correct, decide_eq_true_iff]
    change (nodeCodec.decode ρ (messageSource message)).val = (nodeCodec.decode ρ source).val ↔ _
    rw [Fin.val_inj, messageSource_correct]
    simp only [p, decide_eq_true_iff, Codec.decode]
  have byValue (message : Expr messageCodec.ty) :
      (Expr.eq (messageSource message) source).eval ρ = p (message.eval ρ) := by
    apply Bool.eq_iff_iff.mpr
    rw [nodeCodec.equal_correct, messageSource_correct]
    simp only [p, decide_eq_true_iff, Codec.decode]
  have hb : (queue.eval ρ).length ≤ capacity := by
    simpa [Codec.decode, Codec.list] using bound
  have hId := Container.takeFirst_correct ρ
    (fun message => Expr.eq (finValue (messageSource message)) (finValue source))
    p byId capacity queue hb
  have hValue := Container.takeFirst_correct ρ
    (fun message => Expr.eq (messageSource message) source)
    p byValue capacity queue hb
  have same : (queueTakeFirstById capacity source queue).eval ρ =
      (queueTakeFirst capacity source queue).eval ρ := hId.trans hValue.symm
  exact (congrArg (messageCodec.prod queueCodec).option.equiv same).trans
    (queueTakeFirst_correct ρ capacity source queue bound)

end CCFRaft.SymbolicTransition
