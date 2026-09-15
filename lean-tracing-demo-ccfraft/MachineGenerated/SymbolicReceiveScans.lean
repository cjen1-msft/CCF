-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicReceiveData

set_option autoImplicit false

namespace CCFRaft.SymbolicReceive

open Symbolic SymbolicModel SymbolicTransition

def rawConfigurationStep (index : Expr .nat) (entry : Expr entryCodec.ty)
    (rest : Expr configurationCodec.list.ty) : Expr configurationCodec.list.ty :=
  .append
    (matchSum entry.snd (fun _ => .nil) fun other =>
      matchSum other (fun _ => .nil) fun sets =>
        matchSum sets (fun nodes => .cons (.pair index nodes) .nil) (fun _ => .nil))
    rest

theorem rawConfigurationStep_correct (ρ : Assignment) (index : Expr .nat)
    (entry : Expr entryCodec.ty) (rest : Expr configurationCodec.list.ty) :
    configurationCodec.list.decode ρ (rawConfigurationStep index entry rest) =
      match (entryCodec.decode ρ entry).content with
      | .reconfiguration nodes => ⟨index.eval ρ, nodes⟩ :: configurationCodec.list.decode ρ rest
      | _ => configurationCodec.list.decode ρ rest := by
  have same : (rawConfigurationStep index entry rest).eval ρ =
      (configurationStep index entry rest).eval ρ := by
    simp only [rawConfigurationStep, configurationStep, Expr.eval, appendSequence_correct,
      Expr.normalize_correct]
  exact (congrArg configurationCodec.list.equiv same).trans
    (configurationStep_correct ρ index entry rest)

def rawConfigurationsFrom (capacity : Nat) (index : Expr .nat) (log : Expr logCodec.ty) :
    Expr configurationCodec.list.ty :=
  foldrFrom rawConfigurationStep .nil capacity index log

theorem rawConfigurationsFrom_correct (ρ : Assignment) (capacity : Nat)
    (index : Expr .nat) (log : Expr logCodec.ty)
    (bound : (logCodec.decode ρ log).length ≤ capacity) :
    configurationCodec.list.decode ρ (rawConfigurationsFrom capacity index log) =
      configurationsInLogFrom (index.eval ρ) (logCodec.decode ρ log) := by
  let f : Nat → Entry Node Nat → List (Configuration Node) → List (Configuration Node) :=
    fun i e acc => match e.content with | .reconfiguration ns => ⟨i, ns⟩ :: acc | _ => acc
  have h := foldrFrom_correct ρ entryCodec.equiv configurationCodec.list.equiv
    rawConfigurationStep (.nil : Expr configurationCodec.list.ty) f
    (rawConfigurationStep_correct ρ) capacity index log
    (by simpa [Codec.decode, Codec.list] using bound)
  have scan (xs : List (Entry Node Nat)) (i : Nat) :
      indexedFold f [] i xs = configurationsInLogFrom i xs := by
    induction xs generalizing i with
    | nil => rfl
    | cons e xs ih =>
      cases hc : e.content <;> simp [indexedFold, f, configurationsInLogFrom, ih, hc]
  simpa [rawConfigurationsFrom, Codec.decode, Codec.list, Expr.eval, scan] using h

end CCFRaft.SymbolicReceive
