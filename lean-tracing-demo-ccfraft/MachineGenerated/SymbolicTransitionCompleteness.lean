-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionAdapter
import MachineGenerated.SymbolicTransitionInputs

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel BoundedSymbolicTrace

theorem freshEntry_complete_preserving (bounds : BoundedState.Bounds) (start : Nat)
    (state : State Node Nat) (within : BoundedState.WithinBounds bounds state) (base : Assignment) :
    ∃ ρ : Assignment,
      evalEntry bounds ρ (freshEntry bounds start) = state ∧
        ∀ index, index < start ∨ start + entryWidth bounds ≤ index → ρ index = base index := by
  let value := (stateCodec bounds.transactionCount).equiv.symm (importEntry bounds state)
  obtain ⟨witness, realizes⟩ := realizes_exists (capacities bounds)
    (stateCodec bounds.transactionCount).ty start value (withinBounds_fits bounds state within)
  let ρ : Assignment := fun index =>
    if start ≤ index ∧ index < start + entryWidth bounds then witness index else base index
  have framed := realizes_congr (capacities bounds) (stateCodec bounds.transactionCount).ty
    start value witness ρ (fun index lo hi => by
      simp only [ρ, entryWidth, if_pos (And.intro lo hi)]) realizes
  have evaluated := fresh_realizes (capacities bounds) ρ _ start value framed
  refine ⟨ρ, ?_, ?_⟩
  · simp [evalEntry, freshEntry, Codec.decode, evaluated, value, importEntry_toData bounds state within]
  · intro index outside
    have absent : ¬(start ≤ index ∧ index < start + entryWidth bounds) := by omega
    simp only [ρ, if_neg absent]

theorem encode_complete_model (bounds : BoundedState.Bounds) (receive : ReceiveAdapter bounds)
    (unknownCount : Nat) (instructions : List Instruction) (base : Assignment) (state : State Node Nat)
    (inScope : traceInputsAtOrAfter (entryWidth bounds) instructions = true)
    (domains : TransactionDomains bounds unknownCount base)
    (follows : Follows bounds base state instructions) :
    ∃ ρ : Assignment,
      (∀ index, entryWidth bounds ≤ index → ρ index = base index) ∧
      evalEntry bounds ρ (freshEntry bounds) = state ∧
      Trace.Holds ρ (SymbolicTraceEncoding.encode bounds (adapter bounds receive)
        unknownCount (freshEntry bounds) instructions) := by
  obtain ⟨ρ, decoded, outside⟩ := freshEntry_complete_preserving bounds 0 state
    (SymbolicTraceEncoding.follows_within bounds base state instructions follows) base
  have same : ∀ index, entryWidth bounds ≤ index → ρ index = base index :=
    fun index lower => outside index (Or.inr (by simpa only [Nat.zero_add] using lower))
  refine ⟨ρ, same, decoded, ?_⟩
  rw [SymbolicTraceEncoding.encode_holds_correct]
  constructor
  · intro index below
    rw [same _ (Nat.le_add_right _ _)]
    exact domains index below
  · rw [decoded]
    exact (follows_inputsAtOrAfter bounds (entryWidth bounds) instructions state ρ base same inScope).mpr follows

theorem encode_satisfiable_iff (bounds : BoundedState.Bounds) (receive : ReceiveAdapter bounds)
    (unknownCount : Nat) (instructions : List Instruction) (base : Assignment)
    (inScope : traceInputsAtOrAfter (entryWidth bounds) instructions = true) :
    (∃ ρ : Assignment,
      (∀ index, entryWidth bounds ≤ index → ρ index = base index) ∧
      Trace.Holds ρ (SymbolicTraceEncoding.encode bounds (adapter bounds receive)
        unknownCount (freshEntry bounds) instructions)) ↔
      TransactionDomains bounds unknownCount base ∧ ∃ state : State Node Nat,
        Follows bounds base state instructions := by
  constructor
  · rintro ⟨ρ, same, accepted⟩
    obtain ⟨domains, follows⟩ := (SymbolicTraceEncoding.encode_holds_correct bounds
      (adapter bounds receive) unknownCount (freshEntry bounds) instructions ρ).mp accepted
    constructor
    · intro index below
      rw [← same _ (Nat.le_add_right _ _)]
      exact domains index below
    · exact ⟨_, (follows_inputsAtOrAfter bounds (entryWidth bounds) instructions
        (evalEntry bounds ρ (freshEntry bounds)) ρ base same inScope).mp follows⟩
  · rintro ⟨domains, state, follows⟩
    obtain ⟨ρ, same, _, accepted⟩ :=
      encode_complete_model bounds receive unknownCount instructions base state inScope domains follows
    exact ⟨ρ, same, accepted⟩

theorem checkedEncoder_satisfiable_iff (bounds : BoundedState.Bounds)
    (unknownCount : Nat) (instructions : List Instruction) (base : Assignment)
    (inScope : traceInputsAtOrAfter (entryWidth bounds) instructions = true) :
    (∃ ρ : Assignment,
      (∀ index, entryWidth bounds ≤ index → ρ index = base index) ∧
      Trace.Holds ρ (checkedEncoder.val bounds unknownCount (freshEntry bounds) instructions)) ↔
      TransactionDomains bounds unknownCount base ∧ ∃ state : State Node Nat,
        Follows bounds base state instructions :=
  encode_satisfiable_iff bounds (modelReceive bounds) unknownCount instructions base inScope

end CCFRaft.SymbolicTransition
