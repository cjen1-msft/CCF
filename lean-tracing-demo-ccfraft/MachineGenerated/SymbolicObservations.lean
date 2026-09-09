-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicOperations
import MachineGenerated.SymbolicEntry
import Shared.SymbolicFinite

set_option autoImplicit false

/-!
# Partial-observation integration

`entryQueue` accepts a symbolic node selector. `firstFromMatches` constrains the
first packet from a source, not any later matching packet. `appendRequestMatches`
exposes typed request fields without fixing omitted payloads.

`observe actual none` adds no constraint. An observed absent optional index is
`observe actual (some (Codec.nat.option.literal none))`. These are distinct.
`setMember` observes one submitted ID or one of the fifteen node-set bits.

The model encoder still needs configuration and retirement scans, signature
indices, set cardinality and quorum predicates, and node-state updates. It also
needs handler correspondence to `Enabled` and `next`, full bounds at each step,
and causal action-owned definitions. Printer sharing names are not causal names.
The raw-schema adapters and the bounded-state-to-`Fits` completeness bridge
remain outside this module. No unbounded completeness claim is made.
-/

namespace CCFRaft.SymbolicModel

open Symbolic

def messageDestination (e : Expr messageCodec.ty) : Expr nodeCodec.ty :=
  matchSum e (fun r => r.snd.snd.snd.snd.snd.snd) fun e =>
    matchSum e (fun r => r.snd.snd.snd.snd) fun e =>
      matchSum e (fun r => r.snd.snd.snd.snd) fun e =>
        matchSum e (fun r => r.snd.snd.snd) fun e =>
          matchSum e (fun r => r.snd.snd.snd.snd) fun e =>
            matchSum e (fun r => r.snd.snd.snd) (fun r => r.snd.snd)

theorem messageDestination_correct (ρ : Assignment) (e : Expr messageCodec.ty) :
    nodeCodec.decode ρ (messageDestination e) = (messageCodec.decode ρ e).destination := by
  generalize he : e.eval ρ = v
  rcases v with r | (r | (r | (r | (r | (r | r))))) <;>
    simp [messageDestination, matchSum, Expr.eval, Codec.decode, he,
      Codec.transport, Codec.sum, Codec.prod, Message.destination]

def messageTerm (e : Expr messageCodec.ty) : Expr .nat :=
  matchSum e Expr.fst fun e =>
    matchSum e Expr.fst fun e =>
      matchSum e Expr.fst fun e =>
        matchSum e Expr.fst fun e =>
          matchSum e Expr.fst fun e => matchSum e Expr.fst Expr.fst

theorem messageTerm_correct (ρ : Assignment) (e : Expr messageCodec.ty) :
    (messageTerm e).eval ρ = (messageCodec.decode ρ e).term := by
  generalize he : e.eval ρ = v
  rcases v with r | (r | (r | (r | (r | (r | r))))) <;>
    simp [messageTerm, matchSum, Expr.eval, Codec.decode, he,
      Codec.transport, Codec.sum, Codec.prod, Codec.nat, Message.term]

-- No observation means no equality, even for inactive payload fields.
def observe {a : Ty} (actual : Expr a) (expected : Option (Expr a)) : Expr .bool :=
  match expected with
  | none => .bool true
  | some value => .eq actual value

theorem observe_correct {a : Ty} (ρ : Assignment) (actual : Expr a)
    (expected : Option (Expr a)) :
    (observe actual expected).eval ρ = true ↔
      ∀ value ∈ expected, actual.eval ρ = value.eval ρ := by
  cases expected <;> simp [observe, Expr.eval]

def appendRequestMatches (message : Expr messageCodec.ty)
    (predicate : Expr appendRequestCodec.ty → Expr .bool) : Expr .bool :=
  matchSum message predicate (fun _ => .bool false)

theorem appendRequestMatches_correct (ρ : Assignment) (message : Expr messageCodec.ty)
    (predicate : Expr appendRequestCodec.ty → Expr .bool)
    (p : AppendEntriesRequest Node Nat → Prop)
    (correct : ∀ request, (predicate request).eval ρ = true ↔ p (appendRequestCodec.decode ρ request)) :
    (appendRequestMatches message predicate).eval ρ = true ↔
      ∃ request, messageCodec.decode ρ message = .appendEntriesRequest request ∧ p request := by
  cases hm : message.eval ρ with
  | inl request =>
      simp [appendRequestMatches, matchSum, Expr.eval, correct, Codec.decode, hm,
        Codec.transport, Codec.sum]
  | inr rest =>
      rcases rest with r | (r | (r | (r | (r | r)))) <;>
        simp [appendRequestMatches, matchSum, Expr.eval, Codec.decode, hm,
          Codec.transport, Codec.sum]

def firstFromMatches (capacity : Nat) (source : Expr nodeCodec.ty)
    (queue : Expr queueCodec.ty) (predicate : Expr messageCodec.ty → Expr .bool) : Expr .bool :=
  optionalTest (queueTakeFirst capacity source queue) (fun pair => predicate pair.fst)

theorem firstFromMatches_correct (ρ : Assignment) (capacity : Nat)
    (source : Expr nodeCodec.ty) (queue : Expr queueCodec.ty)
    (predicate : Expr messageCodec.ty → Expr .bool) (p : Message Node Nat → Prop)
    (correct : ∀ message, (predicate message).eval ρ = true ↔ p (messageCodec.decode ρ message))
    (bound : (queueCodec.decode ρ queue).length ≤ capacity) :
    (firstFromMatches capacity source queue predicate).eval ρ = true ↔
      ∃ message rest,
        takeFirstFrom (nodeCodec.decode ρ source) (queueCodec.decode ρ queue) =
          some (message, rest) ∧ p message := by
  have hp (pair : Expr (messageCodec.prod queueCodec).ty) :
      (predicate pair.fst).eval ρ = true ↔
        p (((messageCodec.prod queueCodec).decode ρ pair).1) := by
    simpa [Codec.decode, Codec.prod, Expr.eval] using correct pair.fst
  rw [firstFromMatches, optionalTest_correct (messageCodec.prod queueCodec)
    ρ _ _ (fun pair => p pair.1) hp, queueTakeFirst_correct ρ capacity source queue bound]
  constructor
  · rintro ⟨⟨m, rest⟩, h, hp⟩
    exact ⟨m, rest, h, hp⟩
  · rintro ⟨m, rest, h, hp⟩
    exact ⟨(m, rest), h, hp⟩

def entryQueue (transactions : Nat) (e : Expr (stateCodec transactions).ty)
    (node : Expr nodeCodec.ty) : Expr queueCodec.ty :=
  tableSelect e.snd.fst node

theorem entryQueue_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (e : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    queueCodec.decode ρ (entryQueue bounds.transactionCount e node) =
      (evalEntry bounds ρ e).network (nodeCodec.decode ρ node) := by
  simp [entryQueue, tableSelect_correct, evalEntry, EntryData.toData, BoundedState.decode,
    Codec.decode, Codec.prod, nodeTableCodec, Codec.table, Codec.transport,
    BoundedState.NodeTable.get, Codec.fin, Expr.eval]
  rfl

end CCFRaft.SymbolicModel
