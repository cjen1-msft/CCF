module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepEffectCases

open CCF Consensus Consensus.Proofs Consensus.Model Consensus.Model.Node Safety SolvedWitnesses

set_option maxRecDepth 8192

-- The fold's induction variable is abstract in the normalized case. Use
-- the actual append caller's flush effect, for which the empty tail is an
-- induction hypothesis and an arbitrary head only updates the sent index.
theorem flushCons [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
    (h : step_foldlM__items_nil f t c) : step_foldlM__items_cons f t c := by
  obtain ⟨_, ⟨self, state, event, post, outputs, root, which, ran, front, original⟩,
    entries, rfl⟩ := h
  let flush := fun (s : NodeState) (p : NodeID × Nat) =>
    sendEntries (Capabilities.record self) self s p.1 p.2
  refine ⟨NodeID × Nat, flush, .inl ⟨Capabilities.record self, self, .append entries,
    ⟨state, event, post, outputs, root, which, ran, front, original, rfl⟩,
    entries, rfl, rfl, rfl, ?_⟩, [], ?_, ?_⟩
  · rfl
  · intro _ kept
    exact Direct.Keeps.pure' kept
  · rintro _ ⟨_, _⟩ kept
    unfold flush sendEntries
    exact Direct.Keeps.seq' fun _ => Direct.Keeps.seq' fun _ => Direct.Keeps.pure' kept.withSent

end ConsensusCoverage.DeepEffectCases
