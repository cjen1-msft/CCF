module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.Classes
import all ConsensusCoverage.Classes
import all Consensus.Proofs.SafetyInvariant

/-!
# The generated state questions under the invariant

Both state questions ask for two present nodes whose committed prefixes lie within
comparable committed parts. Under `Inv` every present node has a backed commit prefix,
so each question holds exactly when some node is present: take the same node twice.
-/

namespace ConsensusCoverage.StateBasis

open Consensus Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

/-- The single semantic coordinate of the state questions. -/
public def Present [Config.InitialConfiguration] (f : Frame) : Prop := f.current.nodes ≠ []

public theorem ctx_iff_present [Config.InitialConfiguration] (f : Frame) (inv : Inv f)
    (b : Classes.StateBranch) : Classes.ctx f b ↔ Present f := by
  constructor
  · intro h
    cases b <;> obtain ⟨_, _, _, _, now, _⟩ := h <;> exact List.ne_nil_of_mem now
  · intro nonempty
    obtain ⟨⟨n, st⟩, mem⟩ := List.exists_mem_of_ne_nil _ nonempty
    obtain ⟨term, backed⟩ := (inv.commit_backed n st mem).1
    obtain ⟨e, part, commit, le, sub⟩ := backed
    cases b <;>
      exact ⟨n, n, st, st, mem, mem, term, ⟨e, part, commit, le, sub⟩, e,
        ⟨part, commit, le, sub⟩, part, ⟨commit, le, sub⟩, commit, ⟨le, sub⟩, le, sub,
        term, ⟨e, part, commit, le, sub⟩, e, ⟨part, commit, le, sub⟩, part,
        ⟨commit, le, sub⟩, commit, ⟨le, sub⟩, le, sub, List.prefix_refl _⟩

end ConsensusCoverage.StateBasis
