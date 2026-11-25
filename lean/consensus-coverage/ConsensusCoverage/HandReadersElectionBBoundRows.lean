module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersElectionBBounds
import all ConsensusCoverage.HandReadersElectionBBounds
import all ConsensusCoverage.HandReadersElectionBReflect
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ActionProfile
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElectionB.Bounds

open HandReadersA ActionProfile ReadersAtoms Consensus.Proofs Safety
set_option maxRecDepth 16384
set_option maxHeartbeats 0
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

-- Keep the adapter indirect: specializing it with these four reflected
-- functions would duplicate their compiled bodies in the dispatcher.
@[noinline, nospecialize] private def readView (f : [Config.InitialConfiguration] → XView → Bool) : Reader :=
  fun cfg s a t hist => (ofXAction cfg s t hist a).any (@f ⟨cfg⟩)

@[noinline, nospecialize] private def row (b : Classes.StepBranch) (f : [Config.InitialConfiguration] → XView → Bool)
    (h : ∀ [Config.InitialConfiguration] {fr t} (c : Ctx fr t) (x : XView) (_ : x.Matches c),
      f x = true ↔ SolvedWitnesses.sig c b) : Exact b where
  eval := readView @f
  eq_label := (Reflect.exact b @f h).eq_label

def empty : Exact .maxCommittableIndexBounded_values_nil :=
  row _ (@Reflected.R.step_maxCommittableIndexBounded_values_nil)
    (fun c x ok => Reflected.R.step_maxCommittableIndexBounded_values_nil_iff _ _ c x ok)

def nonempty : Exact .maxCommittableIndexBounded_values_cons :=
  row _ (@Reflected.R.step_maxCommittableIndexBounded_values_cons)
    (fun c x ok => Reflected.R.step_maxCommittableIndexBounded_values_cons_iff _ _ c x ok)

def signature : Exact .maxCommittableIndexBounded_signature_pos :=
  row _ (@Reflected.R.step_maxCommittableIndexBounded_signature_pos)
    (fun c x ok => Reflected.R.step_maxCommittableIndexBounded_signature_pos_iff _ _ c x ok)

def nonsignature : Exact .maxCommittableIndexBounded_signature_neg :=
  row _ (@Reflected.R.step_maxCommittableIndexBounded_signature_neg)
    (fun c x ok => Reflected.R.step_maxCommittableIndexBounded_signature_neg_iff _ _ c x ok)

end ConsensusCoverage.HandReadersElectionB.Bounds
