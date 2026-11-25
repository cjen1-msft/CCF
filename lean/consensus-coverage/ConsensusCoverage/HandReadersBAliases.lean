module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.SolvedWitnesses

namespace ConsensusCoverage.HandReadersBAliases

open ActionProfile

private theorem equal (s : Step) (a b : Classes.StepBranch)
    (h : @SolvedWitnesses.sig ⟨s.cfg⟩ _ _ s.context a ↔ @SolvedWitnesses.sig ⟨s.cfg⟩ _ _ s.context b) :
    label s (.step a) = label s (.step b) := by
  letI : Consensus.Proofs.Config.InitialConfiguration := ⟨s.cfg⟩
  exact Bool.eq_iff_iff.mpr ((label_true s (.step a)).trans ((SolvedWitnesses.sig_iff s.context a).trans
    (h.trans ((SolvedWitnesses.sig_iff s.context b).symm.trans (label_true s (.step b)).symm))))

/-- The normalized loop generalizes its continuation constructor. A runtime
break and a runtime yield are not opposite answers to these proof questions. -/
public theorem loop (s : Step) : label s (.step .forIn__step_done) = label s (.step .forIn__step_yield) :=
  equal s _ _ Iff.rfl

/-- Both content constructors enter exactly the same signature-classification
callers. The questions do not inspect the recorded event's content tag. -/
public theorem content (s : Step) :
    label s (.step .isSignature_eq_true_content_transaction) = label s (.step .isSignature_eq_true_content_signature) :=
  equal s _ _ Iff.rfl

end ConsensusCoverage.HandReadersBAliases
